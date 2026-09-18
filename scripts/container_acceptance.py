"""Run inside the built image to check installed assets, non-root execution and the API."""

import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

from tracefoundry_ir.store import Store


def main():
    if os.name != "nt" and os.getuid() == 0:
        raise RuntimeError("Container must run as an unprivileged user")
    with tempfile.TemporaryDirectory(prefix="tfir-container-") as directory:
        data = Path(directory) / "state"
        store = Store.initialize(data)
        password = secrets.token_urlsafe(24)
        store.add_user("smoke-analyst", password, ["analyst", "supervisor"])
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        process = subprocess.Popen(  # noqa: S603 - fixed interpreter and module; no shell
            [
                sys.executable,
                "-m",
                "tracefoundry_ir.cli",
                "--data-dir",
                str(data),
                "serve",
                "--port",
                str(port),
            ],
            stdout=subprocess.DEVNULL,
        )
        try:
            with httpx.Client(
                base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=5
            ) as client:
                deadline = time.monotonic() + 20
                while True:
                    try:
                        response = client.get("/health")
                        response.raise_for_status()
                        break
                    except httpx.HTTPError:
                        if time.monotonic() >= deadline or process.poll() is not None:
                            raise
                        time.sleep(0.1)
                for path in ("/", "/static/app.js", "/static/styles.css"):
                    response = client.get(path)
                    response.raise_for_status()
                    if not response.content:
                        raise RuntimeError("Missing packaged browser assets")
                login = client.post(
                    "/api/login", json={"username": "smoke-analyst", "password": password}
                )
                login.raise_for_status()
                client.headers["x-csrf-token"] = login.json()["csrf_token"]
                case = client.post(
                    "/api/cases",
                    json={
                        "title": "Container acceptance",
                        "description": "Synthetic installed package acceptance check",
                    },
                )
                case.raise_for_status()
                base = "/api/cases/" + case.json()["id"]
                decision = client.post(
                    base + "/decisions",
                    json={
                        "tool": "record_gap",
                        "purpose": "Confirm installed authority gates",
                        "arguments": {
                            "description": "This container test uses synthetic data only",
                            "affected_scope": "smoke test",
                        },
                    },
                )
                decision.raise_for_status()
                body = decision.json()
                path = base + "/decisions/" + body["body"]["id"]
                if client.post(path + "/execute").status_code != 403:
                    raise RuntimeError("Unreviewed operation was not blocked")
                review = client.post(
                    path + "/reviews",
                    json={
                        "password": password,
                        "verdict": "approve",
                        "rationale": "Reviewed synthetic scope and configured local authority",
                        "decision_digest": body["digest"],
                    },
                )
                review.raise_for_status()
                result = client.post(path + "/execute")
                result.raise_for_status()
                if result.json()["state"] != "COMPLETED":
                    raise RuntimeError("Reviewed operation failed")
                client.get(base + "/audit").raise_for_status()
            print(
                json.dumps(
                    {
                        "container_acceptance": "PASS",
                        "non_root": True,
                        "static_assets": True,
                        "human_gate": True,
                    }
                )
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
