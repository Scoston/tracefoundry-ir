import base64
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tracefoundry_ir.app import create_app
from tracefoundry_ir.security import canonical
from tracefoundry_ir.store import Store

PASSWORD = "Synthetic-test-password-42!"
SAMPLE = {
    "Records": [
        {
            "eventTime": "2026-09-18T09:00:00Z",
            "eventName": "StopLogging",
            "userIdentity": {"arn": "arn:aws:iam::111122223333:user/fixture"},
            "sourceIPAddress": "192.0.2.10",
        },
        {
            "eventTime": "2026-09-18T09:01:00Z",
            "eventName": "CreateAccessKey",
            "userIdentity": {"arn": "arn:aws:iam::111122223333:user/fixture"},
        },
        {
            "eventTime": "2026-09-18T09:02:00Z",
            "eventName": "GetObject",
            "userIdentity": {"arn": "arn:aws:iam::111122223333:user/fixture"},
        },
    ]
}


class Harness:
    def __init__(self, directory: Path, provider=None):
        self.store = Store.initialize(directory)
        self.store.add_user("alice", PASSWORD, ["admin", "analyst", "supervisor"])
        self.store.add_user("bob", PASSWORD, ["supervisor"])
        self.store.add_user("charlie", PASSWORD, ["analyst"])
        self.store.add_user("outsider", PASSWORD, ["supervisor"], "other")
        self.app = create_app(directory, provider=provider)
        self.clients = {}
        self.alice = self.login("alice")
        self.bob = self.login("bob")
        self.case = self.alice.post(
            "/api/cases",
            json={
                "title": "Synthetic credential investigation",
                "description": "Investigate a bounded synthetic CloudTrail export",
            },
        ).json()["id"]
        self.base = "/api/cases/" + self.case
        assert self.alice.post(self.base + "/members", json={"username": "bob"}).status_code == 200

    def login(self, username):
        client = TestClient(self.app)
        result = client.post("/api/login", json={"username": username, "password": PASSWORD})
        assert result.status_code == 200, result.text
        client.headers["x-csrf-token"] = result.json()["csrf_token"]
        self.clients[username] = client
        return client

    def stage(self, data=None, **overrides):
        data = canonical(SAMPLE) if data is None else data
        payload = {
            "filename": "synthetic-cloudtrail.json",
            "source": "Synthetic fixture",
            "content_base64": base64.b64encode(data).decode(),
            "coverage": "partial",
            "coverage_note": "Fictional events; no live source or complete source coverage",
            **overrides,
        }
        result = self.alice.post(self.base + "/evidence", json=payload)
        assert result.status_code == 201, result.text
        return result.json()

    def propose(self, tool, arguments, **overrides):
        result = self.alice.post(
            self.base + "/decisions",
            json={
                "tool": tool,
                "arguments": arguments,
                "purpose": "Explicit synthetic test operation",
                **overrides,
            },
        )
        assert result.status_code == 201, result.text
        return result.json()

    def review(self, decision, client=None, verdict="approve", **overrides):
        return (client or self.alice).post(
            self.base + "/decisions/" + decision["body"]["id"] + "/reviews",
            json={
                "verdict": verdict,
                "password": PASSWORD,
                "rationale": "Checked the exact scope and preserved evidence",
                "decision_digest": decision["digest"],
                **overrides,
            },
        )

    def execute(self, decision, client=None):
        return (client or self.alice).post(
            self.base + "/decisions/" + decision["body"]["id"] + "/execute"
        )

    def imported(self, data=None, format_name="cloudtrail"):
        artifact = self.stage(data)
        decision = self.propose(
            "import_logs", {"artifact_id": artifact["id"], "format": format_name}
        )
        assert self.review(decision).status_code == 201
        result = self.execute(decision)
        assert result.status_code == 200 and result.json()["state"] == "COMPLETED", result.text
        return artifact

    def close(self):
        for client in self.clients.values():
            client.close()


@pytest.fixture
def harness(tmp_path):
    h = Harness(tmp_path / "state")
    yield h
    h.close()
