"""Exercise the real analyst UI using disposable state and synthetic evidence."""

import argparse
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
from playwright.sync_api import expect, sync_playwright

from tracefoundry_ir.store import Store


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", choices=["firefox", "chromium"], default="firefox")
    parser.add_argument("--screenshots", default="")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    screenshot_dir = Path(args.screenshots).resolve() if args.screenshots else None
    if screenshot_dir:
        screenshot_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tfir-browser-") as temporary:
        data = Path(temporary) / "state"
        store = Store.initialize(data)
        passwords = {
            "analyst-one": secrets.token_urlsafe(24),
            "reviewer-two": secrets.token_urlsafe(24),
        }
        store.add_user("analyst-one", passwords["analyst-one"], ["admin", "analyst", "supervisor"])
        store.add_user("reviewer-two", passwords["reviewer-two"], ["supervisor"])
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        environment = {**os.environ, "PYTHONPATH": str(root / "src")}
        with (Path(temporary) / "server.log").open("wb") as log:
            process = subprocess.Popen(  # noqa: S603 - fixed local interpreter and source module
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
                cwd=root,
                env=environment,
                stdout=log,
                stderr=log,
            )
            try:
                base = f"http://127.0.0.1:{port}"
                print("Browser check: waiting for loopback service", flush=True)
                deadline = time.monotonic() + 15
                while True:
                    try:
                        response = httpx.get(base + "/health", timeout=1, trust_env=False)
                        if response.status_code == 200:
                            break
                    except httpx.HTTPError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("Local test server did not start") from None
                        time.sleep(0.1)
                with sync_playwright() as playwright:
                    print("Browser check: launching browser", flush=True)
                    browser = getattr(playwright, args.browser).launch(headless=True, timeout=30000)
                    context = browser.new_context(viewport={"width": 1440, "height": 1100})
                    page = context.new_page()
                    page.set_default_timeout(15000)
                    errors = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.goto(base)
                    print("Browser check: testing the analyst workflow", flush=True)
                    if screenshot_dir:
                        page.screenshot(path=str(screenshot_dir / "login.png"), full_page=True)

                    def login(username):
                        page.get_by_label("Username", exact=True).fill(username)
                        page.get_by_label("Password", exact=True).fill(passwords[username])
                        page.get_by_role("button", name="Sign in", exact=False).click()
                        expect(page.locator("#workspace")).to_be_visible()

                    def sign_and_execute(username, *, execute=True):
                        page.locator('button[data-action="review"]:not([disabled])').first.click()
                        page.get_by_label("Review rationale").fill(
                            "Checked exact selected evidence, scope, expiry, and tool arguments."
                        )
                        page.get_by_label("Re-enter your password").fill(passwords[username])
                        page.get_by_role("button", name="Sign human approval").click()
                        expect(page.locator("#modal")).not_to_be_visible()
                        if execute:
                            page.locator(
                                'button[data-action="execute"]:not([disabled])'
                            ).first.click()
                            expect(
                                page.locator(".decision").first.locator(".badge").first
                            ).to_have_text("COMPLETED")

                    def propose(tool, purpose):
                        page.get_by_role("button", name="+ Propose operation").click()
                        page.get_by_label("Operation", exact=True).select_option(tool)
                        page.get_by_label("Purpose of this operation").fill(purpose)
                        page.get_by_role("button", name="Submit for human review").click()
                        expect(page.locator("#modal")).not_to_be_visible()

                    login("analyst-one")
                    page.get_by_role("button", name="+ New investigation").click()
                    page.get_by_label("Case title").fill("AWS credential & audit review")
                    page.get_by_label("Investigation purpose").fill(
                        "Review audit configuration and credential changes in a bounded synthetic AWS export. Validate authorization and preserve collection gaps."
                    )
                    page.get_by_role("button", name="Save", exact=True).click()
                    expect(
                        page.get_by_role("heading", name="AWS credential & audit review")
                    ).to_be_visible()
                    page.get_by_role("button", name="Manage access").click()
                    page.locator('#modal input[name="username"]').fill("reviewer-two")
                    page.get_by_role("button", name="Save", exact=True).click()
                    expect(page.locator("#modal")).not_to_be_visible()
                    page.get_by_role("button", name="Evidence", exact=True).click()
                    page.get_by_role("button", name="+ Stage evidence").click()
                    page.locator("#source-file").set_input_files(
                        root / "examples" / "cloudtrail-synthetic.json"
                    )
                    page.get_by_label("Source system").fill("Synthetic AWS CloudTrail export")
                    page.get_by_label("Coverage declaration").select_option("partial")
                    page.get_by_label("Coverage limits").fill(
                        "Three fictional events. This fixture does not establish source completeness or malicious intent."
                    )
                    page.get_by_role("button", name="Preserve exact bytes").click()
                    expect(page.locator("#modal")).not_to_be_visible()
                    page.get_by_role("button", name="Propose import").click()
                    page.get_by_label("Purpose of this operation").fill(
                        "Normalize the exact staged synthetic CloudTrail export."
                    )
                    page.get_by_role("button", name="Submit for human review").click()
                    expect(page.locator("#modal")).not_to_be_visible()
                    expect(page.locator('button[data-action="execute"]').first).to_be_disabled()
                    sign_and_execute("analyst-one")
                    propose("timeline", "Build a bounded timeline from this one preserved export.")
                    sign_and_execute("analyst-one")
                    propose(
                        "suggest_findings",
                        "Identify candidate audit and credential changes for a human.",
                    )
                    sign_and_execute("analyst-one")
                    page.get_by_role("button", name="Findings", exact=True).click()
                    expect(page.get_by_text("candidate · unreviewed").first).to_be_visible()
                    page.get_by_role("button", name="Propose acceptance").first.click()
                    page.get_by_label("Purpose of this operation").fill(
                        "Retain this evidence-linked hypothesis with its stated limitations."
                    )
                    page.get_by_role("button", name="Submit for human review").click()
                    expect(page.locator("#modal")).not_to_be_visible()
                    sign_and_execute("analyst-one")
                    page.get_by_role("button", name="+ Propose operation").click()
                    page.get_by_label("Operation", exact=True).select_option("export_case")
                    page.get_by_label("recipient", exact=True).select_option("reviewer-two")
                    page.get_by_label("Purpose of this operation").fill(
                        "Release the exact snapshot to the named second reviewer."
                    )
                    page.get_by_role("button", name="Submit for human review").click()
                    expect(page.locator("#modal")).not_to_be_visible()
                    sign_and_execute("analyst-one", execute=False)
                    expect(page.locator('button[data-action="execute"]').first).to_be_disabled()
                    page.get_by_role("button", name="Overview", exact=True).click()
                    if screenshot_dir:
                        expect(page.locator("#toast")).not_to_be_visible(timeout=10000)
                        page.screenshot(path=str(screenshot_dir / "workspace.png"), full_page=True)
                    page.get_by_role("button", name="Decisions", exact=True).click()
                    if screenshot_dir:
                        page.screenshot(path=str(screenshot_dir / "decisions.png"), full_page=True)
                    page.get_by_role("button", name="Sign out", exact=False).click()
                    login("reviewer-two")
                    page.get_by_role("button", name="Decisions", exact=True).click()
                    sign_and_execute("reviewer-two")
                    page.get_by_role("button", name="Evidence", exact=True).click()
                    export_row = page.locator("tr").filter(has_text="case-export.zip")
                    with page.expect_download() as download:
                        export_row.get_by_role("button", name="Retrieve bytes").click()
                    assert download.value.suggested_filename.endswith(".zip")
                    page.get_by_role("button", name="Audit trail", exact=True).click()
                    expect(page.get_by_role("heading", name="Accountability trail")).to_be_visible()
                    page.get_by_role("button", name="Findings", exact=True).click()
                    page.get_by_role("button", name="Challenge finding", exact=True).first.click()
                    page.get_by_label("explanation", exact=True).fill(
                        "This record may reflect a legitimate maintenance change; assess the source context."
                    )
                    page.get_by_label("Purpose of this operation").fill(
                        "Challenge the inference without altering the historical finding."
                    )
                    page.get_by_role("button", name="Submit for human review").click()
                    expect(page.locator("#modal")).not_to_be_visible()
                    sign_and_execute("reviewer-two")
                    page.get_by_role("button", name="Findings", exact=True).click()
                    page.get_by_role(
                        "button", name="Propose challenge resolution", exact=True
                    ).click()
                    page.get_by_label("disposition", exact=True).select_option(
                        "uncertainty_retained"
                    )
                    page.get_by_label("explanation", exact=True).fill(
                        "Reviewers retain uncertainty because the synthetic source cannot establish intent."
                    )
                    page.get_by_label("Purpose of this operation").fill(
                        "Resolve the challenge with explicit uncertainty and a second human review."
                    )
                    page.get_by_role("button", name="Submit for human review").click()
                    expect(page.locator("#modal")).not_to_be_visible()
                    sign_and_execute("reviewer-two", execute=False)
                    page.get_by_role("button", name="Sign out", exact=False).click()
                    login("analyst-one")
                    page.get_by_role("button", name="Decisions", exact=True).click()
                    sign_and_execute("analyst-one")
                    page.get_by_role("button", name="Findings", exact=True).click()
                    expect(page.get_by_text("uncertainty retained", exact=True)).to_be_visible()
                    if screenshot_dir:
                        page.screenshot(path=str(screenshot_dir / "challenges.png"), full_page=True)
                    page.get_by_role("button", name="Overview", exact=True).click()
                    page.set_viewport_size({"width": 390, "height": 844})
                    assert page.evaluate(
                        "document.documentElement.scrollWidth <= window.innerWidth"
                    ), "Page overflows mobile width"
                    if screenshot_dir:
                        expect(page.locator("#toast")).not_to_be_visible(timeout=10000)
                        page.screenshot(path=str(screenshot_dir / "mobile.png"), full_page=True)
                    page.get_by_role("button", name="Change password", exact=True).click()
                    page.get_by_label("Current password", exact=True).fill(passwords["analyst-one"])
                    passwords["analyst-one"] = secrets.token_urlsafe(24)
                    page.get_by_label("New password", exact=True).fill(passwords["analyst-one"])
                    page.get_by_label("Confirm new password", exact=True).fill(
                        passwords["analyst-one"]
                    )
                    page.get_by_role("button", name="Save", exact=True).click()
                    expect(page.locator("#login-view")).to_be_visible()
                    expect(page.locator("#main-content")).to_be_empty()
                    login("analyst-one")
                    assert not errors, errors
                    context.close()
                    browser.close()
                print(
                    json.dumps(
                        {
                            "browser": args.browser,
                            "result": "PASS",
                            "flows": [
                                "login",
                                "case",
                                "membership",
                                "stage",
                                "unapproved_block",
                                "review",
                                "execute",
                                "timeline",
                                "candidates",
                                "accepted_finding",
                                "two_person_export",
                                "download",
                                "audit",
                                "finding_challenge",
                                "two_person_challenge_resolution",
                                "password_change",
                                "logout_clears_case_data",
                                "mobile_no_overflow",
                            ],
                            "page_errors": 0,
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
