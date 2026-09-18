import json

import httpx
import pytest
from conftest import PASSWORD
from fastapi.testclient import TestClient

from tracefoundry_ir.provider import ModelProvider
from tracefoundry_ir.security import canonical
from tracefoundry_ir.tools import parse_logs, validate_pack


def test_sessions_csrf_origin_and_content_type(harness):
    h = harness
    anonymous = TestClient(h.app)
    assert anonymous.get(h.base).status_code == 401
    assert (
        anonymous.get(h.base, headers={"Authorization": "Bearer wrong-audience-token"}).status_code
        == 401
    )
    r = h.alice.post(
        "/api/cases",
        json={"title": "Case", "description": "A synthetic case"},
        headers={"x-csrf-token": "invalid"},
    )
    assert r.status_code == 403
    assert (
        h.alice.post("/api/logout", headers={"Origin": "https://untrusted.example"}).status_code
        == 403
    )
    assert (
        h.alice.post("/api/cases", content="{}", headers={"Content-Type": "text/plain"}).status_code
        == 415
    )
    anonymous.close()


def test_duplicate_keys_and_body_limits(harness):
    h = harness
    assert (
        h.alice.post(
            "/api/cases",
            content='{"title":"a","title":"b","description":"x"}',
            headers={"Content-Type": "application/json"},
        ).status_code
        == 422
    )
    assert (
        h.alice.post(
            "/api/cases", content=b"x" * 4_100_001, headers={"Content-Type": "application/json"}
        ).status_code
        == 413
    )


def test_cookie_and_browser_security_headers(harness):
    result = harness.alice.post("/api/login", json={"username": "alice", "password": PASSWORD})
    cookie = result.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie
    headers = harness.alice.get("/").headers
    assert "script-src 'self'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["cache-control"] == "no-store"


def test_invalid_host_rejected(harness):
    assert harness.alice.get("/", headers={"Host": "evil.example"}).status_code == 400


def test_login_and_review_rate_limits(harness):
    h = harness
    for _ in range(5):
        assert (
            h.alice.post("/api/login", json={"username": "alice", "password": "bad"}).status_code
            == 401
        )
    assert (
        h.alice.post("/api/login", json={"username": "alice", "password": PASSWORD}).status_code
        == 429
    )
    d = h.propose(
        "record_gap", {"description": "A synthetic collection gap", "affected_scope": "logs"}
    )
    for _ in range(5):
        assert h.review(d, password="bad").status_code == 403
    assert h.review(d).status_code == 429


def test_logout_and_disabled_accounts_lose_access(harness):
    h = harness
    assert h.bob.post("/api/logout").status_code == 200
    assert h.bob.get(h.base).status_code == 401
    bob = h.login("bob")
    h.store.change_user("bob", active=False)
    assert bob.get(h.base).status_code == 401


@pytest.mark.parametrize(
    "format_name,data,action",
    [
        (
            "cloudtrail",
            {"Records": [{"eventTime": "2026-09-18T01:00:00Z", "eventName": "StopLogging"}]},
            "StopLogging",
        ),
        (
            "m365",
            {
                "value": [
                    {
                        "AuditData": json.dumps(
                            {
                                "CreationTime": "2026-09-18T01:00:00Z",
                                "Operation": "EditFlow",
                                "UserId": "synthetic@example.invalid",
                            }
                        )
                    }
                ]
            },
            "EditFlow",
        ),
        (
            "ocsf",
            [
                {
                    "time": 1758157200000,
                    "activity_name": "Logon",
                    "actor": {"user": {"name": "fixture"}},
                    "src_endpoint": {"ip": "192.0.2.1"},
                }
            ],
            "Logon",
        ),
        (
            "generic",
            [{"event_time": "2026-09-18T01:00:00Z", "action": "FixtureEvent"}],
            "FixtureEvent",
        ),
    ],
)
def test_parsers_preserve_locators_and_record_hashes(format_name, data, action):
    rows, warnings = parse_logs(canonical(data), "a" * 32, format_name)
    assert rows[0]["action"] == action
    assert rows[0]["locator"] and len(rows[0]["record_sha256"]) == 64
    assert rows[0]["chunk_id"] == "a" * 32 + ":0"
    assert not warnings


def test_jsonl_preserves_line_numbers_and_gaps():
    rows, warnings = parse_logs(b'{"action":"first"}\n\n{"action":"second"}', "a" * 32, "generic")
    assert [r["locator"] for r in rows] == ["line:1", "line:3"]
    assert len(warnings) == 2
    rows, warnings = parse_logs(b"[]", "a" * 32, "generic")
    assert not rows and "does not establish absence" in warnings[0]


def test_design_examples_not_importable_as_authority(harness):
    a = harness.stage(b'{"example_only":true,"eventName":"StopLogging"}')
    d = harness.propose("import_logs", {"artifact_id": a["id"], "format": "cloudtrail"})
    harness.review(d)
    r = harness.execute(d).json()
    assert r["state"] == "FAILED" and r["result"]["error"] == "log_parse_failed"


def test_source_integrity_failure_is_not_erased_by_local_hash(harness):
    a = harness.stage(
        source_integrity="failed", integrity_note="Native source digest validation failed"
    )
    d = harness.propose("import_logs", {"artifact_id": a["id"], "format": "cloudtrail"})
    harness.review(d)
    result = harness.execute(d).json()["result"]
    assert result["source_integrity"] == "failed"


def test_candidates_are_not_accepted_findings(harness):
    a = harness.imported()
    d = harness.propose("suggest_findings", {"artifact_ids": [a["id"]]})
    harness.review(d)
    result = harness.execute(d).json()["result"]
    assert len(result["findings"]) == 2
    assert all(f["classification"] == "hypothesis" for f in result["findings"])
    assert harness.alice.get(harness.base).json()["findings"] == []
    f = result["findings"][0]
    accepted = harness.propose(
        "accept_finding",
        {k: f[k] for k in ["claim", "classification", "severity", "citations", "limitations"]},
    )
    assert harness.execute(accepted).status_code == 403
    harness.review(accepted)
    assert harness.execute(accepted).json()["state"] == "COMPLETED"
    assert harness.alice.get(harness.base).json()["findings"][0]["classification"] == "hypothesis"


def test_timeline_explicit_limit_reports_truncation(harness):
    a = harness.imported()
    d = harness.propose("timeline", {"artifact_ids": [a["id"]], "limit": 1})
    harness.review(d)
    result = harness.execute(d).json()["result"]
    assert result["truncated"] and result["matched"] == 3 and len(result["rows"]) == 1


def pack_fixture():
    return {
        "name": "Audit visibility",
        "version": "1.0.0",
        "sources": [
            {
                "title": "Synthetic test method",
                "url": "https://example.invalid/research",
                "method_note": "Exact action-name matching for tests",
            }
        ],
        "rules": [
            {
                "id": "logging-stop",
                "field": "action",
                "equals": "StopLogging",
                "claim": "Audit logging was stopped; investigate authorization.",
                "severity": "high",
            }
        ],
        "tests": [
            {"event": {"action": "StopLogging"}, "expected_rule_ids": ["logging-stop"]},
            {"event": {"action": "GetObject"}, "expected_rule_ids": []},
        ],
    }


@pytest.mark.parametrize(
    "attack", ["executable", "wrong_expected", "duplicate_rule", "no_negative"]
)
def test_invalid_research_packs_rejected(attack):
    pack = pack_fixture()
    if attack == "executable":
        pack["code"] = "arbitrary instructions"
    if attack == "wrong_expected":
        pack["tests"][0]["expected_rule_ids"] = []
    if attack == "duplicate_rule":
        pack["rules"].append(pack["rules"][0])
    if attack == "no_negative":
        pack["tests"][1] = pack["tests"][0]
    with pytest.raises(ValueError):
        validate_pack(canonical(pack))


def test_pack_release_and_run_require_separate_reviews(harness):
    h = harness
    evidence = h.imported()
    pack = h.stage(canonical(pack_fixture()))
    d = h.propose("promote_pack", {"artifact_id": pack["id"]})
    h.review(d)
    assert h.execute(d).status_code == 403
    h.review(d, h.bob)
    result = h.execute(d).json()["result"]
    run = h.propose("run_pack", {"artifact_ids": [evidence["id"]], "pack_id": result["pack_id"]})
    assert h.execute(run).status_code == 403
    h.review(run)
    assert len(h.execute(run).json()["result"]["findings"]) == 1


def test_model_response_with_fabricated_citation_is_preserved_but_rejected(monkeypatch):
    monkeypatch.setenv("TFIR_MODEL_URL", "https://model.example.invalid/v1/chat/completions")
    monkeypatch.setenv("TFIR_MODEL_ALLOWED_HOSTS", "model.example.invalid")
    monkeypatch.setenv("TFIR_MODEL_NAME", "fixture")
    monkeypatch.setenv("TFIR_MODEL_API_KEY", "a-test-only-placeholder")
    provider = ModelProvider()
    raw = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "findings": [
                                {
                                    "claim": "An unsupported finding",
                                    "classification": "hypothesis",
                                    "citations": ["fake:9"],
                                }
                            ]
                        }
                    )
                }
            }
        ]
    }
    client_type = httpx.Client
    monkeypatch.setattr(
        "tracefoundry_ir.provider.httpx.Client",
        lambda **kwargs: client_type(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json=raw)), **kwargs
        ),
    )
    output, transcript = provider.assess(
        "Investigate these test events", [{"chunk_id": "a" * 32 + ":0"}]
    )
    assert output["review_status"] == "rejected_by_validator"
    assert transcript["response_base64"]
    assert "a-test-only-placeholder" not in json.dumps(transcript)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://example.invalid/v1",
        "https://evil.invalid/v1",
        "https://user:password@model.example.invalid/v1",
        "https://model.example.invalid/v1?key=secret",
    ],
)
def test_unapproved_model_endpoints_rejected(monkeypatch, endpoint):
    monkeypatch.setenv("TFIR_MODEL_URL", endpoint)
    monkeypatch.setenv("TFIR_MODEL_ALLOWED_HOSTS", "model.example.invalid")
    monkeypatch.setenv("TFIR_MODEL_NAME", "fixture")
    monkeypatch.setenv("TFIR_MODEL_API_KEY", "placeholder")
    with pytest.raises(ValueError):
        ModelProvider()
