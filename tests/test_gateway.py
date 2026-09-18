from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from conftest import PASSWORD, SAMPLE, Harness

from tracefoundry_ir import tools
from tracefoundry_ir.store import Fault


def test_no_approval_no_execution(harness):
    h = harness
    a = h.stage()
    d = h.propose("import_logs", {"artifact_id": a["id"], "format": "cloudtrail"})
    assert h.execute(d).status_code == 403
    with h.store.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM executions").fetchone()[0] == 0
        assert c.execute("SELECT COUNT(*) FROM chunks").fetchone()[0] == 0


def test_approve_execute_and_replay_are_single_use(harness):
    h = harness
    a = h.stage()
    d = h.propose("import_logs", {"artifact_id": a["id"], "format": "cloudtrail"})
    review = h.review(d)
    assert review.status_code == 201
    assert review.json()["body"]["principal_kind"] == "human"
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: h.execute(d), range(2)))
    assert {r.status_code for r in responses} == {200}
    assert len({r.json()["id"] for r in responses}) == 1
    assert h.execute(d).json()["state"] == "COMPLETED"
    with h.store.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM chunks").fetchone()[0] == len(SAMPLE["Records"])
        assert c.execute("SELECT COUNT(*) FROM executions").fetchone()[0] == 1


@pytest.mark.parametrize(
    "attack", ["wrong_digest", "wrong_password", "extra_identity", "extra_approval_flag"]
)
def test_review_cannot_be_forged(harness, attack):
    h = harness
    d = h.propose(
        "record_gap",
        {"description": "A known collection coverage gap", "affected_scope": "CloudTrail"},
    )
    changes = {
        "wrong_digest": {"decision_digest": "0" * 64},
        "wrong_password": {"password": "not-the-password"},
        "extra_identity": {"subject": "bob"},
        "extra_approval_flag": {"approved": True},
    }[attack]
    assert h.review(d, **changes).status_code in {403, 409, 422}
    assert h.execute(d).status_code == 403


def test_proposer_cannot_lower_policy(harness):
    result = harness.alice.post(
        harness.base + "/decisions",
        json={
            "tool": "close_case",
            "arguments": {
                "conclusion": "Synthetic closure note",
                "residual_uncertainty": "No live source coverage",
            },
            "purpose": "Try to lower trusted approval policy",
            "required_role_groups": [],
        },
    )
    assert result.status_code == 422


def test_agent_identity_cannot_log_in(harness):
    harness.store.add_user("robot", PASSWORD, ["supervisor"], kind="service")
    result = harness.alice.post("/api/login", json={"username": "robot", "password": PASSWORD})
    assert result.status_code == 403


def test_rejected_decision_never_executes(harness):
    d = harness.propose(
        "record_gap", {"description": "An unsupported proposed gap", "affected_scope": "unknown"}
    )
    assert harness.review(d, verdict="reject").status_code == 201
    assert harness.execute(d).status_code == 409


def test_expiration_does_not_auto_approve(harness):
    d = harness.propose(
        "record_gap",
        {"description": "A synthetic source gap", "affected_scope": "logs"},
        ttl_minutes=1,
    )
    assert harness.review(d).status_code == 201
    future = (datetime.now(UTC) + timedelta(minutes=2)).isoformat()
    with patch("tracefoundry_ir.service.now", return_value=future):
        assert harness.execute(d).status_code == 410


def test_revocation_blocks_dispatch_even_if_materialized_row_removed(harness):
    h = harness
    d = h.propose(
        "record_gap", {"description": "An explicitly recorded gap", "affected_scope": "logs"}
    )
    review = h.review(d).json()
    r = h.alice.post(
        h.base + "/approvals/" + review["body"]["id"] + "/revoke",
        json={"reason": "Scope must be reconsidered"},
    )
    assert r.status_code == 200
    with h.store.connect() as c:
        c.execute("DELETE FROM revocations")
        c.commit()
    assert h.execute(d).status_code == 403


def test_current_role_loss_blocks_prior_approval(harness):
    h = harness
    d = h.propose(
        "close_case",
        {
            "conclusion": "Synthetic investigation complete",
            "residual_uncertainty": "No production source was used",
        },
    )
    assert h.review(d, h.bob).status_code == 201
    h.store.change_user("bob", roles=["analyst"])
    assert h.execute(d).status_code == 403


def test_case_membership_loss_blocks_prior_approval(harness):
    h = harness
    d = h.propose(
        "close_case",
        {
            "conclusion": "Synthetic investigation complete",
            "residual_uncertainty": "No production source was used",
        },
    )
    assert h.review(d, h.bob).status_code == 201
    assert h.alice.delete(h.base + "/members/bob").status_code == 200
    assert h.execute(d).status_code == 404


def test_same_human_cannot_fill_two_roles(harness):
    h = harness
    a = h.stage()
    d = h.propose("export_case", {"artifact_ids": [a["id"]], "recipient": "bob"})
    assert h.review(d).status_code == 201
    assert h.review(d).status_code == 409
    assert h.execute(d).status_code == 403
    assert h.review(d, h.bob).status_code == 201
    result = h.execute(d)
    assert result.json()["state"] == "COMPLETED", result.text


def test_tool_or_policy_drift_requires_new_review(harness, monkeypatch):
    d = harness.propose(
        "record_gap", {"description": "A known collection gap", "affected_scope": "logs"}
    )
    assert harness.review(d).status_code == 201
    monkeypatch.setattr(tools, "POLICY", "changed-policy")
    assert harness.execute(d).status_code == 409


def test_audit_failure_prevents_intent(harness, monkeypatch):
    d = harness.propose(
        "record_gap", {"description": "A known collection gap", "affected_scope": "logs"}
    )
    assert harness.review(d).status_code == 201

    def fail(*args, **kwargs):
        raise Fault(503, "audit_unavailable")

    monkeypatch.setattr(harness.store, "audit", fail)
    # The app has its own Store instance; fail its authoritative sink.
    monkeypatch.setattr(harness.app.state.service.store, "audit", fail)
    assert harness.execute(d).status_code == 503
    with harness.store.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM executions").fetchone()[0] == 0


def test_checkpoint_failure_after_intent_blocks_dispatch(harness, monkeypatch):
    h = harness
    a = h.stage()
    d = h.propose("import_logs", {"artifact_id": a["id"], "format": "cloudtrail"})
    assert h.review(d).status_code == 201

    def fail(*args):
        raise OSError("simulated witness write failure")

    monkeypatch.setattr(h.app.state.service.store, "checkpoint", fail)
    # Disable TestClient re-raising an intentionally simulated infrastructure exception.
    h.alice.raise_server_exceptions = False
    h.alice._transport.raise_server_exceptions = False
    assert h.execute(d).status_code == 503
    with h.store.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM chunks").fetchone()[0] == 0


def test_fabricated_citations_rejected(harness):
    result = harness.alice.post(
        harness.base + "/decisions",
        json={
            "tool": "accept_finding",
            "purpose": "Attempt fabricated citation",
            "arguments": {
                "claim": "An unsupported conclusion",
                "classification": "observation",
                "severity": "high",
                "citations": [{"chunk_id": "a" * 32 + ":0", "relation": "supports"}],
                "limitations": "No source was supplied",
            },
        },
    )
    assert result.status_code == 422


def test_unknown_tools_and_sql_arguments_rejected(harness):
    for tool, args in [
        ("shell", {"command": "id"}),
        ("timeline", {"artifact_ids": ["fake"], "sql": "SELECT * FROM users"}),
    ]:
        r = harness.alice.post(
            harness.base + "/decisions",
            json={"tool": tool, "arguments": args, "purpose": "Attempt an unauthorized capability"},
        )
        assert r.status_code == 422


def test_cross_tenant_and_case_access_are_blocked(harness):
    h = harness
    for username in ["charlie", "outsider"]:
        client = h.login(username)
        assert client.get(h.base).status_code == 404
        assert client.get(h.base + "/audit").status_code == 404
        assert client.get("/api/cases").json() == []
    assert h.alice.post(h.base + "/members", json={"username": "outsider"}).status_code == 404
    a = h.stage()
    charlie = h.clients["charlie"]
    case2 = charlie.post(
        "/api/cases", json={"title": "Other case", "description": "A separate synthetic case"}
    ).json()["id"]
    r = charlie.post(
        f"/api/cases/{case2}/decisions",
        json={
            "tool": "import_logs",
            "arguments": {"artifact_id": a["id"], "format": "cloudtrail"},
            "purpose": "Attempt evidence from another case",
        },
    )
    assert r.status_code == 404
    assert charlie.get(h.base + "/artifacts/" + a["id"]).status_code == 404


class FakeProvider:
    url = "https://model.example.invalid/v1/chat/completions"

    def __init__(self, fail=False):
        self.calls = 0
        self.fail = fail

    def binding(self):
        return {"endpoint": self.url, "model": "test-fixture", "system_prompt_sha256": "a" * 64}

    def prepare(self, question, rows):
        return {"question": question, "evidence": rows, "model": "test-fixture"}

    def assess(self, question, rows):
        self.calls += 1
        if self.fail:
            raise TimeoutError("synthetic provider timeout")
        return {"findings": [], "review_status": "unreviewed"}, {
            "request": self.prepare(question, rows),
            "response": {"findings": []},
        }


@pytest.mark.parametrize("fail", [False, True])
def test_model_needs_two_reviews_and_never_retries_on_timeout(tmp_path, fail):
    provider = FakeProvider(fail)
    h = Harness(tmp_path / "model-state", provider)
    try:
        a = h.imported()
        d = h.propose(
            "model_assess",
            {
                "artifact_ids": [a["id"]],
                "question": "Assess these events with explicit evidence citations",
            },
        )
        assert h.review(d).status_code == 201
        assert h.execute(d).status_code == 403 and provider.calls == 0
        assert h.review(d, h.bob).status_code == 201
        result = h.execute(d).json()
        assert result["state"] == ("OUTCOME_UNKNOWN" if fail else "COMPLETED")
        assert provider.calls == 1
        assert h.execute(d).json()["id"] == result["id"] and provider.calls == 1
        with h.store.connect() as c:
            assert (
                c.execute("SELECT COUNT(*) FROM artifacts WHERE kind='model_request'").fetchone()[0]
                == 1
            )
        assert not h.alice.get(h.base).json()["findings"]
    finally:
        h.close()


def test_new_analysis_needs_new_approval(harness):
    a = harness.imported()
    d = harness.propose("timeline", {"artifact_ids": [a["id"]], "action": "StopLogging"})
    assert harness.execute(d).status_code == 403


def test_case_closure_requires_supervisor_and_blocks_later_work(harness):
    h = harness
    h.alice.post(h.base + "/members", json={"username": "charlie"})
    charlie = h.login("charlie")
    d = h.propose(
        "close_case",
        {
            "conclusion": "Synthetic case is complete",
            "residual_uncertainty": "No complete source coverage claimed",
        },
    )
    assert h.review(d, charlie).status_code == 403
    assert h.review(d, h.bob).status_code == 201
    assert h.execute(d).json()["state"] == "COMPLETED"
    assert h.alice.get(h.base).json()["closed"] == 1
    assert (
        h.alice.post(
            h.base + "/decisions",
            json={
                "tool": "record_gap",
                "arguments": {"description": "An additional source gap", "affected_scope": "logs"},
                "purpose": "Try changing a closed case",
            },
        ).status_code
        == 409
    )
