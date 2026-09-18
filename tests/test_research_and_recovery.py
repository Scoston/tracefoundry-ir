import json

import httpx
import pytest
from conftest import Harness
from test_gateway import FakeProvider
from test_http_and_tools import pack_fixture

from tracefoundry_ir.provider import ModelProvider
from tracefoundry_ir.security import strict_json


class DraftProvider(FakeProvider):
    def prepare_pack(self, goal, source):
        return {"goal": goal, "source": source, "model": "fixture"}

    def draft_pack(self, goal, source):
        self.calls += 1
        return {"pack": pack_fixture(), "review_status": "unreviewed", "promoted": False}, {
            "request": self.prepare_pack(goal, source),
            "response": pack_fixture(),
        }


def test_research_drafting_requires_disclosure_approval_and_separate_release(tmp_path):
    provider = DraftProvider()
    h = Harness(tmp_path / "research", provider)
    try:
        source = h.stage(
            b"Research fixture: match StopLogging; require human validation and a negative GetObject test."
        )
        draft = h.propose(
            "draft_pack",
            {"artifact_id": source["id"], "goal": "Draft a bounded audit visibility review pack"},
        )
        assert h.execute(draft).status_code == 403 and provider.calls == 0
        h.review(draft)
        assert h.execute(draft).status_code == 403 and provider.calls == 0
        h.review(draft, h.bob)
        result = h.execute(draft).json()
        assert result["state"] == "COMPLETED" and provider.calls == 1
        assert result["result"]["review_status"] == "unreviewed"
        assert h.alice.get(h.base).json()["packs"] == []
        promote = h.propose("promote_pack", {"artifact_id": result["result"]["draft_artifact_id"]})
        assert h.execute(promote).status_code == 403
        h.review(promote)
        h.review(promote, h.bob)
        assert h.execute(promote).json()["state"] == "COMPLETED"
        assert len(h.alice.get(h.base).json()["packs"]) == 1
    finally:
        h.close()


@pytest.mark.parametrize("code_in_pack", [False, True])
def test_actual_model_pack_validator_preserves_output_and_never_promotes(monkeypatch, code_in_pack):
    monkeypatch.setenv("TFIR_MODEL_URL", "https://model.example.invalid/v1/chat/completions")
    monkeypatch.setenv("TFIR_MODEL_ALLOWED_HOSTS", "model.example.invalid")
    monkeypatch.setenv("TFIR_MODEL_NAME", "fixture")
    monkeypatch.setenv("TFIR_MODEL_API_KEY", "test-placeholder")
    pack = pack_fixture()
    if code_in_pack:
        pack["executable"] = "not allowed"
    raw = {"choices": [{"message": {"content": json.dumps(pack)}}]}
    client_type = httpx.Client
    monkeypatch.setattr(
        "tracefoundry_ir.provider.httpx.Client",
        lambda **kwargs: client_type(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json=raw)), **kwargs
        ),
    )
    result, transcript = ModelProvider().draft_pack(
        "Create a bounded audit rule", {"text": "Synthetic method"}
    )
    assert result["promoted"] is False
    assert result["review_status"] == ("rejected_by_validator" if code_in_pack else "unreviewed")
    assert transcript["response_base64"]


def test_session_identity_cannot_be_changed_in_database(harness):
    with harness.store.connect() as c:
        c.execute("UPDATE sessions SET username='bob' WHERE username='alice'")
        c.commit()
    assert harness.alice.get(harness.base).status_code == 401


def test_logged_out_session_cannot_be_restored_from_old_database_row(harness):
    h = harness
    token = h.bob.cookies.get("tfir_session")
    with h.store.connect() as c:
        row = tuple(c.execute("SELECT * FROM sessions WHERE username='bob'").fetchone())
    assert h.bob.post("/api/logout").status_code == 200
    with h.store.connect() as c:
        c.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?)", row)
        c.commit()
    h.bob.cookies.set("tfir_session", token)
    assert h.bob.get(h.base).status_code == 401


def test_invalid_time_window_is_rejected_as_input(harness):
    a = harness.imported()
    result = harness.alice.post(
        harness.base + "/decisions",
        json={
            "tool": "timeline",
            "arguments": {"artifact_ids": [a["id"]], "start": "invalid timestamp"},
            "purpose": "Test invalid bounded query input",
        },
    )
    assert result.status_code == 422


def test_recovery_records_unknown_without_repeating_work(harness):
    h = harness
    decision = h.propose(
        "record_gap", {"description": "A synthetic coverage gap", "affected_scope": "logs"}
    )
    h.review(decision)
    result = h.execute(decision).json()
    # Emulate a process dying with a durable RUNNING intent. Recovery must not call a tool.
    with h.store.connect() as c:
        c.execute("UPDATE executions SET state='RUNNING',result=NULL WHERE id=?", (result["id"],))
        c.commit()
    assert h.app.state.service.recover() == 1
    assert h.execute(decision).json()["state"] == "OUTCOME_UNKNOWN"
    with h.store.connect() as c:
        gaps = [
            strict_json(r[0])
            for r in c.execute(
                "SELECT body FROM audit WHERE ledger=? AND json_extract(body,'$.event')='coverage.gap_declared'",
                (h.case,),
            )
        ]
    assert len(gaps) == 1
