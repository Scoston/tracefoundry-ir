import concurrent.futures
import json

import pytest
from conftest import PASSWORD
from cryptography.exceptions import InvalidTag

from tracefoundry_ir.maintenance import create_backup, inspect_state, restore_backup
from tracefoundry_ir.security import sha256, strict_json
from tracefoundry_ir.store import Fault, Store


def gap(h):
    return h.propose(
        "record_gap",
        {"description": "Known synthetic coverage limitation", "affected_scope": "test logs"},
    )


def abandon(h, monkeypatch):
    decision = gap(h)
    h.review(decision)

    class ProcessStopped(BaseException):
        pass

    def crash(*args):
        raise ProcessStopped()

    with monkeypatch.context() as patch:
        patch.setattr(h.app.state.service, "_local", crash)
        with pytest.raises(ProcessStopped):
            h.app.state.service.execute(
                h.store.session(h.alice.cookies.get("tfir_session")), h.case, decision["body"]["id"]
            )
    assert h.app.state.service.recover() == 1
    return h.execute(decision).json()


def test_rejection_cannot_be_undone_by_changing_cached_state(harness):
    h = harness
    decision = gap(h)
    h.review(decision, verdict="reject")
    with h.store.connect() as c:
        c.execute("UPDATE decisions SET state='PENDING' WHERE id=?", (decision["body"]["id"],))
    assert h.execute(decision).status_code == 503
    assert h.alice.get(h.base).status_code == 503


def test_missing_review_cannot_erase_historical_rejection(harness):
    h = harness
    d = gap(h)
    h.review(d, verdict="reject")
    with h.store.connect() as c:
        c.execute("DELETE FROM approvals WHERE decision_id=?", (d["body"]["id"],))
        c.execute("UPDATE decisions SET state='PENDING' WHERE id=?", (d["body"]["id"],))
    assert h.review(d, h.bob).status_code == 503
    assert h.execute(d).status_code == 503


def test_review_tampering_cannot_be_displayed_as_trusted(harness):
    h = harness
    d = gap(h)
    h.review(d)
    with h.store.connect() as c:
        c.execute("DROP TRIGGER immutable_approvals")
        c.execute(
            "UPDATE approvals SET envelope=json_set(envelope,'$.body.rationale','forged history')"
        )
    assert h.alice.get(h.base).status_code == 503


def test_revocation_presentation_uses_audit_history(harness):
    h = harness
    d = gap(h)
    approval = h.review(d).json()["body"]["id"]
    assert (
        h.alice.post(
            h.base + "/approvals/" + approval + "/revoke",
            json={"reason": "Scope requires another review"},
        ).status_code
        == 200
    )
    with h.store.connect() as c:
        c.execute("DELETE FROM revocations")
    detail = h.alice.get(h.base).json()
    assert detail["decisions"][0]["revoked_approval_ids"] == [approval]
    assert h.execute(d).status_code == 403


@pytest.mark.parametrize("table", ["artifacts", "decisions", "findings"])
def test_deleted_case_projection_is_detected(harness, table):
    h = harness
    if table == "artifacts":
        h.stage()
    elif table == "decisions":
        gap(h)
    else:
        a = h.imported()
        d = h.propose(
            "accept_finding",
            {
                "claim": "Audit logging changed in this synthetic event",
                "classification": "hypothesis",
                "severity": "high",
                "citations": [{"chunk_id": a["id"] + ":0"}],
                "limitations": "Intent and source completeness are not established",
            },
        )
        h.review(d)
        assert h.execute(d).json()["state"] == "COMPLETED"
    with h.store.connect() as c:
        c.execute(f"DELETE FROM {table}")
    assert h.alice.get(h.base).status_code == 503
    with pytest.raises(Fault):
        inspect_state(h.store)


def test_failure_result_is_authenticated(harness):
    h = harness
    a = h.stage(b"not valid json")
    d = h.propose("import_logs", {"artifact_id": a["id"], "format": "cloudtrail"})
    h.review(d)
    result = h.execute(d).json()
    assert result["state"] == "FAILED"
    with h.store.connect() as c:
        c.execute(
            "UPDATE executions SET result=? WHERE id=?",
            (json.dumps({"error": "invented outcome", "retry": "safe_to_retry"}), result["id"]),
        )
    assert h.execute(d).status_code == 503


def test_recovery_refuses_to_rewrite_a_completed_execution(harness):
    h = harness
    d = gap(h)
    h.review(d)
    result = h.execute(d).json()
    with h.store.connect() as c:
        c.execute("UPDATE executions SET state='RUNNING',result=NULL WHERE id=?", (result["id"],))
    with pytest.raises(Fault, match="execution_state_integrity_failed"):
        h.app.state.service.recover()


def test_recovery_cannot_race_active_execution(harness):
    h = harness
    with h.store.dispatch_lock, concurrent.futures.ThreadPoolExecutor() as pool:
        future = pool.submit(h.app.state.service.recover)
        with pytest.raises(Fault, match="active_execution_blocks_recovery"):
            future.result(timeout=5)


def test_unknown_execution_requires_two_reviews_to_reconcile_and_close(harness, monkeypatch):
    h = harness
    unknown = abandon(h, monkeypatch)
    a = h.stage(b"Synthetic independent provider check: unable to establish remote receipt")
    close_args = {
        "conclusion": "Bounded synthetic investigation concluded",
        "residual_uncertainty": "External effect remains indeterminate",
    }
    close = h.propose("close_case", close_args)
    h.review(close)
    assert h.execute(close).json()["result"]["error"] == "unresolved_execution_blocks_closure"
    d = h.propose(
        "reconcile_execution",
        {
            "execution_id": unknown["id"],
            "artifact_ids": [a["id"]],
            "assessment": "unable_to_determine",
            "conclusion": "Independent checks cannot determine the external effect",
            "residual_uncertainty": "No retry is authorized; uncertainty remains explicit",
        },
    )
    h.review(d)
    assert h.execute(d).status_code == 403
    h.review(d, h.bob)
    assert h.execute(d).json()["state"] == "COMPLETED"
    detail = h.alice.get(h.base).json()
    assert (
        next(e for e in detail["executions"] if e["id"] == unknown["id"])["state"]
        == "OUTCOME_UNKNOWN"
    )
    assert detail["reconciliations"][0]["assessment"] == "unable_to_determine"
    second = h.alice.post(
        h.base + "/decisions",
        json={
            "tool": "reconcile_execution",
            "purpose": "Attempt duplicate resolution",
            "arguments": d["body"]["arguments"],
        },
    )
    assert second.status_code == 409
    close = h.propose("close_case", close_args)
    h.review(close)
    assert h.execute(close).json()["state"] == "COMPLETED"


def test_challenge_keeps_original_finding_and_requires_reviewed_resolution(harness):
    h = harness
    a = h.imported()
    cite = [{"chunk_id": a["id"] + ":0", "relation": "supports"}]
    d = h.propose(
        "accept_finding",
        {
            "claim": "Audit collection changed in the supplied record",
            "classification": "hypothesis",
            "severity": "high",
            "citations": cite,
            "limitations": "Intent is not established by this event alone",
        },
    )
    h.review(d)
    original = h.execute(d).json()["result"]
    challenge = h.propose(
        "challenge_finding",
        {
            "finding_id": original["id"],
            "explanation": "The same event is consistent with an approved maintenance action",
            "citations": cite,
        },
    )
    h.review(challenge)
    challenge_result = h.execute(challenge).json()["result"]
    close = h.propose(
        "close_case",
        {
            "conclusion": "The review is complete for this source",
            "residual_uncertainty": "Synthetic source has partial coverage",
        },
    )
    h.review(close)
    assert (
        h.execute(close).json()["result"]["error"] == "unresolved_finding_challenge_blocks_closure"
    )
    resolution = h.propose(
        "resolve_challenge",
        {
            "challenge_id": challenge_result["id"],
            "disposition": "finding_withdrawn",
            "explanation": "Reviewers withdraw the finding because the inference is unsupported",
            "citations": cite,
        },
    )
    h.review(resolution)
    assert h.execute(resolution).status_code == 403
    h.review(resolution, h.bob)
    assert h.execute(resolution).json()["state"] == "COMPLETED"
    detail = h.alice.get(h.base).json()
    assert detail["findings"] == [original]
    assert detail["challenge_resolutions"][0]["disposition"] == "finding_withdrawn"


def test_password_change_revokes_restored_sessions_and_pending_reviews(harness):
    h = harness
    d = gap(h)
    h.review(d, h.bob)
    token = h.bob.cookies.get("tfir_session")
    with h.store.connect() as c:
        old = tuple(c.execute("SELECT * FROM sessions WHERE username='bob'").fetchone())
    changed = h.bob.post(
        "/api/password",
        json={"current_password": PASSWORD, "new_password": "New-synthetic-password-123!"},
    )
    assert changed.status_code == 200
    with h.store.connect() as c:
        c.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?)", old)
    h.bob.cookies.set("tfir_session", token)
    assert h.bob.get(h.base).status_code == 401
    assert h.execute(d).json()["error"] == "approval_identity_changed"
    assert (
        h.alice.post("/api/login", json={"username": "bob", "password": PASSWORD}).status_code
        == 401
    )
    assert (
        h.alice.post(
            "/api/login", json={"username": "bob", "password": "New-synthetic-password-123!"}
        ).status_code
        == 200
    )


def test_password_change_rejects_wrong_current_password(harness):
    response = harness.bob.post(
        "/api/password",
        json={"current_password": "wrong", "new_password": "New-synthetic-password-123!"},
    )
    assert response.status_code == 403
    assert harness.bob.get(harness.base).status_code == 200


def test_audit_pages_pin_one_checkpoint_and_do_not_omit_old_events(harness):
    h = harness
    for _ in range(4):
        h.alice.get(h.base)
    page = h.alice.get(h.base + "/audit?limit=3").json()
    pin = page["checkpoint"]
    events = list(page["events"])
    while page["page"]["has_more"]:
        h.alice.get(h.base)
        page = h.alice.get(
            h.base
            + f"/audit?limit=3&before={page['page']['next_before']}&through={page['page']['through']}"
        ).json()
        assert page["checkpoint"] == pin
        events = page["events"] + events
    assert [int(e["body"]["sequence"]) for e in events] == list(
        range(1, int(pin["body"]["event_count"]) + 1)
    )
    assert events[-1]["hash"] == pin["body"]["head_hash"]
    assert h.alice.get(h.base + "/audit?limit=501").status_code == 422


def test_encrypted_backup_restores_verified_state_and_resets_authority(harness, tmp_path):
    h = harness
    h.imported()
    d = gap(h)
    h.review(d)
    file = tmp_path / "backup.tfir"
    made = create_backup(h.store, file, PASSWORD)
    assert made["sha256"] == sha256(file.read_bytes())
    assert b"Synthetic" not in file.read_bytes() and b"PRIVATE KEY" not in file.read_bytes()
    restored = tmp_path / "restored"
    result = restore_backup(
        file, restored, PASSWORD, made["sha256"], h.store.audit_signer.public_pem
    )
    assert result["restored"] and result["tool_retries"] == 0
    new = Store(restored)
    assert inspect_state(new)["cases"] == 1
    with new.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        old = new.user(c, "alice")
        approval = json.loads(
            c.execute(
                "SELECT envelope FROM approvals WHERE decision_id=?", (d["body"]["id"],)
            ).fetchone()[0]
        )
        assert approval["body"]["identity_event"] != old["identity_event"]


@pytest.mark.parametrize(
    "attack", ["wrong_password", "wrong_pin", "wrong_key", "existing_destination"]
)
def test_restore_rejects_untrusted_or_overwriting_inputs(harness, tmp_path, attack):
    h = harness
    file = tmp_path / "backup.tfir"
    made = create_backup(h.store, file, PASSWORD)
    destination = tmp_path / "restored"
    if attack == "existing_destination":
        destination.mkdir()
        (destination / "keep.txt").write_text("user file")
    with pytest.raises((ValueError, InvalidTag)):
        restore_backup(
            file,
            destination,
            "Wrong-password-123!" if attack == "wrong_password" else PASSWORD,
            "0" * 64 if attack == "wrong_pin" else made["sha256"],
            h.store.approval_signer.public_pem
            if attack == "wrong_key"
            else h.store.audit_signer.public_pem,
        )
    if attack == "existing_destination":
        assert (destination / "keep.txt").read_text() == "user file"
    else:
        assert not destination.exists()


def test_doctor_and_backup_refuse_tampered_evidence(harness, tmp_path):
    h = harness
    h.stage()
    with h.store.connect() as c:
        c.execute("DROP TRIGGER immutable_artifacts")
        c.execute("UPDATE artifacts SET content=?", (b"tampered",))
    with pytest.raises(Fault):
        inspect_state(h.store)
    with pytest.raises(Fault):
        create_backup(h.store, tmp_path / "bad-backup.tfir", PASSWORD)
    assert not (tmp_path / "bad-backup.tfir").exists()


@pytest.mark.parametrize("raw", ['{"value":1e9999}', '{"value":-1e9999}'])
def test_float_overflow_cannot_bypass_strict_json(raw):
    with pytest.raises(ValueError, match="Non-finite"):
        strict_json(raw)


def test_normalized_locator_cannot_be_renamed_without_detection(harness):
    h = harness
    a = h.imported()
    with h.store.connect() as c:
        c.execute("DROP TRIGGER immutable_chunks")
        c.execute("UPDATE chunks SET id=? WHERE id=?", (a["id"] + ":99", a["id"] + ":0"))
    request = h.alice.post(
        h.base + "/decisions",
        json={
            "tool": "timeline",
            "purpose": "Check normalized record locators",
            "arguments": {"artifact_ids": [a["id"]]},
        },
    )
    assert request.status_code == 503


def test_challenge_rechecks_original_finding_before_execution(harness):
    h = harness
    a = h.imported()
    citations = [{"chunk_id": a["id"] + ":0"}]
    d = h.propose(
        "accept_finding",
        {
            "claim": "Synthetic audit activity needs investigation",
            "classification": "hypothesis",
            "severity": "high",
            "citations": citations,
            "limitations": "The source is synthetic and incomplete",
        },
    )
    h.review(d)
    finding = h.execute(d).json()["result"]
    challenge = h.propose(
        "challenge_finding",
        {
            "finding_id": finding["id"],
            "explanation": "This inference needs review against authorized changes",
            "citations": citations,
        },
    )
    h.review(challenge)
    with h.store.connect() as c:
        c.execute("DELETE FROM findings WHERE id=?", (finding["id"],))
    assert h.execute(challenge).status_code == 409


@pytest.mark.parametrize("tool", ["challenge_finding", "resolve_challenge", "reconcile_execution"])
def test_new_workflows_reject_unavailable_target_ids(harness, tool):
    h = harness
    a = h.imported()
    base = {
        "explanation": "The target must be in this exact authorized case",
        "citations": [{"chunk_id": a["id"] + ":0"}],
    }
    arguments = {
        "challenge_finding": {**base, "finding_id": "0" * 32},
        "resolve_challenge": {
            **base,
            "challenge_id": "0" * 32,
            "disposition": "uncertainty_retained",
        },
        "reconcile_execution": {
            "execution_id": "0" * 32,
            "artifact_ids": [a["id"]],
            "assessment": "unable_to_determine",
            "conclusion": "This unknown target cannot be resolved by guessing",
            "residual_uncertainty": "The execution identifier does not resolve",
        },
    }[tool]
    result = h.alice.post(
        h.base + "/decisions",
        json={
            "tool": tool,
            "arguments": arguments,
            "purpose": "Verify target authorization and existence",
        },
    )
    assert result.status_code == 404
