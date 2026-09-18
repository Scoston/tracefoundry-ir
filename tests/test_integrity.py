import io
import sqlite3
import zipfile

import pytest

from tracefoundry_ir.security import (
    Signer,
    canonical,
    digest,
    strict_json,
    verify_signature,
)
from tracefoundry_ir.store import Fault
from tracefoundry_ir.verify import verify_export


def test_rfc8785_number_vector():
    assert (
        canonical({"numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27]})
        == b'{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}'
    )


@pytest.mark.parametrize(
    "raw", ['{"a":1,"a":2}', '{"x":{"a":1,"a":2}}', '{"v":NaN}', '{"v":Infinity}']
)
def test_ambiguous_json_rejected(raw):
    with pytest.raises(ValueError):
        strict_json(raw)


def test_signatures_bind_body_domain_and_trusted_key(tmp_path):
    signer = Signer.create(tmp_path / "one.pem")
    other = Signer.create(tmp_path / "two.pem")
    envelope = signer.sign("TFIR-APPROVAL-v1", {"action": "read"})
    assert verify_signature(envelope, "TFIR-APPROVAL-v1", signer.public_pem)
    assert not verify_signature(envelope, "TFIR-CHECKPOINT-v1", signer.public_pem)
    assert not verify_signature(envelope, "TFIR-APPROVAL-v1", other.public_pem)
    envelope["body"]["action"] = "delete"
    assert not verify_signature(envelope, "TFIR-APPROVAL-v1", signer.public_pem)


def test_audit_update_delete_triggers(harness):
    with harness.store.connect() as c:
        for command in ["UPDATE audit SET hash='broken'", "DELETE FROM audit"]:
            with pytest.raises(sqlite3.IntegrityError):
                c.execute(command)


@pytest.mark.parametrize("attack", ["interior", "suffix", "all", "head", "checkpoint_missing"])
def test_tampered_audit_blocks_access(harness, attack):
    h = harness
    h.stage()
    with h.store.connect() as c:
        if attack in {"interior", "suffix", "all"}:
            c.execute("DROP TRIGGER audit_no_delete")
            if attack == "interior":
                c.execute("DELETE FROM audit WHERE ledger=? AND seq=2", (h.case,))
            elif attack == "suffix":
                c.execute(
                    "DELETE FROM audit WHERE ledger=? AND seq=(SELECT MAX(seq) FROM audit WHERE ledger=?)",
                    (h.case, h.case),
                )
            else:
                c.execute("DELETE FROM audit WHERE ledger=?", (h.case,))
            c.commit()
        elif attack == "head":
            c.execute("DROP TRIGGER audit_no_update")
            c.execute("UPDATE audit SET hash=? WHERE ledger=? AND seq=1", ("0" * 64, h.case))
            c.commit()
        else:
            h.store.checkpoint_path(h.case).unlink()
    assert h.alice.get(h.base).status_code == 503


def test_forged_checkpoint_does_not_establish_trust(harness, tmp_path):
    h = harness
    path = h.store.checkpoint_path(h.case)
    original = strict_json(path.read_bytes())
    forged = Signer.create(tmp_path / "untrusted.pem").sign("TFIR-CHECKPOINT-v1", original["body"])
    path.write_bytes(canonical(forged))
    assert h.alice.get(h.base).status_code == 503


@pytest.mark.parametrize("attack", ["bytes", "metadata", "chunk"])
def test_evidence_tampering_detected(harness, attack):
    h = harness
    a = h.imported()
    with h.store.connect() as c:
        if attack == "chunk":
            c.execute("DROP TRIGGER immutable_chunks")
            row = c.execute("SELECT id,body FROM chunks LIMIT 1").fetchone()
            body = strict_json(row["body"])
            body["action"] = "ForgedEvent"
            c.execute("UPDATE chunks SET body=? WHERE id=?", (canonical(body).decode(), row["id"]))
        else:
            c.execute("DROP TRIGGER immutable_artifacts")
            if attack == "bytes":
                c.execute("UPDATE artifacts SET content=? WHERE id=?", (b"broken", a["id"]))
            else:
                meta = dict(a)
                meta["source"] = "Forged source"
                c.execute(
                    "UPDATE artifacts SET metadata=? WHERE id=?",
                    (canonical(meta).decode(), a["id"]),
                )
        c.commit()
    r = h.alice.post(
        h.base + "/decisions",
        json={
            "tool": "timeline",
            "arguments": {"artifact_ids": [a["id"]]},
            "purpose": "Read a tampered evidence boundary",
        },
    )
    assert r.status_code == 503


def test_decision_tampering_with_recomputed_hash_still_fails_history(harness):
    h = harness
    d = h.propose(
        "record_gap", {"description": "A known source collection gap", "affected_scope": "logs"}
    )
    with h.store.connect() as c:
        c.execute("DROP TRIGGER immutable_decisions")
        body = d["body"]
        body["arguments"]["affected_scope"] = "Different source"
        c.execute(
            "UPDATE decisions SET body=?,digest=? WHERE id=?",
            (canonical(body).decode(), digest("TFIR-DECISION-v1", body), body["id"]),
        )
        c.commit()
    assert h.execute(d).status_code == 503


def test_removed_execution_cannot_replay_authority(harness):
    h = harness
    d = h.propose(
        "record_gap", {"description": "A known source collection gap", "affected_scope": "logs"}
    )
    h.review(d)
    assert h.execute(d).json()["state"] == "COMPLETED"
    with h.store.connect() as c:
        c.execute("DELETE FROM executions")
        c.execute("UPDATE decisions SET state='PENDING'")
        c.commit()
    assert h.execute(d).status_code == 503


def test_identity_row_cannot_grant_roles(harness):
    h = harness
    with h.store.connect() as c:
        c.execute("UPDATE users SET roles='[\"supervisor\"]' WHERE username='charlie'")
        c.commit()
        with pytest.raises(Fault, match="identity_integrity_failed"):
            h.store.user(c, "charlie")


def exported(h):
    a = h.imported()
    d = h.propose("export_case", {"artifact_ids": [a["id"]], "recipient": "bob"})
    with h.store.connect() as c:
        snapshot = strict_json(
            h.app.state.service._artifact(c, h.case, d["body"]["binding"]["snapshot_id"])[1]
        )
    h.review(d)
    h.review(d, h.bob)
    result = h.execute(d).json()
    assert result["state"] == "COMPLETED", result
    artifact_id = result["result"]["export_artifact_id"]
    assert h.alice.get(h.base + "/artifacts/" + artifact_id).status_code == 403
    response = h.bob.get(h.base + "/artifacts/" + artifact_id)
    assert response.status_code == 200
    return response.content, snapshot["checkpoint"]


def test_export_is_fixed_two_person_and_verifies_offline(harness):
    payload, pin = exported(harness)
    result = verify_export(
        io.BytesIO(payload),
        harness.store.audit_signer.public_pem,
        harness.store.approval_signer.public_pem,
        pin,
    )
    assert result["integrity"] == "verified"
    assert result["source_completeness"] == "not_proven"


@pytest.mark.parametrize(
    "attack", ["evidence", "snapshot", "extra_entry", "unsafe_path", "truncation"]
)
def test_offline_verifier_rejects_modified_exports(harness, attack):
    payload, pin = exported(harness)
    changed = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(payload)) as original, zipfile.ZipFile(changed, "w") as output:
        for name in original.namelist():
            data = original.read(name)
            if attack == "evidence" and name.startswith("artifacts/"):
                data += b"X"
            if attack in {"snapshot", "truncation"} and name == "snapshot.json":
                snapshot = strict_json(data)
                if attack == "snapshot":
                    snapshot["case"]["title"] = "A changed title"
                else:
                    snapshot["events"] = snapshot["events"][:-1]
                data = canonical(snapshot)
            output.writestr(name, data)
        if attack == "extra_entry":
            output.writestr("unapproved.bin", b"unapproved")
        if attack == "unsafe_path":
            output.writestr("../outside", b"unsafe")
    with pytest.raises((ValueError, KeyError)):
        verify_export(
            io.BytesIO(changed.getvalue()),
            harness.store.audit_signer.public_pem,
            harness.store.approval_signer.public_pem,
            pin,
        )


def test_raw_evidence_encrypted_at_rest(harness):
    marker = b"SENSITIVE-SOURCE-MARKER-123456"
    a = harness.stage(marker)
    with harness.store.connect() as c:
        stored = bytes(
            c.execute("SELECT content FROM artifacts WHERE id=?", (a["id"],)).fetchone()[0]
        )
    assert marker not in stored
    assert marker not in (harness.store.directory / "state.sqlite3").read_bytes()
    assert harness.alice.get(harness.base + "/artifacts/" + a["id"]).content == marker


def test_stored_execution_results_are_checked_against_receipts(harness):
    h = harness
    a = h.imported()
    d = h.propose("timeline", {"artifact_ids": [a["id"]]})
    h.review(d)
    execution = h.execute(d).json()
    with h.store.connect() as c:
        c.execute("UPDATE executions SET result='{}' WHERE id=?", (execution["id"],))
        c.commit()
    assert h.alice.get(h.base).status_code == 503


def test_stored_finding_cannot_change_after_human_acceptance(harness):
    h = harness
    a = h.imported()
    d = h.propose(
        "accept_finding",
        {
            "claim": "A source event reports StopLogging",
            "classification": "observation",
            "severity": "medium",
            "citations": [{"chunk_id": a["id"] + ":0", "relation": "supports"}],
            "limitations": "No conclusion about intent or source completeness",
        },
    )
    h.review(d)
    assert h.execute(d).json()["state"] == "COMPLETED"
    with h.store.connect() as c:
        row = c.execute("SELECT id,body FROM findings").fetchone()
        body = strict_json(row["body"])
        body["claim"] = "A fabricated accepted conclusion"
        c.execute("UPDATE findings SET body=? WHERE id=?", (canonical(body).decode(), row["id"]))
        c.commit()
    assert h.alice.get(h.base).status_code == 503
