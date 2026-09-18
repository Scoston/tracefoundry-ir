"""Offline export verification. Never trusts keys merely because an export contains them."""

import re
import zipfile
from pathlib import PurePosixPath

from .security import canonical, digest, sha256, strict_json, verify_signature
from .tools import matching_roles


def verify_export(path, audit_key: bytes, approval_key: bytes, expected_checkpoint: dict) -> dict:
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        require(
            len(names) == len(set(names)) and len(names) <= 1000,
            "Duplicate or excessive archive entries",
        )
        require(
            sum(i.file_size for i in entries) <= 60_000_000, "Archive uncompressed limit exceeded"
        )
        for name in names:
            parsed = PurePosixPath(name)
            require(
                not parsed.is_absolute() and ".." not in parsed.parts and "\\" not in name,
                "Unsafe archive path",
            )
        snapshot_bytes = archive.read("snapshot.json")
        snapshot = strict_json(snapshot_bytes)
        authority = strict_json(archive.read("release-authority.json"))
        events = snapshot["events"]
        previous = "0" * 64
        ledger = snapshot["case"]["id"]
        for index, event in enumerate(events, 1):
            body = event["body"]
            require(
                body["ledger"] == ledger and body["sequence"] == str(index),
                "Audit sequence or ledger mismatch",
            )
            require(
                body["previous_hash"] == previous
                and digest("TFIR-EVENT-v1", body) == event["hash"],
                "Audit hash mismatch",
            )
            previous = event["hash"]
        for checkpoint in (snapshot["checkpoint"], expected_checkpoint):
            require(
                verify_signature(checkpoint, "TFIR-CHECKPOINT-v1", audit_key),
                "Untrusted checkpoint",
            )
            require(
                checkpoint["body"]["ledger"] == ledger
                and checkpoint["body"]["event_count"] == str(len(events))
                and checkpoint["body"]["head_hash"] == previous,
                "Expected checkpoint does not match snapshot; possible truncation or wrong snapshot pin",
            )
        allowed = {"snapshot.json", "release-authority.json", "README.txt"}
        for artifact in snapshot["artifacts"]:
            require(
                bool(re.fullmatch(r"[a-f0-9]{32}", artifact["id"])), "Invalid artifact identifier"
            )
            name = "artifacts/" + artifact["id"] + ".bin"
            allowed.add(name)
            data = archive.read(name)
            require(
                len(data) == artifact["byte_count"] and sha256(data) == artifact["sha256"],
                "Evidence byte integrity failed",
            )
            require(artifact["case_id"] == ledger, "Cross-case artifact")
        require(set(names) == allowed, "Unexpected or missing archive entries")
        for decision in snapshot["decisions"]:
            require(
                digest("TFIR-DECISION-v1", strict_json(decision["body"])) == decision["digest"],
                "Decision integrity failed",
            )
        for approval in snapshot["approvals"]:
            require(
                verify_signature(approval, "TFIR-APPROVAL-v1", approval_key),
                "Historical approval signature failed",
            )
        # A valid hash over a projection is insufficient: bind its records back to the ledger.
        by_event = {}
        for event in events:
            by_event.setdefault(event["body"]["event"], []).append(event["body"])
        proposed = {
            e["payload"]["decision_id"]: e["payload"] for e in by_event.get("decision.proposed", [])
        }
        require(
            len(snapshot["decisions"]) == len(proposed)
            and {d["id"] for d in snapshot["decisions"]} == set(proposed),
            "Decision history omitted or duplicated",
        )
        for record in snapshot["decisions"]:
            require(
                record["id"] in proposed
                and proposed[record["id"]]["decision_digest"] == record["digest"]
                and record["case_id"] == ledger,
                "Decision history binding failed",
            )
        reviews = {e["payload"]["approval_id"]: e for e in by_event.get("decision.reviewed", [])}
        require(
            len(snapshot["approvals"]) == len(reviews)
            and {a["body"]["id"] for a in snapshot["approvals"]} == set(reviews),
            "Review history omitted or duplicated",
        )
        for approval in snapshot["approvals"]:
            body = approval["body"]
            record = reviews.get(body["id"])
            require(
                record is not None
                and record["payload"]["attestation_sha256"] == sha256(canonical(approval))
                and record["actor"] == body["subject"]
                and body["case_id"] == ledger,
                "Review history binding failed",
            )
        preserved = {
            e["payload"]["artifact_id"]: e["payload"]
            for e in by_event.get("artifact.preserved", [])
        }
        selected = [a["id"] for a in snapshot["artifacts"]]
        omitted = snapshot["omitted_artifact_ids"]
        require(
            len(selected) == len(set(selected))
            and len(omitted) == len(set(omitted))
            and not set(selected) & set(omitted)
            and set(selected) | set(omitted) == set(preserved),
            "Evidence selection or omission manifest changed",
        )
        for artifact in snapshot["artifacts"]:
            require(
                preserved[artifact["id"]]["metadata_sha256"] == sha256(canonical(artifact)),
                "Evidence metadata history binding failed",
            )
        decision = authority["decision"]
        require(
            digest("TFIR-DECISION-v1", decision["body"]) == decision["digest"],
            "Release decision integrity failed",
        )
        require(
            decision["body"]["tool"] == "export_case" and decision["body"]["case_id"] == ledger,
            "Wrong release action",
        )
        require(
            sorted(decision["body"]["arguments"]["artifact_ids"]) == sorted(selected)
            and decision["body"]["tenant"] == snapshot["case"]["tenant"],
            "Release selection or tenant changed",
        )
        require(
            decision["body"]["binding"]["snapshot_sha256"] == sha256(snapshot_bytes),
            "Export scope was changed",
        )
        receipt = authority["release_receipt"]
        require(
            verify_signature(receipt, "TFIR-RELEASE-v1", audit_key),
            "Release receipt signature failed",
        )
        require(
            receipt["body"]["decision_digest"] == decision["digest"]
            and receipt["body"]["snapshot_sha256"] == sha256(snapshot_bytes)
            and receipt["body"]["recipient"] == decision["body"]["arguments"]["recipient"],
            "Release receipt binding failed",
        )
        require(
            decision["body"]["created_at"]
            <= receipt["body"]["released_at"]
            <= decision["body"]["expires_at"],
            "Release outside decision lifetime",
        )
        reviewers = []
        approval_ids = []
        for approval in authority["approvals"]:
            require(
                verify_signature(approval, "TFIR-APPROVAL-v1", approval_key),
                "Release approval signature failed",
            )
            body = approval["body"]
            require(
                body["verdict"] == "approve"
                and body["principal_kind"] == "human"
                and body["decision_digest"] == decision["digest"]
                and body["case_id"] == ledger,
                "Release approval binding failed",
            )
            require(
                body["reviewed_at"] <= receipt["body"]["released_at"] <= body["expires_at"],
                "Release outside approval lifetime",
            )
            reviewers.append({"username": body["subject"], "roles": body["roles_at_review"]})
            approval_ids.append(body["id"])
        require(
            sorted(approval_ids) == sorted(receipt["body"]["approval_ids"]),
            "Release approval list changed",
        )
        require(
            matching_roles([["analyst", "supervisor"], ["supervisor"]], reviewers),
            "Distinct human release approvals missing",
        )
        return {
            "integrity": "verified",
            "checkpoint": "matches_supplied_external_pin",
            "artifacts": len(snapshot["artifacts"]),
            "events": len(events),
            "source_completeness": "not_proven",
            "omitted_artifacts": len(snapshot["omitted_artifact_ids"]),
            "authority_limit": "Historical current-role checks depend on the trusted release service attestation; administrator identity history is not included.",
        }
