"""Case operations and the mandatory approval gateway."""

import base64
import io
import sqlite3
import zipfile
from datetime import UTC, datetime, timedelta

from pydantic import ValidationError

from . import models, tools
from .provider import ModelProvider
from .security import (
    canonical,
    digest,
    now,
    sha256,
    strict_json,
    verify_signature,
)
from .store import Fault, Store, encoded, uid


class Service:
    def __init__(self, store: Store, provider=None):
        self.store = store
        self.provider = provider or ModelProvider()
        self.tool_digest = tools.registry_digest()

    def _case(self, c, case_id: str, actor: dict, *, open_required=False):
        current = self.store.user(c, actor["username"])
        case = c.execute(
            "SELECT * FROM cases WHERE id=? AND tenant=?", (case_id, current["tenant"])
        ).fetchone()
        member = c.execute(
            "SELECT active FROM members WHERE case_id=? AND username=?",
            (case_id, actor["username"]),
        ).fetchone()
        if current["kind"] != "human" or not case or not member or not member[0]:
            raise Fault(404, "case_not_found")
        self.store.verify_ledger(c, case_id)
        origin = c.execute("SELECT body FROM audit WHERE ledger=? AND seq=1", (case_id,)).fetchone()
        initial = strict_json(origin[0]) if origin else {}
        if (
            initial.get("event") != "case.created"
            or initial["payload"]["tenant"] != case["tenant"]
            or initial["actor"] != case["creator"]
            or initial["payload"]["title_sha256"] != sha256(case["title"].encode())
            or initial["payload"]["description_sha256"] != sha256(case["description"].encode())
        ):
            raise Fault(503, "case_metadata_integrity_failed")
        closure = c.execute(
            "SELECT 1 FROM audit WHERE ledger=? AND json_extract(body,'$.event')='case.closed'",
            (case_id,),
        ).fetchone()
        if bool(closure) != bool(case["closed"]):
            raise Fault(503, "case_status_integrity_failed")
        grant = c.execute(
            "SELECT body FROM audit WHERE ledger=? AND json_extract(body,'$.event') IN ('member.added','member.removed') AND json_extract(body,'$.payload.username')=? ORDER BY seq DESC LIMIT 1",
            (case_id, actor["username"]),
        ).fetchone()
        if not grant or strict_json(grant[0])["event"] != "member.added":
            raise Fault(403, "membership_not_attested")
        if open_required and case["closed"]:
            raise Fault(409, "case_closed")
        return dict(case)

    def create_case(self, actor: dict, request: models.CaseCreate) -> dict:
        case_id, created = uid(), now()
        with self.store.transaction(case_id) as c:
            current = self.store.user(c, actor["username"])
            if current["kind"] != "human" or not set(current["roles"]) & {
                "analyst",
                "supervisor",
                "admin",
            }:
                raise Fault(403, "human_case_originator_required")
            c.execute(
                "INSERT INTO cases VALUES (?,?,?,?,?,?,0)",
                (
                    case_id,
                    current["tenant"],
                    request.title,
                    request.description,
                    actor["username"],
                    created,
                ),
            )
            c.execute("INSERT INTO members VALUES (?,?,1)", (case_id, actor["username"]))
            self.store.audit(
                c,
                case_id,
                actor,
                "case.created",
                {
                    "case_id": case_id,
                    "title_sha256": sha256(request.title.encode()),
                    "description_sha256": sha256(request.description.encode()),
                    "tenant": current["tenant"],
                },
            )
            self.store.audit(c, case_id, actor, "member.added", {"username": actor["username"]})
        return {"id": case_id, "title": request.title, "created": created}

    def list_cases(self, actor: dict) -> list[dict]:
        with self.store.transaction("admin-" + actor["tenant"]) as c:
            rows = [
                dict(r)
                for r in c.execute(
                    "SELECT cases.* FROM cases JOIN members ON cases.id=members.case_id WHERE members.username=? AND members.active=1 AND cases.tenant=? ORDER BY created DESC",
                    (actor["username"], actor["tenant"]),
                )
            ]
            rows = [r for r in rows if self._case(c, r["id"], actor)]
            self.store.audit(
                c, "admin-" + actor["tenant"], actor, "cases.listed", {"count": len(rows)}
            )
        return rows

    def membership(self, actor: dict, case_id: str, username: str, *, remove=False):
        with self.store.transaction(case_id) as c:
            case = self._case(c, case_id, actor)
            current = self.store.user(c, actor["username"])
            if not set(current["roles"]) & {"admin", "supervisor"}:
                raise Fault(403, "supervisor_or_admin_required")
            target = self.store.user(c, username)
            if target["tenant"] != case["tenant"] or target["kind"] != "human":
                raise Fault(404, "eligible_user_not_found")
            if remove and username == case["creator"]:
                raise Fault(409, "case_originator_membership_is_retained")
            c.execute(
                "INSERT INTO members VALUES (?,?,?) ON CONFLICT(case_id,username) DO UPDATE SET active=excluded.active",
                (case_id, username, 0 if remove else 1),
            )
            self.store.audit(
                c,
                case_id,
                actor,
                "member.removed" if remove else "member.added",
                {"username": username},
            )
        return {"username": username, "active": not remove}

    def _artifact(self, c, case_id: str, artifact_id: str) -> tuple[dict, bytes]:
        row = c.execute(
            "SELECT * FROM artifacts WHERE id=? AND case_id=?", (artifact_id, case_id)
        ).fetchone()
        if not row:
            raise Fault(404, "artifact_not_found")
        metadata = strict_json(row["metadata"])
        receipt = c.execute(
            "SELECT body FROM audit WHERE ledger=? AND json_extract(body,'$.event')='artifact.preserved' AND json_extract(body,'$.payload.artifact_id')=?",
            (case_id, artifact_id),
        ).fetchone()
        if not receipt or strict_json(receipt[0])["payload"]["metadata_sha256"] != sha256(
            canonical(metadata)
        ):
            raise Fault(503, "artifact_metadata_integrity_failed")
        try:
            data = self.store.vault.decrypt(row["content"], case_id + ":" + artifact_id)
        except Exception as exc:
            raise Fault(503, "artifact_decryption_failed") from exc
        if sha256(data) != metadata["sha256"] or len(data) != metadata["byte_count"]:
            raise Fault(503, "artifact_integrity_failed")
        return metadata, data

    def _save_artifact(self, c, case_id: str, data: bytes, metadata: dict, kind: str) -> dict:
        artifact_id = uid()
        metadata = {
            **metadata,
            "id": artifact_id,
            "case_id": case_id,
            "sha256": sha256(data),
            "byte_count": len(data),
            "acquired_at": now(),
            "kind": kind,
        }
        c.execute(
            "INSERT INTO artifacts VALUES (?,?,?,?,?)",
            (
                artifact_id,
                case_id,
                encoded(metadata),
                self.store.vault.encrypt(data, case_id + ":" + artifact_id),
                kind,
            ),
        )
        self.store.audit(
            c,
            case_id,
            "evidence-vault",
            "artifact.preserved",
            {
                "artifact_id": artifact_id,
                "sha256": metadata["sha256"],
                "metadata_sha256": sha256(canonical(metadata)),
                "kind": kind,
            },
        )
        return metadata

    def stage(self, actor: dict, case_id: str, request: models.EvidenceUpload):
        try:
            data = base64.b64decode(request.content_base64, validate=True)
        except ValueError as exc:
            raise Fault(422, "invalid_base64") from exc
        if not 1 <= len(data) <= 2_000_000:
            raise Fault(413, "artifact_size_limit_is_2MB")
        if request.source_integrity == "verified_externally" and len(request.integrity_note) < 20:
            raise Fault(422, "external_verification_description_required")
        with self.store.transaction(case_id) as c:
            self._case(c, case_id, actor, open_required=True)
            metadata = self._save_artifact(
                c, case_id, data, request.model_dump(exclude={"content_base64"}), "source"
            )
            self.store.audit(
                c,
                case_id,
                actor,
                "evidence.staged",
                {
                    "artifact_id": metadata["id"],
                    "sha256": metadata["sha256"],
                    "byte_count": len(data),
                    "coverage": request.coverage,
                    "source_integrity": request.source_integrity,
                    "instruction": "human_selected_exact_bytes",
                },
            )
        return metadata

    def _rows(self, c, case_id: str, artifact_ids: list[str]) -> list[dict]:
        if len(set(artifact_ids)) != len(artifact_ids):
            raise Fault(422, "duplicate_artifact_ids")
        rows = []
        for artifact_id in artifact_ids:
            self._artifact(c, case_id, artifact_id)
            chunks = [
                strict_json(r[0])
                for r in c.execute(
                    "SELECT body FROM chunks WHERE artifact_id=? ORDER BY id", (artifact_id,)
                )
            ]
            chunks.sort(key=lambda row: int(row["chunk_id"].rsplit(":", 1)[1]))
            imported = c.execute(
                "SELECT body FROM audit WHERE ledger=? AND json_extract(body,'$.event')='evidence.normalized' AND json_extract(body,'$.payload.artifact_id')=?",
                (case_id, artifact_id),
            ).fetchone()
            if not imported:
                raise Fault(409, "artifact_requires_approved_import")
            if strict_json(imported[0])["payload"]["chunks_sha256"] != sha256(canonical(chunks)):
                raise Fault(503, "normalized_evidence_integrity_failed")
            rows.extend(chunks)
            if len(rows) > 10000:
                raise Fault(422, "selected_evidence_exceeds_10000_record_budget")
        return rows

    def _references(self, c, case_id: str, args: dict) -> list[dict]:
        ids = set(args.get("artifact_ids", []))
        if "artifact_id" in args:
            ids.add(args["artifact_id"])
        for citation in args.get("citations", []):
            chunk = c.execute(
                "SELECT artifact_id FROM chunks WHERE id=?", (citation["chunk_id"],)
            ).fetchone()
            if not chunk:
                raise Fault(422, "unresolvable_citation")
            ids.add(chunk[0])
        if args.get("citations"):
            self._rows(c, case_id, sorted(ids))
        return [
            {
                "artifact_id": artifact_id,
                "sha256": self._artifact(c, case_id, artifact_id)[0]["sha256"],
            }
            for artifact_id in sorted(ids)
        ]

    def _research(self, c, case_id: str, artifact_id: str) -> dict:
        metadata, data = self._artifact(c, case_id, artifact_id)
        if len(data) > 120000:
            raise Fault(422, "research_text_exceeds_120KB")
        try:
            source_text = data.decode("utf-8")
        except UnicodeError as exc:
            raise Fault(422, "research_requires_utf8_text_or_markdown") from exc
        if "\x00" in source_text:
            raise Fault(422, "research_requires_plain_text")
        return {
            "artifact_id": artifact_id,
            "sha256": metadata["sha256"],
            "source": metadata["source"],
            "text": source_text,
        }

    def _snapshot(self, c, case_id: str, artifact_ids: list[str]) -> dict:
        # This data is frozen before approvals, so later case changes cannot expand the export.
        artifacts = [self._artifact(c, case_id, a)[0] for a in artifact_ids]
        events = self.store.audit_events(c, case_id)
        snapshot = {
            "schema_version": "runtime-0.1",
            "case": dict(c.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()),
            "artifacts": artifacts,
            "events": events,
            "checkpoint": strict_json(self.store.checkpoint_path(case_id).read_bytes()),
            "decisions": [
                dict(r) for r in c.execute("SELECT * FROM decisions WHERE case_id=?", (case_id,))
            ],
            "findings": [
                self._finding(c, r)
                for r in c.execute("SELECT * FROM findings WHERE case_id=?", (case_id,))
            ],
            "omitted_artifact_ids": [
                r[0]
                for r in c.execute("SELECT id FROM artifacts WHERE case_id=?", (case_id,))
                if r[0] not in artifact_ids
            ],
            "coverage_statement": "A selected case snapshot; source completeness is not proven. Local checkpoint is not an independent witness.",
        }
        snapshot["approvals"] = [
            strict_json(r[0])
            for r in c.execute(
                "SELECT envelope FROM approvals JOIN decisions ON decisions.id=approvals.decision_id WHERE decisions.case_id=?",
                (case_id,),
            )
        ]
        snapshot["revocations"] = [
            dict(r)
            for r in c.execute(
                "SELECT revocations.* FROM revocations JOIN approvals ON approvals.id=revocations.approval_id JOIN decisions ON decisions.id=approvals.decision_id WHERE decisions.case_id=?",
                (case_id,),
            )
        ]
        return snapshot

    def propose(self, actor: dict, case_id: str, request: models.Proposal) -> dict:
        if self.tool_digest != tools.registry_digest():
            raise Fault(409, "runtime_source_changed_restart_required")
        if request.tool not in tools.REGISTRY:
            raise Fault(422, "tool_not_registered")
        argument_model, groups, _ = tools.REGISTRY[request.tool]
        try:
            args = argument_model.model_validate(request.arguments).model_dump()
        except ValidationError as exc:
            raise Fault(422, "invalid_tool_arguments") from exc
        with self.store.transaction(case_id) as c:
            case = self._case(c, case_id, actor, open_required=request.tool != "export_case")
            refs = self._references(c, case_id, args)
            binding = {}
            if request.tool == "draft_pack":
                source = self._research(c, case_id, args["artifact_id"])
                self.provider.prepare_pack(args["goal"], source)
                binding = self.provider.binding()
            if request.tool in {"timeline", "suggest_findings", "run_pack", "model_assess"}:
                rows = self._rows(c, case_id, args["artifact_ids"])
                if request.tool == "timeline":
                    try:
                        tools.bounded_rows(rows, args)
                    except ValueError as exc:
                        raise Fault(422, "invalid_time_window") from exc
                if request.tool == "model_assess":
                    binding = self.provider.binding()
                    if len(canonical({"question": args["question"], "evidence": rows})) > 128000:
                        raise Fault(422, "model_context_limit_exceeded")
            if request.tool == "promote_pack":
                try:
                    pack = tools.validate_pack(self._artifact(c, case_id, args["artifact_id"])[1])
                except (ValueError, UnicodeError, TypeError, OverflowError) as exc:
                    raise Fault(422, "pack_validation_failed") from exc
                binding = {
                    "pack_sha256": sha256(canonical(pack)),
                    "tests_passed": len(pack["tests"]),
                }
            if request.tool == "run_pack":
                pack = self._pack(c, case_id, args["pack_id"])
                if not pack or sha256(canonical(strict_json(pack["body"]))) != pack["digest"]:
                    raise Fault(409, "pack_not_available_or_integrity_failed")
                binding = {"pack_sha256": pack["digest"]}
            if request.tool == "export_case":
                recipient = self.store.user(c, args["recipient"])
                self._case(c, case_id, recipient)
                snapshot = self._snapshot(c, case_id, args["artifact_ids"])
                frozen = self._save_artifact(
                    c,
                    case_id,
                    canonical(snapshot),
                    {"filename": "snapshot.json", "source": "case snapshot", "coverage": "partial"},
                    "export_snapshot",
                )
                binding = {
                    "snapshot_id": frozen["id"],
                    "snapshot_sha256": frozen["sha256"],
                    "event_count": len(snapshot["events"]),
                    "artifact_count": len(snapshot["artifacts"]),
                }
            decision_id = uid()
            body = {
                "schema_version": "runtime-0.1",
                "id": decision_id,
                "case_id": case_id,
                "tenant": case["tenant"],
                "proposer": actor["username"],
                "created_at": now(),
                "expires_at": (
                    datetime.now(UTC) + timedelta(minutes=request.ttl_minutes)
                ).isoformat(),
                "tool": request.tool,
                "tool_digest": tools.registry_digest(),
                "policy_version": tools.POLICY,
                "arguments": args,
                "purpose": request.purpose,
                "evidence": refs,
                "required_role_groups": groups,
                "human_required": True,
                "binding": binding,
            }
            hashed = digest("TFIR-DECISION-v1", body)
            c.execute(
                "INSERT INTO decisions(id,case_id,body,digest) VALUES (?,?,?,?)",
                (decision_id, case_id, encoded(body), hashed),
            )
            self.store.audit(
                c,
                case_id,
                actor,
                "decision.proposed",
                {
                    "decision_id": decision_id,
                    "decision_digest": hashed,
                    "tool": request.tool,
                    "evidence": refs,
                },
            )
        return {"body": body, "digest": hashed, "state": "PENDING"}

    def _decision(self, c, case_id: str, decision_id: str) -> dict:
        row = c.execute(
            "SELECT * FROM decisions WHERE id=? AND case_id=?", (decision_id, case_id)
        ).fetchone()
        if not row:
            raise Fault(404, "decision_not_found")
        result = dict(row)
        result["body"] = strict_json(result["body"])
        if result["body"].get("example_only") or result["body"].get("human_required") is not True:
            raise Fault(403, "invalid_authority_record")
        if digest("TFIR-DECISION-v1", result["body"]) != result["digest"]:
            raise Fault(503, "decision_integrity_failed")
        receipt = c.execute(
            "SELECT body FROM audit WHERE ledger=? AND json_extract(body,'$.event')='decision.proposed' AND json_extract(body,'$.payload.decision_id')=?",
            (case_id, decision_id),
        ).fetchone()
        if not receipt or strict_json(receipt[0])["payload"]["decision_digest"] != result["digest"]:
            raise Fault(503, "decision_history_mismatch")
        return result

    def _current(self, c, decision: dict):
        body = decision["body"]
        if body["expires_at"] <= now():
            raise Fault(410, "decision_expired")
        if decision["state"] == "REJECTED":
            raise Fault(409, "decision_rejected")
        if (
            body["policy_version"] != tools.POLICY
            or body["tool_digest"] != self.tool_digest
            or body["tool_digest"] != tools.registry_digest()
            or body["tool"] not in tools.REGISTRY
            or body["required_role_groups"] != tools.REGISTRY[body["tool"]][1]
        ):
            raise Fault(409, "policy_or_tool_changed")
        if self._references(c, body["case_id"], body["arguments"]) != body["evidence"]:
            raise Fault(409, "evidence_changed")
        if (
            body["tool"] in {"model_assess", "draft_pack"}
            and body["binding"] != self.provider.binding()
        ):
            raise Fault(409, "model_configuration_changed")
        if body["tool"] == "run_pack":
            pack = self._pack(c, body["case_id"], body["arguments"]["pack_id"])
            if (
                not pack
                or sha256(canonical(strict_json(pack["body"]))) != body["binding"]["pack_sha256"]
            ):
                raise Fault(409, "pack_changed")

    def review(self, actor: dict, case_id: str, decision_id: str, request: models.Review):
        self.store.reauthenticate(actor, request.password)
        with self.store.transaction(case_id) as c:
            self._case(c, case_id, actor)
            current = self.store.user(c, actor["username"])
            decision = self._decision(c, case_id, decision_id)
            self._current(c, decision)
            if decision["digest"] != request.decision_digest:
                raise Fault(409, "reviewed_decision_changed")
            if decision["state"] != "PENDING":
                raise Fault(409, "decision_already_consumed")
            groups = decision["body"]["required_role_groups"]
            if not any(set(group) & set(current["roles"]) for group in groups):
                raise Fault(403, "reviewer_role_not_eligible")
            approval_id = uid()
            body = {
                "id": approval_id,
                "decision_id": decision_id,
                "decision_digest": decision["digest"],
                "case_id": case_id,
                "tenant": current["tenant"],
                "subject": actor["username"],
                "principal_kind": "human",
                "auth_event": actor["auth_event"],
                "authentication_method": "local_password_reauthenticated",
                "roles_at_review": current["roles"],
                "policy_version": tools.POLICY,
                "verdict": request.verdict,
                "rationale": request.rationale,
                "review_view_digest": digest("TFIR-REVIEW-VIEW-v1", decision["body"]),
                "reviewed_at": now(),
                "expires_at": decision["body"]["expires_at"],
            }
            envelope = self.store.approval_signer.sign("TFIR-APPROVAL-v1", body)
            try:
                c.execute(
                    "INSERT INTO approvals VALUES (?,?,?,?)",
                    (approval_id, decision_id, actor["username"], encoded(envelope)),
                )
            except sqlite3.IntegrityError as exc:
                raise Fault(409, "human_already_reviewed") from exc
            if request.verdict == "reject":
                c.execute("UPDATE decisions SET state='REJECTED' WHERE id=?", (decision_id,))
            self.store.audit(
                c,
                case_id,
                actor,
                "decision.reviewed",
                {
                    "decision_id": decision_id,
                    "approval_id": approval_id,
                    "verdict": request.verdict,
                    "attestation_sha256": sha256(canonical(envelope)),
                },
            )
        return envelope

    def _approved(self, c, decision: dict) -> list[dict]:
        self._current(c, decision)
        reviewers, envelopes = [], []
        for row in c.execute("SELECT * FROM approvals WHERE decision_id=?", (decision["id"],)):
            envelope = strict_json(row["envelope"])
            body = envelope["body"]
            if not verify_signature(
                envelope, "TFIR-APPROVAL-v1", self.store.approval_signer.public_pem
            ):
                raise Fault(403, "approval_signature_invalid")
            if (
                body["id"] != row["id"]
                or body["principal_kind"] != "human"
                or body["decision_digest"] != decision["digest"]
                or body["decision_id"] != decision["id"]
                or body["case_id"] != decision["case_id"]
                or body["tenant"] != decision["body"]["tenant"]
                or body["subject"] != row["username"]
                or body["policy_version"] != tools.POLICY
                or body["verdict"] != "approve"
                or body["expires_at"] <= now()
            ):
                raise Fault(403, "approval_not_valid")
            if c.execute(
                "SELECT 1 FROM audit WHERE ledger=? AND json_extract(body,'$.event')='approval.revoked' AND json_extract(body,'$.payload.approval_id')=?",
                (decision["case_id"], body["id"]),
            ).fetchone():
                raise Fault(403, "approval_revoked")
            current = self.store.user(c, body["subject"])
            self._case(c, decision["case_id"], current)
            reviewers.append(current)
            envelopes.append(envelope)
        if not tools.matching_roles(decision["body"]["required_role_groups"], reviewers):
            raise Fault(403, "required_human_approvals_missing")
        return envelopes

    def revoke(self, actor: dict, case_id: str, approval_id: str, reason: str):
        with self.store.transaction(case_id) as c:
            self._case(c, case_id, actor)
            row = c.execute(
                "SELECT approvals.* FROM approvals JOIN decisions ON decisions.id=approvals.decision_id WHERE approvals.id=? AND decisions.case_id=?",
                (approval_id, case_id),
            ).fetchone()
            if not row:
                raise Fault(404, "approval_not_found")
            current = self.store.user(c, actor["username"])
            if row["username"] != actor["username"] and "supervisor" not in current["roles"]:
                raise Fault(403, "revocation_not_authorized")
            c.execute(
                "INSERT OR IGNORE INTO revocations VALUES (?,?,?)",
                (approval_id, actor["username"], reason),
            )
            self.store.audit(
                c,
                case_id,
                actor,
                "approval.revoked",
                {
                    "approval_id": approval_id,
                    "reason": reason,
                    "limitation": "Revocation cannot reverse an already dispatched operation.",
                },
            )
        return {"revoked": True}

    def _local(self, c, actor, case_id, decision) -> dict:
        body, args = decision["body"], decision["body"]["arguments"]
        tool = body["tool"]
        if tool == "import_logs":
            if c.execute(
                "SELECT 1 FROM audit WHERE ledger=? AND json_extract(body,'$.event')='evidence.normalized' AND json_extract(body,'$.payload.artifact_id')=?",
                (case_id, args["artifact_id"]),
            ).fetchone():
                raise Fault(409, "artifact_already_imported")
            metadata, data = self._artifact(c, case_id, args["artifact_id"])
            try:
                rows, warnings = tools.parse_logs(data, args["artifact_id"], args["format"])
            except (ValueError, UnicodeError, TypeError, OverflowError, RecursionError) as exc:
                raise Fault(422, "log_parse_failed") from exc
            for row in rows:
                c.execute(
                    "INSERT INTO chunks VALUES (?,?,?)",
                    (row["chunk_id"], args["artifact_id"], encoded(row)),
                )
            self.store.audit(
                c,
                case_id,
                actor,
                "evidence.normalized",
                {
                    "artifact_id": args["artifact_id"],
                    "record_count": len(rows),
                    "format": args["format"],
                    "warning_count": len(warnings),
                    "source_sha256": metadata["sha256"],
                    "chunks_sha256": sha256(canonical(rows)),
                },
            )
            return {
                "record_count": len(rows),
                "warnings": warnings,
                "coverage": metadata["coverage"],
                "source_integrity": metadata["source_integrity"],
            }
        if tool == "timeline":
            return tools.bounded_rows(self._rows(c, case_id, args["artifact_ids"]), args)
        if tool == "suggest_findings":
            return {
                "findings": tools.candidates(self._rows(c, case_id, args["artifact_ids"])),
                "engine": "deterministic rules; no model invoked",
                "review_status": "unreviewed",
            }
        if tool == "accept_finding":
            finding_id = uid()
            finding = {
                **args,
                "id": finding_id,
                "decision_id": decision["id"],
                "accepted_at": now(),
                "review_status": "human_accepted",
                "evidence": body["evidence"],
            }
            c.execute(
                "INSERT INTO findings VALUES (?,?,?,?)",
                (finding_id, case_id, decision["id"], encoded(finding)),
            )
            return finding
        if tool == "record_gap":
            self.store.audit(c, case_id, actor, "coverage.gap_declared", args)
            return {"gap": args}
        if tool == "close_case":
            open_runs = c.execute(
                "SELECT COUNT(*) FROM executions JOIN decisions ON decisions.id=executions.decision_id WHERE decisions.case_id=? AND executions.state IN ('RUNNING','OUTCOME_UNKNOWN') AND decisions.id!=?",
                (case_id, decision["id"]),
            ).fetchone()[0]
            if open_runs:
                raise Fault(409, "unresolved_execution_blocks_closure")
            c.execute("UPDATE cases SET closed=1 WHERE id=?", (case_id,))
            self.store.audit(
                c, case_id, actor, "case.closed", {"decision_id": decision["id"], **args}
            )
            return {"closed": True, **args}
        if tool == "promote_pack":
            pack = tools.validate_pack(self._artifact(c, case_id, args["artifact_id"])[1])
            hashed = sha256(canonical(pack))
            if hashed != body["binding"]["pack_sha256"]:
                raise Fault(409, "pack_changed")
            pack_id = uid()
            c.execute(
                "INSERT INTO packs VALUES (?,?,?,?,?)",
                (pack_id, case_id, encoded(pack), hashed, decision["id"]),
            )
            return {
                "pack_id": pack_id,
                "name": pack["name"],
                "digest": hashed,
                "tests_passed": len(pack["tests"]),
            }
        if tool == "run_pack":
            pack = strict_json(
                c.execute(
                    "SELECT body FROM packs WHERE id=? AND case_id=?", (args["pack_id"], case_id)
                ).fetchone()[0]
            )
            return {
                "findings": tools.run_pack(pack, self._rows(c, case_id, args["artifact_ids"])),
                "review_status": "unreviewed",
                "pack_digest": body["binding"]["pack_sha256"],
            }
        if tool == "export_case":
            self._case(c, case_id, self.store.user(c, args["recipient"]))
            metadata, snapshot_bytes = self._artifact(c, case_id, body["binding"]["snapshot_id"])
            if metadata["sha256"] != body["binding"]["snapshot_sha256"]:
                raise Fault(409, "export_snapshot_changed")
            snapshot = strict_json(snapshot_bytes)
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("snapshot.json", snapshot_bytes)
                authority = self._approved(c, decision)
                receipt = self.store.audit_signer.sign(
                    "TFIR-RELEASE-v1",
                    {
                        "decision_digest": decision["digest"],
                        "snapshot_sha256": metadata["sha256"],
                        "recipient": args["recipient"],
                        "released_at": now(),
                        "approval_ids": [a["body"]["id"] for a in authority],
                    },
                )
                archive.writestr(
                    "release-authority.json",
                    canonical(
                        {
                            "decision": {"body": body, "digest": decision["digest"]},
                            "approvals": authority,
                            "release_receipt": receipt,
                        }
                    ),
                )
                for evidence in snapshot["artifacts"]:
                    current, data = self._artifact(c, case_id, evidence["id"])
                    if current["sha256"] != evidence["sha256"]:
                        raise Fault(409, "export_artifact_changed")
                    archive.writestr("artifacts/" + evidence["id"] + ".bin", data)
                archive.writestr(
                    "README.txt",
                    "Verify with independently obtained audit and approval public keys and the expected checkpoint. Included records do not prove complete source coverage.\n",
                )
            result = self._save_artifact(
                c,
                case_id,
                stream.getvalue(),
                {
                    "filename": "case-export.zip",
                    "source": "approved case export",
                    "recipient": args["recipient"],
                    "decision_id": decision["id"],
                    "coverage": "partial",
                },
                "export",
            )
            return {
                "export_artifact_id": result["id"],
                "sha256": result["sha256"],
                "recipient": args["recipient"],
            }
        raise Fault(422, "unsupported_tool")

    def execute(self, actor: dict, case_id: str, decision_id: str) -> dict:
        with self.store.transaction(case_id) as c:
            self._case(c, case_id, actor)
            decision = self._decision(c, case_id, decision_id)
            previous = c.execute(
                "SELECT * FROM executions WHERE decision_id=?", (decision_id,)
            ).fetchone()
            if previous:
                self.store.audit(
                    c, case_id, actor, "execution.status_read", {"execution_id": previous["id"]}
                )
                return self.execution_dict(c, previous)
            if c.execute(
                "SELECT 1 FROM audit WHERE ledger=? AND json_extract(body,'$.event')='execution.intent' AND json_extract(body,'$.payload.decision_id')=?",
                (case_id, decision_id),
            ).fetchone():
                raise Fault(503, "execution_record_missing_do_not_retry")
            self._case(c, case_id, actor, open_required=decision["body"]["tool"] != "export_case")
            approvals = self._approved(c, decision)
            execution_id = uid()
            c.execute(
                "INSERT INTO executions VALUES (?,?, 'RUNNING', NULL,?,?)",
                (execution_id, decision_id, now(), now()),
            )
            c.execute("UPDATE decisions SET state='CONSUMED' WHERE id=?", (decision_id,))
            self.store.audit(
                c,
                case_id,
                actor,
                "execution.intent",
                {
                    "execution_id": execution_id,
                    "decision_id": decision_id,
                    "decision_digest": decision["digest"],
                    "approval_ids": [a["body"]["id"] for a in approvals],
                    "single_use": True,
                },
            )
        # The durable intent and checkpoint exist before any model request or local tool effect.
        remote_started = False
        try:
            if decision["body"]["tool"] in {"model_assess", "draft_pack"}:
                is_draft = decision["body"]["tool"] == "draft_pack"
                args = decision["body"]["arguments"]
                with self.store.transaction(case_id) as c:
                    self._case(c, case_id, actor, open_required=True)
                    self._approved(c, decision)
                    context = (
                        self._research(c, case_id, args["artifact_id"])
                        if is_draft
                        else self._rows(c, case_id, args["artifact_ids"])
                    )
                    prepared = (
                        self.provider.prepare_pack(args["goal"], context)
                        if is_draft
                        else self.provider.prepare(args["question"], context)
                    )
                    request_artifact = self._save_artifact(
                        c,
                        case_id,
                        canonical(prepared),
                        {
                            "filename": "model-request.json",
                            "source": "approved application-visible request",
                            "coverage": "complete_application_request",
                        },
                        "model_request",
                    )
                    self.store.audit(
                        c,
                        case_id,
                        actor,
                        "model.request_authorized",
                        {
                            "execution_id": execution_id,
                            "context_sha256": sha256(canonical(context)),
                            "request_artifact_id": request_artifact["id"],
                            "request_sha256": request_artifact["sha256"],
                            "binding": decision["body"]["binding"],
                        },
                    )
                remote_started = True
                result, transcript = (
                    self.provider.draft_pack(args["goal"], context)
                    if is_draft
                    else self.provider.assess(args["question"], context)
                )
                with self.store.transaction(case_id) as c:
                    artifact = self._save_artifact(
                        c,
                        case_id,
                        canonical(transcript),
                        {
                            "filename": "model-transaction.json",
                            "source": "application-visible model transaction",
                            "coverage": "complete_application_exchange",
                        },
                        "model_transaction",
                    )
                    result["transaction_artifact_id"] = artifact["id"]
                    if is_draft and result.get("pack"):
                        draft = self._save_artifact(
                            c,
                            case_id,
                            canonical(result["pack"]),
                            {
                                "filename": "unreviewed-research-pack.json",
                                "source": "Model-drafted research pack; not released",
                                "source_version": "unavailable",
                                "source_integrity": "not_checked",
                                "coverage": "unknown",
                                "coverage_note": "Human validation of research fidelity and independent tests is required before pack release.",
                            },
                            "source",
                        )
                        result["draft_artifact_id"] = draft["id"]
                    self.store.audit(
                        c,
                        case_id,
                        actor,
                        "model.response_preserved",
                        {
                            "execution_id": execution_id,
                            "artifact_id": artifact["id"],
                            "sha256": artifact["sha256"],
                            "review_status": result["review_status"],
                        },
                    )
                    self._complete(c, case_id, actor, execution_id, result)
            else:
                with self.store.transaction(case_id) as c:
                    self._case(
                        c, case_id, actor, open_required=decision["body"]["tool"] != "export_case"
                    )
                    self._approved(c, decision)
                    result = self._local(c, actor, case_id, decision)
                    self._complete(c, case_id, actor, execution_id, result)
        except Exception as exc:
            state = "OUTCOME_UNKNOWN" if remote_started else "FAILED"
            code = exc.code if isinstance(exc, Fault) else "tool_failed"
            with self.store.transaction(case_id) as c:
                c.execute(
                    "UPDATE executions SET state=?,result=?,updated=? WHERE id=?",
                    (
                        state,
                        encoded({"error": code, "retry": "new_human_review_required"}),
                        now(),
                        execution_id,
                    ),
                )
                self.store.audit(
                    c,
                    case_id,
                    actor,
                    "execution.failed",
                    {"execution_id": execution_id, "state": state, "error": code},
                )
        with self.store.connect() as c:
            return self.execution_dict(
                c, c.execute("SELECT * FROM executions WHERE id=?", (execution_id,)).fetchone()
            )

    def _complete(self, c, case_id, actor, execution_id, result):
        c.execute(
            "UPDATE executions SET state='COMPLETED',result=?,updated=? WHERE id=?",
            (encoded(result), now(), execution_id),
        )
        self.store.audit(
            c,
            case_id,
            actor,
            "execution.completed",
            {"execution_id": execution_id, "result_sha256": sha256(canonical(result))},
        )

    def execution_dict(self, c, row):
        result = {**dict(row), "result": strict_json(row["result"]) if row["result"] else None}
        case = c.execute(
            "SELECT case_id FROM decisions WHERE id=?", (row["decision_id"],)
        ).fetchone()
        intent = c.execute(
            "SELECT body FROM audit WHERE ledger=? AND json_extract(body,'$.event')='execution.intent' AND json_extract(body,'$.payload.execution_id')=?",
            (case[0], row["id"]),
        ).fetchone()
        if not intent or strict_json(intent[0])["payload"]["decision_id"] != row["decision_id"]:
            raise Fault(503, "execution_intent_integrity_failed")
        receipt = c.execute(
            "SELECT body FROM audit WHERE ledger=? AND json_extract(body,'$.event') IN ('execution.completed','execution.failed','execution.recovered_as_unknown') AND json_extract(body,'$.payload.execution_id')=? ORDER BY seq DESC LIMIT 1",
            (case[0], row["id"]),
        ).fetchone()
        receipt = strict_json(receipt[0]) if receipt else None
        if result["state"] == "COMPLETED":
            if (
                not receipt
                or receipt["event"] != "execution.completed"
                or receipt["payload"]["result_sha256"] != sha256(canonical(result["result"]))
            ):
                raise Fault(503, "execution_result_integrity_failed")
        elif result["state"] == "RUNNING":
            if receipt or result["result"] is not None:
                raise Fault(503, "execution_state_integrity_failed")
        elif result["state"] in {"FAILED", "OUTCOME_UNKNOWN"}:
            if (
                not receipt
                or (
                    receipt["event"] == "execution.failed"
                    and receipt["payload"]["state"] != result["state"]
                )
                or (
                    receipt["event"] == "execution.recovered_as_unknown"
                    and result["state"] != "OUTCOME_UNKNOWN"
                )
                or receipt["event"] == "execution.completed"
            ):
                raise Fault(503, "execution_state_integrity_failed")
        else:
            raise Fault(503, "unknown_execution_state")
        return result

    def _finding(self, c, row):
        finding = strict_json(row["body"])
        execution = c.execute(
            "SELECT * FROM executions WHERE decision_id=?", (row["decision_id"],)
        ).fetchone()
        if not execution:
            raise Fault(503, "finding_execution_missing")
        verified = self.execution_dict(c, execution)
        if (
            verified["state"] != "COMPLETED"
            or verified["result"] != finding
            or finding.get("id") != row["id"]
        ):
            raise Fault(503, "finding_integrity_failed")
        return finding

    def _pack(self, c, case_id, pack_id):
        row = c.execute(
            "SELECT * FROM packs WHERE id=? AND case_id=?", (pack_id, case_id)
        ).fetchone()
        if not row:
            raise Fault(404, "pack_not_found")
        decision = self._decision(c, case_id, row["decision_id"])
        expected = decision["body"]["binding"].get("pack_sha256")
        if (
            decision["body"]["tool"] != "promote_pack"
            or sha256(canonical(strict_json(row["body"]))) != expected
            or row["digest"] != expected
        ):
            raise Fault(503, "pack_release_integrity_failed")
        execution = c.execute(
            "SELECT * FROM executions WHERE decision_id=?", (row["decision_id"],)
        ).fetchone()
        if not execution:
            raise Fault(503, "pack_release_receipt_missing")
        verified = self.execution_dict(c, execution)
        if (
            verified["state"] != "COMPLETED"
            or verified["result"].get("pack_id") != pack_id
            or verified["result"].get("digest") != expected
        ):
            raise Fault(503, "pack_release_receipt_invalid")
        return row

    def detail(self, actor: dict, case_id: str) -> dict:
        with self.store.transaction(case_id) as c:
            case = self._case(c, case_id, actor)
            case["members"] = [
                dict(r)
                for r in c.execute(
                    "SELECT username,active FROM members WHERE case_id=?", (case_id,)
                )
            ]
            case["artifacts"] = [
                self._artifact(c, case_id, r[0])[0]
                for r in c.execute(
                    "SELECT id FROM artifacts WHERE case_id=? AND kind!='export_snapshot'",
                    (case_id,),
                )
            ]
            case["decisions"] = [
                self._decision(c, case_id, r[0])
                for r in c.execute(
                    "SELECT id FROM decisions WHERE case_id=? ORDER BY rowid DESC", (case_id,)
                )
            ]
            for decision in case["decisions"]:
                decision["approvals"] = [
                    strict_json(r[0])
                    for r in c.execute(
                        "SELECT envelope FROM approvals WHERE decision_id=?", (decision["id"],)
                    )
                ]
                decision["revoked_approval_ids"] = [
                    r[0]
                    for r in c.execute(
                        "SELECT revocations.approval_id FROM revocations JOIN approvals ON approvals.id=revocations.approval_id WHERE approvals.decision_id=?",
                        (decision["id"],),
                    )
                ]
            case["executions"] = [
                self.execution_dict(c, r)
                for r in c.execute(
                    "SELECT executions.* FROM executions JOIN decisions ON decisions.id=executions.decision_id WHERE decisions.case_id=? ORDER BY executions.created DESC",
                    (case_id,),
                )
            ]
            case["findings"] = [
                self._finding(c, r)
                for r in c.execute("SELECT * FROM findings WHERE case_id=?", (case_id,))
            ]
            case["packs"] = [
                {
                    "id": r["id"],
                    "digest": r["digest"],
                    "name": strict_json(self._pack(c, case_id, r["id"])["body"])["name"],
                }
                for r in c.execute("SELECT * FROM packs WHERE case_id=?", (case_id,))
            ]
            self.store.audit(c, case_id, actor, "case.viewed", {"case_id": case_id})
        with self.store.lock, self.store.connect() as c:
            case["integrity"] = self.store.verify_ledger(c, case_id)
        return case

    def audit_view(self, actor: dict, case_id: str):
        with self.store.transaction(case_id) as c:
            self._case(c, case_id, actor)
            self.store.audit(c, case_id, actor, "audit.viewed", {"case_id": case_id})
            events = self.store.audit_events(c, case_id)
        return {
            "events": events,
            "checkpoint": strict_json(self.store.checkpoint_path(case_id).read_bytes()),
        }

    def artifact_download(self, actor: dict, case_id: str, artifact_id: str):
        with self.store.transaction(case_id) as c:
            self._case(c, case_id, actor)
            metadata, data = self._artifact(c, case_id, artifact_id)
            if metadata["kind"] == "export_snapshot":
                raise Fault(403, "snapshot_requires_export_approval")
            if metadata["kind"] == "export":
                if metadata["recipient"] != actor["username"]:
                    raise Fault(403, "named_export_recipient_required")
                self._approved(c, self._decision(c, case_id, metadata["decision_id"]))
            self.store.audit(
                c,
                case_id,
                actor,
                "artifact.downloaded",
                {
                    "artifact_id": artifact_id,
                    "sha256": metadata["sha256"],
                    "instruction": "human_requested_exact_artifact",
                },
            )
        return metadata, data

    def deny(self, actor: dict | None, code: str, route: str):
        ledger = "admin-" + actor["tenant"] if actor else "authentication"
        with self.store.transaction(ledger) as c:
            self.store.audit(
                c, ledger, actor or "anonymous", "request.denied", {"code": code, "route": route}
            )

    def recover(self):
        """Explicit administrator instruction; never repeats an interrupted tool call."""
        with self.store.connect() as c:
            rows = c.execute(
                "SELECT executions.id,decisions.case_id FROM executions JOIN decisions ON decisions.id=executions.decision_id WHERE executions.state='RUNNING'"
            ).fetchall()
        for row in rows:
            with self.store.transaction(row["case_id"]) as c:
                c.execute(
                    "UPDATE executions SET state='OUTCOME_UNKNOWN',updated=? WHERE id=? AND state='RUNNING'",
                    (now(), row["id"]),
                )
                self.store.audit(
                    c,
                    row["case_id"],
                    "local-administrator",
                    "execution.recovered_as_unknown",
                    {"execution_id": row["id"], "retry_permitted": False},
                )
        return len(rows)
