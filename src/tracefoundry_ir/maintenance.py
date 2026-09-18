"""Explicit local maintenance. No integrity repair, tool replay, or remote calls."""

import io
import os
import re
import sqlite3
import tempfile
import zipfile
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from filelock import Timeout

from .security import canonical, now, secret_write, sha256, strict_json, verify_signature
from .service import Service
from .store import Fault, Store, uid

MAGIC = b"TFIR-BACKUP-1\0"
MAX_BYTES = 256_000_000
FIXED = {
    "state.sqlite3",
    "keys/approvals.pem",
    "keys/audit.pem",
    "keys/vault.key",
    "trust/approvals-public.pem",
    "trust/audit-public.pem",
}


def _allowed(name: str) -> bool:
    return name in FIXED or bool(
        re.fullmatch(r"checkpoints/[a-f0-9]{64}(?:-[1-9][0-9]*)?\.json", name)
    )


def _key(password: str, salt: bytes) -> bytes:
    if not 14 <= len(password) <= 256:
        raise ValueError("Backup passphrase must contain 14 to 256 characters")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())


def inspect_state(store: Store) -> dict:
    """Read and verify all local evidence; do not bless a new checkpoint or fix a row."""
    service = Service(store)
    with store.lock, store.connect() as c:
        if (
            c.execute("PRAGMA integrity_check").fetchone()[0] != "ok"
            or c.execute("PRAGMA foreign_key_check").fetchone()
        ):
            raise Fault(503, "database_integrity_failed")
        for name, signer in (("audit", store.audit_signer), ("approvals", store.approval_signer)):
            if (store.directory / "trust" / f"{name}-public.pem").read_bytes() != signer.public_pem:
                raise Fault(503, "local_trust_key_mismatch")
        ledgers = {r[0] for r in c.execute("SELECT DISTINCT ledger FROM audit")}
        for path in (store.directory / "checkpoints").glob("*.json"):
            envelope = strict_json(path.read_bytes())
            if not verify_signature(envelope, "TFIR-CHECKPOINT-v1", store.audit_signer.public_pem):
                raise Fault(503, "checkpoint_history_untrusted")
            body = envelope["body"]
            ledger, sequence = body["ledger"], int(body["event_count"])
            expected_names = {
                sha256(ledger.encode()) + ".json",
                sha256(ledger.encode()) + "-" + str(sequence) + ".json",
            }
            event = c.execute(
                "SELECT hash FROM audit WHERE ledger=? AND seq=?", (ledger, sequence)
            ).fetchone()
            if path.name not in expected_names or not event or event[0] != body["head_hash"]:
                raise Fault(503, "checkpoint_history_mismatch")
            ledgers.add(ledger)
        heads = [store.verify_ledger(c, ledger) for ledger in sorted(ledgers)]
        users = c.execute("SELECT username FROM users").fetchall()
        for row in users:
            store.user(c, row[0], require_active=False)
        cases = c.execute("SELECT * FROM cases").fetchall()
        case_ledgers = {
            r[0]
            for r in c.execute(
                "SELECT ledger FROM audit WHERE json_extract(body,'$.event')='case.created'"
            )
        }
        if case_ledgers != {r["id"] for r in cases}:
            raise Fault(503, "case_inventory_incomplete")
        for case in cases:
            events = store.audit_events(c, case["id"])
            first = events[0]["body"]
            if (
                first["payload"]["tenant"] != case["tenant"]
                or first["actor"] != case["creator"]
                or first["payload"]["title_sha256"] != sha256(case["title"].encode())
                or first["payload"]["description_sha256"] != sha256(case["description"].encode())
                or bool(case["closed"]) != any(e["body"]["event"] == "case.closed" for e in events)
            ):
                raise Fault(503, "case_metadata_integrity_failed")
            service._inventory(c, case["id"])
            for row in c.execute("SELECT id FROM artifacts WHERE case_id=?", (case["id"],)):
                service._artifact(c, case["id"], row[0])
            for event in events:
                if event["body"]["event"] == "evidence.normalized":
                    service._rows(c, case["id"], [event["body"]["payload"]["artifact_id"]])
            for row in c.execute("SELECT id FROM decisions WHERE case_id=?", (case["id"],)):
                service._decision(c, case["id"], row[0])
            for row in c.execute("SELECT * FROM findings WHERE case_id=?", (case["id"],)):
                service._finding(c, row)
            for row in c.execute("SELECT id FROM packs WHERE case_id=?", (case["id"],)):
                service._pack(c, case["id"], row[0])
            for event in (
                "execution.reconciled",
                "finding.challenged",
                "finding.challenge_resolved",
            ):
                service._workflow_records(c, case["id"], event)
        return {
            "local_integrity": "verified",
            "cases": len(cases),
            "users": len(users),
            "heads": heads,
            "independent_witness": "not_configured",
        }


def create_backup(store: Store, destination: Path, password: str) -> dict:
    destination = destination.resolve()
    if destination.exists() or destination.is_relative_to(store.directory):
        raise ValueError("Choose a new backup file outside the live state directory")
    salt, nonce = os.urandom(32), os.urandom(12)
    key = _key(password, salt)
    backup_id = uid()
    try:
        with store.dispatch_lock.acquire(timeout=0), store.lock:
            inspect_state(store)
            with store.transaction("maintenance") as c:
                store.audit(
                    c,
                    "maintenance",
                    "local-administrator",
                    "backup.started",
                    {"backup_id": backup_id},
                )
            with tempfile.TemporaryDirectory(prefix="tfir-backup-") as temporary:
                database = Path(temporary) / "state.sqlite3"
                with store.connect() as source, closing(sqlite3.connect(database)) as target:
                    source.backup(target)
                paths = [
                    database,
                    *(store.directory / name for name in FIXED - {"state.sqlite3"}),
                    *(store.directory / "checkpoints").glob("*.json"),
                ]
                if sum(p.stat().st_size for p in paths) > MAX_BYTES:
                    raise ValueError("Local backup exceeds the 256 MB profile")
                files = {"state.sqlite3": database.read_bytes()}
                for name in FIXED - {"state.sqlite3"}:
                    files[name] = (store.directory / name).read_bytes()
                for path in sorted((store.directory / "checkpoints").glob("*.json")):
                    files["checkpoints/" + path.name] = path.read_bytes()
                if sum(map(len, files.values())) > MAX_BYTES:
                    raise ValueError(
                        "Local backup exceeds the 256 MB profile; use a qualified storage backup service"
                    )
                manifest = store.audit_signer.sign(
                    "TFIR-BACKUP-MANIFEST-v1",
                    {
                        "backup_id": backup_id,
                        "created_at": now(),
                        "files": {
                            name: {"sha256": sha256(data), "bytes": len(data)}
                            for name, data in files.items()
                        },
                    },
                )
                stream = io.BytesIO()
                with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
                    for name, data in files.items():
                        archive.writestr(name, data)
                    archive.writestr("manifest.json", canonical(manifest))
                header = MAGIC + salt + nonce
                encrypted = header + AESGCM(key).encrypt(nonce, stream.getvalue(), header)
                secret_write(destination, encrypted)
            hashed = sha256(encrypted)
            with store.transaction("maintenance") as c:
                store.audit(
                    c,
                    "maintenance",
                    "local-administrator",
                    "backup.completed",
                    {"backup_id": backup_id, "sha256": hashed},
                )
    except Timeout as exc:
        raise Fault(409, "active_execution_blocks_backup") from exc
    return {
        "backup_id": backup_id,
        "sha256": hashed,
        "encrypted": True,
        "independent_pin_required": True,
    }


def restore_backup(
    archive_path: Path, destination: Path, password: str, expected_sha256: str, audit_key: bytes
) -> dict:
    destination = destination.resolve()
    if destination.exists():
        raise ValueError("Restore requires a new directory; existing state is never overwritten")
    if archive_path.stat().st_size > MAX_BYTES + 2_000_000:
        raise ValueError("Backup size limit exceeded")
    encrypted = archive_path.read_bytes()
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256) or sha256(encrypted) != expected_sha256:
        raise ValueError("Backup does not match the independently retained SHA-256 pin")
    if not encrypted.startswith(MAGIC) or len(encrypted) < len(MAGIC) + 60:
        raise ValueError("Unknown or truncated backup format")
    salt = encrypted[len(MAGIC) : len(MAGIC) + 32]
    nonce = encrypted[len(MAGIC) + 32 : len(MAGIC) + 44]
    header = encrypted[: len(MAGIC) + 44]
    content = AESGCM(_key(password, salt)).decrypt(nonce, encrypted[len(header) :], header)
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        entries = archive.infolist()
        names = [i.filename for i in entries]
        if (
            len(names) != len(set(names))
            or len(names) > 100000
            or sum(i.file_size for i in entries) > MAX_BYTES + 2_000_000
            or any(not _allowed(n) and n != "manifest.json" for n in names)
        ):
            raise ValueError("Unsafe, duplicate, or excessive backup archive entries")
        manifest = strict_json(archive.read("manifest.json"))
        if not verify_signature(manifest, "TFIR-BACKUP-MANIFEST-v1", audit_key):
            raise ValueError("Backup manifest signer is not trusted")
        files = manifest["body"]["files"]
        if set(names) != set(files) | {"manifest.json"} or not FIXED <= set(files):
            raise ValueError("Backup inventory is incomplete")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(
            prefix="tfir-restore-", dir=destination.parent
        ) as temporary:
            restored = Path(temporary) / "state"
            for name, expected in files.items():
                data = archive.read(name)
                if len(data) != expected["bytes"] or sha256(data) != expected["sha256"]:
                    raise ValueError("Backup file integrity failed")
                secret_write(restored / name, data)
            store = Store(restored)
            result = inspect_state(store)
            # Recovery never revives cached sessions or pending authority from the backup.
            with store.connect() as c:
                users = [r[0] for r in c.execute("SELECT username FROM users")]
            for username in users:
                store.change_user(
                    username,
                    reason="backup restore invalidated prior sessions and pending approvals",
                )
            with store.transaction("maintenance") as c:
                store.audit(
                    c,
                    "maintenance",
                    "local-administrator",
                    "backup.restored",
                    {
                        "backup_id": manifest["body"]["backup_id"],
                        "archive_sha256": expected_sha256,
                        "authority_reset": True,
                    },
                )
            inspect_state(store)
            if destination.exists():
                raise ValueError("Restore destination was created by another process")
            restored.rename(destination)
    return {
        **result,
        "restored": True,
        "sessions_and_pending_approvals_invalidated": True,
        "tool_retries": 0,
    }
