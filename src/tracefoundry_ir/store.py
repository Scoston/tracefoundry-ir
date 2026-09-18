"""Serialized durable storage. A failed checkpoint blocks further operations."""

import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from filelock import FileLock

from .security import (
    Signer,
    Vault,
    canonical,
    digest,
    now,
    password_hash,
    password_matches,
    secret_write,
    sha256,
    strict_json,
    verify_signature,
)

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
 username TEXT PRIMARY KEY, tenant TEXT NOT NULL, roles TEXT NOT NULL, kind TEXT NOT NULL,
 active INTEGER NOT NULL, password TEXT NOT NULL, attestation TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username),
 csrf_hash TEXT NOT NULL, auth_event TEXT NOT NULL, expires TEXT NOT NULL, attestation TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS login_attempts (
 bucket TEXT NOT NULL, happened TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS attempt_bucket ON login_attempts(bucket, happened);
CREATE TABLE IF NOT EXISTS cases (
 id TEXT PRIMARY KEY, tenant TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL,
 creator TEXT NOT NULL, created TEXT NOT NULL, closed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS members (
 case_id TEXT NOT NULL REFERENCES cases(id), username TEXT NOT NULL REFERENCES users(username),
 active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(case_id, username));
CREATE TABLE IF NOT EXISTS artifacts (
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id), metadata TEXT NOT NULL,
 content BLOB NOT NULL, kind TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS chunks (
 id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL REFERENCES artifacts(id), body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS decisions (
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id), body TEXT NOT NULL,
 digest TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'PENDING');
CREATE TABLE IF NOT EXISTS approvals (
 id TEXT PRIMARY KEY, decision_id TEXT NOT NULL REFERENCES decisions(id),
 username TEXT NOT NULL REFERENCES users(username), envelope TEXT NOT NULL,
 UNIQUE(decision_id, username));
CREATE TABLE IF NOT EXISTS revocations (
 approval_id TEXT PRIMARY KEY REFERENCES approvals(id), actor TEXT NOT NULL, reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS executions (
 id TEXT PRIMARY KEY, decision_id TEXT UNIQUE NOT NULL REFERENCES decisions(id),
 state TEXT NOT NULL, result TEXT, created TEXT NOT NULL, updated TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings (
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
 decision_id TEXT NOT NULL REFERENCES decisions(id), body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS packs (
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id), body TEXT NOT NULL,
 digest TEXT NOT NULL, decision_id TEXT NOT NULL REFERENCES decisions(id));
CREATE TABLE IF NOT EXISTS audit (
 ledger TEXT NOT NULL, seq INTEGER NOT NULL, hash TEXT NOT NULL, body TEXT NOT NULL,
 PRIMARY KEY(ledger,seq));
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
 BEGIN SELECT RAISE(ABORT, 'Audit records are append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
 BEGIN SELECT RAISE(ABORT, 'Audit records are append only'); END;
CREATE TRIGGER IF NOT EXISTS immutable_decisions BEFORE UPDATE OF body,digest,case_id ON decisions
 BEGIN SELECT RAISE(ABORT, 'Decision bodies are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_approvals BEFORE UPDATE ON approvals
 BEGIN SELECT RAISE(ABORT, 'Approval attestations are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_artifacts BEFORE UPDATE ON artifacts
 BEGIN SELECT RAISE(ABORT, 'Artifacts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_chunks BEFORE UPDATE ON chunks
 BEGIN SELECT RAISE(ABORT, 'Evidence chunks are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_packs BEFORE UPDATE ON packs
 BEGIN SELECT RAISE(ABORT, 'Released packs are immutable'); END;
"""


class Fault(Exception):
    def __init__(self, status: int, code: str):
        self.status = status
        self.code = code
        super().__init__(code)


def encoded(value) -> str:
    return canonical(value).decode()


def uid() -> str:
    return secrets.token_hex(16)


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class Store:
    def __init__(self, directory: Path):
        self.directory = directory.resolve()
        if not (self.directory / "state.sqlite3").exists():
            raise RuntimeError("Initialize first: tracefoundry init")
        self.lock = FileLock(str(self.directory / "transaction.lock"), timeout=30)
        self.dispatch_lock = FileLock(str(self.directory / "dispatch.lock"), timeout=60)
        self.approval_signer = Signer(self.directory / "keys" / "approvals.pem")
        self.audit_signer = Signer(self.directory / "keys" / "audit.pem")
        self.vault = Vault(self.directory / "keys" / "vault.key")
        self._dummy_hash = password_hash(secrets.token_urlsafe(24))
        with self.connect() as connection:
            version = connection.execute("SELECT value FROM metadata WHERE key='schema'").fetchone()
            if not version or version[0] != "1":
                raise RuntimeError("Unsupported database schema; do not auto-migrate evidence")

    @classmethod
    def initialize(cls, directory: Path):
        directory = directory.resolve()
        if directory.exists() and any(directory.iterdir()):
            raise ValueError("Initialization requires a new or empty data directory")
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        if os.name != "nt":
            directory.chmod(0o700)
        (directory / "checkpoints").mkdir(mode=0o700)
        for name in ("approvals", "audit"):
            signer = Signer.create(directory / "keys" / f"{name}.pem")
            secret_write(directory / "trust" / f"{name}-public.pem", signer.public_pem)
        secret_write(directory / "keys" / "vault.key", secrets.token_bytes(32))
        connection = sqlite3.connect(directory / "state.sqlite3")
        try:
            connection.executescript(SCHEMA)
            connection.execute("INSERT INTO metadata VALUES ('schema', '1')")
            connection.commit()
        finally:
            connection.close()
        if os.name != "nt":
            (directory / "state.sqlite3").chmod(0o600)
        return cls(directory)

    def connect(self):
        connection = sqlite3.connect(
            self.directory / "state.sqlite3", timeout=30, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def checkpoint_path(self, ledger: str) -> Path:
        return self.directory / "checkpoints" / (sha256(ledger.encode()) + ".json")

    def audit_events(self, connection, ledger: str) -> list[dict]:
        return [
            {"body": strict_json(row["body"]), "hash": row["hash"]}
            for row in connection.execute(
                "SELECT * FROM audit WHERE ledger=? ORDER BY seq", (ledger,)
            )
        ]

    def verify_ledger(self, connection, ledger: str) -> dict:
        events = self.audit_events(connection, ledger)
        previous = "0" * 64
        for i, event in enumerate(events, 1):
            body = event["body"]
            if (
                body.get("sequence") != str(i)
                or body.get("ledger") != ledger
                or body.get("previous_hash") != previous
                or digest("TFIR-EVENT-v1", body) != event["hash"]
            ):
                raise Fault(503, "audit_integrity_failed")
            previous = event["hash"]
        if events and datetime.fromisoformat(events[-1]["body"]["timestamp"]) > datetime.now(
            UTC
        ) + timedelta(seconds=5):
            raise Fault(503, "clock_behind_audit_history")
        path = self.checkpoint_path(ledger)
        if events or path.exists():
            if not path.exists():
                raise Fault(503, "checkpoint_missing")
            checkpoint = strict_json(path.read_bytes())
            if not verify_signature(checkpoint, "TFIR-CHECKPOINT-v1", self.audit_signer.public_pem):
                raise Fault(503, "checkpoint_untrusted")
            body = checkpoint["body"]
            if (
                body.get("ledger") != ledger
                or body.get("event_count") != str(len(events))
                or body.get("head_hash") != previous
            ):
                raise Fault(503, "checkpoint_head_mismatch")
        return {
            "ledger": ledger,
            "event_count": len(events),
            "head_hash": previous,
            "local_integrity": "verified",
            "independent_witness": "not_configured",
        }

    def checkpoint(self, connection, ledger: str):
        row = connection.execute(
            "SELECT seq,hash FROM audit WHERE ledger=? ORDER BY seq DESC LIMIT 1", (ledger,)
        ).fetchone()
        if not row:
            return
        envelope = self.audit_signer.sign(
            "TFIR-CHECKPOINT-v1",
            {
                "schema_version": "1",
                "ledger": ledger,
                "event_count": str(row["seq"]),
                "head_hash": row["hash"],
                "created_at": now(),
            },
        )
        history = (
            self.directory
            / "checkpoints"
            / (sha256(ledger.encode()) + "-" + str(row["seq"]) + ".json")
        )
        if history.exists():
            existing = strict_json(history.read_bytes())
            if (
                not verify_signature(existing, "TFIR-CHECKPOINT-v1", self.audit_signer.public_pem)
                or existing["body"]["head_hash"] != row["hash"]
            ):
                raise Fault(503, "checkpoint_history_conflict")
            envelope = existing
        else:
            secret_write(history, canonical(envelope))
        secret_write(self.checkpoint_path(ledger), canonical(envelope), replace=True)

    @contextmanager
    def transaction(self, ledger: str):
        with self.lock:
            connection = self.connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                self.verify_ledger(connection, ledger)
                yield connection
                connection.commit()
                # Commit and external witness are not atomic. Fail closed on any mismatch.
                self.checkpoint(connection, ledger)
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    def audit(self, connection, ledger: str, actor: dict | str, event: str, payload: dict) -> str:
        last = connection.execute(
            "SELECT seq,hash FROM audit WHERE ledger=? ORDER BY seq DESC LIMIT 1", (ledger,)
        ).fetchone()
        body = {
            "schema_version": "1",
            "ledger": ledger,
            "sequence": str(last["seq"] + 1 if last else 1),
            "previous_hash": last["hash"] if last else "0" * 64,
            "timestamp": now(),
            "event": event,
            "actor": actor if isinstance(actor, str) else actor["username"],
            "auth_event": None if isinstance(actor, str) else actor.get("auth_event"),
            "payload": payload,
        }
        hashed = digest("TFIR-EVENT-v1", body)
        connection.execute(
            "INSERT INTO audit VALUES (?,?,?,?)",
            (ledger, int(body["sequence"]), hashed, encoded(body)),
        )
        return hashed

    def add_user(
        self,
        username: str,
        password: str,
        roles: list[str],
        tenant: str = "local",
        kind: str = "human",
    ):
        import re

        if (
            not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", username)
            or not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", tenant)
            or not roles
            or set(roles) - {"admin", "analyst", "supervisor"}
            or kind not in {"human", "service"}
        ):
            raise ValueError("Invalid username, tenant, roles, or principal kind")
        hashed = password_hash(password)
        body = {
            "username": username,
            "tenant": tenant,
            "roles": sorted(set(roles)),
            "kind": kind,
            "active": True,
            "password_digest": sha256(hashed.encode()),
        }
        envelope = self.audit_signer.sign("TFIR-IDENTITY-v1", body)
        ledger = "admin-" + tenant
        with self.transaction(ledger) as c:
            c.execute(
                "INSERT INTO users VALUES (?,?,?,?,?,?,?)",
                (username, tenant, encoded(body["roles"]), kind, 1, hashed, encoded(envelope)),
            )
            self.audit(
                c,
                ledger,
                "local-administrator",
                "identity.created",
                {"username": username, "identity_digest": digest("TFIR-IDENTITY-v1", body)},
            )

    def change_user(
        self,
        username: str,
        *,
        roles: list[str] | None = None,
        active: bool | None = None,
        password: str | None = None,
        actor: dict | None = None,
        reason: str = "trusted host administration",
    ):
        hashed = password_hash(password) if password is not None else None
        with self.lock, self.connect() as c:
            existing = self.user(c, username, require_active=False)
        if roles is not None and (not roles or set(roles) - {"admin", "analyst", "supervisor"}):
            raise ValueError("Invalid roles")
        with self.transaction("admin-" + existing["tenant"]) as c:
            self.user(c, username, require_active=False)
            row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            body = strict_json(row["attestation"])["body"]
            if roles is not None:
                body["roles"] = sorted(set(roles))
            if active is not None:
                body["active"] = active
            if hashed is not None:
                body["password_digest"] = sha256(hashed.encode())
            envelope = self.audit_signer.sign("TFIR-IDENTITY-v1", body)
            c.execute(
                "UPDATE users SET roles=?,active=?,password=?,attestation=? WHERE username=?",
                (
                    encoded(body["roles"]),
                    int(body["active"]),
                    hashed or row["password"],
                    encoded(envelope),
                    username,
                ),
            )
            c.execute("DELETE FROM sessions WHERE username=?", (username,))
            self.audit(
                c,
                "admin-" + existing["tenant"],
                actor or "local-administrator",
                "identity.changed",
                {
                    "username": username,
                    "identity_digest": digest("TFIR-IDENTITY-v1", body),
                    "reason": reason,
                    "password_changed": hashed is not None,
                },
            )

    def change_password(self, actor: dict, current_password: str, new_password: str):
        # Keep reauthentication and credential replacement in one serialized boundary.
        with self.lock:
            self.reauthenticate(actor, current_password)
            self.change_user(
                actor["username"],
                password=new_password,
                actor=actor,
                reason="human requested password change",
            )

    def user(self, c, username: str, *, require_active=True) -> dict:
        row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            raise Fault(401, "authentication_required")
        record = dict(row)
        record["roles"] = strict_json(record["roles"])
        body = {
            "username": username,
            "tenant": record["tenant"],
            "roles": record["roles"],
            "kind": record["kind"],
            "active": bool(record["active"]),
            "password_digest": sha256(record["password"].encode()),
        }
        envelope = strict_json(record["attestation"])
        if envelope["body"] != body or not verify_signature(
            envelope, "TFIR-IDENTITY-v1", self.audit_signer.public_pem
        ):
            raise Fault(503, "identity_integrity_failed")
        ledger = "admin-" + record["tenant"]
        self.verify_ledger(c, ledger)
        latest = c.execute(
            "SELECT body,hash FROM audit WHERE ledger=? AND json_extract(body,'$.event') IN ('identity.created','identity.changed') AND json_extract(body,'$.payload.username')=? ORDER BY seq DESC LIMIT 1",
            (ledger, username),
        ).fetchone()
        if not latest or strict_json(latest[0])["payload"]["identity_digest"] != digest(
            "TFIR-IDENTITY-v1", body
        ):
            raise Fault(503, "identity_history_mismatch")
        if require_active and not record["active"]:
            raise Fault(401, "account_disabled")
        record["identity_event"] = latest["hash"]
        return record

    def login(self, username: str, password: str, peer: str) -> tuple[dict, str, str]:
        bucket = sha256((peer + "\0" + username).encode())
        cutoff = (datetime.now(UTC) - timedelta(minutes=15)).isoformat()
        with self.lock, self.connect() as c:
            count = c.execute(
                "SELECT COUNT(*) FROM login_attempts WHERE bucket=? AND happened>?",
                (bucket, cutoff),
            ).fetchone()[0]
            if count >= 5:
                raise Fault(429, "login_rate_limited")
            row = c.execute(
                "SELECT password,tenant FROM users WHERE username=?", (username,)
            ).fetchone()
            matched = password_matches(password, row["password"] if row else self._dummy_hash)
            if not matched or not row:
                c.execute("DELETE FROM login_attempts WHERE happened<?", (cutoff,))
                c.execute("INSERT INTO login_attempts VALUES (?,?)", (bucket, now()))
                c.commit()
                with self.transaction("authentication") as a:
                    self.audit(
                        a,
                        "authentication",
                        "anonymous",
                        "authentication.denied",
                        {
                            "subject_digest": sha256(username.encode()),
                            "peer_digest": sha256(peer.encode()),
                        },
                    )
                raise Fault(401, "invalid_credentials")
            actor = self.user(c, username)
            if actor["kind"] != "human":
                raise Fault(403, "human_session_required")
        token, csrf, auth_event = secrets.token_urlsafe(32), secrets.token_urlsafe(32), uid()
        session_body = {
            "token_hash": sha256(token.encode()),
            "username": username,
            "csrf_hash": sha256(csrf.encode()),
            "auth_event": auth_event,
            "expires": (datetime.now(UTC) + timedelta(minutes=30)).isoformat(),
        }
        with self.transaction("admin-" + actor["tenant"]) as c:
            # An account change between password verification and session creation must win.
            current = self.user(c, username)
            if current["identity_event"] != actor["identity_event"]:
                raise Fault(401, "identity_changed_during_login")
            session_body["identity_event"] = current["identity_event"]
            session_attestation = self.audit_signer.sign("TFIR-SESSION-v1", session_body)
            c.execute(
                "INSERT INTO sessions VALUES (?,?,?,?,?,?)",
                (
                    *(
                        session_body[k]
                        for k in ("token_hash", "username", "csrf_hash", "auth_event", "expires")
                    ),
                    encoded(session_attestation),
                ),
            )
            self.audit(
                c,
                "admin-" + actor["tenant"],
                username,
                "authentication.succeeded",
                {
                    "auth_event": auth_event,
                    "session_sha256": sha256(canonical(session_attestation)),
                },
            )
        return (
            {"username": username, "roles": actor["roles"], "tenant": actor["tenant"]},
            token,
            csrf,
        )

    def session(self, token: str | None) -> dict:
        if not token:
            raise Fault(401, "authentication_required")
        with self.lock, self.connect() as c:
            session = c.execute(
                "SELECT * FROM sessions WHERE token_hash=?", (sha256(token.encode()),)
            ).fetchone()
            if not session or session["expires"] <= now():
                raise Fault(401, "session_expired")
            envelope = strict_json(session["attestation"])
            expected = {
                k: session[k]
                for k in ("token_hash", "username", "csrf_hash", "auth_event", "expires")
            }
            expected["identity_event"] = envelope["body"].get("identity_event")
            if envelope["body"] != expected or not verify_signature(
                envelope, "TFIR-SESSION-v1", self.audit_signer.public_pem
            ):
                raise Fault(401, "session_attestation_invalid")
            actor = self.user(c, session["username"])
            if expected["identity_event"] != actor["identity_event"]:
                raise Fault(401, "session_identity_changed")
            issued = c.execute(
                "SELECT body FROM audit WHERE ledger=? AND json_extract(body,'$.event')='authentication.succeeded' AND json_extract(body,'$.payload.auth_event')=?",
                ("admin-" + actor["tenant"], session["auth_event"]),
            ).fetchone()
            if not issued or strict_json(issued[0])["payload"].get("session_sha256") != sha256(
                canonical(envelope)
            ):
                raise Fault(401, "session_issue_receipt_missing")
            logged_out = c.execute(
                "SELECT 1 FROM audit WHERE ledger=? AND json_extract(body,'$.event')='authentication.logged_out' AND json_extract(body,'$.payload.auth_event')=?",
                ("admin-" + actor["tenant"], session["auth_event"]),
            ).fetchone()
            if logged_out:
                raise Fault(401, "session_revoked")
            if actor["kind"] != "human":
                raise Fault(403, "human_session_required")
            actor.update(
                {
                    "auth_event": session["auth_event"],
                    "csrf_hash": session["csrf_hash"],
                    "session_hash": session["token_hash"],
                }
            )
            return actor

    def reauthenticate(self, actor: dict, password: str):
        bucket = "review-" + actor["username"]
        cutoff = (datetime.now(UTC) - timedelta(minutes=15)).isoformat()
        with self.lock, self.connect() as c:
            current = self.user(c, actor["username"])
            attempts = c.execute(
                "SELECT COUNT(*) FROM login_attempts WHERE bucket=? AND happened>?",
                (bucket, cutoff),
            ).fetchone()[0]
            if attempts >= 5:
                raise Fault(429, "review_rate_limited")
            if current["kind"] != "human" or not password_matches(password, current["password"]):
                c.execute("INSERT INTO login_attempts VALUES (?,?)", (bucket, now()))
                c.commit()
                raise Fault(403, "human_reauthentication_failed")
            c.execute("DELETE FROM login_attempts WHERE bucket=?", (bucket,))
            c.commit()
            return current["identity_event"]
