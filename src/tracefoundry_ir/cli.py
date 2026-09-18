import argparse
import getpass
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from .security import sha256, strict_json
from .store import Store


def main():
    parser = argparse.ArgumentParser(
        prog="tracefoundry", description="Human-authorized incident investigations"
    )
    parser.add_argument("--data-dir", default=os.getenv("TFIR_DATA_DIR", "var"))
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Create protected state and an initial human account")
    init.add_argument("--username", required=True)
    init.add_argument("--tenant", default="local")
    user = sub.add_parser("user-add", help="Add a named human from the trusted host console")
    user.add_argument("--username", required=True)
    user.add_argument("--roles", default="analyst")
    user.add_argument("--tenant", default="local")
    update = sub.add_parser(
        "user-update", help="Change roles or disable an account; invalidates sessions"
    )
    update.add_argument("--username", required=True)
    update.add_argument("--roles")
    active = update.add_mutually_exclusive_group()
    active.add_argument("--disable", action="store_true")
    active.add_argument("--enable", action="store_true")
    update.add_argument("--reason", required=True)
    reset = sub.add_parser(
        "password-reset",
        help="Reset a local human credential and invalidate sessions and pending approvals",
    )
    reset.add_argument("--username", required=True)
    reset.add_argument("--reason", required=True)
    sub.add_parser(
        "doctor",
        help="Verify database, trust keys, all ledgers, evidence and recorded authority; never repair",
    )
    backup = sub.add_parser(
        "backup", help="Create an encrypted, signed local backup while no tool is executing"
    )
    backup.add_argument("--out", required=True)
    restore = sub.add_parser(
        "restore",
        help="Restore a trusted backup into a new data directory; never overwrite or retry tools",
    )
    restore.add_argument("archive")
    restore.add_argument("--expected-sha256", required=True)
    restore.add_argument("--audit-key", required=True)
    serve = sub.add_parser("serve", help="Start the analyst console")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", default=8000, type=int)
    sub.add_parser("recover", help="Mark interrupted executions unknown; never retry them")
    checkpoint = sub.add_parser(
        "checkpoint", help="Copy a signed checkpoint for independent retention"
    )
    checkpoint.add_argument("case_id")
    checkpoint.add_argument("--sequence", type=int)
    checkpoint.add_argument("--out", required=True)
    verify = sub.add_parser(
        "verify-export", help="Verify an export offline using independently trusted material"
    )
    verify.add_argument("archive")
    verify.add_argument("--audit-key", required=True)
    verify.add_argument("--approval-key", required=True)
    verify.add_argument("--expected-checkpoint", required=True)
    pack = sub.add_parser("validate-pack")
    pack.add_argument("file")
    args = parser.parse_args()
    directory = Path(args.data_dir)
    if args.command == "verify-export":
        from .verify import verify_export

        result = verify_export(
            args.archive,
            Path(args.audit_key).read_bytes(),
            Path(args.approval_key).read_bytes(),
            strict_json(Path(args.expected_checkpoint).read_bytes()),
        )
        print(json.dumps(result, indent=2))
        return
    if args.command == "restore":
        from .maintenance import restore_backup

        result = restore_backup(
            Path(args.archive),
            directory,
            getpass.getpass("Backup passphrase: "),
            args.expected_sha256,
            Path(args.audit_key).read_bytes(),
        )
        print(json.dumps(result, indent=2))
        return
    if args.command == "validate-pack":
        from .tools import validate_pack

        result = validate_pack(Path(args.file).read_bytes())
        print(
            json.dumps(
                {"name": result["name"], "tests_passed": len(result["tests"]), "promoted": False}
            )
        )
        return
    if args.command in {"init", "user-add"}:
        password = getpass.getpass("Password (14+ characters): ")
        if password != getpass.getpass("Confirm password: "):
            parser.error("Passwords differ")
        # Validate before creating any state, so a rejected password does not strand initialization.
        from .security import password_hash

        password_hash(password)
        store = Store.initialize(directory) if args.command == "init" else Store(directory)
        roles = (
            ["admin", "analyst", "supervisor"] if args.command == "init" else args.roles.split(",")
        )
        store.add_user(args.username, password, roles, args.tenant)
        print(f"Human account created: {args.username}. No operational decisions were approved.")
    elif args.command == "user-update":
        if len(args.reason.strip()) < 8 or not (args.roles or args.disable or args.enable):
            parser.error(
                "Choose an account change and provide a reason of at least eight characters"
            )
        Store(directory).change_user(
            args.username,
            roles=args.roles.split(",") if args.roles else None,
            active=False if args.disable else True if args.enable else None,
            reason=args.reason,
        )
        print("Account updated; existing sessions and pending approvals invalidated.")
    elif args.command == "password-reset":
        if len(args.reason.strip()) < 8:
            parser.error("Provide a reason of at least eight characters")
        password = getpass.getpass("New password (14+ characters): ")
        if password != getpass.getpass("Confirm new password: "):
            parser.error("Passwords differ")
        Store(directory).change_user(args.username, password=password, reason=args.reason)
        print(
            "Password reset; sessions and pending approvals invalidated. Account activation was not changed."
        )
    elif args.command == "doctor":
        from .maintenance import inspect_state

        print(json.dumps(inspect_state(Store(directory)), indent=2))
    elif args.command == "backup":
        from .maintenance import create_backup

        password = getpass.getpass("Backup passphrase (14+ characters): ")
        if password != getpass.getpass("Confirm backup passphrase: "):
            parser.error("Passphrases differ")
        print(json.dumps(create_backup(Store(directory), Path(args.out), password), indent=2))
    elif args.command == "serve":
        if args.host not in {"127.0.0.1", "localhost", "::1"}:
            origin = urlsplit(os.getenv("TFIR_ORIGIN", ""))
            allowed = os.getenv("TFIR_ALLOWED_HOSTS", "").split(",")
            if (
                os.getenv("TFIR_SECURE_COOKIES") != "true"
                or origin.scheme != "https"
                or not origin.hostname
                or origin.hostname not in allowed
                or "*" in allowed
                or origin.username
                or origin.password
                or origin.path
                or origin.query
                or origin.fragment
            ):
                parser.error(
                    "Non-loopback serving requires secure cookies, an exact HTTPS origin, and an explicit matching allowed host behind TLS"
                )
        import uvicorn

        from .app import create_app

        uvicorn.run(
            create_app(directory),
            host=args.host,
            port=args.port,
            access_log=False,
            proxy_headers=False,
        )
    elif args.command == "recover":
        from .service import Service

        print(json.dumps({"marked_unknown": Service(Store(directory)).recover(), "retried": 0}))
    elif args.command == "checkpoint":
        store = Store(directory)
        with store.lock, store.connect() as c:
            store.verify_ledger(c, args.case_id)
            source = store.checkpoint_path(args.case_id)
            if args.sequence is not None:
                source = (
                    store.directory
                    / "checkpoints"
                    / (sha256(args.case_id.encode()) + "-" + str(args.sequence) + ".json")
                )
            Path(args.out).write_bytes(source.read_bytes())
        print(
            f"Checkpoint copied to {args.out}; retain it outside this application's administration."
        )


if __name__ == "__main__":
    main()
