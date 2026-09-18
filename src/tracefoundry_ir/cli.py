import argparse
import getpass
import json
import os
from pathlib import Path

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
    update.add_argument("--disable", action="store_true")
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
        Store(directory).change_user(
            args.username,
            roles=args.roles.split(",") if args.roles else None,
            active=False if args.disable else None,
        )
        print("Account updated; existing sessions invalidated.")
    elif args.command == "serve":
        if args.host not in {"127.0.0.1", "localhost", "::1"} and (
            os.getenv("TFIR_SECURE_COOKIES") != "true" or not os.getenv("TFIR_ORIGIN")
        ):
            parser.error(
                "Non-loopback serving requires TFIR_SECURE_COOKIES=true and TFIR_ORIGIN behind TLS"
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
