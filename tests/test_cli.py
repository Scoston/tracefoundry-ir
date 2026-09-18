import json
import sys

import pytest
from conftest import PASSWORD

from tracefoundry_ir.cli import main
from tracefoundry_ir.store import Store


def test_cli_account_lifecycle_and_diagnostics(tmp_path, monkeypatch, capsys):
    directory = tmp_path / "state"
    monkeypatch.setattr("getpass.getpass", lambda prompt: PASSWORD)

    def run(*args):
        monkeypatch.setattr(sys, "argv", ["tracefoundry", "--data-dir", str(directory), *args])
        main()
        return capsys.readouterr().out

    run("init", "--username", "operator")
    run("user-add", "--username", "reviewer", "--roles", "supervisor")
    run(
        "user-update",
        "--username",
        "reviewer",
        "--disable",
        "--reason",
        "Account suspension requested",
    )
    run(
        "password-reset", "--username", "reviewer", "--reason", "Verified local credential recovery"
    )
    store = Store(directory)
    with store.connect() as c:
        assert not store.user(c, "reviewer", require_active=False)["active"]
    run(
        "user-update",
        "--username",
        "reviewer",
        "--enable",
        "--reason",
        "Verified account return to service",
    )
    assert json.loads(run("doctor"))["local_integrity"] == "verified"
    assert json.loads(run("recover"))["retried"] == 0
    backup = tmp_path / "backup.tfir"
    made = json.loads(run("backup", "--out", str(backup)))
    original = directory
    directory = tmp_path / "restored"
    result = json.loads(
        run(
            "restore",
            str(backup),
            "--expected-sha256",
            made["sha256"],
            "--audit-key",
            str(original / "trust" / "audit-public.pem"),
        )
    )
    assert result["restored"] is True


@pytest.mark.parametrize(
    "origin,allowed",
    [
        ("http://ir.example", "ir.example"),
        ("https://ir.example/path", "ir.example"),
        ("https://user@ir.example", "ir.example"),
        ("https://ir.example", "*"),
        ("https://ir.example", "wrong.example"),
    ],
)
def test_cli_rejects_unsafe_external_bind_configuration(tmp_path, monkeypatch, origin, allowed):
    monkeypatch.setenv("TFIR_SECURE_COOKIES", "true")
    monkeypatch.setenv("TFIR_ORIGIN", origin)
    monkeypatch.setenv("TFIR_ALLOWED_HOSTS", allowed)
    monkeypatch.setattr(
        sys,
        "argv",
        ["tracefoundry", "--data-dir", str(tmp_path / "not-created"), "serve", "--host", "0.0.0.0"],
    )
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
