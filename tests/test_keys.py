"""Tests for GnuPG preparation and evidence-key export."""

from collections.abc import Sequence

import pytest

from fact import keys
from fact.errors import ToolkitError
from fact.models import ToolResult


def make_result(
    argv: Sequence[str],
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> ToolResult:
    """Build a command result for mocked GnuPG invocations."""
    return ToolResult(list(argv), returncode, stdout, stderr)


def test_prepare_gnupg_interactive_configures_pinentry_and_agent(
    tmp_path, monkeypatch
) -> None:
    """Configure pinentry, terminal access and the agent for interactive GnuPG."""
    home = tmp_path / "keyring"
    monkeypatch.setattr(keys, "require", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(keys, "_terminal_name", lambda: "/dev/pts/7")
    monkeypatch.setattr(keys, "_find_pinentry", lambda: "/usr/bin/pinentry-curses")

    calls = []

    def fake_run(argv, **kwargs):
        """Simulate successful GnuPG and agent commands."""
        calls.append((argv, kwargs))
        if argv[-2:] == ["--list-dirs", "agent-socket"]:
            return make_result(argv, stdout=str(home / "S.gpg-agent") + "\n")
        return make_result(argv)

    monkeypatch.setattr(keys, "run", fake_run)

    env = keys.prepare_gnupg(home, interactive=True)

    assert env["GNUPGHOME"] == str(home)
    assert env["GPG_TTY"] == "/dev/pts/7"
    assert home.stat().st_mode & 0o777 == 0o700
    config = (home / "gpg-agent.conf").read_text(encoding="utf-8")
    assert "pinentry-program /usr/bin/pinentry-curses" in config
    assert any("--launch" in argv for argv, _ in calls)


def test_prepare_gnupg_reports_missing_pinentry(tmp_path, monkeypatch) -> None:
    """Report when interactive signing has no usable pinentry programme."""
    monkeypatch.setattr(keys, "require", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(keys, "_terminal_name", lambda: "/dev/pts/7")
    monkeypatch.setattr(keys, "_find_pinentry", lambda: None)

    with pytest.raises(ToolkitError, match="No usable pinentry"):
        keys.prepare_gnupg(tmp_path / "keyring", interactive=True)


def test_prepare_gnupg_reports_missing_terminal(tmp_path, monkeypatch) -> None:
    """Report when interactive signing has no controlling terminal."""
    monkeypatch.setattr(keys, "require", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(keys, "_terminal_name", lambda: None)

    with pytest.raises(ToolkitError, match="interactive terminal"):
        keys.prepare_gnupg(tmp_path / "keyring", interactive=True)


def test_export_keypair_writes_and_verifies_backup(tmp_path, monkeypatch) -> None:
    """Export a complete evidence-key backup with secure permissions."""
    home = tmp_path / "pgp" / "keyring"
    output = tmp_path / "keys"
    fingerprint = "0B63E08D9683B88CB568B5E92B42891B609F41E1"

    monkeypatch.setattr(
        keys,
        "prepare_gnupg",
        lambda path, interactive: {"GNUPGHOME": str(path)},
    )
    monkeypatch.setattr(keys, "fingerprint", lambda path, env=None: fingerprint)

    def fake_run(argv, **kwargs):
        """Return deterministic material for each mocked export operation."""
        if "--export-secret-keys" in argv:
            return make_result(
                argv,
                stdout=(
                    "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
                    "secret\n"
                    "-----END PGP PRIVATE KEY BLOCK-----\n"
                ),
            )
        if "--export-ownertrust" in argv:
            return make_result(argv, stdout=f"{fingerprint}:6:\n")
        if "--export" in argv:
            return make_result(
                argv,
                stdout=(
                    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
                    "public\n"
                    "-----END PGP PUBLIC KEY BLOCK-----\n"
                ),
            )
        if "--import" in argv:
            return make_result(argv)
        raise AssertionError(argv)

    monkeypatch.setattr(keys, "run", fake_run)
    result = keys.export_keypair(home, output)

    assert result["fingerprint"] == fingerprint
    assert (output / "evidence-public-key.asc").exists()
    assert (output / "evidence-secret-key.asc").exists()
    assert (output / "evidence-ownertrust.txt").exists()
    assert (output / "SHA256SUMS.txt").exists()
    readme = (output / "KEY_BACKUP_README.txt").read_text(encoding="utf-8")
    assert "Retaining it in this format" in readme
    assert output.stat().st_mode & 0o777 == 0o700
    assert (output / "evidence-secret-key.asc").stat().st_mode & 0o777 == 0o600


def test_export_keypair_refuses_overwrite_without_force(tmp_path, monkeypatch) -> None:
    """Refuse to replace an existing secret-key backup without --force."""
    home = tmp_path / "keyring"
    output = tmp_path / "keys"
    output.mkdir()
    (output / "evidence-secret-key.asc").write_text("existing", encoding="utf-8")
    monkeypatch.setattr(keys, "prepare_gnupg", lambda path, interactive: {})
    monkeypatch.setattr(keys, "fingerprint", lambda path, env=None: "ABC")

    with pytest.raises(ToolkitError, match="--force"):
        keys.export_keypair(home, output)


def test_ensure_key_exports_existing_key(tmp_path, monkeypatch) -> None:
    """Export an existing evidence key without interactive generation."""
    fingerprint = "A" * 40
    home = tmp_path / "keyring"
    public_key = tmp_path / "evidence-public-key.asc"
    fingerprint_file = tmp_path / "fingerprint.txt"
    monkeypatch.setattr(
        keys, "prepare_gnupg", lambda *args, **kwargs: {"GNUPGHOME": str(home)}
    )
    monkeypatch.setattr(keys, "fingerprint", lambda *args, **kwargs: fingerprint)
    monkeypatch.setattr(
        keys,
        "run",
        lambda argv, **kwargs: make_result(
            argv,
            stdout="-----BEGIN PGP PUBLIC KEY BLOCK-----\npublic\n",
        ),
    )

    result = keys.ensure_key(home, public_key, fingerprint_file)

    assert result == fingerprint
    assert public_key.read_text(encoding="utf-8").startswith("-----BEGIN")
    assert fingerprint_file.read_text(encoding="ascii").strip() == fingerprint
    assert fingerprint_file.stat().st_mode & 0o777 == 0o600


def test_ensure_key_rejects_noninteractive_generation(tmp_path, monkeypatch) -> None:
    """Refuse key generation when no key and no interactive terminal exist."""
    monkeypatch.setattr(keys, "prepare_gnupg", lambda *args, **kwargs: {})
    monkeypatch.setattr(keys, "fingerprint", lambda *args, **kwargs: None)
    monkeypatch.setattr(keys.sys.stdin, "isatty", lambda: False)

    with pytest.raises(ToolkitError, match="interactive key generation"):
        keys.ensure_key(tmp_path / "home", tmp_path / "pub", tmp_path / "fpr")


def test_sign_reports_failure(tmp_path, monkeypatch) -> None:
    """Raise a descriptive error when archive signing fails."""
    monkeypatch.setattr(keys, "prepare_gnupg", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        keys,
        "run",
        lambda argv, **kwargs: make_result(
            argv, returncode=2, stderr="bad passphrase\n"
        ),
    )

    with pytest.raises(ToolkitError, match="bad passphrase"):
        keys.sign(tmp_path / "home", tmp_path / "archive", tmp_path / "sig", "FPR")


def test_fingerprint_reads_first_gpg_fingerprint(tmp_path, monkeypatch) -> None:
    """Return the first fingerprint in GnuPG colon output."""
    monkeypatch.setattr(keys, "require", lambda command: command)
    monkeypatch.setattr(
        keys,
        "run",
        lambda argv, **kwargs: make_result(
            argv, stdout="sec:::::::::\nfpr:::::::::ABCDEF:\n"
        ),
    )

    assert keys.fingerprint(tmp_path) == "ABCDEF"
