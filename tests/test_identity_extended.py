"""Extended tests for operator identity management and signing."""

import hashlib
import json
from pathlib import Path

import pytest

from fact import identity
from fact.errors import ToolkitError
from fact.models import ToolResult

FINGERPRINT = "A" * 40
SIGNING_FINGERPRINT = "B" * 40


def valid_data() -> dict[str, object]:
    """Return a valid operator identity mapping."""
    return {
        "operator_id": "jane.doe",
        "name": " Jane Doe ",
        "public_contact": " jane@example.test ",
        "organisation": " Example Unit ",
        "role": " Examiner ",
        "operator_key_fingerprint": FINGERPRINT.lower(),
        "operator_signing_subkey_fingerprint": SIGNING_FINGERPRINT.lower(),
    }


def test_validate_identity_normalises_fields() -> None:
    """Normalise optional text and key fingerprints."""
    result = identity.validate_identity(valid_data())

    assert result.name == "Jane Doe"
    assert result.public_contact == "jane@example.test"
    assert result.operator_key_fingerprint == FINGERPRINT
    assert result.operator_signing_subkey_fingerprint == SIGNING_FINGERPRINT


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("name", "", "is required"),
        ("operator_id", "Invalid ID", "operator_id must use"),
        ("operator_key_fingerprint", "ABC", "full hexadecimal"),
    ],
)
def test_validate_identity_rejects_invalid_fields(
    field: str, value: str, message: str
) -> None:
    """Reject missing, malformed, and abbreviated identity values."""
    data = valid_data()
    data[field] = value

    with pytest.raises(ToolkitError, match=message):
        identity.validate_identity(data)


def test_save_and_load_active_identity(tmp_path: Path) -> None:
    """Persist an identity, pin its digest, and load it as active."""
    expected = identity.validate_identity(valid_data())
    path = identity.save_identity(tmp_path, expected)

    loaded, active_path = identity.active_identity(tmp_path)
    config = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))

    assert loaded == expected
    assert active_path == path
    assert (
        config["active_operator_sha256"]
        == hashlib.sha256(path.read_bytes()).hexdigest()
    )
    assert path.stat().st_mode & 0o777 == 0o600


def test_active_identity_detects_profile_tampering(tmp_path: Path) -> None:
    """Reject an active profile whose pinned digest no longer matches."""
    path = identity.save_identity(tmp_path, identity.validate_identity(valid_data()))
    data = valid_data()
    data["name"] = "Changed Name"
    path.write_text(json.dumps(data) + "\n", encoding="utf-8")

    with pytest.raises(ToolkitError, match="digest does not match"):
        identity.active_identity(tmp_path)


def test_load_identity_file_rejects_non_object(tmp_path: Path) -> None:
    """Reject syntactically valid JSON that is not an identity object."""
    path = tmp_path / "identity.json"
    path.write_text("[]\n", encoding="utf-8")

    with pytest.raises(ToolkitError, match="JSON object"):
        identity.load_identity_file(path)


def test_discover_signing_keys_parses_primary_and_subkey(monkeypatch) -> None:
    """Parse usable primary and signing-subkey records from GnuPG output."""
    output = "\n".join(
        [
            "sec:u:255:1:KEYID:1700000000:0:::::sc:",
            f"fpr:::::::::{FINGERPRINT}:",
            "uid:u::::::::Jane Doe <jane@example.test>:",
            "ssb:u:255:1:SUBKEY:1700000001:0:::::s:",
            f"fpr:::::::::{SIGNING_FINGERPRINT}:",
        ]
    )
    monkeypatch.setattr(identity, "require", lambda command: "/usr/bin/gpg")
    monkeypatch.setattr(
        identity,
        "run",
        lambda *args, **kwargs: ToolResult([], 0, output, ""),
    )

    keys = identity.discover_signing_keys()

    assert len(keys) == 2
    assert keys[0].uid == "Jane Doe <jane@example.test>"
    assert keys[1].signing_fingerprint == SIGNING_FINGERPRINT


def test_export_public_key_and_operator_signing(tmp_path: Path, monkeypatch) -> None:
    """Export a public key and create an operator detached signature."""
    operator = identity.validate_identity(valid_data())
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if "--export" in argv:
            return ToolResult(argv, 0, "-----BEGIN PGP PUBLIC KEY BLOCK-----\n", "")
        return ToolResult(argv, 0, "", "")

    monkeypatch.setattr(identity, "run", fake_run)
    output = tmp_path / "operator.asc"
    identity.export_public_key(operator, output)
    identity.sign_with_operator(
        operator, tmp_path / "payload", tmp_path / "payload.asc"
    )

    assert "BEGIN PGP PUBLIC KEY BLOCK" in output.read_text(encoding="utf-8")
    assert any("--detach-sign" in call for call in calls)


def test_sign_with_operator_reports_gpg_failure(tmp_path: Path, monkeypatch) -> None:
    """Convert a failed GnuPG signing command into a toolkit error."""
    operator = identity.validate_identity(valid_data())
    monkeypatch.setattr(
        identity,
        "run",
        lambda *args, **kwargs: ToolResult([], 2, "", "pinentry failed\n"),
    )

    with pytest.raises(ToolkitError, match="pinentry failed"):
        identity.sign_with_operator(operator, tmp_path / "payload", tmp_path / "sig")
