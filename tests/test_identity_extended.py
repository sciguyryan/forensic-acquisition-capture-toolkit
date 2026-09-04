"""Extended tests for operator identity management and signing."""

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


def test_project_public_key_text_and_transaction_helpers(
    tmp_path: Path, monkeypatch
) -> None:
    """Export, sign and verify project authority transaction material."""
    operator = identity.validate_identity(valid_data())

    def export_run(argv, **kwargs):
        return ToolResult(
            argv,
            0,
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nTEST\n-----END PGP PUBLIC KEY BLOCK-----\n",
            "",
        )

    monkeypatch.setattr(identity, "run", export_run)
    assert "BEGIN PGP PUBLIC KEY BLOCK" in identity.export_public_key_text(operator)

    def fake_sign(_operator, payload: Path, signature: Path) -> None:
        assert payload.read_bytes() == b'{"transaction":1}'
        signature.write_text("signature", encoding="utf-8")

    monkeypatch.setattr(identity, "sign_with_operator", fake_sign)
    assert identity.sign_operator_payload(operator, b'{"transaction":1}') == "signature"

    calls = []

    def verify_run(argv, **kwargs):
        calls.append(argv)
        return ToolResult(argv, 0, "", "")

    monkeypatch.setattr(identity, "run", verify_run)
    identity.verify_operator_payload(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nTEST\n", b"payload", "signature"
    )
    assert any("--import" in call for call in calls)
    assert any("--verify" in call for call in calls)


def test_project_public_key_and_signature_verification_fail_closed(monkeypatch) -> None:
    """Reject unavailable retained public keys and invalid transaction signatures."""
    operator = identity.validate_identity(valid_data())
    monkeypatch.setattr(
        identity,
        "run",
        lambda argv, **kwargs: ToolResult(argv, 1, "", "failure"),
    )
    with pytest.raises(ToolkitError, match="public key is unavailable"):
        identity.export_public_key_text(operator)
    with pytest.raises(ToolkitError, match="Unable to import retained"):
        identity.verify_operator_payload("key", b"payload", "signature")

    calls = 0

    def import_then_fail(argv, **kwargs):
        nonlocal calls
        calls += 1
        return ToolResult(argv, 0 if calls == 1 else 1, "", "bad signature")

    monkeypatch.setattr(identity, "run", import_then_fail)
    with pytest.raises(ToolkitError, match="signature is invalid"):
        identity.verify_operator_payload("key", b"payload", "signature")


def test_operator_payload_verification_requires_recorded_signing_fingerprint(
    monkeypatch,
) -> None:
    """Reject a valid signature produced by a different key in the retained bundle."""
    calls = 0

    def fake_run(argv, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ToolResult(argv, 0, "", "")
        return ToolResult(
            argv,
            0,
            "[GNUPG:] VALIDSIG "
            + ("C" * 40)
            + " 2026-09-04 0 4 0 1 10 00 "
            + ("A" * 40)
            + "\n",
            "",
        )

    monkeypatch.setattr(identity, "run", fake_run)
    with pytest.raises(ToolkitError, match="does not match the recorded signing key"):
        identity.verify_operator_payload(
            "PUBLIC KEY", b"payload", "signature", "B" * 40
        )
