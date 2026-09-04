"""Tests for operator identity persistence and integrity checks."""

import hashlib
import json
import os
from pathlib import Path

import pytest

from fact.errors import ToolkitError
from fact.identity import (
    OperatorIdentity,
    active_identity,
    load_identity_file,
    save_identity,
)

PRIMARY_FINGERPRINT = "A" * 40
SIGNING_FINGERPRINT = "B" * 40


def make_identity() -> OperatorIdentity:
    """Return a valid operator identity for configuration tests."""
    return OperatorIdentity(
        1,
        "jane-smith",
        "Jane Smith",
        "forensics@example.org",
        "Example",
        "Analyst",
        PRIMARY_FINGERPRINT,
        SIGNING_FINGERPRINT,
    )


def test_save_and_resolve_active_identity(tmp_path: Path) -> None:
    """Persist, select and resolve an active identity with secure permissions."""
    expected = make_identity()
    profile_path = save_identity(tmp_path, expected)
    loaded, active_path = active_identity(tmp_path)

    assert loaded == expected
    assert active_path == profile_path
    assert os.stat(profile_path).st_mode & 0o777 == 0o600

    config = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    expected_digest = hashlib.sha256(profile_path.read_bytes()).hexdigest()
    assert config["active_operator_sha256"] == expected_digest


def test_profile_tampering_is_detected(tmp_path: Path) -> None:
    """Reject an active identity whose contents no longer match its digest."""
    profile_path = save_identity(tmp_path, make_identity())
    profile_path.write_text(
        profile_path.read_text(encoding="utf-8").replace("Jane Smith", "Mallory"),
        encoding="utf-8",
    )

    with pytest.raises(ToolkitError):
        active_identity(tmp_path)


def test_full_fingerprint_required(tmp_path: Path) -> None:
    """Reject identity files that use abbreviated OpenPGP fingerprints."""
    profile_path = tmp_path / "bad.json"
    profile_path.write_text(
        json.dumps(
            {
                "operator_id": "x",
                "name": "X",
                "operator_key_fingerprint": "1234",
                "operator_signing_subkey_fingerprint": "1234",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ToolkitError):
        load_identity_file(profile_path)
