"""Tests for retained public and confidential FACT notes."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from fact.core import authority, catalogue, notes
from fact.core.authority import (
    accept_contributor,
    accept_ownership_transfer,
    establish_project_genesis,
    invite_contributor,
    propose_ownership_transfer,
)
from fact.core.catalogue import catalogue_path, verify_chain
from fact.core.notes import (
    create_note,
    list_notes,
    read_note,
    revise_note,
    set_note_disclosure,
)
from fact.core.packaging import _apply_note_disclosure
from fact.core.project import _initialise_project as initialise_project
from fact.errors import ToolkitError
from fact.identity import OperatorIdentity


def operator(operator_id: str, marker: str) -> OperatorIdentity:
    return OperatorIdentity(
        1,
        operator_id,
        operator_id.title(),
        None,
        None,
        None,
        marker * 40,
        marker.lower() * 40,
    )


@pytest.fixture(autouse=True)
def fake_crypto(monkeypatch: pytest.MonkeyPatch) -> None:
    def sign(identity: OperatorIdentity, payload: bytes) -> str:
        return f"SIG:{identity.operator_id}:{hashlib.sha256(payload).hexdigest()}"

    monkeypatch.setattr(authority, "sign_operator_payload", sign)
    monkeypatch.setattr(authority, "verify_operator_payload", lambda *args: None)
    monkeypatch.setattr(catalogue, "verify_operator_payload", lambda *args: None)
    monkeypatch.setattr(
        notes, "encrypt_for_project_keys", lambda payload, keys: b"ENC:" + payload[::-1]
    )
    monkeypatch.setattr(
        notes,
        "decrypt_confidential_payload",
        lambda payload: payload.removeprefix(b"ENC:")[::-1],
    )


def project(root: Path) -> tuple[OperatorIdentity, OperatorIdentity, OperatorIdentity]:
    owner = operator("owner", "A")
    alice = operator("alice", "B")
    bob = operator("bob", "C")
    initialise_project(root, "P-NOTES", "Notes")
    establish_project_genesis(root, owner, "PUBLIC OWNER")
    invite_contributor(root, owner, alice, "PUBLIC ALICE")
    accept_contributor(root, alice)
    invite_contributor(root, owner, bob, "PUBLIC BOB")
    accept_contributor(root, bob)
    return owner, alice, bob


def test_project_note_is_retained_and_revision_history_is_append_only(
    tmp_path: Path,
) -> None:
    owner, alice, _ = project(tmp_path)
    note_id = create_note(tmp_path, alice, "Observation", "First", visibility="project")
    assert note_id == "NOTE-000001"
    assert read_note(tmp_path, owner, note_id)["body"] == "First"
    assert (
        revise_note(tmp_path, alice, note_id, "Observation", "Second", "Clarified") == 2
    )
    assert read_note(tmp_path, owner, note_id)["body"] == "Second"
    assert read_note(tmp_path, owner, note_id, revision=1)["body"] == "First"
    assert list_notes(tmp_path)[0]["latest_revision"] == 2
    assert verify_chain(tmp_path)["event_count"] >= 1


def test_confidential_note_is_restricted_and_stored_only_as_ciphertext(
    tmp_path: Path,
) -> None:
    owner, alice, bob = project(tmp_path)
    note_id = create_note(
        tmp_path, alice, "Privileged", "Never plaintext", visibility="confidential"
    )
    assert read_note(tmp_path, alice, note_id)["body"] == "Never plaintext"
    assert read_note(tmp_path, owner, note_id)["body"] == "Never plaintext"
    with pytest.raises(ToolkitError, match="restricted"):
        read_note(tmp_path, bob, note_id)
    connection = sqlite3.connect(catalogue_path(tmp_path))
    try:
        payload = connection.execute(
            "SELECT payload FROM note_revisions WHERE note_id = ?", (note_id,)
        ).fetchone()[0]
    finally:
        connection.close()
    assert b"Never plaintext" not in bytes(payload)
    assert bytes(payload).startswith(b"ENC:")


def test_only_author_revises_and_owner_controls_package_disclosure(
    tmp_path: Path,
) -> None:
    owner, alice, bob = project(tmp_path)
    note_id = create_note(tmp_path, alice, "A", "B")
    with pytest.raises(ToolkitError, match="Only the note author"):
        revise_note(tmp_path, bob, note_id, "A", "C", "No")
    with pytest.raises(ToolkitError, match="Only the current project owner"):
        set_note_disclosure(tmp_path, alice, note_id, True)
    set_note_disclosure(tmp_path, owner, note_id, True)
    assert list_notes(tmp_path)[0]["package_disclosure"] == "include"


def test_package_snapshot_withholds_payload_without_deleting_note_record(
    tmp_path: Path,
) -> None:
    owner, alice, _ = project(tmp_path)
    withheld = create_note(tmp_path, alice, "Hidden", "Do not disclose")
    included = create_note(tmp_path, owner, "Included", "Disclose this")
    set_note_disclosure(tmp_path, owner, included, True)
    snapshot = tmp_path / "snapshot.sqlite"
    source = sqlite3.connect(catalogue_path(tmp_path))
    target = sqlite3.connect(snapshot)
    source.backup(target)
    source.close()
    target.close()
    _apply_note_disclosure(snapshot)
    connection = sqlite3.connect(snapshot)
    try:
        rows = dict(
            connection.execute(
                "SELECT note_id, payload FROM note_revisions WHERE revision = 1"
            ).fetchall()
        )
    finally:
        connection.close()
    assert rows[withheld] is None
    assert rows[included] is not None


def test_project_transfer_reencrypts_before_owner_state_and_rolls_back_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner, alice, bob = project(tmp_path)
    note_id = create_note(
        tmp_path, bob, "Secret", "Sensitive", visibility="confidential"
    )
    transfer_id = propose_ownership_transfer(
        tmp_path, owner, alice.operator_id, "Rotation"
    )
    calls = 0

    def fail_second(payload: bytes, keys: list[str]) -> bytes:
        nonlocal calls
        calls += 1
        raise ToolkitError("synthetic encryption failure")

    monkeypatch.setattr(notes, "encrypt_for_project_keys", fail_second)
    with pytest.raises(ToolkitError, match="synthetic"):
        accept_ownership_transfer(tmp_path, alice)
    connection = sqlite3.connect(catalogue_path(tmp_path))
    try:
        owner_id = connection.execute(
            "SELECT owner_id FROM ownership WHERE scope_type = 'project'"
        ).fetchone()[0]
        transfer_state = connection.execute(
            "SELECT state FROM ownership_transfers WHERE transfer_id = ?",
            (transfer_id,),
        ).fetchone()[0]
        payload = connection.execute(
            "SELECT payload FROM note_revisions WHERE note_id = ?", (note_id,)
        ).fetchone()[0]
    finally:
        connection.close()
    assert owner_id == owner.operator_id
    assert transfer_state == "pending"
    assert bytes(payload).startswith(b"ENC:")


def test_successful_project_transfer_cycles_confidential_ciphertext_once_in_transfer_event(
    tmp_path: Path,
) -> None:
    owner, alice, bob = project(tmp_path)
    create_note(tmp_path, bob, "Secret", "Sensitive", visibility="confidential")
    transfer_id = propose_ownership_transfer(
        tmp_path, owner, alice.operator_id, "Rotation"
    )
    assert accept_ownership_transfer(tmp_path, alice) == transfer_id
    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.row_factory = sqlite3.Row
    try:
        event = connection.execute(
            "SELECT details_json FROM audit_events WHERE event_type = 'OWNERSHIP_TRANSFER_ACCEPTED'"
        ).fetchone()
        owner_id = connection.execute(
            "SELECT owner_id FROM ownership WHERE scope_type = 'project'"
        ).fetchone()[0]
    finally:
        connection.close()
    assert owner_id == alice.operator_id
    assert "confidential_revision_count" in event["details_json"]
    connection = sqlite3.connect(catalogue_path(tmp_path))
    try:
        revisions = connection.execute(
            "SELECT revision, payload_sha256 FROM note_revisions ORDER BY revision"
        ).fetchall()
    finally:
        connection.close()
    assert [row[0] for row in revisions] == [1, 2]
    assert all(row[1] for row in revisions)


def test_missing_committed_note_is_a_sanctity_violation(tmp_path: Path) -> None:
    _, alice, _ = project(tmp_path)
    note_id = create_note(tmp_path, alice, "Retained", "Must remain")
    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute("DELETE FROM note_revisions WHERE note_id = ?", (note_id,))
    connection.execute("DELETE FROM notes WHERE note_id = ?", (note_id,))
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="Committed note tree"):
        verify_chain(tmp_path)


def test_note_validation_fails_closed(tmp_path: Path) -> None:
    _, alice, _ = project(tmp_path)
    with pytest.raises(ToolkitError, match="visibility"):
        create_note(tmp_path, alice, "Bad", "Bad", visibility="private")
    with pytest.raises(ToolkitError, match="Unknown FACT note"):
        read_note(tmp_path, alice, "NOTE-999999")
    note_id = create_note(tmp_path, alice, "Good", "Body")
    with pytest.raises(ToolkitError, match="requires a reason"):
        revise_note(tmp_path, alice, note_id, "Good", "Changed", "  ")


def test_note_pointer_and_disclosure_tampering_are_sanctity_violations(
    tmp_path: Path,
) -> None:
    _owner, alice, _ = project(tmp_path)
    note_id = create_note(tmp_path, alice, "Retained", "One")
    revise_note(tmp_path, alice, note_id, "Retained", "Two", "Update")
    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute(
        "UPDATE notes SET latest_revision = 1 WHERE note_id = ?", (note_id,)
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="revision pointer"):
        verify_chain(tmp_path)

    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute(
        "UPDATE notes SET latest_revision = 2, package_disclosure = 'include' WHERE note_id = ?",
        (note_id,),
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="disclosure state"):
        verify_chain(tmp_path)


def test_note_payload_tampering_is_detected(tmp_path: Path) -> None:
    _, alice, _ = project(tmp_path)
    note_id = create_note(tmp_path, alice, "Retained", "Original")
    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute(
        "UPDATE note_revisions SET payload = ? WHERE note_id = ?",
        (b"tampered", note_id),
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="payload integrity"):
        verify_chain(tmp_path)


def test_note_lookup_and_case_validation_errors(tmp_path: Path) -> None:
    _, alice, _ = project(tmp_path)
    with pytest.raises(ToolkitError, match="Unknown FACT case"):
        create_note(tmp_path, alice, "Case", "Body", case_id="CASE-999999")
    note_id = create_note(tmp_path, alice, "Revision", "Body")
    with pytest.raises(ToolkitError, match="Unknown revision"):
        read_note(tmp_path, alice, note_id, revision=99)
    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute(
        "UPDATE note_revisions SET payload = NULL WHERE note_id = ?", (note_id,)
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="withheld"):
        read_note(tmp_path, alice, note_id)
