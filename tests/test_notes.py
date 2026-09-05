"""Tests for file-backed project and confidential FACT notes."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tarfile
from pathlib import Path

import pytest

from fact.core import authority, catalogue, notes, packaging
from fact.core.authority import (
    accept_contributor,
    accept_ownership_transfer,
    establish_project_genesis,
    invite_contributor,
    propose_ownership_transfer,
)
from fact.core.catalogue import catalogue_path, issue_identifier, verify_chain
from fact.core.files import FileCandidate, commit_files
from fact.core.notes import (
    create_note,
    list_notes,
    read_note,
    revise_note,
    set_note_disclosure,
)
from fact.core.packaging import _apply_note_disclosure
from fact.core.project import _initialise_project as initialise_project
from fact.core.project import create_case
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


def _revision_file(root: Path, note_id: str, revision: int = 1) -> tuple[str, Path]:
    connection = sqlite3.connect(catalogue_path(root))
    try:
        file_id = connection.execute(
            "SELECT file_id FROM note_revisions WHERE note_id = ? AND revision = ?",
            (note_id, revision),
        ).fetchone()[0]
        storage_path = connection.execute(
            "SELECT storage_path FROM files WHERE file_id = ?", (file_id,)
        ).fetchone()[0]
    finally:
        connection.close()
    return str(file_id), root / str(storage_path)


def test_project_note_revisions_are_ordinary_immutable_project_files(tmp_path: Path) -> None:
    owner, alice, _ = project(tmp_path)
    note_id = create_note(tmp_path, alice, "Observation", "First", visibility="project")
    assert note_id == "NOTE-000001"
    first_file_id, first_path = _revision_file(tmp_path, note_id)
    assert first_file_id == "FILE-000001"
    assert first_path.parent.parent == tmp_path / "files"
    assert read_note(tmp_path, owner, note_id)["body"] == "First"

    assert revise_note(tmp_path, alice, note_id, "Observation", "Second", "Clarified") == 2
    second_file_id, second_path = _revision_file(tmp_path, note_id, 2)
    assert second_file_id == "FILE-000002"
    assert second_path != first_path
    assert first_path.is_file()
    assert read_note(tmp_path, owner, note_id)["body"] == "Second"
    assert read_note(tmp_path, owner, note_id, revision=1)["body"] == "First"
    assert list_notes(tmp_path)[0]["latest_revision"] == 2
    verify_chain(tmp_path)


def test_confidential_note_file_contains_ciphertext_not_plaintext(tmp_path: Path) -> None:
    owner, alice, bob = project(tmp_path)
    note_id = create_note(
        tmp_path, alice, "Privileged", "Never plaintext", visibility="confidential"
    )
    file_id, path = _revision_file(tmp_path, note_id)
    stored = path.read_bytes()
    assert b"Never plaintext" not in stored
    assert stored.startswith(b"ENC:")
    connection = sqlite3.connect(catalogue_path(tmp_path))
    try:
        row = connection.execute(
            "SELECT classification, sha256 FROM files WHERE file_id = ?", (file_id,)
        ).fetchone()
    finally:
        connection.close()
    assert row[0] == "confidential-note-revision"
    assert row[1] == hashlib.sha256(stored).hexdigest()
    assert read_note(tmp_path, alice, note_id)["body"] == "Never plaintext"
    assert read_note(tmp_path, owner, note_id)["body"] == "Never plaintext"
    with pytest.raises(ToolkitError, match="restricted"):
        read_note(tmp_path, bob, note_id)


def test_case_and_file_associated_note_uses_case_file_store_and_relationship(tmp_path: Path) -> None:
    _, alice, _ = project(tmp_path)
    case_id = create_case(tmp_path)
    acquisition_id = issue_identifier(tmp_path, "acquisition", "ACQ")
    target = tmp_path / "target.bin"
    target.write_bytes(b"target evidence")
    target_file_id = str(
        commit_files(
            tmp_path,
            case_id=case_id,
            acquisition_id=acquisition_id,
            actor_id=alice.operator_id,
            candidates=[FileCandidate(target, "target.bin", "primary")],
        )[0]["file_id"]
    )
    note_id = create_note(
        tmp_path,
        alice,
        "Review",
        "This concerns the target file",
        case_id=case_id,
        subject_file_id=target_file_id,
    )
    revision_file_id, path = _revision_file(tmp_path, note_id)
    assert path.parent.parent == tmp_path / "cases" / case_id / "files"
    connection = sqlite3.connect(catalogue_path(tmp_path))
    try:
        relationship = connection.execute(
            "SELECT relationship FROM file_relationships "
            "WHERE parent_file_id = ? AND child_file_id = ?",
            (target_file_id, revision_file_id),
        ).fetchone()[0]
    finally:
        connection.close()
    assert relationship == "note-about"
    assert read_note(tmp_path, alice, note_id)["subject_file_id"] == target_file_id
    verify_chain(tmp_path)


def test_only_author_revises_and_owner_controls_package_disclosure(tmp_path: Path) -> None:
    owner, alice, bob = project(tmp_path)
    note_id = create_note(tmp_path, alice, "A", "B")
    with pytest.raises(ToolkitError, match="Only the note author"):
        revise_note(tmp_path, bob, note_id, "A", "C", "No")
    with pytest.raises(ToolkitError, match="Only the current project owner"):
        set_note_disclosure(tmp_path, alice, note_id, True)
    set_note_disclosure(tmp_path, owner, note_id, True)
    assert list_notes(tmp_path)[0]["package_disclosure"] == "include"


def test_package_disclosure_selects_files_without_erasing_catalogue_history(tmp_path: Path) -> None:
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

    selected = _apply_note_disclosure(snapshot)
    assert {item["note_id"] for item in selected} == {withheld}
    connection = sqlite3.connect(snapshot)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM note_revisions"
        ).fetchone()[0] == 2
    finally:
        connection.close()



def test_project_package_omits_only_withheld_note_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner, alice, _ = project(tmp_path)
    withheld_note = create_note(tmp_path, alice, "Hidden", "Do not disclose")
    included_note = create_note(tmp_path, owner, "Visible", "Disclose this")
    set_note_disclosure(tmp_path, owner, included_note, True)
    withheld_file_id, withheld_path = _revision_file(tmp_path, withheld_note)
    included_file_id, included_path = _revision_file(tmp_path, included_note)

    monkeypatch.setattr(packaging, "prepare_gnupg", lambda *args, **kwargs: {})
    monkeypatch.setattr(packaging, "fingerprint", lambda *args, **kwargs: "A" * 40)
    monkeypatch.setattr(
        packaging,
        "_export_public_key",
        lambda *args, **kwargs: (
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nTEST\n"
            "-----END PGP PUBLIC KEY BLOCK-----\n"
        ),
    )
    monkeypatch.setattr(
        packaging,
        "sign",
        lambda home, payload, signature, fpr: signature.write_text(
            "signature", encoding="ascii"
        ),
    )
    monkeypatch.setattr(packaging, "_verify_signature", lambda *args, **kwargs: None)

    output = tmp_path.parent / "notes-package.fact.tar.gz"
    packaging.create_project_package(tmp_path, tmp_path, output)
    with tarfile.open(output, "r:gz") as archive:
        names = set(archive.getnames())
        descriptor_handle = archive.extractfile("FACT-PACKAGE/PACKAGE.json")
        assert descriptor_handle is not None
        descriptor = json.load(descriptor_handle)

    withheld_relative = withheld_path.relative_to(tmp_path).as_posix()
    included_relative = included_path.relative_to(tmp_path).as_posix()
    assert withheld_relative not in names
    assert included_relative in names
    assert descriptor["withheld_note_file_ids"] == [withheld_file_id]
    assert included_file_id not in descriptor["withheld_note_file_ids"]

def test_project_transfer_failure_leaves_owner_and_file_lineage_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner, alice, bob = project(tmp_path)
    note_id = create_note(tmp_path, bob, "Secret", "Sensitive", visibility="confidential")
    original_file_id, original_path = _revision_file(tmp_path, note_id)
    transfer_id = propose_ownership_transfer(tmp_path, owner, alice.operator_id, "Rotation")

    def fail_encryption(payload: bytes, keys: list[str]) -> bytes:
        raise ToolkitError("synthetic encryption failure")

    monkeypatch.setattr(notes, "encrypt_for_project_keys", fail_encryption)
    with pytest.raises(ToolkitError, match="synthetic"):
        accept_ownership_transfer(tmp_path, alice)
    connection = sqlite3.connect(catalogue_path(tmp_path))
    try:
        owner_id = connection.execute(
            "SELECT owner_id FROM ownership WHERE scope_type = 'project'"
        ).fetchone()[0]
        transfer_state = connection.execute(
            "SELECT state FROM ownership_transfers WHERE transfer_id = ?", (transfer_id,)
        ).fetchone()[0]
        revisions = connection.execute(
            "SELECT revision, file_id FROM note_revisions WHERE note_id = ?", (note_id,)
        ).fetchall()
    finally:
        connection.close()
    assert owner_id == owner.operator_id
    assert transfer_state == "pending"
    assert revisions == [(1, original_file_id)]
    assert original_path.is_file()


def test_successful_project_transfer_appends_cryptographic_revision_file(tmp_path: Path) -> None:
    owner, alice, bob = project(tmp_path)
    note_id = create_note(tmp_path, bob, "Secret", "Sensitive", visibility="confidential")
    first_file_id, first_path = _revision_file(tmp_path, note_id)
    transfer_id = propose_ownership_transfer(tmp_path, owner, alice.operator_id, "Rotation")
    assert accept_ownership_transfer(tmp_path, alice) == transfer_id

    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.row_factory = sqlite3.Row
    try:
        event = connection.execute(
            "SELECT details_json FROM audit_events "
            "WHERE event_type = 'OWNERSHIP_TRANSFER_ACCEPTED'"
        ).fetchone()
        revisions = connection.execute(
            "SELECT revision, file_id, revision_type FROM note_revisions ORDER BY revision"
        ).fetchall()
    finally:
        connection.close()
    assert "confidential_revision_count" in event["details_json"]
    assert [(row["revision"], row["revision_type"]) for row in revisions] == [
        (1, "content"),
        (2, "cryptographic"),
    ]
    assert revisions[0]["file_id"] == first_file_id
    assert revisions[1]["file_id"] != first_file_id
    assert first_path.is_file()
    assert read_note(tmp_path, alice, note_id)["body"] == "Sensitive"
    verify_chain(tmp_path)


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
    with pytest.raises(ToolkitError, match="Unknown FACT case"):
        create_note(tmp_path, alice, "Case", "Body", case_id="CASE-999999")
    note_id = create_note(tmp_path, alice, "Good", "Body")
    with pytest.raises(ToolkitError, match="requires a reason"):
        revise_note(tmp_path, alice, note_id, "Good", "Changed", "  ")
    with pytest.raises(ToolkitError, match="Unknown revision"):
        read_note(tmp_path, alice, note_id, revision=99)


def test_note_pointer_disclosure_and_file_pointer_tampering_are_detected(tmp_path: Path) -> None:
    owner, alice, _ = project(tmp_path)
    note_id = create_note(tmp_path, alice, "Retained", "One")
    revise_note(tmp_path, alice, note_id, "Retained", "Two", "Update")
    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute("UPDATE notes SET latest_revision = 1 WHERE note_id = ?", (note_id,))
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

    # Restore the signed disclosure transition, then forge the revision's file pointer.
    set_note_disclosure(tmp_path, owner, note_id, True)
    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute(
        "UPDATE note_revisions SET file_id = 'FILE-999999' "
        "WHERE note_id = ? AND revision = 2",
        (note_id,),
    )
    connection.commit()
    connection.close()
    with pytest.raises((ToolkitError, sqlite3.IntegrityError)):
        verify_chain(tmp_path)


def test_note_file_byte_tampering_and_removal_are_detected(tmp_path: Path) -> None:
    _, alice, _ = project(tmp_path)
    note_id = create_note(tmp_path, alice, "Retained", "Original")
    _, path = _revision_file(tmp_path, note_id)
    original = path.read_bytes()
    path.write_bytes(b"tampered")
    with pytest.raises(ToolkitError, match="bytes have changed"):
        verify_chain(tmp_path)
    path.write_bytes(original)
    path.unlink()
    with pytest.raises(ToolkitError, match="missing from the authoritative tree"):
        verify_chain(tmp_path)


def test_cross_case_subject_file_is_rejected_without_committing_note_file(tmp_path: Path) -> None:
    _, alice, _ = project(tmp_path)
    first_case = create_case(tmp_path)
    second_case = create_case(tmp_path)
    acquisition_id = issue_identifier(tmp_path, "acquisition", "ACQ")
    source = tmp_path / "source.txt"
    source.write_text("evidence", encoding="utf-8")
    file_id = str(
        commit_files(
            tmp_path,
            case_id=first_case,
            acquisition_id=acquisition_id,
            actor_id=alice.operator_id,
            candidates=[FileCandidate(source, "source.txt", "primary")],
        )[0]["file_id"]
    )
    before = {path for path in tmp_path.rglob("FILE-*") if path.is_dir()}
    with pytest.raises(ToolkitError, match="another case"):
        create_note(
            tmp_path,
            alice,
            "Wrong case",
            "Body",
            case_id=second_case,
            subject_file_id=file_id,
        )
    after = {path for path in tmp_path.rglob("FILE-*") if path.is_dir()}
    assert after == before
