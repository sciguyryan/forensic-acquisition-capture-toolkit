"""Tests for owner-controlled confidential authority transfer."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from fact.core import authority, catalogue, notes
from fact.core.authority import (
    accept_contributor,
    establish_project_genesis,
    invite_contributor,
)
from fact.core.catalogue import catalogue_path, verify_chain
from fact.core.confidential_authority import (
    accept_confidential_authority_transfer,
    cancel_confidential_authority_transfer,
    list_confidential_authority_transfers,
    propose_confidential_authority_transfer,
    reject_confidential_authority_transfer,
)
from fact.core.export_policy import confidential_authority
from fact.core.notes import create_note, read_note
from fact.core.project import _initialise_project as initialise_project
from fact.errors import ToolkitError
from fact.identity import OperatorIdentity


def operator(operator_id: str, char: str) -> OperatorIdentity:
    return OperatorIdentity(
        1,
        operator_id,
        operator_id.title(),
        f"{operator_id}@example.test",
        "Example",
        "Investigator",
        char * 40,
        char.lower() * 40,
    )


@pytest.fixture(autouse=True)
def fake_crypto(monkeypatch: pytest.MonkeyPatch) -> None:
    def sign(identity: OperatorIdentity, payload: bytes) -> str:
        return f"TEST:{identity.operator_id}:{hashlib.sha256(payload).hexdigest()}"

    monkeypatch.setattr(authority, "sign_operator_payload", sign)
    monkeypatch.setattr(authority, "verify_operator_payload", lambda *args: None)
    monkeypatch.setattr(catalogue, "verify_operator_payload", lambda *args: None)
    monkeypatch.setattr(
        notes, "encrypt_for_project_keys", lambda payload, keys: b"ENC:" + payload
    )
    monkeypatch.setattr(
        notes,
        "decrypt_confidential_payload",
        lambda payload: payload[4:] if payload.startswith(b"ENC:") else payload,
    )


def setup_members(root: Path):
    owner = operator("owner", "A")
    alice = operator("alice", "B")
    bob = operator("bob", "C")
    initialise_project(root, "P-CONF", "Confidential authority")
    establish_project_genesis(root, owner, "PUBLIC OWNER")
    invite_contributor(root, owner, alice, "PUBLIC ALICE")
    accept_contributor(root, alice)
    invite_contributor(root, owner, bob, "PUBLIC BOB")
    accept_contributor(root, bob)
    return owner, alice, bob


def test_owner_proposes_incoming_accepts_and_provenance_does_not_move(
    tmp_path: Path,
) -> None:
    owner, alice, bob = setup_members(tmp_path)
    note_id = create_note(
        tmp_path,
        alice,
        "Secret",
        "Sensitive body",
        visibility="confidential",
    )
    before = confidential_authority(tmp_path, "note", note_id)
    assert before["creator_id"] == "alice"
    assert before["authority_id"] == "alice"

    transfer_id = propose_confidential_authority_transfer(
        tmp_path,
        owner,
        from_operator_id="alice",
        to_operator_id="bob",
        objects=[note_id],
        reason="Alice is leaving the investigation",
    )
    assert transfer_id == "TRANSFER-000001"
    assert list_confidential_authority_transfers(tmp_path)[0]["state"] == "pending"

    accept_confidential_authority_transfer(tmp_path, bob, transfer_id)
    after = confidential_authority(tmp_path, "note", note_id)
    assert after["creator_id"] == "alice"
    assert after["authority_id"] == "bob"
    assert list_confidential_authority_transfers(tmp_path)[0]["state"] == "accepted"
    assert read_note(tmp_path, bob, note_id)["body"] == "Sensitive body"
    assert read_note(tmp_path, owner, note_id)["body"] == "Sensitive body"
    with pytest.raises(ToolkitError, match="current authenticated authority"):
        read_note(tmp_path, alice, note_id)
    assert verify_chain(tmp_path)["event_count"] > 0


def test_only_owner_may_propose_and_only_incoming_may_accept(tmp_path: Path) -> None:
    owner, alice, _bob = setup_members(tmp_path)
    note_id = create_note(tmp_path, alice, "Secret", "Body", visibility="confidential")
    with pytest.raises(ToolkitError, match="Only the current project owner"):
        propose_confidential_authority_transfer(
            tmp_path,
            alice,
            from_operator_id="alice",
            to_operator_id="bob",
            objects=[note_id],
            reason="Not authorised",
        )

    transfer_id = propose_confidential_authority_transfer(
        tmp_path,
        owner,
        from_operator_id="alice",
        to_operator_id="bob",
        objects=[note_id],
        reason="Transfer",
    )
    with pytest.raises(ToolkitError, match="nominated incoming"):
        accept_confidential_authority_transfer(tmp_path, alice, transfer_id)


def test_reject_and_cancel_are_retained_history(tmp_path: Path) -> None:
    owner, alice, bob = setup_members(tmp_path)
    first = create_note(tmp_path, alice, "A", "Body", visibility="confidential")
    transfer = propose_confidential_authority_transfer(
        tmp_path,
        owner,
        from_operator_id="alice",
        to_operator_id="bob",
        objects=[first],
        reason="Proposed",
    )
    reject_confidential_authority_transfer(
        tmp_path, bob, transfer, "Not taking custody"
    )
    assert list_confidential_authority_transfers(tmp_path)[0]["state"] == "rejected"
    assert confidential_authority(tmp_path, "note", first)["authority_id"] == "alice"

    second = create_note(tmp_path, alice, "B", "Body", visibility="confidential")
    transfer2 = propose_confidential_authority_transfer(
        tmp_path,
        owner,
        from_operator_id="alice",
        to_operator_id="bob",
        objects=[second],
        reason="Second proposal",
    )
    cancel_confidential_authority_transfer(
        tmp_path, owner, transfer2, "No longer required"
    )
    assert list_confidential_authority_transfers(tmp_path)[1]["state"] == "cancelled"
    assert verify_chain(tmp_path)["event_count"] > 0


def test_pending_transfer_blocks_related_second_proposal_and_stale_authority(
    tmp_path: Path,
) -> None:
    owner, alice, bob = setup_members(tmp_path)
    note_id = create_note(tmp_path, alice, "A", "Body", visibility="confidential")
    transfer = propose_confidential_authority_transfer(
        tmp_path,
        owner,
        from_operator_id="alice",
        to_operator_id="bob",
        objects=[note_id],
        reason="First",
    )
    with pytest.raises(ToolkitError, match="already pending"):
        propose_confidential_authority_transfer(
            tmp_path,
            owner,
            from_operator_id="alice",
            to_operator_id="bob",
            objects=[note_id],
            reason="Duplicate",
        )

    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute(
        "UPDATE confidential_authority SET authority_id = 'bob' WHERE object_id = ?",
        (note_id,),
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="authority changed"):
        accept_confidential_authority_transfer(tmp_path, bob, transfer)


def test_transfer_scope_validation_and_generic_crypto_refusal(tmp_path: Path) -> None:
    owner, alice, _bob = setup_members(tmp_path)
    note_id = create_note(tmp_path, alice, "A", "Body", visibility="confidential")
    with pytest.raises(
        ToolkitError, match="Unsupported confidential authority object ID"
    ):
        propose_confidential_authority_transfer(
            tmp_path,
            owner,
            from_operator_id="alice",
            to_operator_id="bob",
            objects=["UNKNOWN-1"],
            reason="Bad",
        )
    with pytest.raises(ToolkitError, match="not currently controlled"):
        propose_confidential_authority_transfer(
            tmp_path,
            owner,
            from_operator_id="bob",
            to_operator_id="alice",
            objects=[note_id],
            reason="Wrong source",
        )
