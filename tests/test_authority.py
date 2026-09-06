"""Tests for signed project authority, ownership and approval state."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from fact.core import authority, catalogue
from fact.core.authority import (
    accept_contributor,
    accept_ownership_transfer,
    assign_case_owner,
    cancel_ownership_transfer,
    current_owner,
    decide_record,
    establish_project_genesis,
    invite_contributor,
    list_members,
    list_records,
    propose_ownership_transfer,
    record_acquisition,
    reject_contributor,
    reject_ownership_transfer,
    remove_contributor,
    require_registered_operator,
)
from fact.core.catalogue import catalogue_path, issue_identifier, verify_chain
from fact.core.files import FileCandidate, commit_files
from fact.core.project import _initialise_project as initialise_project
from fact.core.project import create_case
from fact.errors import ToolkitError
from fact.identity import OperatorIdentity


def operator(operator_id: str, name: str, fingerprint_char: str) -> OperatorIdentity:
    """Return a deterministic test operator with distinct full fingerprints."""
    return OperatorIdentity(
        1,
        operator_id,
        name,
        f"{operator_id}@example.test",
        "Example Unit",
        "Investigator",
        fingerprint_char * 40,
        fingerprint_char.lower() * 40,
    )


@pytest.fixture(autouse=True)
def fake_signatures(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise signed-transaction plumbing without requiring test secret keys."""

    def sign(identity: OperatorIdentity, payload: bytes) -> str:
        digest = hashlib.sha256(payload).hexdigest()
        return f"TEST-SIGNATURE:{identity.operator_id}:{digest}"

    monkeypatch.setattr(authority, "sign_operator_payload", sign)
    monkeypatch.setattr(authority, "verify_operator_payload", lambda *args: None)
    monkeypatch.setattr(catalogue, "verify_operator_payload", lambda *args: None)


def make_project(
    tmp_path: Path,
) -> tuple[OperatorIdentity, OperatorIdentity, OperatorIdentity]:
    owner = operator("owner", "Owner Example", "A")
    alice = operator("alice", "Alice Contributor", "B")
    bob = operator("bob", "Bob Contributor", "C")
    initialise_project(tmp_path, "P-1", "Authority project")
    establish_project_genesis(tmp_path, owner, "PUBLIC OWNER KEY")
    return owner, alice, bob


def invite_and_accept(
    root: Path, owner: OperatorIdentity, contributor: OperatorIdentity
) -> None:
    invite_contributor(root, owner, contributor, f"PUBLIC {contributor.operator_id}")
    accept_contributor(root, contributor)


def record_test_acquisition(
    root: Path,
    actor: OperatorIdentity,
    *,
    acquisition_id: str,
    case_id: str,
    payload: bytes = b"evidence",
    completed_utc: str = "2026-09-04T12:00:00Z",
) -> str:
    """Commit one representative file and bind it to an acquisition event."""

    source = root / f"{acquisition_id}.bin"
    source.write_bytes(payload)
    files = commit_files(
        root,
        case_id=case_id,
        acquisition_id=acquisition_id,
        actor_id=actor.operator_id,
        candidates=[FileCandidate(source, "evidence.bin", "primary")],
    )
    return record_acquisition(
        root,
        actor,
        acquisition_id=acquisition_id,
        case_id=case_id,
        collector="screenshot",
        completed_utc=completed_utc,
        file_ids=[str(files[0]["file_id"])],
        record={"source": {"collector": "screenshot"}},
    )


def test_bootstrap_binds_owner_and_verifies_reconstructed_state(tmp_path: Path) -> None:
    owner, _, _ = make_project(tmp_path)

    assert current_owner(tmp_path)["owner_id"] == owner.operator_id
    assert list_members(tmp_path)[0]["membership_role"] == "owner"
    resolved = require_registered_operator(tmp_path, owner)
    assert resolved["membership_state"] == "active"
    verified = verify_chain(tmp_path)
    assert verified["event_count"] == 1


def test_project_identity_cannot_be_redefined_by_unrecorded_local_state(
    tmp_path: Path,
) -> None:
    owner, _, _ = make_project(tmp_path)
    forged = OperatorIdentity(
        owner.schema_version,
        owner.operator_id,
        "Different Name",
        owner.public_contact,
        owner.organisation,
        owner.role,
        owner.operator_key_fingerprint,
        owner.operator_signing_subkey_fingerprint,
    )
    with pytest.raises(ToolkitError, match="does not match the project-retained"):
        require_registered_operator(tmp_path, forged)


def test_direct_operator_and_key_tampering_is_detected(tmp_path: Path) -> None:
    make_project(tmp_path)
    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute(
        "UPDATE operators SET name = 'Mallory' WHERE operator_id = 'owner'"
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="current operators state"):
        verify_chain(tmp_path)

    other = tmp_path / "key"
    make_project(other)
    connection = sqlite3.connect(catalogue_path(other))
    connection.execute(
        "UPDATE operator_keys SET public_key = 'REPLACED' WHERE operator_id = 'owner'"
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="current operator keys state"):
        verify_chain(other)


def test_contributor_must_accept_own_invitation(tmp_path: Path) -> None:
    owner, alice, _ = make_project(tmp_path)
    invite_contributor(tmp_path, owner, alice, "PUBLIC ALICE")
    pending = {item["operator_id"]: item for item in list_members(tmp_path)}
    assert pending[alice.operator_id]["state"] == "pending"
    with pytest.raises(ToolkitError, match="not an active project member"):
        require_registered_operator(tmp_path, alice)

    accept_contributor(tmp_path, alice)
    active = {item["operator_id"]: item for item in list_members(tmp_path)}
    assert active[alice.operator_id]["state"] == "active"
    assert verify_chain(tmp_path)["event_count"] == 3


def test_contributor_can_reject_and_owner_can_remove_active_member(
    tmp_path: Path,
) -> None:
    owner, alice, bob = make_project(tmp_path)
    invite_contributor(tmp_path, owner, alice, "PUBLIC ALICE")
    reject_contributor(tmp_path, alice)
    assert {item["operator_id"]: item for item in list_members(tmp_path)}["alice"][
        "state"
    ] == "rejected"

    invite_and_accept(tmp_path, owner, bob)
    with pytest.raises(ToolkitError, match="requires a reason"):
        remove_contributor(tmp_path, owner, bob.operator_id, "")
    remove_contributor(tmp_path, owner, bob.operator_id, "Engagement ended")
    assert {item["operator_id"]: item for item in list_members(tmp_path)}["bob"][
        "state"
    ] == "removed"
    verify_chain(tmp_path)


def test_project_ownership_transfer_requires_signed_acceptance(tmp_path: Path) -> None:
    owner, alice, _ = make_project(tmp_path)
    invite_and_accept(tmp_path, owner, alice)
    transfer_id = propose_ownership_transfer(
        tmp_path, owner, alice.operator_id, "Handover of responsibility"
    )
    assert transfer_id.startswith("XFER-")
    assert current_owner(tmp_path)["owner_id"] == owner.operator_id

    accepted = accept_ownership_transfer(tmp_path, alice)
    assert accepted == transfer_id
    assert current_owner(tmp_path)["owner_id"] == alice.operator_id
    members = {item["operator_id"]: item for item in list_members(tmp_path)}
    assert members["owner"]["membership_role"] == "contributor"
    assert members["alice"]["membership_role"] == "owner"
    verify_chain(tmp_path)


def test_ownership_transfer_can_be_rejected_or_cancelled_without_rewrite(
    tmp_path: Path,
) -> None:
    owner, alice, bob = make_project(tmp_path)
    invite_and_accept(tmp_path, owner, alice)
    invite_and_accept(tmp_path, owner, bob)

    first = propose_ownership_transfer(
        tmp_path, owner, alice.operator_id, "First offer"
    )
    assert reject_ownership_transfer(tmp_path, alice, "Declined") == first
    assert current_owner(tmp_path)["owner_id"] == owner.operator_id

    second = propose_ownership_transfer(
        tmp_path, owner, bob.operator_id, "Second offer"
    )
    assert cancel_ownership_transfer(tmp_path, owner, "Plans changed") == second
    assert current_owner(tmp_path)["owner_id"] == owner.operator_id
    verify_chain(tmp_path)


def test_case_owner_is_hash_chained_and_contributor_record_starts_pending(
    tmp_path: Path,
) -> None:
    owner, alice, _ = make_project(tmp_path)
    invite_and_accept(tmp_path, owner, alice)
    case_id = create_case(tmp_path, "Case")
    assign_case_owner(tmp_path, case_id, owner)
    assert (
        current_owner(tmp_path, scope_type="case", scope_id=case_id)["owner_id"]
        == owner.operator_id
    )

    acquisition_id = issue_identifier(tmp_path, "acquisition", "ACQ")
    status = record_test_acquisition(
        tmp_path, alice, acquisition_id=acquisition_id, case_id=case_id
    )
    assert status == "pending"
    assert list_records(tmp_path)[0]["status"] == "pending"

    decide_record(tmp_path, owner, acquisition_id, "approved")
    record = list_records(tmp_path)[0]
    assert record["status"] == "approved"
    assert record["decided_by"] == owner.operator_id
    verify_chain(tmp_path)


def test_owner_submission_is_immediately_approved_and_rejection_is_retained(
    tmp_path: Path,
) -> None:
    owner, alice, _ = make_project(tmp_path)
    invite_and_accept(tmp_path, owner, alice)
    case_id = create_case(tmp_path)
    assign_case_owner(tmp_path, case_id, owner)
    owner_acquisition_id = issue_identifier(tmp_path, "acquisition", "ACQ")
    assert (
        record_test_acquisition(
            tmp_path,
            owner,
            acquisition_id=owner_acquisition_id,
            case_id=case_id,
            payload=b"owner evidence",
            completed_utc="2026-09-04T13:00:00Z",
        )
        == "approved"
    )
    with pytest.raises(ToolkitError, match="already approved"):
        decide_record(tmp_path, owner, owner_acquisition_id, "rejected", "No")

    pending_acquisition_id = issue_identifier(tmp_path, "acquisition", "ACQ")
    record_test_acquisition(
        tmp_path,
        alice,
        acquisition_id=pending_acquisition_id,
        case_id=case_id,
        payload=b"pending evidence",
        completed_utc="2026-09-04T14:00:00Z",
    )
    with pytest.raises(ToolkitError, match="requires a reason"):
        decide_record(tmp_path, owner, pending_acquisition_id, "rejected", "")
    decide_record(tmp_path, owner, pending_acquisition_id, "rejected", "Out of scope")
    rejected = {item["object_id"]: item for item in list_records(tmp_path)}[
        pending_acquisition_id
    ]
    assert rejected["status"] == "rejected"
    assert rejected["decision_reason"] == "Out of scope"
    verify_chain(tmp_path)


def test_authority_event_and_signature_envelope_tampering_is_detected(
    tmp_path: Path,
) -> None:
    make_project(tmp_path)
    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute(
        "UPDATE audit_events SET details_json = replace(details_json, 'TEST-SIGNATURE', 'BAD-SIGNATURE') "
        "WHERE event_type = 'PROJECT_GENESIS'"
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="event hash is invalid"):
        verify_chain(tmp_path)


def test_authority_signature_verification_failure_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_project(tmp_path)

    def fail(*args: object) -> None:
        raise ToolkitError("Operator transaction signature is invalid")

    monkeypatch.setattr(catalogue, "verify_operator_payload", fail)
    with pytest.raises(ToolkitError, match="signature is invalid"):
        verify_chain(tmp_path)


def test_owned_project_wrapper_unwinds_failed_authority_bootstrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Do not leave an apparently usable ownerless project after bootstrap failure."""
    from fact.core import project as project_module

    owner = operator("owner", "Owner", "A")
    monkeypatch.setattr(
        project_module,
        "establish_project_genesis",
        lambda *args, **kwargs: (_ for _ in ()).throw(ToolkitError("signing failed")),
    )
    with pytest.raises(ToolkitError, match="signing failed"):
        project_module.initialise_owned_project(
            tmp_path, "P-1", "Project", owner, "PUBLIC KEY"
        )
    assert not (tmp_path / "PROJECT.toml").exists()
    assert not (tmp_path / ".fact").exists()


def test_owned_case_marks_identifier_failed_when_owner_binding_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Never leave a failed owner-binding attempt reusable as another case."""
    from fact.core import project as project_module

    owner, _, _ = make_project(tmp_path)
    monkeypatch.setattr(
        project_module,
        "assign_case_owner",
        lambda *args, **kwargs: (_ for _ in ()).throw(ToolkitError("cannot sign")),
    )
    with pytest.raises(ToolkitError, match="cannot sign"):
        project_module.create_owned_case(tmp_path, owner, "Case", "Comment")
    rows = catalogue.list_identifiers(tmp_path, "case")
    assert rows[0]["state"] == "failed"


def test_session_authentication_proves_retained_key_possession(tmp_path: Path) -> None:
    """Authenticate a shell session without treating that as transaction approval."""
    from fact.core.authority import authenticate_operator_session

    owner, _, _ = make_project(tmp_path)
    authenticated = authenticate_operator_session(tmp_path, owner)
    assert authenticated.operator_id == owner.operator_id
    assert (
        authenticated.signing_fingerprint == owner.operator_signing_subkey_fingerprint
    )
    assert len(authenticated.challenge_sha256) == 64


def test_uninitialised_project_fails_closed_for_protected_operations(
    tmp_path: Path,
) -> None:
    """Reject ownerless projects rather than retrofitting current authority."""
    from fact.core.authority import require_project_authority

    initialise_project(tmp_path, "P-LEGACY", "Legacy")
    with pytest.raises(
        ToolkitError, match="not compatible with the current FACT trust model"
    ):
        require_project_authority(tmp_path)


def test_membership_ownership_and_record_status_tampering_is_detected(
    tmp_path: Path,
) -> None:
    """Detect direct edits to authority state even when history is untouched."""
    owner, alice, _ = make_project(tmp_path)
    invite_and_accept(tmp_path, owner, alice)
    case_id = create_case(tmp_path, "Tamper detection")
    assign_case_owner(tmp_path, case_id, owner)
    acquisition_id = issue_identifier(tmp_path, "acquisition", "ACQ")
    record_test_acquisition(
        tmp_path,
        alice,
        acquisition_id=acquisition_id,
        case_id=case_id,
        payload=b"tamper test evidence",
        completed_utc="2026-09-04T15:00:00Z",
    )

    scenarios = (
        (
            "membership",
            "UPDATE project_memberships SET state = 'removed' WHERE operator_id = 'alice'",
            "current project memberships state",
        ),
        (
            "ownership",
            "UPDATE ownership SET owner_id = 'alice' WHERE scope_type = 'case'",
            "current ownership state",
        ),
        (
            "record",
            "UPDATE record_authority SET status = 'approved' WHERE object_id = ?",
            "current record authority state",
        ),
    )
    original = catalogue_path(tmp_path).read_bytes()
    for name, statement, match in scenarios:
        catalogue_path(tmp_path).write_bytes(original)
        connection = sqlite3.connect(catalogue_path(tmp_path))
        if name == "record":
            connection.execute(statement, (acquisition_id,))
        else:
            connection.execute(statement)
        connection.commit()
        connection.close()
        with pytest.raises(ToolkitError, match=match):
            verify_chain(tmp_path)


def test_record_acquisition_requires_live_catalogue_identifier(tmp_path: Path) -> None:
    """Refuse to attach authority state to an invented acquisition identifier."""
    owner, _, _ = make_project(tmp_path)
    case_id = create_case(tmp_path, "Identifier binding")
    assign_case_owner(tmp_path, case_id, owner)
    with pytest.raises(ToolkitError, match="not active in the catalogue"):
        record_acquisition(
            tmp_path,
            owner,
            acquisition_id="ACQ-999999",
            case_id=case_id,
            collector="screenshot",
            completed_utc="2026-09-04T16:00:00Z",
            file_ids=["FILE-999999"],
            record={"source": {"collector": "screenshot"}},
        )


def test_genesis_does_not_recreate_missing_authority_schema(tmp_path: Path) -> None:
    """Fail closed instead of retrofitting authority tables into another schema."""
    owner = operator("owner", "Owner Example", "A")
    initialise_project(tmp_path, "P-1", "Authority project")
    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute("DROP TABLE record_authority")
    connection.commit()
    connection.close()

    with pytest.raises(ToolkitError, match="authority schema is incomplete"):
        establish_project_genesis(tmp_path, owner, "PUBLIC OWNER KEY")

    connection = sqlite3.connect(catalogue_path(tmp_path))
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    finally:
        connection.close()
    assert "record_authority" not in tables


def test_operator_uuid_is_unique_immutable_and_bound_to_signed_event_hash(
    tmp_path: Path,
) -> None:
    """Bind human authority events to stable UUID identity anchors."""
    owner, alice, _ = make_project(tmp_path)
    invite_and_accept(tmp_path, owner, alice)

    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.row_factory = sqlite3.Row
    operators = connection.execute(
        "SELECT operator_id, operator_uuid FROM operators ORDER BY operator_id"
    ).fetchall()
    assert len({row["operator_uuid"] for row in operators}) == 2
    for row in operators:
        assert str(row["operator_uuid"])

    event = connection.execute(
        "SELECT actor_kind, actor_id, actor_uuid, credential_fingerprint, "
        "authority_basis FROM audit_events WHERE event_type = 'CONTRIBUTOR_ACCEPTED'"
    ).fetchone()
    assert event["actor_kind"] == "operator"
    assert event["actor_id"] == alice.operator_id
    assert event["actor_uuid"] == next(
        row["operator_uuid"]
        for row in operators
        if row["operator_id"] == alice.operator_id
    )
    assert event["credential_fingerprint"] == alice.operator_signing_subkey_fingerprint
    assert event["authority_basis"] == "signed-authority-transaction"

    connection.execute(
        "UPDATE audit_events SET actor_uuid = ? WHERE event_type = 'CONTRIBUTOR_ACCEPTED'",
        ("00000000-0000-4000-8000-000000000000",),
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="event hash is invalid"):
        verify_chain(tmp_path)


def test_operator_uuid_live_state_tampering_is_detected(tmp_path: Path) -> None:
    """Reject a direct UUID rewrite even when the rolling event rows are untouched."""
    owner, _, _ = make_project(tmp_path)

    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute(
        "UPDATE operators SET operator_uuid = ? WHERE operator_id = ?",
        ("00000000-0000-4000-8000-000000000001", owner.operator_id),
    )
    connection.commit()
    connection.close()

    with pytest.raises(ToolkitError, match="operator"):
        verify_chain(tmp_path)


def test_project_local_operator_references_are_stable_and_resolvable(
    tmp_path: Path,
) -> None:
    """Allocate immutable OPERATOR references independently of friendly aliases."""
    owner, alice, _ = make_project(tmp_path)
    invite_and_accept(tmp_path, owner, alice)

    members = {item["operator_id"]: item for item in list_members(tmp_path)}
    assert members["owner"]["operator_ref"] == "OPERATOR-000001"
    assert members["alice"]["operator_ref"] == "OPERATOR-000002"

    by_ref = authority.registered_operator_identity(tmp_path, "OPERATOR-000002")
    assert by_ref.operator_id == "alice"
    by_uuid = authority.registered_operator_identity(
        tmp_path, str(members["alice"]["operator_uuid"])
    )
    assert by_uuid.operator_id == "alice"
    assert current_owner(tmp_path)["operator_ref"] == "OPERATOR-000001"
    verify_chain(tmp_path)


def test_operator_reference_tampering_is_detected(tmp_path: Path) -> None:
    """Treat project-local operator references as authenticated identity state."""
    make_project(tmp_path)
    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute(
        "UPDATE operators SET operator_ref = 'OPERATOR-999999' WHERE operator_id = 'owner'"
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="current operators state"):
        verify_chain(tmp_path)


def test_complete_initialisation_enrols_additional_local_operator_before_activation(
    tmp_path: Path,
) -> None:
    from fact.core.project import initialise_owned_project

    owner_identity = operator("owner", "Owner", "A")
    contributor = operator("analyst", "Analyst", "B")
    initialise_owned_project(
        tmp_path,
        "P-SETUP",
        "Complete setup",
        owner_identity,
        "PUBLIC OWNER",
        additional_operators=[(contributor, "PUBLIC ANALYST")],
    )

    members = {row["operator_id"]: row for row in list_members(tmp_path)}
    assert members["owner"]["membership_role"] == "owner"
    assert members["analyst"]["membership_role"] == "contributor"
    assert members["analyst"]["state"] == "active"
    assert not (tmp_path / ".fact-initialising").exists()
    assert verify_chain(tmp_path)["event_count"] >= 3


def test_complete_initialisation_unwinds_failed_initial_contributor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fact.core import project as project_module

    owner_identity = operator("owner", "Owner", "A")
    contributor = operator("analyst", "Analyst", "B")
    monkeypatch.setattr(
        project_module,
        "invite_contributor",
        lambda *args, **kwargs: (_ for _ in ()).throw(ToolkitError("invite failed")),
    )
    with pytest.raises(ToolkitError, match="invite failed"):
        project_module.initialise_owned_project(
            tmp_path,
            "P-SETUP",
            "Complete setup",
            owner_identity,
            "PUBLIC OWNER",
            additional_operators=[(contributor, "PUBLIC ANALYST")],
        )
    assert not (tmp_path / "PROJECT.toml").exists()
    assert not (tmp_path / ".fact").exists()
    assert not (tmp_path / ".fact-initialising").exists()
