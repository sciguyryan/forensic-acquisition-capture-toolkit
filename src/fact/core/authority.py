"""Manage project identity, responsibility, membership and signed authority state.

FACT keeps project-relevant operator identity inside the project catalogue. Local
operator profiles remain a convenience for finding signing keys, but they are not
project authority and cannot redefine a historical operator after the fact.

Every authority mutation is represented by a canonical transaction signed by the
operator performing it and then appended to the catalogue's rolling hash chain.
Private keys, passphrases and GnuPG agent state remain outside the project.
"""

from __future__ import annotations

import hashlib
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from ..errors import ToolkitError
from ..identity import (
    OperatorIdentity,
    sign_operator_payload,
    verify_operator_payload,
)
from .catalogue import (
    _append_event,
    _canonical,
    _connect,
    _current_event_context,
    _utc_now,
    _write_transaction,
)

AUTHORITY_SCHEMA_VERSION = 1
AUTHORITY_TRANSACTION_SCHEMA = "fact-authority-transaction/v1"
AUTHENTICATION_CHALLENGE_SCHEMA = "fact-operator-authentication/v1"


@dataclass(frozen=True, slots=True)
class AuthenticatedOperator:
    """Describe cryptographically authenticated operator context for one session."""

    operator_id: str
    signing_fingerprint: str
    authenticated_at: str
    challenge_sha256: str


def _authority_tables(connection: sqlite3.Connection) -> None:
    """Create authority tables without altering historical project state.

    ``sqlite3.Connection.executescript`` implicitly commits an active
    transaction, so each statement is executed individually. Authority setup
    must remain inside FACT's ``BEGIN IMMEDIATE`` boundary when called from a
    project mutation.
    """
    statements = (
        """
        CREATE TABLE IF NOT EXISTS operators (
            operator_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            public_contact TEXT,
            organisation TEXT,
            role_label TEXT,
            state TEXT NOT NULL CHECK(state IN ('active', 'retired')),
            created_sequence INTEGER NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS operator_keys (
            operator_id TEXT NOT NULL,
            primary_fingerprint TEXT NOT NULL,
            signing_fingerprint TEXT NOT NULL,
            public_key TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('active', 'retired', 'revoked')),
            valid_from_sequence INTEGER NOT NULL,
            valid_until_sequence INTEGER,
            PRIMARY KEY(operator_id, signing_fingerprint),
            FOREIGN KEY(operator_id) REFERENCES operators(operator_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS project_memberships (
            operator_id TEXT PRIMARY KEY,
            membership_role TEXT NOT NULL CHECK(membership_role IN ('owner', 'contributor')),
            state TEXT NOT NULL CHECK(state IN ('pending', 'active', 'rejected', 'removed')),
            added_sequence INTEGER NOT NULL,
            resolved_sequence INTEGER,
            FOREIGN KEY(operator_id) REFERENCES operators(operator_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS ownership (
            scope_type TEXT NOT NULL CHECK(scope_type IN ('project', 'case')),
            scope_id TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            effective_from_sequence INTEGER NOT NULL,
            PRIMARY KEY(scope_type, scope_id),
            FOREIGN KEY(owner_id) REFERENCES operators(operator_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS ownership_transfers (
            transfer_id TEXT PRIMARY KEY,
            scope_type TEXT NOT NULL CHECK(scope_type IN ('project', 'case')),
            scope_id TEXT NOT NULL,
            from_operator_id TEXT NOT NULL,
            to_operator_id TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('pending', 'accepted', 'rejected', 'cancelled')),
            reason TEXT NOT NULL,
            proposed_sequence INTEGER NOT NULL,
            resolved_sequence INTEGER,
            FOREIGN KEY(from_operator_id) REFERENCES operators(operator_id),
            FOREIGN KEY(to_operator_id) REFERENCES operators(operator_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS record_authority (
            object_type TEXT NOT NULL,
            object_id TEXT NOT NULL,
            scope_type TEXT NOT NULL CHECK(scope_type IN ('project', 'case')),
            scope_id TEXT NOT NULL,
            submitted_by TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
            submitted_sequence INTEGER NOT NULL,
            decided_by TEXT,
            decision_sequence INTEGER,
            decision_reason TEXT,
            archive_sha256 TEXT,
            PRIMARY KEY(object_type, object_id),
            FOREIGN KEY(submitted_by) REFERENCES operators(operator_id),
            FOREIGN KEY(decided_by) REFERENCES operators(operator_id)
        )
        """,
    )
    for statement in statements:
        connection.execute(statement)
    connection.execute(
        "INSERT OR IGNORE INTO metadata(key, value) VALUES ('authority_schema_version', ?)",
        (str(AUTHORITY_SCHEMA_VERSION),),
    )


def _require_authority_tables(connection: sqlite3.Connection) -> None:
    """Require the authority schema without mutating a project during a read."""
    required = {
        "operators",
        "operator_keys",
        "project_memberships",
        "ownership",
        "ownership_transfers",
        "record_authority",
    }
    available = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    missing = sorted(required - available)
    if missing:
        raise ToolkitError(
            "Project authority schema is incomplete: " + ", ".join(missing)
        )


def authority_enabled(project_root: Path) -> bool:
    """Return whether the project has an established signed authority root."""
    connection = _connect(project_root)
    try:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key = 'authority_state'"
        ).fetchone()
        return row is not None and str(row[0]) == "active"
    finally:
        connection.close()


def require_project_authority(project_root: Path) -> None:
    """Fail closed when a project has no signed authority root."""

    if not authority_enabled(project_root):
        raise ToolkitError(
            "Project authority has not been established; run 'fact authority bootstrap' first"
        )


def _transaction(
    connection: sqlite3.Connection,
    *,
    actor: OperatorIdentity,
    event_type: str,
    object_type: str,
    object_id: str,
    data: dict[str, object],
) -> tuple[dict[str, object], str]:
    """Build and sign the exact transaction that will enter the audit chain."""
    sequence, previous = _current_event_context(connection)
    occurred_at = _utc_now()
    project_id = str(
        connection.execute(
            "SELECT value FROM metadata WHERE key = 'project_id'"
        ).fetchone()[0]
    )
    transaction = {
        "schema": AUTHORITY_TRANSACTION_SCHEMA,
        "project_id": project_id,
        "event_sequence": sequence,
        "occurred_at": occurred_at,
        "event_type": event_type,
        "object_type": object_type,
        "object_id": object_id,
        "actor_id": actor.operator_id,
        "actor_key_fingerprint": actor.operator_signing_subkey_fingerprint,
        "previous_hash": previous,
        "data": data,
    }
    signature = sign_operator_payload(actor, _canonical(transaction))
    return transaction, signature


def _append_signed(
    connection: sqlite3.Connection,
    *,
    actor: OperatorIdentity,
    event_type: str,
    object_type: str,
    object_id: str,
    data: dict[str, object],
    verification_key: str,
) -> int:
    """Sign, verify and append one authority transaction atomically."""
    transaction, signature = _transaction(
        connection,
        actor=actor,
        event_type=event_type,
        object_type=object_type,
        object_id=object_id,
        data=data,
    )
    verify_operator_payload(
        verification_key,
        _canonical(transaction),
        signature,
        actor.operator_signing_subkey_fingerprint,
    )
    _append_event(
        connection,
        event_type,
        object_type,
        object_id,
        {
            "authority_transaction": transaction,
            "authority_signature": signature,
        },
        occurred_at=str(transaction["occurred_at"]),
        expected_sequence=int(transaction["event_sequence"]),
        expected_previous=str(transaction["previous_hash"]),
    )
    return int(transaction["event_sequence"])


def _identity_data(identity: OperatorIdentity, public_key: str) -> dict[str, object]:
    return {
        "identity": asdict(identity),
        "public_key": public_key,
        "public_key_sha256": hashlib.sha256(public_key.encode("utf-8")).hexdigest(),
    }


def _operator_row(connection: sqlite3.Connection, operator_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM operators WHERE operator_id = ?", (operator_id,)
    ).fetchone()
    if row is None:
        raise ToolkitError(f"Operator is not registered in this project: {operator_id}")
    return row


def _key_row(connection: sqlite3.Connection, operator_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM operator_keys WHERE operator_id = ? AND state = 'active'",
        (operator_id,),
    ).fetchone()
    if row is None:
        raise ToolkitError(f"Operator has no active project signing key: {operator_id}")
    return row


def require_registered_operator(
    project_root: Path, identity: OperatorIdentity, *, require_active: bool = True
) -> dict[str, object]:
    """Bind a local profile to the immutable project identity it claims to represent."""
    connection = _connect(project_root)
    try:
        _require_authority_tables(connection)
        row = _operator_row(connection, identity.operator_id)
        key = _key_row(connection, identity.operator_id)
        expected = {
            "name": identity.name,
            "public_contact": identity.public_contact,
            "organisation": identity.organisation,
            "role_label": identity.role,
            "primary_fingerprint": identity.operator_key_fingerprint,
            "signing_fingerprint": identity.operator_signing_subkey_fingerprint,
        }
        actual = {
            "name": row["name"],
            "public_contact": row["public_contact"],
            "organisation": row["organisation"],
            "role_label": row["role_label"],
            "primary_fingerprint": key["primary_fingerprint"],
            "signing_fingerprint": key["signing_fingerprint"],
        }
        if actual != expected:
            raise ToolkitError(
                "Local operator profile does not match the project-retained identity"
            )
        membership = connection.execute(
            "SELECT membership_role, state FROM project_memberships WHERE operator_id = ?",
            (identity.operator_id,),
        ).fetchone()
        if require_active and (membership is None or membership["state"] != "active"):
            raise ToolkitError(
                f"Operator is not an active project member: {identity.operator_id}"
            )
        return {
            "operator_id": identity.operator_id,
            "membership_role": membership["membership_role"] if membership else None,
            "membership_state": membership["state"] if membership else None,
            "public_key": str(key["public_key"]),
        }
    finally:
        connection.close()


def authenticate_operator_session(
    project_root: Path, identity: OperatorIdentity
) -> AuthenticatedOperator:
    """Prove possession of the project-retained operator key for this session.

    Session authentication is deliberately separate from transaction signing. A
    successful challenge proves that the current shell session controls the key
    bound to the retained project identity, while consequential catalogue
    mutations still receive their own detached transaction signatures.
    """
    registered = require_registered_operator(project_root, identity)
    connection = _connect(project_root)
    try:
        project_id = str(
            connection.execute(
                "SELECT value FROM metadata WHERE key = 'project_id'"
            ).fetchone()[0]
        )
    finally:
        connection.close()
    authenticated_at = _utc_now()
    challenge = {
        "schema": AUTHENTICATION_CHALLENGE_SCHEMA,
        "project_id": project_id,
        "operator_id": identity.operator_id,
        "signing_fingerprint": identity.operator_signing_subkey_fingerprint,
        "authenticated_at": authenticated_at,
        "nonce": uuid.uuid4().hex,
        "purpose": "interactive-session",
    }
    payload = _canonical(challenge)
    signature = sign_operator_payload(identity, payload)
    verify_operator_payload(
        str(registered["public_key"]),
        payload,
        signature,
        identity.operator_signing_subkey_fingerprint,
    )
    return AuthenticatedOperator(
        identity.operator_id,
        identity.operator_signing_subkey_fingerprint,
        authenticated_at,
        hashlib.sha256(payload).hexdigest(),
    )


def bootstrap_project_authority(
    project_root: Path,
    owner: OperatorIdentity,
    public_key: str,
) -> None:
    """Establish the first signed owner before a project may accept work."""
    with _write_transaction(project_root) as connection:
        _authority_tables(connection)
        existing = connection.execute("SELECT COUNT(*) FROM operators").fetchone()[0]
        if existing:
            raise ToolkitError("Project authority has already been established")
        data = _identity_data(owner, public_key)
        data["ownership_scope"] = "project"
        sequence = _append_signed(
            connection,
            actor=owner,
            event_type="AUTHORITY_BOOTSTRAPPED",
            object_type="project",
            object_id=str(
                connection.execute(
                    "SELECT value FROM metadata WHERE key = 'project_id'"
                ).fetchone()[0]
            ),
            data=data,
            verification_key=public_key,
        )
        connection.execute(
            "INSERT INTO operators VALUES (?, ?, ?, ?, ?, 'active', ?)",
            (
                owner.operator_id,
                owner.name,
                owner.public_contact,
                owner.organisation,
                owner.role,
                sequence,
            ),
        )
        connection.execute(
            "INSERT INTO operator_keys VALUES (?, ?, ?, ?, 'active', ?, NULL)",
            (
                owner.operator_id,
                owner.operator_key_fingerprint,
                owner.operator_signing_subkey_fingerprint,
                public_key,
                sequence,
            ),
        )
        connection.execute(
            "INSERT INTO project_memberships VALUES (?, 'owner', 'active', ?, ?)",
            (owner.operator_id, sequence, sequence),
        )
        project_id = str(
            connection.execute(
                "SELECT value FROM metadata WHERE key = 'project_id'"
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO ownership VALUES ('project', ?, ?, ?)",
            (project_id, owner.operator_id, sequence),
        )
        connection.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES ('authority_state', 'active')"
        )


def current_owner(
    project_root: Path, *, scope_type: str = "project", scope_id: str | None = None
) -> dict[str, object]:
    """Return the current responsible owner for a project or case."""
    connection = _connect(project_root)
    try:
        _require_authority_tables(connection)
        project_id = str(
            connection.execute(
                "SELECT value FROM metadata WHERE key = 'project_id'"
            ).fetchone()[0]
        )
        resolved_scope = project_id if scope_type == "project" else scope_id
        if not resolved_scope:
            raise ToolkitError("Case ownership requires a case identifier")
        row = connection.execute(
            "SELECT o.owner_id, o.effective_from_sequence, p.name "
            "FROM ownership o JOIN operators p ON p.operator_id = o.owner_id "
            "WHERE o.scope_type = ? AND o.scope_id = ?",
            (scope_type, resolved_scope),
        ).fetchone()
        if row is None:
            raise ToolkitError(f"No owner is recorded for {scope_type} {resolved_scope}")
        return dict(row)
    finally:
        connection.close()


def assign_case_owner(
    project_root: Path, case_id: str, actor: OperatorIdentity
) -> None:
    """Assign a newly created case to the current project owner."""
    with _write_transaction(project_root) as connection:
        _authority_tables(connection)
        project_id = str(
            connection.execute(
                "SELECT value FROM metadata WHERE key = 'project_id'"
            ).fetchone()[0]
        )
        owner = connection.execute(
            "SELECT owner_id FROM ownership WHERE scope_type = 'project' AND scope_id = ?",
            (project_id,),
        ).fetchone()
        if owner is None or owner["owner_id"] != actor.operator_id:
            raise ToolkitError("Only the current project owner may establish case ownership")
        key = _key_row(connection, actor.operator_id)
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="CASE_OWNERSHIP_ASSIGNED",
            object_type="case",
            object_id=case_id,
            data={"owner_id": actor.operator_id},
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "INSERT INTO ownership VALUES ('case', ?, ?, ?)",
            (case_id, actor.operator_id, sequence),
        )


def invite_contributor(
    project_root: Path,
    actor: OperatorIdentity,
    contributor: OperatorIdentity,
    contributor_public_key: str,
) -> None:
    """Invite a contributor; the invitation is inert until the contributor accepts."""
    with _write_transaction(project_root) as connection:
        _authority_tables(connection)
        project_id = str(
            connection.execute(
                "SELECT value FROM metadata WHERE key = 'project_id'"
            ).fetchone()[0]
        )
        owner = connection.execute(
            "SELECT owner_id FROM ownership WHERE scope_type = 'project' AND scope_id = ?",
            (project_id,),
        ).fetchone()
        if owner is None or owner["owner_id"] != actor.operator_id:
            raise ToolkitError("Only the current project owner may invite contributors")
        if contributor.operator_id == actor.operator_id:
            raise ToolkitError("The project owner is already an active project member")
        if connection.execute(
            "SELECT 1 FROM operators WHERE operator_id = ?", (contributor.operator_id,)
        ).fetchone():
            raise ToolkitError(
                f"Operator already exists in project authority: {contributor.operator_id}"
            )
        key = _key_row(connection, actor.operator_id)
        data = _identity_data(contributor, contributor_public_key)
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="CONTRIBUTOR_INVITED",
            object_type="operator",
            object_id=contributor.operator_id,
            data=data,
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "INSERT INTO operators VALUES (?, ?, ?, ?, ?, 'active', ?)",
            (
                contributor.operator_id,
                contributor.name,
                contributor.public_contact,
                contributor.organisation,
                contributor.role,
                sequence,
            ),
        )
        connection.execute(
            "INSERT INTO operator_keys VALUES (?, ?, ?, ?, 'active', ?, NULL)",
            (
                contributor.operator_id,
                contributor.operator_key_fingerprint,
                contributor.operator_signing_subkey_fingerprint,
                contributor_public_key,
                sequence,
            ),
        )
        connection.execute(
            "INSERT INTO project_memberships VALUES (?, 'contributor', 'pending', ?, NULL)",
            (contributor.operator_id, sequence),
        )


def accept_contributor(project_root: Path, actor: OperatorIdentity) -> None:
    """Accept a pending invitation using the invited contributor's own key."""
    with _write_transaction(project_root) as connection:
        _authority_tables(connection)
        membership = connection.execute(
            "SELECT state FROM project_memberships WHERE operator_id = ?",
            (actor.operator_id,),
        ).fetchone()
        if membership is None or membership["state"] != "pending":
            raise ToolkitError("Operator has no pending contributor invitation")
        key = _key_row(connection, actor.operator_id)
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="CONTRIBUTOR_ACCEPTED",
            object_type="operator",
            object_id=actor.operator_id,
            data={"membership_role": "contributor"},
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "UPDATE project_memberships SET state = 'active', resolved_sequence = ? "
            "WHERE operator_id = ?",
            (sequence, actor.operator_id),
        )


def reject_contributor(project_root: Path, actor: OperatorIdentity) -> None:
    """Reject a pending invitation while retaining the invited identity historically."""
    with _write_transaction(project_root) as connection:
        _authority_tables(connection)
        membership = connection.execute(
            "SELECT state FROM project_memberships WHERE operator_id = ?",
            (actor.operator_id,),
        ).fetchone()
        if membership is None or membership["state"] != "pending":
            raise ToolkitError("Operator has no pending contributor invitation")
        key = _key_row(connection, actor.operator_id)
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="CONTRIBUTOR_REJECTED",
            object_type="operator",
            object_id=actor.operator_id,
            data={"membership_role": "contributor"},
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "UPDATE project_memberships SET state = 'rejected', resolved_sequence = ? "
            "WHERE operator_id = ?",
            (sequence, actor.operator_id),
        )


def remove_contributor(
    project_root: Path, actor: OperatorIdentity, operator_id: str, reason: str
) -> None:
    """Remove an active contributor without deleting their historical identity."""
    if not reason.strip():
        raise ToolkitError("Removing a contributor requires a reason")
    with _write_transaction(project_root) as connection:
        _authority_tables(connection)
        project_id = str(
            connection.execute(
                "SELECT value FROM metadata WHERE key = 'project_id'"
            ).fetchone()[0]
        )
        owner = connection.execute(
            "SELECT owner_id FROM ownership WHERE scope_type = 'project' AND scope_id = ?",
            (project_id,),
        ).fetchone()
        if owner is None or owner["owner_id"] != actor.operator_id:
            raise ToolkitError("Only the current project owner may remove contributors")
        membership = connection.execute(
            "SELECT membership_role, state FROM project_memberships WHERE operator_id = ?",
            (operator_id,),
        ).fetchone()
        if membership is None or membership["membership_role"] != "contributor":
            raise ToolkitError(f"Operator is not a project contributor: {operator_id}")
        if membership["state"] != "active":
            raise ToolkitError(f"Contributor is not active: {operator_id}")
        key = _key_row(connection, actor.operator_id)
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="CONTRIBUTOR_REMOVED",
            object_type="operator",
            object_id=operator_id,
            data={"reason": reason.strip()},
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "UPDATE project_memberships SET state = 'removed', resolved_sequence = ? "
            "WHERE operator_id = ?",
            (sequence, operator_id),
        )


def list_members(project_root: Path) -> list[dict[str, object]]:
    """List retained project operators and their current membership state."""
    connection = _connect(project_root)
    try:
        _require_authority_tables(connection)
        rows = connection.execute(
            "SELECT p.operator_id, p.name, m.membership_role, m.state, "
            "k.signing_fingerprint FROM operators p "
            "JOIN project_memberships m ON m.operator_id = p.operator_id "
            "JOIN operator_keys k ON k.operator_id = p.operator_id AND k.state = 'active' "
            "ORDER BY p.created_sequence, p.operator_id"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def _scope_id(
    connection: sqlite3.Connection, scope_type: str, scope_id: str | None
) -> str:
    if scope_type == "project":
        return str(
            connection.execute(
                "SELECT value FROM metadata WHERE key = 'project_id'"
            ).fetchone()[0]
        )
    if scope_type == "case" and scope_id:
        return scope_id
    raise ToolkitError("Ownership scope must identify a project or case")


def propose_ownership_transfer(
    project_root: Path,
    actor: OperatorIdentity,
    to_operator_id: str,
    reason: str,
    *,
    scope_type: str = "project",
    scope_id: str | None = None,
) -> str:
    """Propose a transfer; responsibility does not change until acceptance."""
    if not reason.strip():
        raise ToolkitError("Ownership transfer requires a reason")
    with _write_transaction(project_root) as connection:
        _authority_tables(connection)
        resolved_scope = _scope_id(connection, scope_type, scope_id)
        owner = connection.execute(
            "SELECT owner_id FROM ownership WHERE scope_type = ? AND scope_id = ?",
            (scope_type, resolved_scope),
        ).fetchone()
        if owner is None or owner["owner_id"] != actor.operator_id:
            raise ToolkitError("Only the current owner may propose an ownership transfer")
        target = connection.execute(
            "SELECT state FROM project_memberships WHERE operator_id = ?",
            (to_operator_id,),
        ).fetchone()
        if target is None or target["state"] != "active":
            raise ToolkitError("Ownership may only be transferred to an active project member")
        if to_operator_id == actor.operator_id:
            raise ToolkitError("Ownership is already held by that operator")
        pending = connection.execute(
            "SELECT transfer_id FROM ownership_transfers WHERE scope_type = ? "
            "AND scope_id = ? AND state = 'pending'",
            (scope_type, resolved_scope),
        ).fetchone()
        if pending:
            raise ToolkitError(
                f"Ownership transfer is already pending: {pending['transfer_id']}"
            )
        transfer_id = f"XFER-{uuid.uuid4().hex[:16].upper()}"
        key = _key_row(connection, actor.operator_id)
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="OWNERSHIP_TRANSFER_PROPOSED",
            object_type=scope_type,
            object_id=resolved_scope,
            data={
                "transfer_id": transfer_id,
                "from_operator_id": actor.operator_id,
                "to_operator_id": to_operator_id,
                "reason": reason.strip(),
            },
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "INSERT INTO ownership_transfers VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, NULL)",
            (
                transfer_id,
                scope_type,
                resolved_scope,
                actor.operator_id,
                to_operator_id,
                reason.strip(),
                sequence,
            ),
        )
        return transfer_id


def _pending_transfer(
    connection: sqlite3.Connection,
    actor_id: str,
    *,
    scope_type: str,
    scope_id: str | None,
    as_owner: bool,
) -> sqlite3.Row:
    resolved_scope = _scope_id(connection, scope_type, scope_id)
    field = "from_operator_id" if as_owner else "to_operator_id"
    row = connection.execute(
        f"SELECT * FROM ownership_transfers WHERE scope_type = ? AND scope_id = ? "
        f"AND {field} = ? AND state = 'pending' ORDER BY proposed_sequence DESC LIMIT 1",
        (scope_type, resolved_scope, actor_id),
    ).fetchone()
    if row is None:
        raise ToolkitError("No matching pending ownership transfer exists")
    return row


def accept_ownership_transfer(
    project_root: Path,
    actor: OperatorIdentity,
    *,
    scope_type: str = "project",
    scope_id: str | None = None,
) -> str:
    """Accept responsibility using the incoming owner's registered signing key."""
    with _write_transaction(project_root) as connection:
        _authority_tables(connection)
        transfer = _pending_transfer(
            connection,
            actor.operator_id,
            scope_type=scope_type,
            scope_id=scope_id,
            as_owner=False,
        )
        key = _key_row(connection, actor.operator_id)
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="OWNERSHIP_TRANSFER_ACCEPTED",
            object_type=str(transfer["scope_type"]),
            object_id=str(transfer["scope_id"]),
            data={
                "transfer_id": str(transfer["transfer_id"]),
                "from_operator_id": str(transfer["from_operator_id"]),
                "to_operator_id": actor.operator_id,
            },
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "UPDATE ownership_transfers SET state = 'accepted', resolved_sequence = ? "
            "WHERE transfer_id = ?",
            (sequence, transfer["transfer_id"]),
        )
        connection.execute(
            "UPDATE ownership SET owner_id = ?, effective_from_sequence = ? "
            "WHERE scope_type = ? AND scope_id = ?",
            (
                actor.operator_id,
                sequence,
                transfer["scope_type"],
                transfer["scope_id"],
            ),
        )
        if transfer["scope_type"] == "project":
            connection.execute(
                "UPDATE project_memberships SET membership_role = 'contributor' "
                "WHERE operator_id = ?",
                (transfer["from_operator_id"],),
            )
            connection.execute(
                "UPDATE project_memberships SET membership_role = 'owner', state = 'active' "
                "WHERE operator_id = ?",
                (actor.operator_id,),
            )
        return str(transfer["transfer_id"])


def reject_ownership_transfer(
    project_root: Path,
    actor: OperatorIdentity,
    reason: str,
    *,
    scope_type: str = "project",
    scope_id: str | None = None,
) -> str:
    """Reject an offered ownership transfer without erasing the proposal."""
    if not reason.strip():
        raise ToolkitError("Rejecting an ownership transfer requires a reason")
    with _write_transaction(project_root) as connection:
        _authority_tables(connection)
        transfer = _pending_transfer(
            connection,
            actor.operator_id,
            scope_type=scope_type,
            scope_id=scope_id,
            as_owner=False,
        )
        key = _key_row(connection, actor.operator_id)
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="OWNERSHIP_TRANSFER_REJECTED",
            object_type=str(transfer["scope_type"]),
            object_id=str(transfer["scope_id"]),
            data={"transfer_id": str(transfer["transfer_id"]), "reason": reason.strip()},
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "UPDATE ownership_transfers SET state = 'rejected', resolved_sequence = ? "
            "WHERE transfer_id = ?",
            (sequence, transfer["transfer_id"]),
        )
        return str(transfer["transfer_id"])


def cancel_ownership_transfer(
    project_root: Path,
    actor: OperatorIdentity,
    reason: str,
    *,
    scope_type: str = "project",
    scope_id: str | None = None,
) -> str:
    """Cancel the current owner's pending proposal before it is accepted."""
    if not reason.strip():
        raise ToolkitError("Cancelling an ownership transfer requires a reason")
    with _write_transaction(project_root) as connection:
        _authority_tables(connection)
        transfer = _pending_transfer(
            connection,
            actor.operator_id,
            scope_type=scope_type,
            scope_id=scope_id,
            as_owner=True,
        )
        key = _key_row(connection, actor.operator_id)
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="OWNERSHIP_TRANSFER_CANCELLED",
            object_type=str(transfer["scope_type"]),
            object_id=str(transfer["scope_id"]),
            data={"transfer_id": str(transfer["transfer_id"]), "reason": reason.strip()},
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "UPDATE ownership_transfers SET state = 'cancelled', resolved_sequence = ? "
            "WHERE transfer_id = ?",
            (sequence, transfer["transfer_id"]),
        )
        return str(transfer["transfer_id"])


def record_acquisition(
    project_root: Path,
    actor: OperatorIdentity,
    *,
    acquisition_id: str,
    case_id: str,
    archive: Path,
    archive_sha256: str,
    collector: str,
    completed_utc: str,
) -> str:
    """Enter a sealed acquisition into project authority immediately.

    An owner's own acquisition is authoritative immediately. A contributor's
    acquisition is retained in exactly the same rolling history but begins in
    ``pending`` state until the responsible case owner approves or rejects it.
    """
    with _write_transaction(project_root) as connection:
        _authority_tables(connection)
        identifier = connection.execute(
            "SELECT namespace, state FROM identifiers WHERE identifier = ?",
            (acquisition_id,),
        ).fetchone()
        if (
            identifier is None
            or identifier["namespace"] != "acquisition"
            or identifier["state"] != "active"
        ):
            raise ToolkitError(
                f"Acquisition identifier is not active in the catalogue: {acquisition_id}"
            )
        membership = connection.execute(
            "SELECT membership_role, state FROM project_memberships WHERE operator_id = ?",
            (actor.operator_id,),
        ).fetchone()
        if membership is None or membership["state"] != "active":
            raise ToolkitError("Only an active project member may submit an acquisition")
        owner = connection.execute(
            "SELECT owner_id FROM ownership WHERE scope_type = 'case' AND scope_id = ?",
            (case_id,),
        ).fetchone()
        if owner is None:
            raise ToolkitError(f"Case has no recorded responsible owner: {case_id}")
        status = "approved" if owner["owner_id"] == actor.operator_id else "pending"
        key = _key_row(connection, actor.operator_id)
        data = {
            "case_id": case_id,
            "archive_filename": archive.name,
            "archive_sha256": archive_sha256,
            "collector": collector,
            "completed_utc": completed_utc,
            "status": status,
        }
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="ACQUISITION_RECORDED",
            object_type="acquisition",
            object_id=acquisition_id,
            data=data,
            verification_key=str(key["public_key"]),
        )
        decided_by = actor.operator_id if status == "approved" else None
        decision_sequence = sequence if status == "approved" else None
        connection.execute(
            "INSERT INTO record_authority("
            "object_type, object_id, scope_type, scope_id, submitted_by, status, "
            "submitted_sequence, decided_by, decision_sequence, decision_reason, archive_sha256"
            ") VALUES ('acquisition', ?, 'case', ?, ?, ?, ?, ?, ?, NULL, ?)",
            (
                acquisition_id,
                case_id,
                actor.operator_id,
                status,
                sequence,
                decided_by,
                decision_sequence,
                archive_sha256,
            ),
        )
        return status


def decide_record(
    project_root: Path,
    actor: OperatorIdentity,
    object_id: str,
    decision: str,
    reason: str | None = None,
) -> None:
    """Approve or reject a pending acquisition as the responsible case owner."""
    if decision not in {"approved", "rejected"}:
        raise ToolkitError("Record decision must be approved or rejected")
    if decision == "rejected" and not (reason or "").strip():
        raise ToolkitError("Rejecting a record requires a reason")
    with _write_transaction(project_root) as connection:
        _authority_tables(connection)
        record = connection.execute(
            "SELECT * FROM record_authority WHERE object_type = 'acquisition' AND object_id = ?",
            (object_id,),
        ).fetchone()
        if record is None:
            raise ToolkitError(f"Unknown authority record: {object_id}")
        if record["status"] != "pending":
            raise ToolkitError(f"Record is already {record['status']}: {object_id}")
        owner = connection.execute(
            "SELECT owner_id FROM ownership WHERE scope_type = ? AND scope_id = ?",
            (record["scope_type"], record["scope_id"]),
        ).fetchone()
        if owner is None or owner["owner_id"] != actor.operator_id:
            raise ToolkitError("Only the responsible owner may decide a pending record")
        key = _key_row(connection, actor.operator_id)
        event_type = "RECORD_APPROVED" if decision == "approved" else "RECORD_REJECTED"
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type=event_type,
            object_type="acquisition",
            object_id=object_id,
            data={"reason": (reason or "").strip() or None},
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "UPDATE record_authority SET status = ?, decided_by = ?, decision_sequence = ?, decision_reason = ? "
            "WHERE object_type = 'acquisition' AND object_id = ?",
            (decision, actor.operator_id, sequence, (reason or "").strip() or None, object_id),
        )


def list_records(project_root: Path) -> list[dict[str, object]]:
    """List authority status for recorded evidential objects."""
    connection = _connect(project_root)
    try:
        _require_authority_tables(connection)
        rows = connection.execute(
            "SELECT object_type, object_id, scope_id, submitted_by, status, submitted_sequence, "
            "decided_by, decision_sequence, decision_reason, archive_sha256 "
            "FROM record_authority ORDER BY submitted_sequence"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()
