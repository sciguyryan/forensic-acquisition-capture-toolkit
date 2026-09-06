"""Authenticated, provenance-aware access state for confidential FACT objects.

Cryptographic possession is never treated as sufficient authority.  FACT first
resolves the current authenticated access state for the stable operator identity
and confidential object.  Access may have several independent authority bases;
revoking one basis therefore does not erase another surviving grant.

This module establishes the authority model only.  The existing confidential
note ciphertext format remains in place until the later envelope-encryption
phase selects and implements reviewed cryptographic primitives.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from ..errors import ToolkitError
from ..identity import OperatorIdentity
from .authority import _append_signed, _key_row

SUPPORTED_OBJECT_TYPES = {"file", "note", "artefact"}
SUPPORTED_AUTHORITY_BASES = {
    "object-owner",
    "explicit-grant",
    "project-owner",
    "case-role",
    "recovery-authority",
    "system-policy",
}


@dataclass(frozen=True)
class EffectiveConfidentialAccess:
    """Current access decision and the independently surviving grant bases."""

    operator_id: str
    object_type: str
    object_id: str
    authority_bases: tuple[str, ...]

    @property
    def allowed(self) -> bool:
        return bool(self.authority_bases)


def _validate(object_type: str, authority_basis: str) -> None:
    if object_type not in SUPPORTED_OBJECT_TYPES:
        raise ToolkitError(f"Unsupported confidential object type: {object_type}")
    if authority_basis not in SUPPORTED_AUTHORITY_BASES:
        raise ToolkitError(
            f"Unsupported confidential authority basis: {authority_basis}"
        )


def effective_access(
    connection: sqlite3.Connection,
    operator_id: str,
    object_type: str,
    object_id: str,
) -> EffectiveConfidentialAccess:
    """Resolve access from all active authenticated grant bases."""

    rows = connection.execute(
        "SELECT authority_basis FROM confidential_access_grants "
        "WHERE operator_id = ? AND object_type = ? AND object_id = ? "
        "AND revoked_sequence IS NULL ORDER BY granted_sequence, authority_basis",
        (operator_id, object_type, object_id),
    ).fetchall()
    return EffectiveConfidentialAccess(
        operator_id,
        object_type,
        object_id,
        tuple(str(row["authority_basis"]) for row in rows),
    )


def require_confidential_access(
    connection: sqlite3.Connection,
    operator_id: str,
    object_type: str,
    object_id: str,
) -> EffectiveConfidentialAccess:
    """Fail closed unless at least one current authority basis survives."""

    access = effective_access(connection, operator_id, object_type, object_id)
    if not access.allowed:
        raise ToolkitError(
            "Confidential object is restricted: current authenticated authority does not permit access"
        )
    return access


def grant_access(
    connection: sqlite3.Connection,
    actor: OperatorIdentity,
    *,
    operator_id: str,
    object_type: str,
    object_id: str,
    authority_basis: str,
    reason: str,
) -> int:
    """Append an independently revocable confidential-access grant."""

    _validate(object_type, authority_basis)
    if not reason.strip():
        raise ToolkitError("Confidential access grant requires a reason")
    existing = connection.execute(
        "SELECT 1 FROM confidential_access_grants WHERE operator_id = ? "
        "AND object_type = ? AND object_id = ? AND authority_basis = ? "
        "AND revoked_sequence IS NULL",
        (operator_id, object_type, object_id, authority_basis),
    ).fetchone()
    if existing is not None:
        return -1
    key = _key_row(connection, actor.operator_id)
    sequence = _append_signed(
        connection,
        actor=actor,
        event_type="CONFIDENTIAL_ACCESS_GRANTED",
        object_type=object_type,
        object_id=object_id,
        data={
            "operator_id": operator_id,
            "authority_basis": authority_basis,
            "reason": reason.strip(),
        },
        verification_key=str(key["public_key"]),
    )
    connection.execute(
        "INSERT INTO confidential_access_grants(operator_id, object_type, object_id, "
        "authority_basis, granted_sequence, revoked_sequence, grant_reason, revoke_reason) "
        "VALUES (?, ?, ?, ?, ?, NULL, ?, NULL)",
        (
            operator_id,
            object_type,
            object_id,
            authority_basis,
            sequence,
            reason.strip(),
        ),
    )
    return sequence


def revoke_access_basis(
    connection: sqlite3.Connection,
    actor: OperatorIdentity,
    *,
    operator_id: str,
    object_type: str,
    object_id: str,
    authority_basis: str,
    reason: str,
) -> int:
    """Revoke one authority basis without disturbing any surviving basis."""

    _validate(object_type, authority_basis)
    if not reason.strip():
        raise ToolkitError("Confidential access revocation requires a reason")
    row = connection.execute(
        "SELECT granted_sequence FROM confidential_access_grants WHERE operator_id = ? "
        "AND object_type = ? AND object_id = ? AND authority_basis = ? "
        "AND revoked_sequence IS NULL ORDER BY granted_sequence DESC LIMIT 1",
        (operator_id, object_type, object_id, authority_basis),
    ).fetchone()
    if row is None:
        return -1
    key = _key_row(connection, actor.operator_id)
    sequence = _append_signed(
        connection,
        actor=actor,
        event_type="CONFIDENTIAL_ACCESS_REVOKED",
        object_type=object_type,
        object_id=object_id,
        data={
            "operator_id": operator_id,
            "authority_basis": authority_basis,
            "granted_sequence": int(row["granted_sequence"]),
            "reason": reason.strip(),
        },
        verification_key=str(key["public_key"]),
    )
    connection.execute(
        "UPDATE confidential_access_grants SET revoked_sequence = ?, revoke_reason = ? "
        "WHERE operator_id = ? AND object_type = ? AND object_id = ? "
        "AND authority_basis = ? AND granted_sequence = ?",
        (
            sequence,
            reason.strip(),
            operator_id,
            object_type,
            object_id,
            authority_basis,
            int(row["granted_sequence"]),
        ),
    )
    return sequence


def transition_project_owner_access(
    connection: sqlite3.Connection,
    actor: OperatorIdentity,
    *,
    outgoing_owner_id: str,
    incoming_owner_id: str,
) -> dict[str, int]:
    """Apply only the project-owner grant consequences of ownership transfer.

    Direct object ownership, explicit grants and every other independent basis
    remain untouched.  This is intentionally separate from cryptographic
    re-encryption so the historical reason for each access decision is visible.
    """

    objects = connection.execute(
        "SELECT object_type, object_id FROM confidential_authority "
        "ORDER BY object_type, object_id"
    ).fetchall()
    revoked = 0
    granted = 0
    for row in objects:
        object_type = str(row["object_type"])
        object_id = str(row["object_id"])
        result = revoke_access_basis(
            connection,
            actor,
            operator_id=outgoing_owner_id,
            object_type=object_type,
            object_id=object_id,
            authority_basis="project-owner",
            reason="Project ownership transferred to another operator",
        )
        revoked += int(result >= 0)
        result = grant_access(
            connection,
            actor,
            operator_id=incoming_owner_id,
            object_type=object_type,
            object_id=object_id,
            authority_basis="project-owner",
            reason="Operator became the current project owner",
        )
        granted += int(result >= 0)
    return {
        "project_owner_grants_revoked": revoked,
        "project_owner_grants_added": granted,
    }
