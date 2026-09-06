"""Project-owned export policy and confidential disclosure authority.

Export authority is catalogue state rather than a CLI convention. Policy
changes are signed append-only events, allowing a later export to identify the
exact rules that were in force when disclosure occurred.
"""

from __future__ import annotations

from pathlib import Path

from ..errors import ToolkitError
from ..identity import OperatorIdentity
from .authority import _append_signed, _key_row, require_registered_operator
from .catalogue import _connect, _write_transaction

POLICY_FIELDS = {
    "ordinary_export": {"owner", "members"},
    "ciphertext_export": {"owner", "members"},
    "confidential_plaintext_export": {"owner", "authority"},
    "broad_scope_export": {"owner", "members"},
}


def get_export_policy(project_root: Path) -> dict[str, object]:
    """Return the current authenticated project export policy."""

    connection = _connect(project_root)
    try:
        row = connection.execute(
            "SELECT * FROM export_policy WHERE policy_id = 'project'"
        ).fetchone()
        if row is None:
            raise ToolkitError("Project export policy is missing")
        return dict(row)
    finally:
        connection.close()


def set_export_policy(
    project_root: Path,
    actor: OperatorIdentity,
    **changes: str,
) -> dict[str, object]:
    """Replace selected export-policy fields; only the project owner may do so."""

    require_registered_operator(project_root, actor)
    unknown = set(changes) - set(POLICY_FIELDS)
    if unknown:
        raise ToolkitError("Unknown export policy field: " + ", ".join(sorted(unknown)))
    for field, value in changes.items():
        if value not in POLICY_FIELDS[field]:
            raise ToolkitError(f"Unsupported {field} policy value: {value}")

    with _write_transaction(project_root) as connection:
        project_id = str(
            connection.execute(
                "SELECT value FROM metadata WHERE key = 'project_id'"
            ).fetchone()[0]
        )
        owner = connection.execute(
            "SELECT owner_id FROM ownership WHERE scope_type = 'project' AND scope_id = ?",
            (project_id,),
        ).fetchone()
        if owner is None or str(owner["owner_id"]) != actor.operator_id:
            raise ToolkitError(
                "Only the current project owner may change export policy"
            )
        current_row = connection.execute(
            "SELECT * FROM export_policy WHERE policy_id = 'project'"
        ).fetchone()
        if current_row is None:
            raise ToolkitError("Project export policy is missing")
        current = dict(current_row)
        updated = {field: str(current[field]) for field in POLICY_FIELDS}
        updated.update(changes)
        key = _key_row(connection, actor.operator_id)
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="EXPORT_POLICY_CHANGED",
            object_type="project",
            object_id=project_id,
            data={
                "previous": {field: current[field] for field in POLICY_FIELDS},
                "policy": updated,
            },
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "UPDATE export_policy SET ordinary_export = ?, ciphertext_export = ?, "
            "confidential_plaintext_export = ?, broad_scope_export = ?, updated_sequence = ? "
            "WHERE policy_id = 'project'",
            (
                updated["ordinary_export"],
                updated["ciphertext_export"],
                updated["confidential_plaintext_export"],
                updated["broad_scope_export"],
                sequence,
            ),
        )
        return {**updated, "updated_sequence": sequence, "policy_id": "project"}


def _project_owner_id(connection) -> str:
    project_id = str(
        connection.execute(
            "SELECT value FROM metadata WHERE key = 'project_id'"
        ).fetchone()[0]
    )
    row = connection.execute(
        "SELECT owner_id FROM ownership WHERE scope_type = 'project' AND scope_id = ?",
        (project_id,),
    ).fetchone()
    if row is None:
        raise ToolkitError("Project has no current owner")
    return str(row["owner_id"])


def require_export_authority(
    project_root: Path,
    actor: OperatorIdentity,
    *,
    broad_scope: bool,
    ciphertext_only: bool = False,
) -> dict[str, object]:
    """Require ordinary/ciphertext export authority under the current policy."""

    require_registered_operator(project_root, actor)
    connection = _connect(project_root)
    try:
        policy_row = connection.execute(
            "SELECT * FROM export_policy WHERE policy_id = 'project'"
        ).fetchone()
        if policy_row is None:
            raise ToolkitError("Project export policy is missing")
        owner_id = _project_owner_id(connection)
        field = (
            "broad_scope_export"
            if broad_scope
            else "ciphertext_export"
            if ciphertext_only
            else "ordinary_export"
        )
        required = str(policy_row[field])
        if required == "owner" and actor.operator_id != owner_id:
            raise ToolkitError(
                f"Project export policy reserves {field.replace('_', ' ')} to the owner"
            )
        return dict(policy_row)
    finally:
        connection.close()


def confidential_authority(
    project_root: Path, object_type: str, object_id: str
) -> dict[str, object]:
    """Return current confidential authority for a retained object."""

    connection = _connect(project_root)
    try:
        row = connection.execute(
            "SELECT * FROM confidential_authority WHERE object_type = ? AND object_id = ?",
            (object_type, object_id),
        ).fetchone()
        if row is None:
            raise ToolkitError(
                f"No confidential authority is recorded for {object_type} {object_id}"
            )
        return dict(row)
    finally:
        connection.close()


def require_confidential_plaintext_authority(
    project_root: Path,
    actor: OperatorIdentity,
    *,
    object_type: str,
    object_id: str,
) -> dict[str, object]:
    """Require project-owner or current object authority for plaintext export."""

    require_registered_operator(project_root, actor)
    connection = _connect(project_root)
    try:
        policy = connection.execute(
            "SELECT * FROM export_policy WHERE policy_id = 'project'"
        ).fetchone()
        if policy is None:
            raise ToolkitError("Project export policy is missing")
        owner_id = _project_owner_id(connection)
        authority = connection.execute(
            "SELECT * FROM confidential_authority WHERE object_type = ? AND object_id = ?",
            (object_type, object_id),
        ).fetchone()
        if authority is None:
            raise ToolkitError(
                f"No confidential authority is recorded for {object_type} {object_id}"
            )
        rule = str(policy["confidential_plaintext_export"])
        allowed = actor.operator_id == owner_id
        if rule == "authority":
            allowed = allowed or actor.operator_id == str(authority["authority_id"])
        if not allowed:
            raise ToolkitError(
                "Plaintext confidential export requires the current project owner "
                "or the object's current confidential authority"
            )
        return {
            "policy": dict(policy),
            "authority": dict(authority),
            "owner_id": owner_id,
        }
    finally:
        connection.close()
