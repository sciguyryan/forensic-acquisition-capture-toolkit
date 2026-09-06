"""Transfer confidential-material authority without rewriting provenance.

Authorship and creation provenance never move. The project owner alone may
propose reassignment of current confidential authority, and the incoming active
operator must explicitly accept before any authority changes. Cryptographic
material is transitioned before the authority table is advanced.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from ..errors import ToolkitError
from ..identity import OperatorIdentity
from .authority import _append_signed, _key_row, require_registered_operator
from .catalogue import _connect, _write_transaction, issue_identifier
from .notes import reencrypt_confidential_notes_for_authority_transfer

_SUPPORTED_TYPES = {"note", "file", "artefact"}


def _project_id(connection) -> str:
    return str(
        connection.execute(
            "SELECT value FROM metadata WHERE key = 'project_id'"
        ).fetchone()[0]
    )


def _owner_id(connection) -> str:
    project_id = _project_id(connection)
    row = connection.execute(
        "SELECT owner_id FROM ownership WHERE scope_type = 'project' AND scope_id = ?",
        (project_id,),
    ).fetchone()
    if row is None:
        raise ToolkitError("Project has no current owner")
    return str(row["owner_id"])


def _normalise_scope(objects: list[str]) -> list[dict[str, str]]:
    scope: list[dict[str, str]] = []
    seen: set[str] = set()
    for value in objects:
        token = value.strip()
        if not token or token in seen:
            continue
        seen.add(token)
        if token.startswith("NOTE-"):
            object_type = "note"
        elif token.startswith("FILE-"):
            object_type = "file"
        elif token.startswith("ART-"):
            object_type = "artefact"
        else:
            raise ToolkitError(f"Unsupported confidential authority object ID: {token}")
        scope.append({"object_type": object_type, "object_id": token})
    if not scope:
        raise ToolkitError(
            "Confidential authority transfer requires at least one object"
        )
    return scope


def propose_confidential_authority_transfer(
    project_root: Path,
    actor: OperatorIdentity,
    *,
    from_operator_id: str,
    to_operator_id: str,
    objects: list[str],
    reason: str,
) -> str:
    """Propose an owner-controlled transfer that requires incoming acceptance."""

    require_registered_operator(project_root, actor)
    if not reason.strip():
        raise ToolkitError("Confidential authority transfer requires a reason")
    if from_operator_id == to_operator_id:
        raise ToolkitError(
            "Confidential authority transfer requires different operators"
        )
    scope = _normalise_scope(objects)
    transfer_id = issue_identifier(project_root, "authority_transfer", "TRANSFER")
    with _write_transaction(project_root) as connection:
        if _owner_id(connection) != actor.operator_id:
            raise ToolkitError(
                "Only the current project owner may propose confidential authority transfer"
            )
        target = connection.execute(
            "SELECT state FROM project_memberships WHERE operator_id = ?",
            (to_operator_id,),
        ).fetchone()
        if target is None or str(target["state"]) != "active":
            raise ToolkitError(
                "Incoming confidential authority must be an active project member"
            )
        for item in scope:
            row = connection.execute(
                "SELECT authority_id FROM confidential_authority "
                "WHERE object_type = ? AND object_id = ?",
                (item["object_type"], item["object_id"]),
            ).fetchone()
            if row is None:
                raise ToolkitError(
                    f"No confidential authority exists for {item['object_id']}"
                )
            if str(row["authority_id"]) != from_operator_id:
                raise ToolkitError(
                    f"{item['object_id']} is not currently controlled by {from_operator_id}"
                )
        existing = connection.execute(
            "SELECT transfer_id FROM confidential_authority_transfers "
            "WHERE state = 'pending' AND (from_operator_id = ? OR to_operator_id = ?)",
            (from_operator_id, to_operator_id),
        ).fetchone()
        if existing is not None:
            raise ToolkitError(
                f"A related confidential authority transfer is already pending: {existing['transfer_id']}"
            )
        key = _key_row(connection, actor.operator_id)
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="CONFIDENTIAL_AUTHORITY_TRANSFER_PROPOSED",
            object_type="authority_transfer",
            object_id=transfer_id,
            data={
                "from_operator_id": from_operator_id,
                "to_operator_id": to_operator_id,
                "scope": scope,
                "reason": reason.strip(),
            },
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "INSERT INTO confidential_authority_transfers(transfer_id, from_operator_id, "
            "to_operator_id, scope_json, state, reason, proposed_sequence, resolved_sequence) "
            "VALUES (?, ?, ?, ?, 'pending', ?, ?, NULL)",
            (
                transfer_id,
                from_operator_id,
                to_operator_id,
                json.dumps(scope, sort_keys=True, separators=(",", ":")),
                reason.strip(),
                sequence,
            ),
        )
    return transfer_id


def _pending_transfer(connection, transfer_id: str):
    row = connection.execute(
        "SELECT * FROM confidential_authority_transfers WHERE transfer_id = ?",
        (transfer_id,),
    ).fetchone()
    if row is None:
        raise ToolkitError(f"Unknown confidential authority transfer: {transfer_id}")
    if str(row["state"]) != "pending":
        raise ToolkitError(
            f"Confidential authority transfer is already {row['state']}: {transfer_id}"
        )
    return row


def accept_confidential_authority_transfer(
    project_root: Path, actor: OperatorIdentity, transfer_id: str
) -> str:
    """Accept and atomically complete a pending confidential authority transfer."""

    require_registered_operator(project_root, actor)
    created_directories: list[Path] = []
    try:
        with _write_transaction(project_root) as connection:
            transfer = _pending_transfer(connection, transfer_id)
            if str(transfer["to_operator_id"]) != actor.operator_id:
                raise ToolkitError(
                    "Only the nominated incoming operator may accept this transfer"
                )
            scope = json.loads(str(transfer["scope_json"]))
            if not isinstance(scope, list):
                raise ToolkitError("Confidential authority transfer scope is malformed")
            for item in scope:
                if (
                    not isinstance(item, dict)
                    or item.get("object_type") not in _SUPPORTED_TYPES
                ):
                    raise ToolkitError(
                        "Confidential authority transfer scope is malformed"
                    )
                live = connection.execute(
                    "SELECT authority_id FROM confidential_authority "
                    "WHERE object_type = ? AND object_id = ?",
                    (item["object_type"], item["object_id"]),
                ).fetchone()
                if live is None or str(live["authority_id"]) != str(
                    transfer["from_operator_id"]
                ):
                    raise ToolkitError(
                        "Confidential authority changed while the transfer was pending"
                    )

            # Generic encrypted artefact/file payloads do not yet exist in FACT.
            # Refuse to pretend they can be re-keyed until a payload-specific
            # cryptographic transition is implemented.
            unsupported = [
                str(item["object_id"])
                for item in scope
                if item["object_type"] in {"file", "artefact"}
            ]
            if unsupported:
                raise ToolkitError(
                    "Cryptographic authority transfer is not yet implemented for: "
                    + ", ".join(unsupported)
                )

            note_ids = [
                str(item["object_id"])
                for item in scope
                if item["object_type"] == "note"
            ]
            crypto = reencrypt_confidential_notes_for_authority_transfer(
                connection,
                project_root,
                actor,
                note_ids,
                _owner_id(connection),
            )
            created_directories.extend(crypto.pop("_created_file_directories", []))
            key = _key_row(connection, actor.operator_id)
            sequence = _append_signed(
                connection,
                actor=actor,
                event_type="CONFIDENTIAL_AUTHORITY_TRANSFER_ACCEPTED",
                object_type="authority_transfer",
                object_id=transfer_id,
                data={
                    "from_operator_id": str(transfer["from_operator_id"]),
                    "to_operator_id": actor.operator_id,
                    "scope": scope,
                    "cryptographic_transition": crypto,
                },
                verification_key=str(key["public_key"]),
            )
            for item in scope:
                connection.execute(
                    "UPDATE confidential_authority SET authority_id = ?, effective_sequence = ? "
                    "WHERE object_type = ? AND object_id = ?",
                    (
                        actor.operator_id,
                        sequence,
                        item["object_type"],
                        item["object_id"],
                    ),
                )
            connection.execute(
                "UPDATE confidential_authority_transfers SET state = 'accepted', "
                "resolved_sequence = ? WHERE transfer_id = ?",
                (sequence, transfer_id),
            )
        return transfer_id
    except Exception:
        for directory in reversed(created_directories):
            shutil.rmtree(directory, ignore_errors=True)
        raise


def reject_confidential_authority_transfer(
    project_root: Path, actor: OperatorIdentity, transfer_id: str, reason: str
) -> str:
    """Reject a proposed transfer as the nominated incoming operator."""

    require_registered_operator(project_root, actor)
    if not reason.strip():
        raise ToolkitError("Rejecting a transfer requires a reason")
    with _write_transaction(project_root) as connection:
        transfer = _pending_transfer(connection, transfer_id)
        if str(transfer["to_operator_id"]) != actor.operator_id:
            raise ToolkitError(
                "Only the nominated incoming operator may reject this transfer"
            )
        key = _key_row(connection, actor.operator_id)
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="CONFIDENTIAL_AUTHORITY_TRANSFER_REJECTED",
            object_type="authority_transfer",
            object_id=transfer_id,
            data={"reason": reason.strip()},
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "UPDATE confidential_authority_transfers SET state = 'rejected', "
            "resolved_sequence = ? WHERE transfer_id = ?",
            (sequence, transfer_id),
        )
    return transfer_id


def cancel_confidential_authority_transfer(
    project_root: Path, actor: OperatorIdentity, transfer_id: str, reason: str
) -> str:
    """Cancel a pending transfer; only the current project owner may do so."""

    require_registered_operator(project_root, actor)
    if not reason.strip():
        raise ToolkitError("Cancelling a transfer requires a reason")
    with _write_transaction(project_root) as connection:
        _pending_transfer(connection, transfer_id)
        if _owner_id(connection) != actor.operator_id:
            raise ToolkitError(
                "Only the current project owner may cancel this transfer"
            )
        key = _key_row(connection, actor.operator_id)
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="CONFIDENTIAL_AUTHORITY_TRANSFER_CANCELLED",
            object_type="authority_transfer",
            object_id=transfer_id,
            data={"reason": reason.strip()},
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "UPDATE confidential_authority_transfers SET state = 'cancelled', "
            "resolved_sequence = ? WHERE transfer_id = ?",
            (sequence, transfer_id),
        )
    return transfer_id


def list_confidential_authority_transfers(
    project_root: Path,
) -> list[dict[str, object]]:
    """List retained authority-transfer history without exposing ciphertext."""

    connection = _connect(project_root)
    try:
        rows = connection.execute(
            "SELECT * FROM confidential_authority_transfers "
            "ORDER BY proposed_sequence, transfer_id"
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["scope"] = json.loads(str(item.pop("scope_json")))
            result.append(item)
        return result
    finally:
        connection.close()
