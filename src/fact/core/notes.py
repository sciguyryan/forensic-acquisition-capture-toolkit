"""Retain attributable project notes without weakening evidential sanctity.

Project notes are readable by authenticated project members. Confidential notes
are encrypted before they cross the SQLite boundary and are readable only by
their author and the current project owner. Revisions append history; committed
note records are never deleted by normal FACT operations.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from ..errors import ToolkitError
from ..identity import (
    OperatorIdentity,
    decrypt_confidential_payload,
    encrypt_for_project_keys,
)
from .authority import (
    _append_signed,
    _key_row,
    _require_authority_tables,
    current_owner,
    registered_operator_public_key,
    require_registered_operator,
)
from .catalogue import _connect, _write_transaction, issue_identifier

NOTE_PAYLOAD_SCHEMA = "fact-note-payload/v1"


def _payload(title: str, body: str) -> bytes:
    data = {"schema": NOTE_PAYLOAD_SCHEMA, "title": title, "body": body}
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _decode(payload: bytes) -> dict[str, str]:
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolkitError("Note payload is malformed") from exc
    if (
        data.get("schema") != NOTE_PAYLOAD_SCHEMA
        or not isinstance(data.get("title"), str)
        or not isinstance(data.get("body"), str)
    ):
        raise ToolkitError("Note payload has an unsupported schema")
    return {"title": data["title"], "body": data["body"]}


def _project_owner_id(connection: sqlite3.Connection) -> str:
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


def _recipient_keys(project_root: Path, author_id: str, owner_id: str) -> list[str]:
    return [
        registered_operator_public_key(project_root, operator_id)
        for operator_id in dict.fromkeys((author_id, owner_id))
    ]


def create_note(
    project_root: Path,
    actor: OperatorIdentity,
    title: str,
    body: str,
    *,
    visibility: str = "project",
    case_id: str | None = None,
) -> str:
    """Create an immutable first note revision and return its never-reused ID."""
    require_registered_operator(project_root, actor)
    if visibility not in {"project", "confidential"}:
        raise ToolkitError("Note visibility must be 'project' or 'confidential'")
    raw = _payload(title.strip(), body)
    if visibility == "confidential":
        owner_id = str(current_owner(project_root)["owner_id"])
        stored = encrypt_for_project_keys(
            raw, _recipient_keys(project_root, actor.operator_id, owner_id)
        )
    else:
        stored = raw
    note_id = issue_identifier(project_root, "note", "NOTE")
    with _write_transaction(project_root) as connection:
        _require_authority_tables(connection)
        if case_id is not None:
            case = connection.execute(
                "SELECT state FROM identifiers WHERE namespace = 'case' AND identifier = ?",
                (case_id,),
            ).fetchone()
            if case is None:
                raise ToolkitError(f"Unknown FACT case: {case_id}")
        key = _key_row(connection, actor.operator_id)
        digest = hashlib.sha256(stored).hexdigest()
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="NOTE_CREATED",
            object_type="note",
            object_id=note_id,
            data={
                "visibility": visibility,
                "author_id": actor.operator_id,
                "case_id": case_id,
                "revision": 1,
                "payload_sha256": digest,
                "package_disclosure": "withheld",
            },
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "INSERT INTO notes VALUES (?, ?, ?, ?, ?, 1, 'withheld')",
            (note_id, visibility, actor.operator_id, case_id, sequence),
        )
        connection.execute(
            "INSERT INTO note_revisions VALUES (?, 1, ?, ?, ?, ?, NULL)",
            (note_id, stored, digest, sequence, actor.operator_id),
        )
    return note_id


def list_notes(project_root: Path) -> list[dict[str, object]]:
    """List retained note metadata without exposing note bodies."""
    connection = _connect(project_root)
    try:
        return [
            dict(row)
            for row in connection.execute(
                "SELECT note_id, visibility, author_id, case_id, latest_revision, package_disclosure "
                "FROM notes ORDER BY created_sequence, note_id"
            ).fetchall()
        ]
    finally:
        connection.close()


def read_note(
    project_root: Path,
    actor: OperatorIdentity,
    note_id: str,
    *,
    revision: int | None = None,
) -> dict[str, object]:
    """Read one note revision subject to project and confidential access rules."""
    require_registered_operator(project_root, actor)
    connection = _connect(project_root)
    try:
        note = connection.execute(
            "SELECT * FROM notes WHERE note_id = ?", (note_id,)
        ).fetchone()
        if note is None:
            raise ToolkitError(f"Unknown FACT note: {note_id}")
        if note["visibility"] == "confidential":
            owner_id = _project_owner_id(connection)
            if actor.operator_id not in {str(note["author_id"]), owner_id}:
                raise ToolkitError(
                    "Confidential note is restricted to its author and current project owner"
                )
        selected = revision or int(note["latest_revision"])
        row = connection.execute(
            "SELECT * FROM note_revisions WHERE note_id = ? AND revision = ?",
            (note_id, selected),
        ).fetchone()
        if row is None:
            raise ToolkitError(f"Unknown revision {selected} for note {note_id}")
        if row["payload"] is None:
            raise ToolkitError("Note content was withheld from this project package")
        stored = bytes(row["payload"])
        if hashlib.sha256(stored).hexdigest() != row["payload_sha256"]:
            raise ToolkitError("Note payload integrity check failed")
        raw = (
            decrypt_confidential_payload(stored)
            if note["visibility"] == "confidential"
            else stored
        )
        content = _decode(raw)
        return {
            "note_id": note_id,
            "visibility": str(note["visibility"]),
            "author_id": str(note["author_id"]),
            "case_id": note["case_id"],
            "revision": selected,
            "title": content["title"],
            "body": content["body"],
        }
    finally:
        connection.close()


def revise_note(
    project_root: Path,
    actor: OperatorIdentity,
    note_id: str,
    title: str,
    body: str,
    reason: str,
) -> int:
    """Append a note revision; prior revisions remain permanently retained."""
    require_registered_operator(project_root, actor)
    if not reason.strip():
        raise ToolkitError("Note revision requires a reason")
    connection = _connect(project_root)
    try:
        note = connection.execute(
            "SELECT * FROM notes WHERE note_id = ?", (note_id,)
        ).fetchone()
        if note is None:
            raise ToolkitError(f"Unknown FACT note: {note_id}")
        if str(note["author_id"]) != actor.operator_id:
            raise ToolkitError("Only the note author may revise a retained note")
        visibility = str(note["visibility"])
    finally:
        connection.close()
    raw = _payload(title.strip(), body)
    if visibility == "confidential":
        owner_id = str(current_owner(project_root)["owner_id"])
        stored = encrypt_for_project_keys(
            raw, _recipient_keys(project_root, actor.operator_id, owner_id)
        )
    else:
        stored = raw
    with _write_transaction(project_root) as connection:
        note = connection.execute(
            "SELECT * FROM notes WHERE note_id = ?", (note_id,)
        ).fetchone()
        if note is None or str(note["author_id"]) != actor.operator_id:
            raise ToolkitError("Note authority changed while revision was prepared")
        revision = int(note["latest_revision"]) + 1
        digest = hashlib.sha256(stored).hexdigest()
        key = _key_row(connection, actor.operator_id)
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="NOTE_REVISED",
            object_type="note",
            object_id=note_id,
            data={
                "revision": revision,
                "payload_sha256": digest,
                "reason": reason.strip(),
            },
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "INSERT INTO note_revisions VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                note_id,
                revision,
                stored,
                digest,
                sequence,
                actor.operator_id,
                reason.strip(),
            ),
        )
        connection.execute(
            "UPDATE notes SET latest_revision = ? WHERE note_id = ?",
            (revision, note_id),
        )
        return revision


def set_note_disclosure(
    project_root: Path, actor: OperatorIdentity, note_id: str, include: bool
) -> None:
    """Set explicit package disclosure policy; only the project owner may disclose."""
    require_registered_operator(project_root, actor)
    with _write_transaction(project_root) as connection:
        if _project_owner_id(connection) != actor.operator_id:
            raise ToolkitError(
                "Only the current project owner may change note package disclosure"
            )
        note = connection.execute(
            "SELECT note_id FROM notes WHERE note_id = ?", (note_id,)
        ).fetchone()
        if note is None:
            raise ToolkitError(f"Unknown FACT note: {note_id}")
        disclosure = "include" if include else "withheld"
        key = _key_row(connection, actor.operator_id)
        _append_signed(
            connection,
            actor=actor,
            event_type="NOTE_DISCLOSURE_CHANGED",
            object_type="note",
            object_id=note_id,
            data={"package_disclosure": disclosure},
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "UPDATE notes SET package_disclosure = ? WHERE note_id = ?",
            (disclosure, note_id),
        )


def reencrypt_confidential_notes_for_transfer(
    connection: sqlite3.Connection,
    project_root: Path,
    incoming_owner: OperatorIdentity,
) -> dict[str, object]:
    """Append new immutable ciphertext revisions for an incoming project owner.

    Re-encryption never rewrites historical ciphertext. Each confidential note's
    current revision is decrypted in process memory and encrypted for the note
    author and incoming owner. The replacement is appended as a new revision
    inside the caller's ownership-transfer transaction. Any failure rolls back
    every new revision and leaves ownership unchanged.
    """
    rows = connection.execute(
        "SELECT r.note_id, r.revision, r.payload, r.payload_sha256, n.author_id "
        "FROM note_revisions r JOIN notes n ON n.note_id = r.note_id "
        "WHERE n.visibility = 'confidential' AND r.revision = n.latest_revision "
        "ORDER BY r.note_id"
    ).fetchall()
    new_hashes: list[str] = []
    key = _key_row(connection, incoming_owner.operator_id)
    for row in rows:
        if row["payload"] is None:
            raise ToolkitError(
                "Cannot transfer ownership while confidential note content is withheld"
            )
        old_ciphertext = bytes(row["payload"])
        if hashlib.sha256(old_ciphertext).hexdigest() != str(row["payload_sha256"]):
            raise ToolkitError(
                "Confidential note ciphertext failed integrity validation"
            )
        plaintext = decrypt_confidential_payload(old_ciphertext)
        try:
            recipient_ids = tuple(
                dict.fromkeys((str(row["author_id"]), incoming_owner.operator_id))
            )
            public_keys = []
            for operator_id in recipient_ids:
                public_key_row = connection.execute(
                    "SELECT public_key FROM operator_keys "
                    "WHERE operator_id = ? AND state = 'active'",
                    (operator_id,),
                ).fetchone()
                if public_key_row is None:
                    raise ToolkitError(
                        f"No active encryption key is retained for operator: {operator_id}"
                    )
                public_keys.append(str(public_key_row[0]))
            replacement = encrypt_for_project_keys(plaintext, public_keys)
            if decrypt_confidential_payload(replacement) != plaintext:
                raise ToolkitError(
                    "Replacement confidential-note ciphertext failed verification"
                )
        finally:
            plaintext = b""
        digest = hashlib.sha256(replacement).hexdigest()
        revision = int(row["revision"]) + 1
        reason = "Cryptographic re-encryption following project ownership transfer"
        sequence = _append_signed(
            connection,
            actor=incoming_owner,
            event_type="NOTE_REENCRYPTED",
            object_type="note",
            object_id=str(row["note_id"]),
            data={
                "revision": revision,
                "payload_sha256": digest,
                "reason": reason,
            },
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "INSERT INTO note_revisions VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                row["note_id"],
                revision,
                replacement,
                digest,
                sequence,
                incoming_owner.operator_id,
                reason,
            ),
        )
        connection.execute(
            "UPDATE notes SET latest_revision = ? WHERE note_id = ?",
            (revision, row["note_id"]),
        )
        new_hashes.append(f"{row['note_id']}:{revision}:{digest}")
    aggregate = hashlib.sha256("\n".join(new_hashes).encode("ascii")).hexdigest()
    return {
        "confidential_revision_count": len(rows),
        "confidential_ciphertext_digest": aggregate,
    }
