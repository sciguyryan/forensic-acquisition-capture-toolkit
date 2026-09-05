"""Retain attributable notes as ordinary immutable FACT files.

A note has a stable ``NOTE-######`` identity, but its content is not a mutable
SQLite payload. Every semantic or cryptographic revision is a separately
checked-in ``FILE-######`` object with its own immutable bytes, hash, provenance
and storage location. The note tables retain only the logical note lineage and
point each revision at the corresponding committed file.

Project notes are readable by authenticated project members. Confidential note
revision files contain ciphertext only and are readable by the note author and
the current project owner. Re-encryption appends another file-backed revision;
it never rewrites historical ciphertext.
"""

from __future__ import annotations

import hashlib
import json
import shutil
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
from .catalogue import _append_event, _connect, _write_transaction, issue_identifier
from .files import (
    FilePayloadCandidate,
    _commit_prepared,
    _prepare_payload_candidates,
    commit_payload_files,
)

NOTE_PAYLOAD_SCHEMA = "fact-note-payload/v1"
NOTE_MEDIA_TYPE = "application/vnd.fact.note+json"
CONFIDENTIAL_NOTE_MEDIA_TYPE = "application/pgp-encrypted"


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


def _revision_candidate(
    note_id: str,
    revision: int,
    stored: bytes,
    visibility: str,
) -> FilePayloadCandidate:
    confidential = visibility == "confidential"
    suffix = ".json.gpg" if confidential else ".json"
    return FilePayloadCandidate(
        stored,
        f"notes/{note_id}/revision-{revision:06d}{suffix}",
        "confidential-note-revision" if confidential else "note-revision",
        CONFIDENTIAL_NOTE_MEDIA_TYPE if confidential else NOTE_MEDIA_TYPE,
        f"Immutable revision {revision} of {note_id}",
    )


def _read_revision_bytes(
    connection: sqlite3.Connection,
    project_root: Path,
    file_id: str,
) -> bytes:
    row = connection.execute(
        "SELECT sha256, size_bytes, storage_path FROM files WHERE file_id = ?", (file_id,)
    ).fetchone()
    if row is None:
        raise ToolkitError(f"Note revision refers to an unknown committed file: {file_id}")
    path = project_root / str(row["storage_path"])
    if path.is_symlink() or not path.is_file():
        raise ToolkitError(f"Committed note revision file is missing: {file_id}")
    stored = path.read_bytes()
    if len(stored) != int(row["size_bytes"]) or hashlib.sha256(stored).hexdigest() != str(
        row["sha256"]
    ):
        raise ToolkitError(f"Note revision file integrity check failed: {file_id}")
    return stored


def _validate_subject_file(
    connection: sqlite3.Connection,
    subject_file_id: str | None,
    case_id: str | None,
) -> None:
    if subject_file_id is None:
        return
    row = connection.execute(
        "SELECT case_id FROM files WHERE file_id = ?", (subject_file_id,)
    ).fetchone()
    if row is None:
        raise ToolkitError(f"Unknown FACT file: {subject_file_id}")
    subject_case = row["case_id"]
    if case_id is not None and subject_case not in {None, case_id}:
        raise ToolkitError("A case note cannot target a file from another case")


def _link_note_file(
    connection: sqlite3.Connection,
    *,
    subject_file_id: str | None,
    revision_file_id: str,
) -> None:
    if subject_file_id is None:
        return
    _append_event(
        connection,
        "FILE_RELATIONSHIP_ADDED",
        "file",
        revision_file_id,
        {"parent_file_id": subject_file_id, "relationship": "note-about"},
    )
    sequence = connection.execute("SELECT MAX(event_sequence) FROM audit_events").fetchone()[0]
    connection.execute(
        "INSERT INTO file_relationships VALUES (?, ?, 'note-about', ?)",
        (subject_file_id, revision_file_id, sequence),
    )


def create_note(
    project_root: Path,
    actor: OperatorIdentity,
    title: str,
    body: str,
    *,
    visibility: str = "project",
    case_id: str | None = None,
    subject_file_id: str | None = None,
) -> str:
    """Create a note whose first revision is an ordinary committed FACT file."""

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
    digest = hashlib.sha256(stored).hexdigest()

    def mutation(connection, committed: list[dict[str, object]]) -> None:
        _require_authority_tables(connection)
        _validate_subject_file(connection, subject_file_id, case_id)
        revision_file_id = str(committed[0]["file_id"])
        key = _key_row(connection, actor.operator_id)
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
                "subject_file_id": subject_file_id,
                "revision": 1,
                "revision_type": "content",
                "file_id": revision_file_id,
                "payload_sha256": digest,
                "package_disclosure": "withheld",
            },
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "INSERT INTO notes(note_id, visibility, author_id, case_id, subject_file_id, "
            "created_sequence, latest_revision, package_disclosure) "
            "VALUES (?, ?, ?, ?, ?, ?, 1, 'withheld')",
            (note_id, visibility, actor.operator_id, case_id, subject_file_id, sequence),
        )
        connection.execute(
            "INSERT INTO note_revisions(note_id, revision, file_id, revision_type, "
            "created_sequence, revised_by, reason) VALUES (?, 1, ?, 'content', ?, ?, NULL)",
            (note_id, revision_file_id, sequence, actor.operator_id),
        )
        _link_note_file(
            connection,
            subject_file_id=subject_file_id,
            revision_file_id=revision_file_id,
        )

    commit_payload_files(
        project_root,
        case_id=case_id,
        acquisition_id=None,
        actor_id=actor.operator_id,
        candidates=[_revision_candidate(note_id, 1, stored, visibility)],
        mutation=mutation,
    )
    return note_id


def list_notes(project_root: Path) -> list[dict[str, object]]:
    """List retained note metadata without exposing note bodies."""

    connection = _connect(project_root)
    try:
        return [
            dict(row)
            for row in connection.execute(
                "SELECT note_id, visibility, author_id, case_id, subject_file_id, "
                "latest_revision, package_disclosure FROM notes "
                "ORDER BY created_sequence, note_id"
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
    """Read one file-backed note revision subject to its access rules."""

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
        stored = _read_revision_bytes(connection, project_root, str(row["file_id"]))
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
            "subject_file_id": note["subject_file_id"],
            "revision": selected,
            "revision_type": str(row["revision_type"]),
            "file_id": str(row["file_id"]),
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
    """Append a semantic note revision as another immutable committed file."""

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
        case_id = note["case_id"]
        subject_file_id = note["subject_file_id"]
        revision = int(note["latest_revision"]) + 1
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
    digest = hashlib.sha256(stored).hexdigest()

    def mutation(connection, committed: list[dict[str, object]]) -> int:
        live = connection.execute(
            "SELECT * FROM notes WHERE note_id = ?", (note_id,)
        ).fetchone()
        if (
            live is None
            or str(live["author_id"]) != actor.operator_id
            or int(live["latest_revision"]) + 1 != revision
        ):
            raise ToolkitError("Note authority or revision state changed while revision was prepared")
        revision_file_id = str(committed[0]["file_id"])
        key = _key_row(connection, actor.operator_id)
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="NOTE_REVISED",
            object_type="note",
            object_id=note_id,
            data={
                "revision": revision,
                "revision_type": "content",
                "file_id": revision_file_id,
                "payload_sha256": digest,
                "reason": reason.strip(),
            },
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "INSERT INTO note_revisions(note_id, revision, file_id, revision_type, "
            "created_sequence, revised_by, reason) VALUES (?, ?, ?, 'content', ?, ?, ?)",
            (
                note_id,
                revision,
                revision_file_id,
                sequence,
                actor.operator_id,
                reason.strip(),
            ),
        )
        connection.execute(
            "UPDATE notes SET latest_revision = ? WHERE note_id = ?", (revision, note_id)
        )
        _link_note_file(
            connection,
            subject_file_id=subject_file_id,
            revision_file_id=revision_file_id,
        )
        return revision

    _, result = commit_payload_files(
        project_root,
        case_id=case_id,
        acquisition_id=None,
        actor_id=actor.operator_id,
        candidates=[_revision_candidate(note_id, revision, stored, visibility)],
        mutation=mutation,
    )
    assert result is not None
    return result


def set_note_disclosure(
    project_root: Path,
    actor: OperatorIdentity,
    note_id: str,
    include: bool,
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
    """Append file-backed cryptographic revisions for an incoming project owner.

    All affected note ciphertext is prepared first. Only after every current
    confidential revision has decrypted, re-encrypted and round-trip validated
    are the new files moved into the authoritative tree and related note
    revisions appended to the caller's ownership-transfer transaction.
    """

    rows = connection.execute(
        "SELECT r.note_id, r.revision, r.file_id, n.author_id, n.case_id, "
        "n.subject_file_id FROM note_revisions r JOIN notes n ON n.note_id = r.note_id "
        "WHERE n.visibility = 'confidential' AND r.revision = n.latest_revision "
        "ORDER BY r.note_id"
    ).fetchall()
    key = _key_row(connection, incoming_owner.operator_id)
    staged: list[tuple[sqlite3.Row, bytes, str]] = []
    for row in rows:
        old_ciphertext = _read_revision_bytes(connection, project_root, str(row["file_id"]))
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
        staged.append((row, replacement, hashlib.sha256(replacement).hexdigest()))

    created_directories: list[Path] = []
    transfer_roots: list[Path] = []
    prepared_revisions = []
    new_hashes: list[str] = []
    try:
        # Prepare every replacement beneath private staging before moving any of
        # them into the authoritative file tree. This keeps ownership transfer
        # genuinely all-or-nothing in evidential meaning.
        for row, replacement, digest in staged:
            revision = int(row["revision"]) + 1
            transfer_root, prepared = _prepare_payload_candidates(
                project_root,
                [
                    _revision_candidate(
                        str(row["note_id"]), revision, replacement, "confidential"
                    )
                ],
            )
            transfer_roots.append(transfer_root)
            prepared_revisions.append((row, digest, revision, prepared))

        for row, digest, revision, prepared in prepared_revisions:
            committed, created = _commit_prepared(
                connection,
                project_root,
                case_id=row["case_id"],
                acquisition_id=None,
                actor_id=incoming_owner.operator_id,
                prepared=prepared,
            )
            created_directories.extend(created)
            revision_file_id = str(committed[0]["file_id"])
            reason = "Cryptographic re-encryption following project ownership transfer"
            sequence = _append_signed(
                connection,
                actor=incoming_owner,
                event_type="NOTE_REENCRYPTED",
                object_type="note",
                object_id=str(row["note_id"]),
                data={
                    "revision": revision,
                    "revision_type": "cryptographic",
                    "file_id": revision_file_id,
                    "payload_sha256": digest,
                    "reason": reason,
                },
                verification_key=str(key["public_key"]),
            )
            connection.execute(
                "INSERT INTO note_revisions(note_id, revision, file_id, revision_type, "
                "created_sequence, revised_by, reason) "
                "VALUES (?, ?, ?, 'cryptographic', ?, ?, ?)",
                (
                    row["note_id"],
                    revision,
                    revision_file_id,
                    sequence,
                    incoming_owner.operator_id,
                    reason,
                ),
            )
            connection.execute(
                "UPDATE notes SET latest_revision = ? WHERE note_id = ?",
                (revision, row["note_id"]),
            )
            _link_note_file(
                connection,
                subject_file_id=row["subject_file_id"],
                revision_file_id=revision_file_id,
            )
            new_hashes.append(f"{row['note_id']}:{revision}:{revision_file_id}:{digest}")
    except Exception:
        for directory in reversed(created_directories):
            shutil.rmtree(directory, ignore_errors=True)
        raise
    finally:
        for transfer_root in transfer_roots:
            shutil.rmtree(transfer_root, ignore_errors=True)

    aggregate = hashlib.sha256("\n".join(new_hashes).encode("ascii")).hexdigest()
    return {
        "confidential_revision_count": len(rows),
        "confidential_ciphertext_digest": aggregate,
        "_created_file_directories": created_directories,
    }
