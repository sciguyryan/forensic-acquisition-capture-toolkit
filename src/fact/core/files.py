"""Commit immutable files into the authoritative FACT evidence tree.

FACT treats every retained evidential payload as a file. Producers may create
material in mutable staging, but a payload becomes authoritative only when FACT
assigns a never-reused ``FILE-######`` identifier, stores its exact bytes in the
project tree, hashes those bytes, and records the check-in in the catalogue and
rolling audit chain.

Project-scoped files live below ``files/``. Case-scoped files live below
``cases/CASE-######/files/``. A case is therefore an evidential grouping, not a
requirement imposed on every file in a project.
"""

from __future__ import annotations

import shutil
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from ..errors import ToolkitError
from .catalogue import _append_event, _utc_now, _write_transaction
from .file_protection import protect_committed_file
from .hashing import digest_bytes, digest_file, project_content_hash

T = TypeVar("T")


@dataclass(slots=True, frozen=True)
class FileCandidate:
    """Describe one regular file to be committed without changing its bytes."""

    path: Path
    logical_path: str
    classification: str
    media_type: str | None = None
    description: str | None = None


@dataclass(slots=True, frozen=True)
class FilePayloadCandidate:
    """Describe already-prepared bytes that should become a committed file."""

    payload: bytes
    logical_path: str
    classification: str
    media_type: str | None = None
    description: str | None = None


def _normalise_logical_path(value: str) -> str:
    logical_path = value.strip().replace("\\", "/")
    if (
        not logical_path
        or logical_path.startswith("/")
        or ".." in Path(logical_path).parts
    ):
        raise ToolkitError(f"Unsafe logical file path: {value}")
    return logical_path


def _allocate_file_identifier(connection) -> tuple[str, int]:
    row = connection.execute(
        "SELECT next_sequence FROM counters WHERE namespace = 'file'"
    ).fetchone()
    if row is None:
        raise ToolkitError(
            "FACT catalogue is missing the required 'file' identifier counter"
        )
    sequence = int(row["next_sequence"])
    identifier = f"FILE-{sequence:06d}"
    issued_at = _utc_now()
    connection.execute(
        "INSERT INTO identifiers(namespace, sequence, identifier, state, issued_at) "
        "VALUES ('file', ?, ?, 'active', ?)",
        (sequence, identifier, issued_at),
    )
    connection.execute(
        "UPDATE counters SET next_sequence = ? WHERE namespace = 'file'",
        (sequence + 1,),
    )
    _append_event(
        connection,
        "IDENTIFIER_ISSUED",
        "file",
        identifier,
        {"sequence": sequence},
    )
    return identifier, sequence


def _scope_root(project_root: Path, case_id: str | None) -> Path:
    return (
        project_root / "files"
        if case_id is None
        else project_root / "cases" / case_id / "files"
    )


def _validate_scope(
    connection, project_root: Path, case_id: str | None, acquisition_id: str | None
) -> None:
    if case_id is not None:
        case_root = project_root / "cases" / case_id
        if not case_root.is_dir():
            raise ToolkitError(f"Unknown FACT case: {case_id}")
        row = connection.execute(
            "SELECT state FROM identifiers WHERE identifier = ? AND namespace = 'case'",
            (case_id,),
        ).fetchone()
        if row is None or row["state"] != "active":
            raise ToolkitError(f"FACT case is not active: {case_id}")
    if acquisition_id is not None:
        if case_id is None:
            raise ToolkitError("An acquisition-scoped file must belong to a case")
        row = connection.execute(
            "SELECT state FROM identifiers WHERE identifier = ? AND namespace = 'acquisition'",
            (acquisition_id,),
        ).fetchone()
        if row is None or row["state"] != "active":
            raise ToolkitError(f"FACT acquisition is not active: {acquisition_id}")


def _commit_prepared(
    connection,
    project_root: Path,
    *,
    case_id: str | None,
    acquisition_id: str | None,
    actor_id: str,
    prepared: list[tuple[str, str, str | None, str | None, Path, str, int]],
) -> tuple[list[dict[str, object]], list[Path]]:
    """Move prepared bytes into the authoritative tree inside a DB transaction.

    The returned directories must be removed by the caller if a later mutation
    in the same SQLite transaction fails. This is how higher-level operations,
    such as note creation, make file check-in and their catalogue relationship
    indivisible in normal failure handling.
    """

    _validate_scope(connection, project_root, case_id, acquisition_id)
    created: list[Path] = []
    committed: list[dict[str, object]] = []
    destination_root = _scope_root(project_root, case_id)
    destination_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    for (
        logical_path,
        classification,
        media_type,
        description,
        temporary,
        content_digest,
        size,
    ) in prepared:
        file_id, _ = _allocate_file_identifier(connection)
        suffix = Path(logical_path).name or "payload"
        destination_dir = destination_root / file_id
        destination_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
        destination = destination_dir / suffix
        temporary.replace(destination)
        created.append(destination_dir)
        storage_path = destination.relative_to(project_root).as_posix()
        event_details = {
            "case_id": case_id,
            "acquisition_id": acquisition_id,
            "actor_id": actor_id,
            "logical_path": logical_path,
            "classification": classification,
            "media_type": media_type,
            "content_digest": content_digest,
            "size_bytes": size,
            "storage_path": storage_path,
        }
        _append_event(
            connection,
            "FILE_COMMITTED",
            "file",
            file_id,
            event_details,
            actor_id=actor_id,
            authority_basis="committed-file-actor",
        )
        sequence = connection.execute(
            "SELECT MAX(event_sequence) FROM audit_events"
        ).fetchone()[0]
        connection.execute(
            "INSERT INTO files(file_id, case_id, acquisition_id, actor_id, logical_path, "
            "classification, media_type, description, content_digest, size_bytes, storage_path, "
            "committed_sequence, presentation_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'presented')",
            (
                file_id,
                case_id,
                acquisition_id,
                actor_id,
                logical_path,
                classification,
                media_type,
                description,
                content_digest,
                size,
                storage_path,
                sequence,
            ),
        )
        committed.append({"file_id": file_id, **event_details})
    return committed, created


def _prepare_path_candidates(
    project_root: Path, candidates: list[FileCandidate]
) -> tuple[Path, list[tuple[str, str, str | None, str | None, Path, str, int]]]:
    transfer_root = (
        project_root / ".fact" / "staging" / f"file-checkin-{uuid.uuid4().hex}"
    )
    transfer_root.mkdir(parents=True, mode=0o700)
    seen_paths: set[str] = set()
    prepared: list[tuple[str, str, str | None, str | None, Path, str, int]] = []
    for index, candidate in enumerate(candidates, start=1):
        source = candidate.path.resolve()
        if candidate.path.is_symlink() or not source.is_file():
            raise ToolkitError(
                f"File check-in requires a regular file: {candidate.path}"
            )
        logical_path = _normalise_logical_path(candidate.logical_path)
        if logical_path in seen_paths:
            raise ToolkitError(
                f"Duplicate logical file path in check-in batch: {logical_path}"
            )
        seen_paths.add(logical_path)
        temporary = transfer_root / f"{index:08d}.payload"
        shutil.copyfile(source, temporary)
        algorithm = project_content_hash(project_root)
        source_hash = digest_file(algorithm, source)
        if digest_file(algorithm, temporary) != source_hash:
            raise ToolkitError(
                f"Prepared file failed byte-for-byte hash validation: {logical_path}"
            )
        prepared.append(
            (
                logical_path,
                candidate.classification,
                candidate.media_type,
                candidate.description,
                temporary,
                source_hash,
                temporary.stat().st_size,
            )
        )
    return transfer_root, prepared


def _prepare_payload_candidates(
    project_root: Path, candidates: list[FilePayloadCandidate]
) -> tuple[Path, list[tuple[str, str, str | None, str | None, Path, str, int]]]:
    transfer_root = (
        project_root / ".fact" / "staging" / f"payload-checkin-{uuid.uuid4().hex}"
    )
    transfer_root.mkdir(parents=True, mode=0o700)
    seen_paths: set[str] = set()
    prepared: list[tuple[str, str, str | None, str | None, Path, str, int]] = []
    for index, candidate in enumerate(candidates, start=1):
        logical_path = _normalise_logical_path(candidate.logical_path)
        if logical_path in seen_paths:
            raise ToolkitError(
                f"Duplicate logical file path in check-in batch: {logical_path}"
            )
        seen_paths.add(logical_path)
        temporary = transfer_root / f"{index:08d}.payload"
        temporary.write_bytes(candidate.payload)
        temporary.chmod(0o600)
        algorithm = project_content_hash(project_root)
        digest = digest_bytes(algorithm, candidate.payload)
        if digest_file(algorithm, temporary) != digest:
            raise ToolkitError(
                f"Prepared payload failed byte-for-byte hash validation: {logical_path}"
            )
        prepared.append(
            (
                logical_path,
                candidate.classification,
                candidate.media_type,
                candidate.description,
                temporary,
                digest,
                len(candidate.payload),
            )
        )
    return transfer_root, prepared


def _commit_with_mutation(
    project_root: Path,
    *,
    case_id: str | None,
    acquisition_id: str | None,
    actor_id: str,
    prepared_root: Path,
    prepared: list[tuple[str, str, str | None, str | None, Path, str, int]],
    mutation: Callable[[object, list[dict[str, object]]], T] | None = None,
) -> tuple[list[dict[str, object]], T | None]:
    created: list[Path] = []
    try:
        with _write_transaction(project_root) as connection:
            committed, created = _commit_prepared(
                connection,
                project_root,
                case_id=case_id,
                acquisition_id=acquisition_id,
                actor_id=actor_id,
                prepared=prepared,
            )
            result = mutation(connection, committed) if mutation is not None else None
        for directory in created:
            for payload in directory.iterdir():
                if payload.is_file() and not payload.is_symlink():
                    protect_committed_file(payload)
        return committed, result
    except Exception:
        for directory in reversed(created):
            shutil.rmtree(directory, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(prepared_root, ignore_errors=True)


def commit_files(
    project_root: Path,
    *,
    case_id: str | None,
    acquisition_id: str | None,
    actor_id: str,
    candidates: list[FileCandidate],
) -> list[dict[str, object]]:
    """Commit a complete batch of files or leave none of that batch committed."""

    if not candidates:
        return []
    project_root = project_root.resolve()
    transfer_root: Path | None = None
    try:
        transfer_root, prepared = _prepare_path_candidates(project_root, candidates)
        committed, _ = _commit_with_mutation(
            project_root,
            case_id=case_id,
            acquisition_id=acquisition_id,
            actor_id=actor_id,
            prepared_root=transfer_root,
            prepared=prepared,
        )
        return committed
    except Exception:
        if transfer_root is not None:
            shutil.rmtree(transfer_root, ignore_errors=True)
        raise


def commit_payload_files(
    project_root: Path,
    *,
    case_id: str | None,
    acquisition_id: str | None,
    actor_id: str,
    candidates: list[FilePayloadCandidate],
    mutation: Callable[[object, list[dict[str, object]]], T] | None = None,
) -> tuple[list[dict[str, object]], T | None]:
    """Commit prepared bytes and an optional related catalogue mutation atomically.

    This specialised path is used when the producer already has the canonical
    bytes in memory, notably note revisions and encrypted representations. The
    bytes are staged with restrictive permissions before they enter the final
    authoritative file tree.
    """

    if not candidates:
        return [], None
    project_root = project_root.resolve()
    transfer_root: Path | None = None
    try:
        transfer_root, prepared = _prepare_payload_candidates(project_root, candidates)
        return _commit_with_mutation(
            project_root,
            case_id=case_id,
            acquisition_id=acquisition_id,
            actor_id=actor_id,
            prepared_root=transfer_root,
            prepared=prepared,
            mutation=mutation,
        )
    except Exception:
        if transfer_root is not None:
            shutil.rmtree(transfer_root, ignore_errors=True)
        raise


def list_files(
    project_root: Path, *, case_id: str | None = None
) -> list[dict[str, object]]:
    """Return committed file metadata without reading or altering payload bytes."""

    from .catalogue import _connect

    connection = _connect(project_root)
    try:
        query = "SELECT * FROM files"
        params: tuple[object, ...] = ()
        if case_id is not None:
            query += " WHERE case_id = ?"
            params = (case_id,)
        query += " ORDER BY committed_sequence, file_id"
        return [dict(row) for row in connection.execute(query, params).fetchall()]
    finally:
        connection.close()


def set_file_presentation(
    project_root: Path,
    file_id: str,
    *,
    state: str,
    reason: str,
) -> None:
    """Change presentation state without erasing the committed file or its history."""

    if state not in {"presented", "retracted", "superseded"}:
        raise ToolkitError("File presentation state is not supported")
    if not reason.strip():
        raise ToolkitError("Changing file presentation requires a reason")
    with _write_transaction(project_root) as connection:
        row = connection.execute(
            "SELECT presentation_state FROM files WHERE file_id = ?", (file_id,)
        ).fetchone()
        if row is None:
            raise ToolkitError(f"Unknown FACT file: {file_id}")
        _append_event(
            connection,
            "FILE_PRESENTATION_CHANGED",
            "file",
            file_id,
            {
                "from": str(row["presentation_state"]),
                "to": state,
                "reason": reason.strip(),
            },
        )
        connection.execute(
            "UPDATE files SET presentation_state = ? WHERE file_id = ?",
            (state, file_id),
        )


def relate_files(
    project_root: Path,
    *,
    parent_file_id: str,
    child_file_id: str,
    relationship: str,
) -> None:
    """Append an explicit relationship between two already committed files."""

    if parent_file_id == child_file_id:
        raise ToolkitError("A file cannot be related to itself as parent and child")
    if not relationship.strip():
        raise ToolkitError("File relationship requires a classification")
    with _write_transaction(project_root) as connection:
        known = {
            str(row["file_id"])
            for row in connection.execute(
                "SELECT file_id FROM files WHERE file_id IN (?, ?)",
                (parent_file_id, child_file_id),
            ).fetchall()
        }
        if known != {parent_file_id, child_file_id}:
            raise ToolkitError("File relationship refers to an unknown committed file")
        _append_event(
            connection,
            "FILE_RELATIONSHIP_ADDED",
            "file",
            child_file_id,
            {"parent_file_id": parent_file_id, "relationship": relationship.strip()},
        )
        sequence = connection.execute(
            "SELECT MAX(event_sequence) FROM audit_events"
        ).fetchone()[0]
        connection.execute(
            "INSERT INTO file_relationships VALUES (?, ?, ?, ?)",
            (parent_file_id, child_file_id, relationship.strip(), sequence),
        )
