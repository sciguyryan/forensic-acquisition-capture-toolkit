"""Commit immutable files into the authoritative FACT evidence tree.

FACT treats every retained evidential payload as a file. Collectors and other
producers may create files in mutable staging, but a file does not become part
of the authoritative project merely because it exists there. Check-in assigns a
never-reused ``FILE-######`` identifier, copies the exact bytes into the case
file store, hashes those bytes, and records the resulting identity in the
catalogue and rolling audit chain.

The filesystem and SQLite cannot share a native transaction. FACT therefore
prepares copies under a private temporary directory, validates every prepared
copy, and performs the catalogue mutation and final renames as one guarded
operation. An ordinary failure removes every file created by the attempted
batch and rolls back the catalogue transaction. Crash recovery is deliberately
conservative: an unexplained file not represented by the catalogue is not
silently adopted as evidence.
"""

from __future__ import annotations

import hashlib
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..errors import ToolkitError
from .catalogue import _append_event, _utc_now, _write_transaction


@dataclass(slots=True, frozen=True)
class FileCandidate:
    """Describe one regular file to be committed without changing its bytes."""

    path: Path
    logical_path: str
    classification: str
    media_type: str | None = None
    description: str | None = None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def commit_files(
    project_root: Path,
    *,
    case_id: str,
    acquisition_id: str | None,
    actor_id: str,
    candidates: list[FileCandidate],
) -> list[dict[str, object]]:
    """Commit a complete batch of files or leave none of that batch committed.

    Duplicate content is intentionally not deduplicated. Two captures of the
    same bytes are two evidential check-ins with different provenance and must
    therefore receive different permanent file identifiers.
    """

    if not candidates:
        return []
    project_root = project_root.resolve()
    case_root = project_root / "cases" / case_id
    if not case_root.is_dir():
        raise ToolkitError(f"Unknown FACT case: {case_id}")

    seen_paths: set[str] = set()
    prepared: list[tuple[FileCandidate, Path, str, int]] = []
    transfer_root = (
        project_root / ".fact" / "staging" / f"file-checkin-{uuid.uuid4().hex}"
    )
    transfer_root.mkdir(parents=True, mode=0o700)
    try:
        for index, candidate in enumerate(candidates, start=1):
            source = candidate.path.resolve()
            if candidate.path.is_symlink() or not source.is_file():
                raise ToolkitError(
                    f"File check-in requires a regular file: {candidate.path}"
                )
            logical_path = candidate.logical_path.strip().replace("\\", "/")
            if (
                not logical_path
                or logical_path.startswith("/")
                or ".." in Path(logical_path).parts
            ):
                raise ToolkitError(
                    f"Unsafe logical file path: {candidate.logical_path}"
                )
            if logical_path in seen_paths:
                raise ToolkitError(
                    f"Duplicate logical file path in check-in batch: {logical_path}"
                )
            seen_paths.add(logical_path)
            temporary = transfer_root / f"{index:08d}.payload"
            shutil.copyfile(source, temporary)
            source_hash = _sha256(source)
            if _sha256(temporary) != source_hash:
                raise ToolkitError(
                    f"Prepared file failed byte-for-byte hash validation: {logical_path}"
                )
            prepared.append(
                (candidate, temporary, source_hash, temporary.stat().st_size)
            )

        created: list[Path] = []
        committed: list[dict[str, object]] = []
        try:
            with _write_transaction(project_root) as connection:
                case_identifier = connection.execute(
                    "SELECT state FROM identifiers WHERE identifier = ? AND namespace = 'case'",
                    (case_id,),
                ).fetchone()
                if case_identifier is None or case_identifier["state"] != "active":
                    raise ToolkitError(f"FACT case is not active: {case_id}")
                if acquisition_id is not None:
                    acquisition = connection.execute(
                        "SELECT state FROM identifiers WHERE identifier = ? AND namespace = 'acquisition'",
                        (acquisition_id,),
                    ).fetchone()
                    if acquisition is None or acquisition["state"] != "active":
                        raise ToolkitError(
                            f"FACT acquisition is not active: {acquisition_id}"
                        )

                for candidate, temporary, sha256, size in prepared:
                    file_id, _ = _allocate_file_identifier(connection)
                    suffix = Path(candidate.logical_path).name or "payload"
                    destination_dir = case_root / "files" / file_id
                    destination_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
                    destination = destination_dir / suffix
                    temporary.replace(destination)
                    created.append(destination_dir)
                    storage_path = destination.relative_to(project_root).as_posix()
                    event_details = {
                        "case_id": case_id,
                        "acquisition_id": acquisition_id,
                        "actor_id": actor_id,
                        "logical_path": candidate.logical_path,
                        "classification": candidate.classification,
                        "media_type": candidate.media_type,
                        "sha256": sha256,
                        "size_bytes": size,
                        "storage_path": storage_path,
                    }
                    _append_event(
                        connection,
                        "FILE_COMMITTED",
                        "file",
                        file_id,
                        event_details,
                    )
                    sequence = connection.execute(
                        "SELECT MAX(event_sequence) FROM audit_events"
                    ).fetchone()[0]
                    connection.execute(
                        "INSERT INTO files(file_id, case_id, acquisition_id, actor_id, logical_path, "
                        "classification, media_type, description, sha256, size_bytes, storage_path, "
                        "committed_sequence, presentation_state) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'presented')",
                        (
                            file_id,
                            case_id,
                            acquisition_id,
                            actor_id,
                            candidate.logical_path,
                            candidate.classification,
                            candidate.media_type,
                            candidate.description,
                            sha256,
                            size,
                            storage_path,
                            sequence,
                        ),
                    )
                    committed.append({"file_id": file_id, **event_details})
        except Exception:
            for directory in reversed(created):
                shutil.rmtree(directory, ignore_errors=True)
            raise
        return committed
    finally:
        shutil.rmtree(transfer_root, ignore_errors=True)


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
