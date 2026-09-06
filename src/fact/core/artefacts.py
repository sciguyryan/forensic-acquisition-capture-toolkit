"""Represent logical artefacts without weakening file-level evidential identity.

Files remain FACT's atomic immutable evidential objects. Artefacts provide a
stable higher-level identity for one or more committed files so review, export
and verification can address a meaningful evidential object without treating a
mutable filename or collector-local path as identity.
"""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path

from ..errors import ToolkitError
from .catalogue import (
    _append_event,
    _connect,
    _write_transaction,
    fail_identifier,
    issue_identifier,
)


def create_acquisition_artefacts(
    project_root: Path,
    *,
    case_id: str,
    acquisition_id: str,
    entries: list[dict[str, str | None]],
) -> list[dict[str, object]]:
    """Create one stable artefact identity for each retained collector artefact.

    ``entries`` must name an already committed file. Identifier allocation is
    deliberately permanent. If catalogue insertion fails after allocation, the
    affected ART identifiers are marked failed rather than becoming reusable.
    """

    if not entries:
        return []
    allocated = [issue_identifier(project_root, "artefact", "ART") for _ in entries]
    try:
        with _write_transaction(project_root) as connection:
            created: list[dict[str, object]] = []
            for artefact_id, entry in zip(allocated, entries, strict=True):
                file_id = str(entry["file_id"])
                file_row = connection.execute(
                    "SELECT case_id, acquisition_id FROM files WHERE file_id = ?",
                    (file_id,),
                ).fetchone()
                if file_row is None:
                    raise ToolkitError(f"Artefact refers to an unknown file: {file_id}")
                if (
                    file_row["case_id"] != case_id
                    or file_row["acquisition_id"] != acquisition_id
                ):
                    raise ToolkitError(
                        f"Artefact file does not belong to {acquisition_id}: {file_id}"
                    )
                role = str(entry["role"])
                description = entry.get("description")
                _append_event(
                    connection,
                    "ARTEFACT_CREATED",
                    "artefact",
                    artefact_id,
                    {
                        "case_id": case_id,
                        "acquisition_id": acquisition_id,
                        "role": role,
                        "description": description,
                        "file_ids": [file_id],
                    },
                )
                sequence = int(
                    connection.execute(
                        "SELECT MAX(event_sequence) FROM audit_events"
                    ).fetchone()[0]
                )
                connection.execute(
                    "INSERT INTO artefacts(artefact_id, case_id, acquisition_id, role, "
                    "description, created_sequence, presentation_state) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'presented')",
                    (artefact_id, case_id, acquisition_id, role, description, sequence),
                )
                connection.execute(
                    "INSERT INTO artefact_files(artefact_id, file_id, member_role, created_sequence) "
                    "VALUES (?, ?, 'primary', ?)",
                    (artefact_id, file_id, sequence),
                )
                created.append(
                    {
                        "artefact_id": artefact_id,
                        "file_id": file_id,
                        "role": role,
                        "case_id": case_id,
                        "acquisition_id": acquisition_id,
                    }
                )
            return created
    except Exception:
        for artefact_id in allocated:
            # An identifier whose artefact event committed is not failed. Suppression
            # is only defensive against an unusual post-commit error.
            with suppress(ToolkitError):
                fail_identifier(project_root, artefact_id, "artefact creation failed")
        raise


def list_artefacts(
    project_root: Path, *, case_id: str | None = None
) -> list[dict[str, object]]:
    """List stable artefact identities and their direct file membership."""

    connection = _connect(project_root)
    try:
        query = (
            "SELECT a.*, GROUP_CONCAT(af.file_id) AS file_ids FROM artefacts a "
            "LEFT JOIN artefact_files af ON af.artefact_id = a.artefact_id"
        )
        params: tuple[object, ...] = ()
        if case_id is not None:
            query += " WHERE a.case_id = ?"
            params = (case_id,)
        query += " GROUP BY a.artefact_id ORDER BY a.created_sequence, a.artefact_id"
        output = []
        for row in connection.execute(query, params).fetchall():
            item = dict(row)
            item["file_ids"] = (
                str(item["file_ids"]).split(",") if item["file_ids"] else []
            )
            output.append(item)
        return output
    finally:
        connection.close()


def artefact_file_ids(project_root: Path, artefact_id: str) -> list[str]:
    """Return direct member files for one immutable artefact."""

    connection = _connect(project_root)
    try:
        exists = connection.execute(
            "SELECT 1 FROM artefacts WHERE artefact_id = ?", (artefact_id,)
        ).fetchone()
        if exists is None:
            raise ToolkitError(f"Unknown FACT artefact: {artefact_id}")
        return [
            str(row[0])
            for row in connection.execute(
                "SELECT file_id FROM artefact_files WHERE artefact_id = ? "
                "ORDER BY created_sequence, file_id",
                (artefact_id,),
            ).fetchall()
        ]
    finally:
        connection.close()
