"""Verification entry points for FACT projects, identities and external material.

Verification has two deliberately different directions. External-file/export
verification proves correspondence back into authenticated project history.
Structural verification starts at an immutable FACT object, verifies its full
evidential subtree, and verifies the catalogue history that anchors it to the
project without rehashing unrelated sibling payloads.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path, PurePosixPath

from ..errors import ToolkitError
from .catalogue import _connect, verify_chain
from .exports import EXPORT_MANIFEST, EXPORT_SCHEMA, _tree_digest


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _base_result(kind: str, target: str) -> dict[str, object]:
    return {
        "schema": "fact-verification-result/v1",
        "status": "verified",
        "verification_kind": kind,
        "target": target,
        "summary": "",
        "scope": {},
        "matches": [],
        "checks": [],
        "warnings": [],
        "limitations": [],
    }


def _chain_summary(
    verified: dict[str, object], file_ids: list[str] | None
) -> dict[str, object]:
    return {
        "project_id": verified["project_id"],
        "event_count": verified["event_count"],
        "chain_head": verified["chain_head"],
        "state_digest": verified["state_digest"],
        "hashed_file_count": verified["hashed_file_count"],
        "file_ids_hashed": file_ids,
    }


def _expand_file_descendants(connection, initial: list[str]) -> list[str]:
    selected = set(initial)
    frontier = list(initial)
    while frontier:
        parent = frontier.pop()
        children = [
            str(row[0])
            for row in connection.execute(
                "SELECT child_file_id FROM file_relationships WHERE parent_file_id = ?",
                (parent,),
            ).fetchall()
        ]
        for child in children:
            if child not in selected:
                selected.add(child)
                frontier.append(child)
    rows = connection.execute(
        "SELECT file_id FROM files ORDER BY committed_sequence, file_id"
    ).fetchall()
    order = [str(row[0]) for row in rows]
    return [file_id for file_id in order if file_id in selected]


def _files_for_object(
    project_root: Path, object_type: str, object_id: str | None
) -> list[str]:
    connection = _connect(project_root)
    try:
        if object_type == "project":
            return [
                str(row[0])
                for row in connection.execute(
                    "SELECT file_id FROM files ORDER BY committed_sequence, file_id"
                ).fetchall()
            ]
        if not object_id:
            raise ToolkitError(
                f"{object_type.title()} verification requires an identifier"
            )
        if object_type == "file":
            row = connection.execute(
                "SELECT file_id FROM files WHERE file_id = ?", (object_id,)
            ).fetchone()
            if row is None:
                raise ToolkitError(f"Unknown FACT file: {object_id}")
            return [object_id]
        if object_type == "artefact":
            exists = connection.execute(
                "SELECT 1 FROM artefacts WHERE artefact_id = ?", (object_id,)
            ).fetchone()
            if exists is None:
                raise ToolkitError(f"Unknown FACT artefact: {object_id}")
            direct = [
                str(row[0])
                for row in connection.execute(
                    "SELECT file_id FROM artefact_files WHERE artefact_id = ? "
                    "ORDER BY created_sequence, file_id",
                    (object_id,),
                ).fetchall()
            ]
            return _expand_file_descendants(connection, direct)
        if object_type == "acquisition":
            known = connection.execute(
                "SELECT 1 FROM identifiers WHERE identifier = ? AND namespace = 'acquisition'",
                (object_id,),
            ).fetchone()
            if known is None:
                raise ToolkitError(f"Unknown FACT acquisition: {object_id}")
            return [
                str(row[0])
                for row in connection.execute(
                    "SELECT file_id FROM files WHERE acquisition_id = ? "
                    "ORDER BY committed_sequence, file_id",
                    (object_id,),
                ).fetchall()
            ]
        if object_type == "case":
            known = connection.execute(
                "SELECT 1 FROM identifiers WHERE identifier = ? AND namespace = 'case'",
                (object_id,),
            ).fetchone()
            if known is None:
                raise ToolkitError(f"Unknown FACT case: {object_id}")
            return [
                str(row[0])
                for row in connection.execute(
                    "SELECT file_id FROM files WHERE case_id = ? ORDER BY committed_sequence, file_id",
                    (object_id,),
                ).fetchall()
            ]
        if object_type == "note":
            known = connection.execute(
                "SELECT 1 FROM notes WHERE note_id = ?", (object_id,)
            ).fetchone()
            if known is None:
                raise ToolkitError(f"Unknown FACT note: {object_id}")
            return [
                str(row[0])
                for row in connection.execute(
                    "SELECT file_id FROM note_revisions WHERE note_id = ? ORDER BY revision",
                    (object_id,),
                ).fetchall()
            ]
        if object_type == "export":
            known = connection.execute(
                "SELECT 1 FROM exports WHERE export_id = ?", (object_id,)
            ).fetchone()
            if known is None:
                raise ToolkitError(f"Unknown FACT export: {object_id}")
            return [
                str(row[0])
                for row in connection.execute(
                    "SELECT file_id FROM export_items WHERE export_id = ? ORDER BY output_path",
                    (object_id,),
                ).fetchall()
            ]
        raise ToolkitError(f"Unsupported FACT verification object type: {object_type}")
    finally:
        connection.close()


def verify_structural(
    project_root: Path, object_type: str, object_id: str | None = None
) -> dict[str, object]:
    """Verify one FACT object downward and its authenticated path to project root."""

    file_ids = _files_for_object(project_root, object_type, object_id)
    verified = verify_chain(
        project_root,
        file_ids_to_hash=None if object_type == "project" else set(file_ids),
    )
    target = object_id or str(verified["project_id"])
    result = _base_result(f"structural-{object_type}", target)
    result["summary"] = (
        f"{object_type.title()} {target} is consistent with authenticated FACT history."
    )
    result["scope"] = {
        "selected_object_type": object_type,
        "selected_object_id": target,
        "descendant_file_count": len(file_ids),
        "project_chain": _chain_summary(
            verified, None if object_type == "project" else file_ids
        ),
    }
    result["checks"] = [
        "Catalogue hash chain and signed authority transactions verified",
        "Selected object's catalogue state matches append-only history",
        f"{verified['hashed_file_count']} selected committed file payload(s) rehashed",
    ]
    if object_type != "project":
        result["limitations"] = [
            "Unrelated sibling file payloads were not rehashed; their catalogue metadata and shared authenticated history were still validated."
        ]
    return result


def verify_external_file(project_root: Path, path: Path) -> dict[str, object]:
    """Prove whether supplied external bytes exactly match committed FACT files."""

    path = path.resolve()
    if path.is_symlink() or not path.is_file():
        raise ToolkitError(f"File verification requires a regular file: {path}")
    digest = _sha256_file(path)
    size = path.stat().st_size
    connection = _connect(project_root)
    try:
        rows = connection.execute(
            "SELECT * FROM files WHERE sha256 = ? AND size_bytes = ? "
            "ORDER BY committed_sequence, file_id",
            (digest, size),
        ).fetchall()
        matches = []
        for row in rows:
            artefacts = [
                str(item[0])
                for item in connection.execute(
                    "SELECT artefact_id FROM artefact_files WHERE file_id = ? ORDER BY artefact_id",
                    (row["file_id"],),
                ).fetchall()
            ]
            matches.append({**dict(row), "artefact_ids": artefacts})
    finally:
        connection.close()
    result = _base_result("external-file-correspondence", str(path))
    result["scope"] = {"observed_sha256": digest, "observed_size_bytes": size}
    if not matches:
        # Verify the history itself so an unmatched result is not produced from a
        # silently corrupted catalogue lookup.
        verified = verify_chain(project_root, file_ids_to_hash=set())
        result["status"] = "unmatched"
        result["summary"] = "The supplied file does not match any committed FACT file."
        result["scope"]["project_chain"] = _chain_summary(verified, [])
        result["checks"] = [
            "Authenticated project history verified",
            "No matching SHA-256 and size pair found",
        ]
        return result
    file_ids = [str(row["file_id"]) for row in matches]
    verified = verify_chain(project_root, file_ids_to_hash=set(file_ids))
    result["summary"] = (
        f"The supplied file is byte-for-byte identical to {len(matches)} committed FACT file identity(s)."
    )
    result["matches"] = matches
    result["scope"]["project_chain"] = _chain_summary(verified, file_ids)
    result["checks"] = [
        "External SHA-256 and size calculated",
        "Every matching authoritative project payload independently rehashed",
        "Matching FILE identities and provenance verified against authenticated history",
    ]
    return result


def _manifest_from_directory(path: Path) -> tuple[dict[str, object], str]:
    """Read and validate an export manifest from a directory export."""

    manifest_path = path / EXPORT_MANIFEST
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ToolkitError(f"FACT export manifest is missing: {manifest_path}")
    payload = manifest_path.read_bytes()
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ToolkitError("FACT export manifest is not valid JSON") from exc
    if not isinstance(data, dict) or data.get("schema") != EXPORT_SCHEMA:
        raise ToolkitError("Unsupported FACT export manifest schema")
    return data, hashlib.sha256(payload).hexdigest()


def _manifest_from_tar(
    path: Path,
) -> tuple[dict[str, object], str, str, dict[str, str]]:
    """Read a tar export safely and return its manifest and member digests.

    The archive is opened and closed entirely inside this helper so callers do
    not own a live ``TarFile`` resource. Member hashes are calculated while the
    archive is open and can therefore be compared later without reopening it.
    """

    with tarfile.open(path, mode="r:gz") as package:
        manifest_members: list[tarfile.TarInfo] = []
        member_hashes: dict[str, str] = {}
        for member in package.getmembers():
            pure = PurePosixPath(member.name)
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or member.issym()
                or member.islnk()
            ):
                raise ToolkitError(f"Unsafe FACT export archive member: {member.name}")
            if pure.name == EXPORT_MANIFEST:
                manifest_members.append(member)
            if member.isfile():
                stream = package.extractfile(member)
                if stream is None:
                    raise ToolkitError(
                        f"FACT export archive member cannot be read: {member.name}"
                    )
                member_hashes[member.name] = hashlib.sha256(stream.read()).hexdigest()

        if len(manifest_members) != 1:
            raise ToolkitError(
                "FACT export archive must contain exactly one export manifest"
            )
        manifest_member = manifest_members[0]
        manifest_stream = package.extractfile(manifest_member)
        if manifest_stream is None:
            raise ToolkitError("FACT export manifest cannot be read")
        payload = manifest_stream.read()
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ToolkitError("FACT export manifest is not valid JSON") from exc
        if not isinstance(data, dict) or data.get("schema") != EXPORT_SCHEMA:
            raise ToolkitError("Unsupported FACT export manifest schema")
        prefix = str(PurePosixPath(manifest_member.name).parent)
        return data, hashlib.sha256(payload).hexdigest(), prefix, member_hashes


def _completed_export_event(connection, export_id: str) -> dict[str, object]:
    rows = connection.execute(
        "SELECT details_json FROM audit_events WHERE event_type = 'EXPORT_COMPLETED' "
        "AND object_id = ?",
        (export_id,),
    ).fetchall()
    if len(rows) != 1:
        raise ToolkitError(
            f"Export does not have exactly one completion event: {export_id}"
        )
    details = json.loads(rows[0]["details_json"])
    return details["authority_transaction"]["data"]


def verify_export(project_root: Path, path: Path) -> dict[str, object]:
    """Verify an external export and map it to its exact chain-recorded EXPORT ID."""

    path = path.resolve()
    if path.suffix == ".gpg":
        digest = _sha256_file(path)
        connection = _connect(project_root)
        try:
            match: tuple[str, dict[str, object]] | None = None
            for row in connection.execute(
                "SELECT object_id, details_json FROM audit_events "
                "WHERE event_type = 'EXPORT_COMPLETED'"
            ).fetchall():
                details = json.loads(row["details_json"])
                data = details["authority_transaction"]["data"]
                if data.get("encrypted_sha256") == digest:
                    match = (str(row["object_id"]), data)
                    break
            if match is None:
                verified = verify_chain(project_root, file_ids_to_hash=set())
                result = _base_result("external-export", str(path))
                result["status"] = "unmatched"
                result["summary"] = (
                    "Encrypted file does not match any recorded FACT export envelope."
                )
                result["scope"] = {
                    "observed_sha256": digest,
                    "project_chain": _chain_summary(verified, []),
                }
                return result
            export_id, _ = match
            file_ids = [
                str(row[0])
                for row in connection.execute(
                    "SELECT file_id FROM export_items WHERE export_id = ? ORDER BY output_path",
                    (export_id,),
                ).fetchall()
            ]
        finally:
            connection.close()
        verified = verify_chain(project_root, file_ids_to_hash=set(file_ids))
        result = _base_result("external-export-encrypted-envelope", str(path))
        result["summary"] = f"Encrypted container exactly matches recorded {export_id}."
        result["matches"] = [{"export_id": export_id, "encrypted_sha256": digest}]
        result["scope"] = {"project_chain": _chain_summary(verified, file_ids)}
        result["limitations"] = [
            "The encrypted envelope was matched exactly, but its internal export files were not decrypted or independently inspected."
        ]
        return result

    archive_member_hashes: dict[str, str] | None = None
    prefix = ""
    if path.is_dir():
        manifest, manifest_sha = _manifest_from_directory(path)
        observed_output_sha = _tree_digest(path)
    elif path.is_file():
        manifest, manifest_sha, prefix, archive_member_hashes = _manifest_from_tar(path)
        observed_output_sha = _sha256_file(path)
    else:
        raise ToolkitError(f"Export verification target does not exist: {path}")

    export_id = str(manifest.get("export_id", ""))
    if not export_id.startswith("EXPORT-"):
        raise ToolkitError("FACT export manifest has no valid EXPORT identifier")
    connection = _connect(project_root)
    try:
        row = connection.execute(
            "SELECT * FROM exports WHERE export_id = ?", (export_id,)
        ).fetchone()
        if row is None or str(row["state"]) != "completed":
            raise ToolkitError(
                f"Manifest refers to an unknown or incomplete export: {export_id}"
            )
        if str(row["manifest_sha256"]) != manifest_sha:
            raise ToolkitError(
                "Export manifest differs from the authenticated completion event"
            )
        if str(row["output_sha256"]) != observed_output_sha:
            raise ToolkitError(
                "External export container/tree digest differs from recorded export"
            )
        event = _completed_export_event(connection, export_id)
        expected_items = {str(item["output_path"]): item for item in event["items"]}
        manifest_items_raw = manifest.get("items")
        if not isinstance(manifest_items_raw, list):
            raise ToolkitError("FACT export manifest item list is malformed")
        manifest_items = {
            str(item["output_path"]): item
            for item in manifest_items_raw
            if isinstance(item, dict)
        }
        if set(manifest_items) != set(expected_items):
            raise ToolkitError(
                "Export manifest membership differs from authenticated export event"
            )
        for output_path, expected in expected_items.items():
            observed = manifest_items[output_path]
            for field in ("file_id", "source_sha256", "output_sha256", "mode"):
                if str(observed.get(field)) != str(expected[field]):
                    raise ToolkitError(
                        f"Export manifest item differs from history: {output_path} ({field})"
                    )
            if archive_member_hashes is None:
                member_path = path / Path(output_path)
                if member_path.is_symlink() or not member_path.is_file():
                    raise ToolkitError(f"Exported file is missing: {output_path}")
                output_hash = _sha256_file(member_path)
            else:
                member_name = str(PurePosixPath(prefix) / PurePosixPath(output_path))
                try:
                    output_hash = archive_member_hashes[member_name]
                except KeyError as exc:
                    raise ToolkitError(
                        f"Exported archive member is missing: {output_path}"
                    ) from exc
            if output_hash != str(expected["output_sha256"]):
                raise ToolkitError(
                    f"Exported file bytes differ from recorded export: {output_path}"
                )
        file_ids = [str(item["file_id"]) for item in expected_items.values()]

        source_anchor = manifest.get("source_project")
        if not isinstance(source_anchor, dict):
            raise ToolkitError("Export manifest lacks source project anchor")
        source_count = int(source_anchor["event_count"])
        if source_count == 0:
            anchored_hash = "0" * 64
        else:
            anchor_row = connection.execute(
                "SELECT event_hash FROM audit_events WHERE event_sequence = ?",
                (source_count,),
            ).fetchone()
            if anchor_row is None:
                raise ToolkitError(
                    "Export source project anchor is beyond current history"
                )
            anchored_hash = str(anchor_row[0])
        if anchored_hash != str(source_anchor["chain_head"]):
            raise ToolkitError(
                "Export source chain head is not present in current project history"
            )
    finally:
        connection.close()
    verified = verify_chain(project_root, file_ids_to_hash=set(file_ids))
    result = _base_result("external-export", str(path))
    result["summary"] = (
        f"External material exactly matches recorded {export_id} and maps to {len(file_ids)} committed FACT file(s)."
    )
    result["matches"] = [
        {
            "export_id": export_id,
            "manifest_sha256": manifest_sha,
            "output_sha256": observed_output_sha,
            "file_ids": file_ids,
        }
    ]
    result["scope"] = {
        "source_project_anchor": manifest["source_project"],
        "project_chain": _chain_summary(verified, file_ids),
    }
    result["checks"] = [
        "Export manifest digest matches authenticated completion event",
        "Export file membership matches authenticated completion event",
        "Every exported output file matches its recorded output digest",
        "Every source FILE identity maps into current authenticated project history",
        "Export source chain head remains an exact prefix of current project history",
    ]
    if any(str(item["mode"]) != "native" for item in expected_items.values()):
        result["warnings"] = [
            "One or more export items are derived representations; their output bytes are verified against the export event rather than claimed to be byte-identical to source FILE payloads."
        ]
    return result


def verify_id(project_root: Path, identifier: str) -> dict[str, object]:
    """Resolve one immutable FACT identifier and apply its native verification semantics."""

    connection = _connect(project_root)
    try:
        row = connection.execute(
            "SELECT namespace, state FROM identifiers WHERE identifier = ?",
            (identifier,),
        ).fetchone()
        if row is None:
            project_id = connection.execute(
                "SELECT value FROM metadata WHERE key = 'project_id'"
            ).fetchone()[0]
            if identifier == str(project_id):
                return verify_structural(project_root, "project")
            raise ToolkitError(f"Unknown immutable FACT identifier: {identifier}")
        namespace = str(row["namespace"])
    finally:
        connection.close()
    mapping = {
        "file": "file",
        "artefact": "artefact",
        "acquisition": "acquisition",
        "case": "case",
        "note": "note",
        "export": "export",
    }
    object_type = mapping.get(namespace)
    if object_type is None:
        raise ToolkitError(
            f"Identifier namespace does not yet have verification semantics: {namespace}"
        )
    result = verify_structural(project_root, object_type, identifier)
    result["scope"]["identifier_state"] = str(row["state"])
    return result
