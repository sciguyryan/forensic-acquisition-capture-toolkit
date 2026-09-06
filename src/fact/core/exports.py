"""Create auditable FACT exports from authoritative project objects.

Exports are disclosures, not new evidence merely because FACT generated them.
Each authoritative export receives a permanent ``EXPORT-######`` identity and
is represented by signed start/completion events in the project chain. The
portable manifest maps every output byte sequence back to immutable FACT file
identities and the exact project chain head observed before disclosure.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from .. import __version__
from ..errors import ToolkitError
from ..identity import OperatorIdentity, decrypt_confidential_payload
from ..keys import prepare_gnupg
from ..services.commands import run
from .authority import _append_signed, _key_row, require_registered_operator
from .catalogue import _connect, _write_transaction, issue_identifier, verify_chain
from .export_policy import (
    require_confidential_plaintext_authority,
    require_export_authority,
)

EXPORT_SCHEMA = "fact-export/v1"
EXPORT_MANIFEST = "FACT-EXPORT.json"
EXPORT_FORMATS = {"directory", "tar"}
EXPORT_VIEWS = {"full", "presented"}
EXPORT_REPRESENTATIONS = {"native"}


def _canonical(data: object) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_leaf(value: str) -> str:
    leaf = Path(value).name.strip()
    return leaf or "payload"


def _project_id(connection) -> str:
    return str(
        connection.execute(
            "SELECT value FROM metadata WHERE key = 'project_id'"
        ).fetchone()[0]
    )


def _file_rows_for_scope(
    connection,
    scope_type: str,
    scope_id: str | None,
    selection_ids: list[str] | None,
) -> list[dict[str, object]]:
    """Resolve an export scope to immutable source file rows."""

    if scope_type == "project":
        rows = connection.execute(
            "SELECT * FROM files ORDER BY committed_sequence, file_id"
        ).fetchall()
    elif scope_type == "case":
        if not scope_id:
            raise ToolkitError("Case export requires a CASE identifier")
        rows = connection.execute(
            "SELECT * FROM files WHERE case_id = ? ORDER BY committed_sequence, file_id",
            (scope_id,),
        ).fetchall()
    elif scope_type == "acquisition":
        if not scope_id:
            raise ToolkitError("Acquisition export requires an ACQ identifier")
        rows = connection.execute(
            "SELECT * FROM files WHERE acquisition_id = ? ORDER BY committed_sequence, file_id",
            (scope_id,),
        ).fetchall()
    elif scope_type == "artefact":
        if not scope_id:
            raise ToolkitError("Artefact export requires an ART identifier")
        exists = connection.execute(
            "SELECT 1 FROM artefacts WHERE artefact_id = ?", (scope_id,)
        ).fetchone()
        if exists is None:
            raise ToolkitError(f"Unknown FACT artefact: {scope_id}")
        rows = connection.execute(
            "SELECT f.* FROM files f JOIN artefact_files af ON af.file_id = f.file_id "
            "WHERE af.artefact_id = ? ORDER BY f.committed_sequence, f.file_id",
            (scope_id,),
        ).fetchall()
    elif scope_type == "file":
        if not scope_id:
            raise ToolkitError("File export requires a FILE identifier")
        rows = connection.execute(
            "SELECT * FROM files WHERE file_id = ?", (scope_id,)
        ).fetchall()
    elif scope_type == "selection":
        ids = list(dict.fromkeys(selection_ids or []))
        if not ids:
            raise ToolkitError("Selection export requires at least one immutable ID")
        file_ids: list[str] = []
        for identifier in ids:
            if identifier.startswith("FILE-"):
                file_ids.append(identifier)
            elif identifier.startswith("ART-"):
                file_ids.extend(
                    str(row[0])
                    for row in connection.execute(
                        "SELECT file_id FROM artefact_files WHERE artefact_id = ?",
                        (identifier,),
                    ).fetchall()
                )
            elif identifier.startswith("ACQ-"):
                file_ids.extend(
                    str(row[0])
                    for row in connection.execute(
                        "SELECT file_id FROM files WHERE acquisition_id = ?",
                        (identifier,),
                    ).fetchall()
                )
            elif identifier.startswith("CASE-"):
                file_ids.extend(
                    str(row[0])
                    for row in connection.execute(
                        "SELECT file_id FROM files WHERE case_id = ?", (identifier,)
                    ).fetchall()
                )
            elif identifier.startswith("NOTE-"):
                file_ids.extend(
                    str(row[0])
                    for row in connection.execute(
                        "SELECT file_id FROM note_revisions WHERE note_id = ? ORDER BY revision",
                        (identifier,),
                    ).fetchall()
                )
            else:
                raise ToolkitError(f"Unsupported selection identifier: {identifier}")
        unique = list(dict.fromkeys(file_ids))
        if not unique:
            raise ToolkitError("Selection did not resolve to any committed files")
        placeholders = ",".join("?" for _ in unique)
        rows = connection.execute(
            f"SELECT * FROM files WHERE file_id IN ({placeholders}) "
            "ORDER BY committed_sequence, file_id",
            tuple(unique),
        ).fetchall()
    else:
        raise ToolkitError(f"Unsupported export scope: {scope_type}")

    if not rows:
        raise ToolkitError(
            f"Export scope contains no committed files: {scope_type} {scope_id or ''}".strip()
        )
    return [dict(row) for row in rows]


def _note_for_file(connection, file_id: str) -> str | None:
    row = connection.execute(
        "SELECT note_id FROM note_revisions WHERE file_id = ?", (file_id,)
    ).fetchone()
    return str(row[0]) if row is not None else None


def _is_confidential(row: dict[str, object]) -> bool:
    return str(row["classification"]).startswith("confidential-")


def _tree_digest(root: Path) -> str:
    """Return a stable content digest for a directory export."""

    inventory: list[dict[str, str]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ToolkitError(
                f"Export tree contains an unexpected symbolic link: {path}"
            )
        if path.is_file():
            inventory.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": _sha256_file(path),
                }
            )
    return _sha256_bytes(_canonical(inventory))


def _canonical_tar_gz(root: Path, output: Path) -> None:
    """Write a deterministic tar.gz representation of an export directory."""

    temporary = output.with_name(f".{output.name}.tmp")
    with temporary.open("wb") as raw:
        import gzip

        with (
            gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped,
            tarfile.open(fileobj=zipped, mode="w") as archive,
        ):
            for path in [root, *sorted(root.rglob("*"))]:
                relative = (
                    Path(root.name)
                    if path == root
                    else Path(root.name) / path.relative_to(root)
                )
                info = archive.gettarinfo(str(path), arcname=relative.as_posix())
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.mode = 0o755 if path.is_dir() else 0o644
                if path.is_file():
                    with path.open("rb") as handle:
                        archive.addfile(info, handle)
                else:
                    archive.addfile(info)
    os.replace(temporary, output)


def _encrypt_output(path: Path, gnupg_home: Path, recipients: list[str]) -> Path:
    """Encrypt one completed tar export for recipient keys in the chosen keyring."""

    output = path.with_name(path.name + ".gpg")
    env = prepare_gnupg(gnupg_home, interactive=False)
    command = [
        "gpg",
        "--homedir",
        str(gnupg_home),
        "--batch",
        "--yes",
        "--trust-model",
        "always",
        "--output",
        str(output),
        "--encrypt",
    ]
    for recipient in recipients:
        command.extend(["--recipient", recipient])
    command.append(str(path))
    result = run(command, env=env, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise ToolkitError(
            "Export encryption failed: "
            + (detail[-1] if detail else "unknown GnuPG error")
        )
    return output


def _start_export(
    project_root: Path,
    actor: OperatorIdentity,
    *,
    export_id: str,
    scope_type: str,
    scope_id: str | None,
    view_mode: str,
    representation: str,
    output_format: str,
    selection_ids: list[str] | None,
    decrypt_confidential: bool,
    encryption_recipients: list[str],
) -> int:
    with _write_transaction(project_root) as connection:
        key = _key_row(connection, actor.operator_id)
        policy = connection.execute(
            "SELECT * FROM export_policy WHERE policy_id = 'project'"
        ).fetchone()
        if policy is None:
            raise ToolkitError("Project export policy is missing")
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="EXPORT_STARTED",
            object_type="export",
            object_id=export_id,
            data={
                "scope_type": scope_type,
                "scope_id": scope_id,
                "selection_ids": list(selection_ids or []),
                "view_mode": view_mode,
                "representation": representation,
                "output_format": output_format,
                "decrypt_confidential": decrypt_confidential,
                "encryption_recipients": encryption_recipients,
                "policy_sequence": int(policy["updated_sequence"]),
            },
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "INSERT INTO exports(export_id, actor_id, scope_type, scope_id, view_mode, "
            "representation, output_format, output_sha256, manifest_sha256, state, "
            "policy_sequence, created_sequence, completed_sequence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, 'preparing', ?, ?, NULL)",
            (
                export_id,
                actor.operator_id,
                scope_type,
                scope_id,
                view_mode,
                representation,
                output_format,
                int(policy["updated_sequence"]),
                sequence,
            ),
        )
        return sequence


def _fail_export(
    project_root: Path, actor: OperatorIdentity, export_id: str, reason: str
) -> None:
    try:
        with _write_transaction(project_root) as connection:
            row = connection.execute(
                "SELECT state FROM exports WHERE export_id = ?", (export_id,)
            ).fetchone()
            if row is None or str(row["state"]) != "preparing":
                return
            key = _key_row(connection, actor.operator_id)
            sequence = _append_signed(
                connection,
                actor=actor,
                event_type="EXPORT_FAILED",
                object_type="export",
                object_id=export_id,
                data={"reason": reason[:1000]},
                verification_key=str(key["public_key"]),
            )
            connection.execute(
                "UPDATE exports SET state = 'failed', completed_sequence = ? WHERE export_id = ?",
                (sequence, export_id),
            )
    except Exception:
        # Preserve the original export failure. A lingering 'preparing' state is
        # intentionally visible to verification and audit rather than hidden.
        return


def _complete_export(
    project_root: Path,
    actor: OperatorIdentity,
    export_id: str,
    *,
    manifest_sha256: str,
    output_sha256: str,
    items: list[dict[str, object]],
    encrypted_sha256: str | None,
) -> int:
    with _write_transaction(project_root) as connection:
        row = connection.execute(
            "SELECT state FROM exports WHERE export_id = ?", (export_id,)
        ).fetchone()
        if row is None or str(row["state"]) != "preparing":
            raise ToolkitError(f"Export is not awaiting completion: {export_id}")
        key = _key_row(connection, actor.operator_id)
        sequence = _append_signed(
            connection,
            actor=actor,
            event_type="EXPORT_COMPLETED",
            object_type="export",
            object_id=export_id,
            data={
                "manifest_sha256": manifest_sha256,
                "output_sha256": output_sha256,
                "encrypted_sha256": encrypted_sha256,
                "items": items,
            },
            verification_key=str(key["public_key"]),
        )
        connection.execute(
            "UPDATE exports SET output_sha256 = ?, manifest_sha256 = ?, state = 'completed', "
            "completed_sequence = ? WHERE export_id = ?",
            (output_sha256, manifest_sha256, sequence, export_id),
        )
        for item in items:
            connection.execute(
                "INSERT INTO export_items(export_id, file_id, output_path, source_sha256, "
                "output_sha256, mode) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    export_id,
                    item["file_id"],
                    item["output_path"],
                    item["source_sha256"],
                    item["output_sha256"],
                    item["mode"],
                ),
            )
        return sequence


def create_export(
    project_root: Path,
    actor: OperatorIdentity,
    *,
    scope_type: str,
    scope_id: str | None = None,
    selection_ids: list[str] | None = None,
    view_mode: str = "presented",
    representation: str = "native",
    output_format: str = "directory",
    output: Path | None = None,
    decrypt_confidential: bool = False,
    encrypt_to: list[str] | None = None,
    toolkit_root: Path | None = None,
    force: bool = False,
) -> dict[str, object]:
    """Create one policy-authorised, chain-recorded FACT export."""

    project_root = project_root.resolve()
    require_registered_operator(project_root, actor)
    if view_mode not in EXPORT_VIEWS:
        raise ToolkitError(f"Unsupported export view: {view_mode}")
    if representation not in EXPORT_REPRESENTATIONS:
        raise ToolkitError(
            "Only native representation is implemented in this iteration; "
            "rendered and archival representations remain explicit future modes"
        )
    if output_format not in EXPORT_FORMATS:
        raise ToolkitError(f"Unsupported export format: {output_format}")
    encrypt_to = list(dict.fromkeys(encrypt_to or []))
    if encrypt_to and output_format != "tar":
        raise ToolkitError("Recipient encryption currently requires --format tar")

    broad_scope = scope_type in {"case", "project", "selection"}
    policy = require_export_authority(
        project_root,
        actor,
        broad_scope=broad_scope,
        ciphertext_only=False,
    )
    verified_before = verify_chain(project_root)

    connection = _connect(project_root)
    try:
        rows = _file_rows_for_scope(connection, scope_type, scope_id, selection_ids)
        if view_mode == "presented":
            rows = [
                row for row in rows if str(row["presentation_state"]) == "presented"
            ]
        if not rows:
            raise ToolkitError("The selected export view contains no files")
        project_id = _project_id(connection)
        confidential_map = {
            str(row["file_id"]): _note_for_file(connection, str(row["file_id"]))
            for row in rows
            if _is_confidential(row)
        }
    finally:
        connection.close()

    if decrypt_confidential:
        for file_id, note_id in confidential_map.items():
            if note_id is None:
                raise ToolkitError(
                    f"Plaintext export is not implemented for generic confidential file {file_id}"
                )
            require_confidential_plaintext_authority(
                project_root,
                actor,
                object_type="note",
                object_id=note_id,
            )
    elif confidential_map:
        # Explicitly enforce the ciphertext policy separately because ordinary
        # export policy must not accidentally imply plaintext authority.
        require_export_authority(
            project_root,
            actor,
            broad_scope=broad_scope,
            ciphertext_only=True,
        )

    export_id = issue_identifier(project_root, "export", "EXPORT")
    _start_export(
        project_root,
        actor,
        export_id=export_id,
        scope_type=scope_type,
        scope_id=scope_id,
        view_mode=view_mode,
        representation=representation,
        output_format=output_format,
        selection_ids=selection_ids,
        decrypt_confidential=decrypt_confidential,
        encryption_recipients=encrypt_to,
    )

    default_name = (
        f"{export_id}"
        if output_format == "directory"
        else f"{export_id}.fact-export.tar.gz"
    )
    destination = (output or (project_root.parent / default_name)).resolve()
    if destination.exists():
        if not force:
            _fail_export(project_root, actor, export_id, "output already exists")
            raise ToolkitError(f"Export output already exists: {destination}")
        if destination.is_dir():
            marker = destination / EXPORT_MANIFEST
            if not marker.is_file():
                _fail_export(
                    project_root, actor, export_id, "unsafe force replacement refused"
                )
                raise ToolkitError(
                    "--force refuses to replace a directory that is not recognisably a FACT export"
                )
            shutil.rmtree(destination)
        else:
            destination.unlink()

    placed_outputs: list[Path] = []
    try:
        with tempfile.TemporaryDirectory(prefix="fact-export-") as temporary:
            root = Path(temporary) / export_id
            root.mkdir(mode=0o700)
            output_items: list[dict[str, object]] = []
            for row in rows:
                file_id = str(row["file_id"])
                source = project_root / str(row["storage_path"])
                if source.is_symlink() or not source.is_file():
                    raise ToolkitError(f"Committed export source is missing: {file_id}")
                source_sha = _sha256_file(source)
                if source_sha != str(row["sha256"]):
                    raise ToolkitError(
                        f"Committed export source has changed: {file_id}"
                    )
                payload: bytes | None = None
                mode = "native"
                leaf = _safe_leaf(str(row["logical_path"]))
                if decrypt_confidential and file_id in confidential_map:
                    payload = decrypt_confidential_payload(source.read_bytes())
                    mode = "derived"
                    if leaf.endswith(".gpg"):
                        leaf = leaf[:-4]
                relative = PurePosixPath("files") / file_id / leaf
                target = root / Path(relative.as_posix())
                target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                if payload is None:
                    shutil.copyfile(source, target)
                else:
                    target.write_bytes(payload)
                target.chmod(0o600)
                output_items.append(
                    {
                        "file_id": file_id,
                        "output_path": relative.as_posix(),
                        "source_sha256": str(row["sha256"]),
                        "output_sha256": _sha256_file(target),
                        "mode": mode,
                        "classification": str(row["classification"]),
                        "case_id": row["case_id"],
                        "acquisition_id": row["acquisition_id"],
                        "logical_path": str(row["logical_path"]),
                    }
                )

            manifest = {
                "schema": EXPORT_SCHEMA,
                "fact_version": __version__,
                "export_id": export_id,
                "project_id": project_id,
                "actor_id": actor.operator_id,
                "scope": {
                    "type": scope_type,
                    "id": scope_id,
                    "selection_ids": list(selection_ids or []),
                },
                "view_mode": view_mode,
                "representation": representation,
                "output_format": output_format,
                "decrypt_confidential": decrypt_confidential,
                "encryption_recipients": encrypt_to,
                "policy_sequence": int(policy["updated_sequence"]),
                "source_project": {
                    "event_count": verified_before["event_count"],
                    "chain_head": verified_before["chain_head"],
                    "state_digest": verified_before["state_digest"],
                },
                "items": output_items,
            }
            manifest_bytes = (
                json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"
            )
            manifest_path = root / EXPORT_MANIFEST
            manifest_path.write_bytes(manifest_bytes)
            manifest_path.chmod(0o600)
            manifest_sha = _sha256_bytes(manifest_bytes)

            encrypted_path: Path | None = None
            encrypted_sha: str | None = None
            if output_format == "directory":
                tree_sha = _tree_digest(root)
                shutil.copytree(root, destination)
                placed_outputs.append(destination)
                output_sha = tree_sha
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                _canonical_tar_gz(root, destination)
                placed_outputs.append(destination)
                output_sha = _sha256_file(destination)
                if encrypt_to:
                    encrypted_path = _encrypt_output(
                        destination,
                        (toolkit_root or project_root) / "pgp" / "keyring",
                        encrypt_to,
                    )
                    placed_outputs.append(encrypted_path)
                    encrypted_sha = _sha256_file(encrypted_path)

        completed_sequence = _complete_export(
            project_root,
            actor,
            export_id,
            manifest_sha256=manifest_sha,
            output_sha256=output_sha,
            items=output_items,
            encrypted_sha256=encrypted_sha,
        )
        verified_after = verify_chain(project_root)
        return {
            "export_id": export_id,
            "output": destination,
            "encrypted": encrypted_path,
            "manifest_sha256": manifest_sha,
            "output_sha256": output_sha,
            "encrypted_sha256": encrypted_sha,
            "file_count": len(output_items),
            "completed_sequence": completed_sequence,
            "verified_event_count": verified_after["event_count"],
        }
    except Exception as exc:
        for path in reversed(placed_outputs):
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            else:
                path.unlink(missing_ok=True)
        _fail_export(project_root, actor, export_id, str(exc))
        raise


def list_exports(project_root: Path) -> list[dict[str, object]]:
    """Return immutable export-event catalogue records."""

    connection = _connect(project_root)
    try:
        return [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM exports ORDER BY created_sequence, export_id"
            ).fetchall()
        ]
    finally:
        connection.close()
