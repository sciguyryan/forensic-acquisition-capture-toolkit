"""Create canonical FACT project packages and optional encrypted envelopes."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
import tomllib
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from .. import __version__
from ..errors import ToolkitError
from ..keys import fingerprint, prepare_gnupg, sign
from ..services.commands import run
from .catalogue import CATALOGUE_DIR, CATALOGUE_NAME, PROJECT_NAME, verify_chain

PACKAGE_SCHEMA = "fact-project-package/v1"
PACKAGE_METADATA_DIR = "FACT-PACKAGE"
PACKAGE_DESCRIPTOR = "PACKAGE.json"
PACKAGE_MANIFEST = "MANIFEST.sha256"
PACKAGE_PUBLIC_KEY = "evidence-public-key.asc"
PACKAGE_FINGERPRINT = "evidence-key-fingerprint.txt"
PACKAGE_LOCK = "package.lock"
PACKAGE_SUFFIX = ".fact.tar.gz"


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _load_project(project_root: Path) -> dict[str, object]:
    path = project_root / PROJECT_NAME
    if not path.is_file():
        raise ToolkitError(f"FACT project file does not exist: {path}")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ToolkitError(f"Unable to read FACT project file: {exc}") from exc
    project_id = data.get("project_id")
    if not isinstance(project_id, str) or not project_id:
        raise ToolkitError("FACT project file has no valid project_id")
    return data


@contextmanager
def _package_lock(project_root: Path) -> Iterator[None]:
    """Prevent cooperative FACT project mutation while a package is built."""
    fact_dir = project_root / CATALOGUE_DIR
    lock = fact_dir / PACKAGE_LOCK
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise ToolkitError(
            f"FACT project is already being packaged or has a stale package lock: {lock}"
        ) from exc
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(f"pid={os.getpid()}\ncreated_at={_utc_now()}\n")
            handle.flush()
            os.fsync(handle.fileno())
        yield
    finally:
        lock.unlink(missing_ok=True)


def _reject_symlinks(root: Path) -> None:
    for path in [root, *root.rglob("*")]:
        if path.is_symlink():
            raise ToolkitError(f"Project packages do not permit symbolic links: {path}")


def _copy_tree(source: Path, destination: Path) -> None:
    if not source.exists():
        return
    _reject_symlinks(source)
    shutil.copytree(source, destination, copy_function=shutil.copy2)


def _snapshot_catalogue(source: Path, destination: Path) -> None:
    """Create a consistent SQLite snapshot using SQLite's backup API."""
    source_connection = sqlite3.connect(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination_connection = sqlite3.connect(destination)
    try:
        source_connection.backup(destination_connection)
        destination_connection.commit()
    finally:
        destination_connection.close()
        source_connection.close()
    destination.chmod(0o600)


_ACQUISITION_SIDECAR_SUFFIXES = (
    ".sha256",
    ".sha512",
    ".asc",
    ".operator.asc",
    ".verification.txt",
)


def _copy_sealed_acquisitions(project_root: Path, destination: Path) -> None:
    """Copy only complete, final sealed acquisition bundles.

    Mutable ``.staging-*`` trees are intentionally excluded. A top-level 7z
    archive is treated as packageable evidence only when every sidecar created
    by the sealing lifecycle is present as a regular non-symlink file. This
    prevents project packaging from silently omitting evidence while also
    avoiding a blind copy of unrelated or incomplete working state.
    """

    source = project_root / "archived"
    if not source.exists():
        return
    if source.is_symlink() or not source.is_dir():
        raise ToolkitError(f"Invalid FACT archived directory: {source}")

    archives = sorted(
        path
        for path in source.iterdir()
        if path.is_file() and path.name.endswith(".7z")
    )
    if not archives:
        return
    destination.mkdir(parents=True, exist_ok=True)
    for archive in archives:
        if archive.is_symlink():
            raise ToolkitError(
                f"Project packages do not permit symbolic links: {archive}"
            )
        required = [
            archive,
            *(Path(str(archive) + suffix) for suffix in _ACQUISITION_SIDECAR_SUFFIXES),
        ]
        for item in required:
            if item.is_symlink() or not item.is_file():
                raise ToolkitError(
                    f"Sealed acquisition bundle is incomplete or unsafe: {item.name}"
                )
        for item in required:
            shutil.copy2(item, destination / item.name)


def _copy_project_state(project_root: Path, staging: Path) -> None:
    """Copy only the project artefacts that belong in a FACT package."""
    shutil.copy2(project_root / PROJECT_NAME, staging / PROJECT_NAME)

    source_fact = project_root / CATALOGUE_DIR
    destination_fact = staging / CATALOGUE_DIR
    destination_fact.mkdir(mode=0o700)
    _snapshot_catalogue(
        source_fact / CATALOGUE_NAME,
        destination_fact / CATALOGUE_NAME,
    )
    for name in ("catalogue-checkpoint.json", "catalogue-checkpoint.json.asc"):
        source = source_fact / name
        if source.exists():
            if source.is_symlink() or not source.is_file():
                raise ToolkitError(f"Invalid catalogue checkpoint artefact: {source}")
            shutil.copy2(source, destination_fact / name)

    _copy_tree(project_root / "cases", staging / "cases")
    _copy_sealed_acquisitions(project_root, staging / "archived")


def _export_public_key(gnupg_home: Path, fpr: str) -> str:
    env = prepare_gnupg(gnupg_home, interactive=False)
    result = run(
        ["gpg", "--homedir", str(gnupg_home), "--batch", "--armor", "--export", fpr],
        env=env,
        check=False,
    )
    if result.returncode != 0 or "BEGIN PGP PUBLIC KEY BLOCK" not in result.stdout:
        detail = (result.stderr or result.stdout).strip().splitlines()
        message = detail[-1] if detail else "unknown GnuPG error"
        raise ToolkitError(f"Evidence public-key export failed: {message}")
    return result.stdout


def _verify_signature(payload: Path, signature: Path, public_key: str) -> None:
    """Verify a detached signature in an isolated temporary GnuPG home."""
    with tempfile.TemporaryDirectory(prefix="fact-package-signature-") as temporary:
        home = Path(temporary) / "keyring"
        home.mkdir(mode=0o700)
        key_path = Path(temporary) / "public-key.asc"
        key_path.write_text(public_key, encoding="utf-8")
        env = {"GNUPGHOME": str(home)}
        imported = run(
            ["gpg", "--batch", "--import", str(key_path)], env=env, check=False
        )
        if imported.returncode != 0:
            raise ToolkitError("Unable to import FACT package verification public key")
        verified = run(
            ["gpg", "--batch", "--verify", str(signature), str(payload)],
            env=env,
            check=False,
        )
        if verified.returncode != 0:
            raise ToolkitError(
                f"Detached signature verification failed: {signature.name}"
            )


def _checkpoint_status(
    staging: Path, verified: dict[str, object], public_key: str
) -> str:
    """Validate a packaged checkpoint when present and report its freshness."""
    fact_dir = staging / CATALOGUE_DIR
    checkpoint = fact_dir / "catalogue-checkpoint.json"
    signature = fact_dir / "catalogue-checkpoint.json.asc"
    if not checkpoint.exists() and not signature.exists():
        return "absent"
    if not checkpoint.is_file() or not signature.is_file():
        raise ToolkitError(
            "Catalogue checkpoint is incomplete; both payload and signature are required"
        )
    _verify_signature(checkpoint, signature, public_key)
    try:
        data = json.loads(checkpoint.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolkitError(f"Catalogue checkpoint cannot be read: {exc}") from exc
    fields = ("project_id", "event_count", "chain_head", "state_digest")
    return (
        "current"
        if all(data.get(field) == verified[field] for field in fields)
        else "stale"
    )


def _manifest_files(root: Path) -> list[Path]:
    manifest = root / PACKAGE_METADATA_DIR / PACKAGE_MANIFEST
    return sorted(
        (
            path
            for path in root.rglob("*")
            if path.is_file() and not path.is_symlink() and path != manifest
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    )


def _write_manifest(root: Path) -> Path:
    output = root / PACKAGE_METADATA_DIR / PACKAGE_MANIFEST
    lines = [
        f"{_sha256(path)}  {path.relative_to(root).as_posix()}"
        for path in _manifest_files(root)
    ]
    output.write_text("\n".join(lines) + "\n", encoding="ascii")
    output.chmod(0o600)
    return output


def _canonical_tar_gz(source: Path, output: Path) -> None:
    """Write a deterministic gzip-compressed POSIX tar archive."""
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    with (
        temporary.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed,
        tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
        ) as archive,
    ):
        for path in sorted(
            source.rglob("*"),
            key=lambda item: item.relative_to(source).as_posix(),
        ):
            if path.is_symlink():
                raise ToolkitError(
                    f"Project packages do not permit symbolic links: {path}"
                )
            relative = path.relative_to(source).as_posix()
            info = archive.gettarinfo(str(path), arcname=relative)
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


def _write_archive_checksum(archive: Path) -> Path:
    output = archive.with_name(archive.name + ".sha256")
    output.write_text(f"{_sha256(archive)}  {archive.name}\n", encoding="ascii")
    return output


def _encrypt_archive(archive: Path, gnupg_home: Path, recipients: list[str]) -> Path:
    output = archive.with_name(archive.name + ".gpg")
    if output.exists():
        output.unlink()
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
    command.append(str(archive))
    result = run(command, env=env, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        message = detail[-1] if detail else "unknown GnuPG error"
        raise ToolkitError(f"Package encryption failed: {message}")
    return output


def _verify_internal_manifest(archive: Path) -> None:
    """Re-open the completed archive and verify every internal manifest entry."""
    with tarfile.open(archive, mode="r:gz") as package:
        members = {member.name: member for member in package.getmembers()}
        for member in members.values():
            member_path = Path(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ToolkitError(
                    f"Unsafe member in generated FACT package: {member.name}"
                )
            if member.issym() or member.islnk():
                raise ToolkitError(
                    f"Unexpected link in generated FACT package: {member.name}"
                )
            if not member.isfile() and not member.isdir():
                raise ToolkitError(
                    f"Unexpected special member in generated FACT package: {member.name}"
                )

        manifest_name = f"{PACKAGE_METADATA_DIR}/{PACKAGE_MANIFEST}"
        manifest_member = members.get(manifest_name)
        if manifest_member is None or not manifest_member.isfile():
            raise ToolkitError(
                "Generated FACT package is missing its internal manifest"
            )
        manifest_stream = package.extractfile(manifest_member)
        if manifest_stream is None:
            raise ToolkitError("Generated FACT package manifest cannot be read")
        manifest_text = manifest_stream.read().decode("ascii")

        for line_number, line in enumerate(manifest_text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                expected, relative = line.split("  ", 1)
            except ValueError as exc:
                raise ToolkitError(
                    f"Generated FACT package has a malformed manifest entry at line {line_number}"
                ) from exc
            member = members.get(relative)
            if member is None or not member.isfile():
                raise ToolkitError(
                    f"Generated FACT package failed manifest verification: {relative}"
                )
            stream = package.extractfile(member)
            if stream is None:
                raise ToolkitError(
                    f"Generated FACT package member cannot be read: {relative}"
                )
            actual = hashlib.sha256(stream.read()).hexdigest()
            if actual != expected:
                raise ToolkitError(
                    f"Generated FACT package failed manifest verification: {relative}"
                )


def create_project_package(
    project_root: Path,
    toolkit_root: Path,
    output: Path | None = None,
    *,
    encrypt_to: list[str] | None = None,
    force: bool = False,
) -> dict[str, Path]:
    """Create, sign, verify, and optionally encrypt a FACT project package."""
    project_root = project_root.resolve()
    toolkit_root = toolkit_root.resolve()
    project = _load_project(project_root)
    project_id = str(project["project_id"])
    archive = (
        output or project_root.parent / f"{project_id}{PACKAGE_SUFFIX}"
    ).resolve()
    signature = archive.with_name(archive.name + ".asc")
    checksum = archive.with_name(archive.name + ".sha256")
    public_key_sidecar = archive.with_name(archive.name + ".public-key.asc")
    fingerprint_sidecar = archive.with_name(archive.name + ".fingerprint.txt")
    encrypted = archive.with_name(archive.name + ".gpg")

    planned = [archive, signature, checksum, public_key_sidecar, fingerprint_sidecar]
    if encrypt_to:
        planned.append(encrypted)
    existing = [path for path in planned if path.exists()]
    if existing and not force:
        names = ", ".join(path.name for path in existing)
        raise ToolkitError(
            f"Package output already exists: {names}. Use --force to replace it."
        )

    gnupg_home = toolkit_root / "pgp" / "keyring"
    env = prepare_gnupg(gnupg_home, interactive=False)
    fpr = fingerprint(gnupg_home, env=env)
    if not fpr:
        raise ToolkitError("No evidence signing key exists; run 'fact keygen' first")
    public_key = _export_public_key(gnupg_home, fpr)

    with _package_lock(project_root):
        verified = verify_chain(project_root)
        if verified["project_id"] != project_id:
            raise ToolkitError(
                "PROJECT.toml project_id does not match the catalogue project_id"
            )

        with tempfile.TemporaryDirectory(prefix="fact-package-build-") as temporary:
            staging = Path(temporary) / project_id
            staging.mkdir(mode=0o700)
            _copy_project_state(project_root, staging)

            # Verify the actual SQLite snapshot that will be packaged, rather than
            # assuming it still matches the live database verified above.
            snapshot_root = Path(temporary) / "snapshot-check"
            snapshot_root.mkdir()
            (snapshot_root / CATALOGUE_DIR).mkdir()
            shutil.copy2(
                staging / CATALOGUE_DIR / CATALOGUE_NAME,
                snapshot_root / CATALOGUE_DIR / CATALOGUE_NAME,
            )
            snapshot_verified = verify_chain(snapshot_root)
            if snapshot_verified != verified:
                raise ToolkitError(
                    "Catalogue changed while the project package was being prepared"
                )

            checkpoint_status = _checkpoint_status(staging, verified, public_key)

            metadata = staging / PACKAGE_METADATA_DIR
            metadata.mkdir(mode=0o700)
            descriptor = {
                "schema": PACKAGE_SCHEMA,
                "package_type": "project",
                "project_id": project_id,
                "fact_version": __version__,
                "catalogue_event_count": verified["event_count"],
                "catalogue_chain_head": verified["chain_head"],
                "catalogue_state_digest": verified["state_digest"],
                "catalogue_checkpoint_status": checkpoint_status,
                "signing_key_fingerprint": fpr,
                "state_timestamp": verified["last_event_at"],
                "included_roots": [PROJECT_NAME, CATALOGUE_DIR, "cases", "archived"],
            }
            (metadata / PACKAGE_DESCRIPTOR).write_text(
                json.dumps(descriptor, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            (metadata / PACKAGE_PUBLIC_KEY).write_text(public_key, encoding="utf-8")
            (metadata / PACKAGE_FINGERPRINT).write_text(fpr + "\n", encoding="ascii")
            _write_manifest(staging)
            _canonical_tar_gz(staging, archive)

    _verify_internal_manifest(archive)
    checksum = _write_archive_checksum(archive)
    if signature.exists():
        signature.unlink()
    sign(gnupg_home, archive, signature, fpr)
    _verify_signature(archive, signature, public_key)
    public_key_sidecar.write_text(public_key, encoding="utf-8")
    fingerprint_sidecar.write_text(fpr + "\n", encoding="ascii")

    outputs = {
        "archive": archive,
        "checksum": checksum,
        "signature": signature,
        "public_key": public_key_sidecar,
        "fingerprint": fingerprint_sidecar,
    }
    if encrypt_to:
        outputs["encrypted"] = _encrypt_archive(archive, gnupg_home, encrypt_to)
    return outputs
