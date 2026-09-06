"""Create and locate FACT projects and their case records."""

from __future__ import annotations

import re
import shutil
from contextlib import suppress
from pathlib import Path

from .. import __version__
from ..errors import ToolkitError
from ..identity import OperatorIdentity
from .authority import assign_case_owner, establish_project_genesis
from .catalogue import (
    PROJECT_NAME,
    SCHEMA_VERSION,
    fail_identifier,
    initialise_catalogue,
    issue_identifier,
    retire_identifier,
)
from .hashing import (
    DEFAULT_CHAIN_HASH,
    DEFAULT_CONTENT_HASH,
    require_hash,
)

_PROJECT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_INITIALISING_NAME = ".fact-initialising"


def _initialise_project(
    root: Path,
    project_id: str,
    title: str,
    *,
    chain_hash: str = DEFAULT_CHAIN_HASH,
    content_hash: str = DEFAULT_CONTENT_HASH,
) -> Path:
    """Create a new FACT project without overwriting an existing project."""
    if not _PROJECT_ID.fullmatch(project_id):
        raise ToolkitError(
            "Project ID must contain only letters, digits, '.', '_' or '-'"
        )
    chain_hash = require_hash(chain_hash)
    content_hash = require_hash(content_hash)
    root.mkdir(parents=True, exist_ok=True)
    project_file = root / PROJECT_NAME
    if project_file.exists() or (root / ".fact").exists():
        raise ToolkitError(f"FACT project already exists at {root}")
    escaped_title = title.replace("\\", "\\\\").replace('"', '\\"')
    project_file.write_text(
        f'schema_version = {SCHEMA_VERSION}\nfact_version = "{__version__}"\n'
        f'project_id = "{project_id}"\ntitle = "{escaped_title}"\n\n'
        f'[integrity]\nchain_hash = "{chain_hash}"\ncontent_hash = "{content_hash}"\n',
        encoding="utf-8",
    )
    project_file.chmod(0o600)
    try:
        initialise_catalogue(
            root, project_id, chain_hash=chain_hash, content_hash=content_hash
        )
        (root / "cases").mkdir(mode=0o700)
        (root / "files").mkdir(mode=0o700)
        crypto = root / ".fact" / "crypto"
        crypto.mkdir(mode=0o700)
        (crypto / "operator-public-keyring").mkdir(mode=0o700)
    except Exception:
        shutil.rmtree(root / ".fact", ignore_errors=True)
        shutil.rmtree(root / "cases", ignore_errors=True)
        shutil.rmtree(root / "files", ignore_errors=True)
        project_file.unlink(missing_ok=True)
        raise
    return project_file


def initialise_owned_project(
    root: Path,
    project_id: str,
    title: str,
    owner: OperatorIdentity,
    owner_public_key: str,
    *,
    chain_hash: str = DEFAULT_CHAIN_HASH,
    content_hash: str = DEFAULT_CONTENT_HASH,
) -> Path:
    """Create a project whose first usable state includes a signed owner.

    Project creation and authority genesis are treated as one operator-facing
    operation. If the owner cannot sign the initial authority transaction, the
    incomplete project is removed rather than leaving an apparently usable
    ownerless project behind.
    """
    root.mkdir(parents=True, exist_ok=True)
    initialising = root / _INITIALISING_NAME
    if initialising.exists():
        raise ToolkitError(
            f"FACT initialisation marker already exists at {initialising}; "
            "inspect the directory before retrying rather than overwriting an interrupted setup"
        )
    initialising.write_text(
        "FACT project initialisation in progress\n", encoding="utf-8"
    )
    initialising.chmod(0o600)
    try:
        project_file = _initialise_project(
            root, project_id, title, chain_hash=chain_hash, content_hash=content_hash
        )
    except Exception:
        initialising.unlink(missing_ok=True)
        raise
    try:
        establish_project_genesis(root, owner, owner_public_key)
        # Initialisation is not considered complete merely because the genesis
        # write returned successfully. Reconstruct the authenticated project
        # state before removing the interruption marker.
        from .verification import verify_structural

        verify_structural(root, "project")
        (root / _INITIALISING_NAME).unlink()
    except Exception:
        # No evidential work is permitted before authority genesis completes, so
        # an unsuccessful bootstrap can safely unwind every path created by this
        # operation. Preserve the caller's project directory itself when it
        # existed before initialisation.
        shutil.rmtree(root / ".fact", ignore_errors=True)
        shutil.rmtree(root / "cases", ignore_errors=True)
        shutil.rmtree(root / "files", ignore_errors=True)
        project_file.unlink(missing_ok=True)
        (root / _INITIALISING_NAME).unlink(missing_ok=True)
        raise
    return project_file


def create_owned_case(
    project_root: Path,
    owner: OperatorIdentity,
    title: str = "",
    comment: str = "",
) -> str:
    """Create a case and bind its initial responsibility to the project owner."""
    identifier = create_case(project_root, title, comment)
    try:
        assign_case_owner(project_root, identifier, owner)
    except Exception as exc:
        with suppress(Exception):
            fail_identifier(project_root, identifier, str(exc))
        raise
    return identifier


def create_case(project_root: Path, title: str = "", comment: str = "") -> str:
    """Allocate a never-reused case ID and create its human-readable record."""
    identifier = issue_identifier(project_root, "case", "CASE")
    case_dir = project_root / "cases" / identifier
    try:
        case_dir.mkdir(parents=True, exist_ok=False)
        case_dir.chmod(0o700)

        def quote(value: str) -> str:
            return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

        (case_dir / "CASE.toml").write_text(
            f'schema_version = 1\ncase_id = "{identifier}"\n'
            f'title = "{quote(title)}"\ncomment = "{quote(comment)}"\n',
            encoding="utf-8",
        )
        (case_dir / "CASE.toml").chmod(0o600)
        (case_dir / "acquisitions").mkdir(mode=0o700)
        (case_dir / "files").mkdir(mode=0o700)
    except Exception as exc:
        # A case identifier is never returned to the sequence even when the
        # filesystem record could not be completed. This prevents a later case
        # from inheriting an identifier already observed in the audit history.
        with suppress(Exception):
            fail_identifier(project_root, identifier, str(exc))
        raise
    return identifier


def retire_case(project_root: Path, identifier: str, reason: str | None = None) -> None:
    """Retire a case ID while deliberately leaving case material untouched."""
    retire_identifier(project_root, identifier, reason)
