"""Create and locate FACT projects and their case records."""

from __future__ import annotations

import re
import shutil
from contextlib import suppress
from pathlib import Path

from ..errors import ToolkitError
from ..identity import OperatorIdentity
from .authority import assign_case_owner, establish_project_genesis
from .catalogue import (
    PROJECT_NAME,
    fail_identifier,
    initialise_catalogue,
    issue_identifier,
    retire_identifier,
)

_PROJECT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _initialise_project(root: Path, project_id: str, title: str) -> Path:
    """Create a new FACT project without overwriting an existing project."""
    if not _PROJECT_ID.fullmatch(project_id):
        raise ToolkitError(
            "Project ID must contain only letters, digits, '.', '_' or '-'"
        )
    root.mkdir(parents=True, exist_ok=True)
    project_file = root / PROJECT_NAME
    if project_file.exists() or (root / ".fact").exists():
        raise ToolkitError(f"FACT project already exists at {root}")
    escaped_title = title.replace("\\", "\\\\").replace('"', '\\"')
    project_file.write_text(
        f'schema_version = 5\nfact_version = "2.12.0"\nproject_id = "{project_id}"\ntitle = "{escaped_title}"\n',
        encoding="utf-8",
    )
    project_file.chmod(0o600)
    try:
        initialise_catalogue(root, project_id)
        (root / "cases").mkdir(mode=0o700)
        (root / "files").mkdir(mode=0o700)
    except Exception:
        project_file.unlink(missing_ok=True)
        raise
    return project_file


def initialise_owned_project(
    root: Path,
    project_id: str,
    title: str,
    owner: OperatorIdentity,
    owner_public_key: str,
) -> Path:
    """Create a project whose first usable state includes a signed owner.

    Project creation and authority genesis are treated as one operator-facing
    operation. If the owner cannot sign the initial authority transaction, the
    incomplete project is removed rather than leaving an apparently usable
    ownerless project behind.
    """
    project_file = _initialise_project(root, project_id, title)
    try:
        establish_project_genesis(root, owner, owner_public_key)
    except Exception:
        # No evidential work is permitted before authority genesis, so a failed
        # initial signature may safely unwind the newly-created empty project.
        shutil.rmtree(root / ".fact", ignore_errors=True)
        shutil.rmtree(root / "cases", ignore_errors=True)
        project_file.unlink(missing_ok=True)
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
