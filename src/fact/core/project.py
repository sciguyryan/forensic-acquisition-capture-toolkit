"""Create and locate FACT projects and their case records."""

from __future__ import annotations

import re
from pathlib import Path

from .catalogue import PROJECT_NAME, initialise_catalogue, issue_identifier, retire_identifier
from ..errors import ToolkitError

_PROJECT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def initialise_project(root: Path, project_id: str, title: str) -> Path:
    """Create a new FACT project without overwriting an existing project."""
    if not _PROJECT_ID.fullmatch(project_id):
        raise ToolkitError("Project ID must contain only letters, digits, '.', '_' or '-'")
    root.mkdir(parents=True, exist_ok=True)
    project_file = root / PROJECT_NAME
    if project_file.exists() or (root / ".fact").exists():
        raise ToolkitError(f"FACT project already exists at {root}")
    escaped_title = title.replace("\\", "\\\\").replace('"', '\\"')
    project_file.write_text(
        f'schema_version = 1\nproject_id = "{project_id}"\ntitle = "{escaped_title}"\n',
        encoding="utf-8",
    )
    project_file.chmod(0o600)
    try:
        initialise_catalogue(root, project_id)
        (root / "cases").mkdir(mode=0o700)
    except Exception:
        project_file.unlink(missing_ok=True)
        raise
    return project_file


def create_case(project_root: Path, title: str = "", comment: str = "") -> str:
    """Allocate a never-reused case ID and create its human-readable record."""
    identifier = issue_identifier(project_root, "case", "CASE")
    case_dir = project_root / "cases" / identifier
    case_dir.mkdir(parents=True, exist_ok=False)
    case_dir.chmod(0o700)
    def quote(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    (case_dir / "CASE.toml").write_text(
        f'schema_version = 1\ncase_id = "{identifier}"\ntitle = "{quote(title)}"\ncomment = "{quote(comment)}"\n',
        encoding="utf-8",
    )
    (case_dir / "CASE.toml").chmod(0o600)
    (case_dir / "acquisitions").mkdir(mode=0o700)
    return identifier


def retire_case(project_root: Path, identifier: str, reason: str | None = None) -> None:
    """Retire a case ID while deliberately leaving case material untouched."""
    retire_identifier(project_root, identifier, reason)
