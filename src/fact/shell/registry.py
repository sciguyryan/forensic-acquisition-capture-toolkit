"""Maintain trusted local project-discovery hints for the interactive shell.

The registry is operational convenience state rather than evidence. Entries are
therefore always revalidated against the project's canonical ``PROJECT.toml``
before use, and duplicate project IDs are treated as ambiguous rather than
silently selecting one path.
"""

from __future__ import annotations

import json
import os
import tomllib
from contextlib import suppress
from pathlib import Path

from ..core.context import discover_project_root
from ..errors import ToolkitError

_REGISTRY_VERSION = 1


def state_directory() -> Path:
    """Return FACT's per-user local state directory without creating it."""

    override = os.environ.get("XDG_STATE_HOME")
    if override:
        return Path(override).expanduser() / "fact"
    return Path.home() / ".local" / "state" / "fact"


def registry_path() -> Path:
    """Return the local shell project-registry path."""

    return state_directory() / "projects.json"


def history_path() -> Path:
    """Return the local interactive-shell history path."""

    return state_directory() / "shell_history"


def _project_id(root: Path) -> str:
    """Read the canonical project ID from a validated FACT project root."""

    project_file = root / "PROJECT.toml"
    try:
        data = tomllib.loads(project_file.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ToolkitError(
            f"Unable to read FACT project record: {project_file}"
        ) from exc
    identifier = str(data.get("project_id", "")).strip()
    if not identifier:
        raise ToolkitError(f"FACT project record has no project_id: {project_file}")
    return identifier


def _load() -> dict[str, list[str]]:
    """Load registry data, failing closed on malformed local state."""

    path = registry_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolkitError(
            f"Unable to read FACT shell project registry: {path}"
        ) from exc
    if data.get("version") != _REGISTRY_VERSION or not isinstance(
        data.get("projects"), dict
    ):
        raise ToolkitError(f"Unsupported FACT shell project registry: {path}")
    projects: dict[str, list[str]] = {}
    for project_id, paths in data["projects"].items():
        if not isinstance(project_id, str) or not isinstance(paths, list):
            raise ToolkitError(f"Malformed FACT shell project registry: {path}")
        projects[project_id] = [item for item in paths if isinstance(item, str)]
    return projects


def _write(projects: dict[str, list[str]]) -> None:
    """Write local registry state atomically with owner-only permissions."""

    path = registry_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with suppress(OSError):
        path.parent.chmod(0o700)
    temporary = path.with_suffix(".tmp")
    payload = {"version": _REGISTRY_VERSION, "projects": projects}
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def register_project(path: Path) -> tuple[str, Path]:
    """Register an explicitly encountered project path as a discovery hint."""

    root = discover_project_root(path).resolve()
    project_id = _project_id(root)
    projects = _load()
    known = projects.setdefault(project_id, [])
    value = str(root)
    if value not in known:
        known.append(value)
        known.sort()
        _write(projects)
    return project_id, root


def registered_projects() -> dict[str, list[Path]]:
    """Return only currently valid registry entries, without guessing ambiguity."""

    result: dict[str, list[Path]] = {}
    for project_id, paths in _load().items():
        valid: list[Path] = []
        for item in paths:
            candidate = Path(item)
            try:
                root = discover_project_root(candidate).resolve()
                if _project_id(root) == project_id and root not in valid:
                    valid.append(root)
            except ToolkitError:
                continue
        if valid:
            result[project_id] = valid
    return result


def resolve_registered_project(project_id: str) -> Path:
    """Resolve a project ID only when exactly one validated path is registered."""

    matches = registered_projects().get(project_id, [])
    if not matches:
        raise ToolkitError(
            f"No validated project is registered as {project_id}; "
            "select it by path first"
        )
    if len(matches) > 1:
        choices = ", ".join(str(item) for item in matches)
        raise ToolkitError(
            f"Project ID {project_id} is ambiguous across registered paths: {choices}"
        )
    return matches[0]
