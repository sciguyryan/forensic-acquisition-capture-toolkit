"""Resolve project and case context without asking operators to transcribe IDs.

FACT deliberately separates identifier *allocation* from identifier *selection*.
Case and acquisition identifiers are catalogue-owned values.  Operators should
normally select a meaningful case by location or title rather than repeatedly
typing an identifier that can be mistyped while still referring to another
valid case.
"""

from __future__ import annotations

import os
import sys
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..errors import ToolkitError
from .catalogue import (
    CATALOGUE_DIR,
    PROJECT_NAME,
    SCHEMA_VERSION,
    list_identifiers,
)

_SELECTED_CASE_NAME = "selected-case"


def _require_current_project(project_root: Path) -> None:
    """Reject projects created under a different FACT trust architecture."""
    project_file = project_root / PROJECT_NAME
    try:
        data = tomllib.loads(project_file.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ToolkitError(
            f"Unable to read FACT project record: {project_file}"
        ) from exc
    schema = data.get("schema_version")
    if schema != SCHEMA_VERSION:
        raise ToolkitError(
            "This project belongs to a different FACT project schema and must be "
            "handled with the FACT version under which it was created; active "
            "legacy projects are not upgraded in place"
        )


@dataclass(slots=True, frozen=True)
class CaseContext:
    """Human-readable case metadata used when preparing an acquisition."""

    case_id: str
    title: str
    comment: str
    path: Path


def discover_project_root(start: Path) -> Path:
    """Return the nearest containing FACT project root.

    Project discovery walks upwards from the supplied path so commands may be
    run from the project root, a case directory, or an acquisition-related
    subdirectory without changing the evidential project that FACT operates on.
    """

    candidate = start.expanduser().resolve()
    if candidate.is_file():
        candidate = candidate.parent
    for path in (candidate, *candidate.parents):
        if (path / ".fact-initialising").exists():
            raise ToolkitError(
                f"FACT project initialisation is incomplete at {path}; "
                "inspect or clean up the interrupted bootstrap before continuing"
            )
        if (path / PROJECT_NAME).is_file() and (
            path / CATALOGUE_DIR / "catalogue.sqlite"
        ).is_file():
            _require_current_project(path)
            return path
    raise ToolkitError(f"No FACT project found at or above: {start}")


def _read_case_file(path: Path) -> CaseContext:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ToolkitError(f"Unable to read FACT case record: {path}") from exc
    case_id = str(data.get("case_id", "")).strip()
    if not case_id:
        raise ToolkitError(f"FACT case record has no case_id: {path}")
    return CaseContext(
        case_id=case_id,
        title=str(data.get("title", "")),
        comment=str(data.get("comment", "")),
        path=path.parent,
    )


def read_case_context(project_root: Path, case_id: str) -> CaseContext:
    """Read one case record and require that its directory matches its ID."""

    path = project_root / "cases" / case_id / "CASE.toml"
    if not path.is_file():
        raise ToolkitError(f"FACT case record does not exist: {case_id}")
    context = _read_case_file(path)
    if context.case_id != case_id:
        raise ToolkitError(
            f"FACT case directory and CASE.toml identifier disagree: {case_id} / {context.case_id}"
        )
    return context


def active_case_contexts(project_root: Path) -> list[CaseContext]:
    """Return active cases in catalogue sequence order with readable metadata."""

    active: list[CaseContext] = []
    for row in list_identifiers(project_root, "case"):
        if row["state"] == "active":
            active.append(read_case_context(project_root, str(row["identifier"])))
    return active


def _require_active(project_root: Path, case_id: str) -> CaseContext:
    rows = {
        str(row["identifier"]): row for row in list_identifiers(project_root, "case")
    }
    row = rows.get(case_id)
    if row is None:
        raise ToolkitError(f"Unknown FACT case: {case_id}")
    if row["state"] != "active":
        raise ToolkitError(f"FACT case is not active: {case_id} ({row['state']})")
    return read_case_context(project_root, case_id)


def infer_case_from_path(project_root: Path, current: Path) -> CaseContext | None:
    """Infer a case when ``current`` is within that case's directory tree."""

    current = current.expanduser().resolve()
    for path in (current, *current.parents):
        if path == project_root:
            break
        case_file = path / "CASE.toml"
        if case_file.is_file():
            context = _read_case_file(case_file)
            expected = project_root / "cases" / context.case_id
            if path.resolve() != expected.resolve():
                raise ToolkitError(
                    f"CASE.toml is outside its canonical project case path: {path}"
                )
            return _require_active(project_root, context.case_id)
    return None


def selected_case_path(project_root: Path) -> Path:
    """Return the project-local pointer used for an explicitly selected case."""

    return project_root / CATALOGUE_DIR / _SELECTED_CASE_NAME


def set_selected_case(project_root: Path, case_id: str) -> CaseContext:
    """Persist an active case selection without changing the case itself."""

    context = _require_active(project_root, case_id)
    path = selected_case_path(project_root)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(case_id + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)
    return context


def clear_selected_case(project_root: Path) -> None:
    """Remove transient case-selection state without altering case evidence."""

    selected_case_path(project_root).unlink(missing_ok=True)


def get_selected_case(project_root: Path) -> CaseContext | None:
    """Return the selected case, rejecting stale pointers to retired cases."""

    path = selected_case_path(project_root)
    if not path.exists():
        return None
    case_id = path.read_text(encoding="utf-8").strip()
    if not case_id:
        raise ToolkitError("FACT selected-case pointer is empty")
    try:
        return _require_active(project_root, case_id)
    except ToolkitError as exc:
        raise ToolkitError(
            f"FACT selected case is no longer usable ({case_id}); run 'fact case select' again"
        ) from exc


def choose_case_interactively(
    project_root: Path,
    *,
    input_fn: Callable[[str], str] = input,
) -> CaseContext:
    """Present active cases as a numbered list and persist the chosen case."""

    cases = active_case_contexts(project_root)
    if not cases:
        raise ToolkitError("FACT project has no active cases; create a case first")
    print("Active FACT cases:")
    for number, case in enumerate(cases, start=1):
        title = case.title or "Untitled case"
        print(f"  {number}. {case.case_id}  {title}")
    response = input_fn("Select case number: ").strip()
    try:
        index = int(response)
    except ValueError as exc:
        raise ToolkitError(
            "Case selection must be a number from the displayed list"
        ) from exc
    if not 1 <= index <= len(cases):
        raise ToolkitError("Case selection is outside the displayed range")
    return set_selected_case(project_root, cases[index - 1].case_id)


def resolve_case_context(
    project_root: Path,
    *,
    explicit_case_id: str | None = None,
    current: Path | None = None,
    interactive: bool | None = None,
    input_fn: Callable[[str], str] = input,
) -> CaseContext:
    """Resolve an acquisition case conservatively and without guessing.

    Resolution precedence is deliberately stable: an explicit ID, path
    context, a persisted selection, the sole active case, then an interactive
    numbered selector.  Multiple active cases never cause an arbitrary choice.
    """

    if explicit_case_id:
        return _require_active(project_root, explicit_case_id)

    inferred = infer_case_from_path(project_root, current or Path.cwd())
    if inferred is not None:
        return inferred

    selected = get_selected_case(project_root)
    if selected is not None:
        return selected

    active = active_case_contexts(project_root)
    if len(active) == 1:
        return active[0]
    if not active:
        raise ToolkitError("FACT project has no active cases; create a case first")

    if interactive is None:
        interactive = sys.stdin.isatty()
    if interactive:
        return choose_case_interactively(project_root, input_fn=input_fn)

    raise ToolkitError(
        "Multiple active cases exist and none is selected; run 'fact case select' "
        "or execute the command from within the intended case directory"
    )
