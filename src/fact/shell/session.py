"""Hold transient interactive-shell context.

Shell context is operator convenience state, not evidence. The selected case is
still persisted through FACT's existing project-local selection mechanism so a
shell command and an ordinary CLI command resolve the same active case.
"""

from __future__ import annotations

import tomllib
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from ..core.authority import (
    AuthenticatedOperator,
    authenticate_operator_session,
)
from ..core.context import discover_project_root, get_selected_case
from ..errors import ToolkitError
from ..identity import resolve_identity
from .registry import register_project, resolve_registered_project


@dataclass(slots=True)
class ShellSession:
    """Represent the project currently bound to one interactive shell session."""

    project_root: Path | None = None
    authenticated_operator: AuthenticatedOperator | None = None

    @classmethod
    def from_start(cls, start: Path) -> ShellSession:
        """Create a session and bind the containing FACT project when possible.

        Starting outside a project is valid. The operator can bind a project
        explicitly later without the shell guessing which project was intended.
        """

        try:
            project_root = discover_project_root(start)
        except ToolkitError:
            project_root = None
        session = cls(project_root=project_root)
        if project_root is not None:
            with suppress(ToolkitError):
                register_project(project_root)
        return session

    def bind_project(self, path: Path) -> Path:
        """Bind an existing FACT project selected explicitly by the operator."""

        self.project_root = discover_project_root(path)
        self.authenticated_operator = None
        with suppress(ToolkitError):
            register_project(self.project_root)
        return self.project_root

    def bind_project_selector(self, selector: str) -> Path:
        """Bind a project by explicit path or a uniquely registered project ID."""

        candidate = Path(selector).expanduser()
        if candidate.exists() or candidate.is_absolute() or "/" in selector:
            return self.bind_project(candidate)
        self.project_root = resolve_registered_project(selector)
        self.authenticated_operator = None
        return self.project_root

    def clear_project(self) -> None:
        """Clear only shell context; project files and selected-case state remain."""

        self.project_root = None
        self.authenticated_operator = None

    def authenticate(self) -> AuthenticatedOperator:
        """Authenticate the active local operator against project-retained identity."""

        project_root = self.require_project()
        identity, _, _ = resolve_identity(project_root, None)
        authenticated = authenticate_operator_session(project_root, identity)
        self.authenticated_operator = authenticated
        return authenticated

    def logout_operator(self) -> None:
        """Clear transient shell authentication without changing project identity."""

        self.authenticated_operator = None

    def require_authenticated_operator(self) -> AuthenticatedOperator:
        """Return current shell authentication or fail closed."""

        if self.authenticated_operator is None:
            raise ToolkitError(
                "This project operation requires an authenticated operator; run 'auth' first"
            )
        return self.authenticated_operator

    def project_id(self) -> str | None:
        """Return the human-readable project ID from ``PROJECT.toml``."""

        if self.project_root is None:
            return None
        project_file = self.project_root / "PROJECT.toml"
        try:
            data = tomllib.loads(project_file.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ToolkitError(
                f"Unable to read FACT project record: {project_file}"
            ) from exc
        project_id = str(data.get("project_id", "")).strip()
        if not project_id:
            raise ToolkitError(f"FACT project record has no project_id: {project_file}")
        return project_id

    def case_id(self) -> str | None:
        """Return the current active case ID, if the project has one selected."""

        if self.project_root is None:
            return None
        selected = get_selected_case(self.project_root)
        return selected.case_id if selected is not None else None

    def prompt(self) -> str:
        """Render context prominently so operators see the target before acting."""

        project_id = self.project_id()
        if project_id is None:
            return "fact> "
        try:
            case_id = self.case_id()
        except ToolkitError:
            # A stale selection is made visually obvious rather than silently
            # discarded. The operator can still run ``case select`` to replace
            # it with an active case.
            return f"{project_id} / !invalid-case> "
        if case_id is None:
            return f"{project_id}> "
        return f"{project_id} / {case_id}> "

    def require_project(self) -> Path:
        """Return the bound project or fail instead of inferring hidden context."""

        if self.project_root is None:
            raise ToolkitError(
                "No FACT project is selected; use 'project select PATH' first"
            )
        return self.project_root
