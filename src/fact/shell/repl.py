"""Implement FACT's small interactive read-evaluate-print loop.

This module deliberately does not perform acquisitions, catalogue mutations,
cryptographic operations, or packaging itself. It translates shell input into
normal FACT command arguments and invokes an injected in-process dispatcher.
That boundary prevents shell convenience features from becoming an alternative
and potentially divergent evidential code path.
"""

from __future__ import annotations

import shlex
from collections.abc import Callable, Sequence
from contextlib import suppress
from pathlib import Path

from ..core.catalogue import list_identifiers
from ..errors import ToolkitError
from .interactive import ReadlineFeatures
from .registry import registered_projects
from .session import ShellSession

Dispatch = Callable[[Sequence[str]], int]
Input = Callable[[str], str]
Output = Callable[[str], None]

_HELP = """FACT interactive shell

Context:
  context                         Show the selected project and case
  project select PATH|PROJECT-ID  Select an existing FACT project
  projects                        Show validated locally registered projects
  select project PATH             Alias for project select
  project clear                   Leave the current project context
  case select [CASE-ID]           Select a case (numbered selector if omitted)
  select case [CASE-ID]           Alias for case select
  case current                    Show the current case
  case list                       List project cases

Operations:
  acquire ...                     Run a collector in the selected project
  catalogue ...                   Run catalogue operations
  package ...                     Package the selected project
  verify ...                      Verify an evidence archive
  project init ...                Create a project using the normal FACT command

Shell:
  help [COMMAND ...]              Show shell or command-specific help
  exit | quit                     Leave the shell

Future case ownership, notes, audit/seal/package lifecycle operations and
review commands will plug into this same dispatcher rather than a second CLI.
"""


def _with_root(project_root: Path, tokens: Sequence[str]) -> list[str]:
    """Prepend the selected project root using the existing global CLI option."""

    return ["--root", str(project_root), *tokens]


def _show_context(session: ShellSession, output_fn: Output) -> None:
    """Display context in a form suitable for an operator sanity check."""

    if session.project_root is None:
        output_fn("Project: none")
        output_fn("Case:    none")
        return
    output_fn(f"Project: {session.project_id()} ({session.project_root})")
    try:
        case_id = session.case_id()
    except ToolkitError:
        output_fn("Case:    invalid selection; run 'case select'")
    else:
        output_fn(f"Case:    {case_id or 'none selected'}")


def _normalise_aliases(tokens: list[str]) -> list[str]:
    """Convert shell-friendly selection aliases to the canonical command shape."""

    if len(tokens) >= 2 and tokens[0] == "select" and tokens[1] in {"project", "case"}:
        return [tokens[1], "select", *tokens[2:]]
    return tokens


def _dispatch_line(
    session: ShellSession,
    tokens: list[str],
    dispatch: Dispatch,
    output_fn: Output,
) -> bool:
    """Dispatch one parsed line and return ``False`` when the shell should exit."""

    if not tokens:
        return True
    tokens = _normalise_aliases(tokens)
    command = tokens[0]

    if command in {"exit", "quit"}:
        return False
    if command == "help":
        if len(tokens) == 1:
            output_fn(_HELP.rstrip())
        else:
            dispatch(["help", *tokens[1:]])
        return True
    if command == "projects":
        projects = registered_projects()
        if not projects:
            output_fn("No validated projects are registered")
        for project_id, paths in projects.items():
            if len(paths) == 1:
                output_fn(f"{project_id}\t{paths[0]}")
            else:
                output_fn(f"{project_id}\tambiguous ({len(paths)} paths)")
        return True
    if command == "context":
        _show_context(session, output_fn)
        return True
    if command == "shell":
        raise ToolkitError("A FACT shell is already active")

    # Project selection changes shell convenience context only. It does not
    # mutate the project or its catalogue, and therefore needs no CLI dispatch.
    if tokens[:2] == ["project", "select"]:
        if len(tokens) != 3:
            raise ToolkitError("Usage: project select PATH|PROJECT-ID")
        root = session.bind_project_selector(tokens[2])
        output_fn(f"Selected project: {session.project_id()} ({root})")
        try:
            case_id = session.case_id()
        except ToolkitError:
            output_fn("Selected case is invalid; run 'case select'")
        else:
            if case_id is not None:
                output_fn(f"Selected case: {case_id}")
        return True
    if tokens[:2] == ["project", "clear"]:
        if len(tokens) != 2:
            raise ToolkitError("Usage: project clear")
        session.clear_project()
        output_fn("Project context cleared")
        return True

    # Project creation is valid without an already selected project. On success
    # we bind the newly created project when its path can be determined from the
    # canonical ``project init`` argument grammar.
    if tokens[:2] == ["project", "init"]:
        status = dispatch(tokens)
        if status == 0:
            # In the canonical grammar the optional path, when present, is the
            # first token after ``project init``. Option values such as the
            # project ID and title must never be mistaken for filesystem paths.
            positional_path = (
                Path(tokens[2])
                if len(tokens) > 2 and not tokens[2].startswith("-")
                else Path.cwd()
            )
            # Project creation has already reported success. Failure to bind
            # shell context must not be misreported as failed project
            # initialisation; the operator can select it later.
            with suppress(ToolkitError):
                session.bind_project(positional_path)
        return True

    # Archive verification is deliberately usable without project context.
    if command == "verify":
        dispatch(tokens)
        return True

    project_root = session.require_project()
    dispatch(_with_root(project_root, tokens))
    return True


def _completion_candidates(session: ShellSession, text: str) -> list[str]:
    """Return conservative command/project completions for the current token."""

    commands = [
        "acquire",
        "case",
        "catalogue",
        "context",
        "exit",
        "help",
        "package",
        "project",
        "projects",
        "quit",
        "select",
        "verify",
        "checkpoint",
        "clear",
        "create",
        "current",
        "init",
        "list",
        "retire",
        "screenshot",
        "youtube",
    ]
    candidates = commands
    if text:
        candidates = [item for item in candidates if item.startswith(text)]
    return candidates


def _readline_candidates(session: ShellSession, text: str) -> list[str]:
    """Add registered project IDs to ordinary command completion candidates."""

    candidates = _completion_candidates(session, text)
    candidates.extend(
        project_id
        for project_id in registered_projects()
        if not text or project_id.startswith(text)
    )
    if session.project_root is not None:
        with suppress(ToolkitError):
            candidates.extend(
                str(item["identifier"])
                for item in list_identifiers(session.project_root, "case")
                if item["state"] == "active"
                and (not text or str(item["identifier"]).startswith(text))
            )
    return candidates


def run_shell(
    *,
    start: Path,
    dispatch: Dispatch,
    input_fn: Input = input,
    output_fn: Output = print,
    show_banner: bool = True,
    history_enabled: bool = True,
) -> int:
    """Run the FACT interactive shell until EOF, ``exit`` or ``quit``.

    ``Ctrl-C`` cancels the current input and returns to a fresh prompt. EOF exits
    cleanly. Unexpected exceptions are not swallowed; only user-facing
    ``ToolkitError`` failures are converted to shell messages here.
    """

    session = ShellSession.from_start(start)
    if show_banner:
        output_fn("FACT interactive shell. Type 'help' for commands.")
        _show_context(session, output_fn)

    interactive = ReadlineFeatures(
        lambda text: _readline_candidates(session, text),
        enabled=input_fn is input,
        history_enabled=history_enabled,
    )
    with interactive:
        while True:
            interactive.before_input()
            try:
                line = input_fn(session.prompt())
            except EOFError:
                output_fn("")
                return 0
            except KeyboardInterrupt:
                output_fn("^C")
                continue
            interactive.after_input(line)

            try:
                tokens = shlex.split(line, posix=True)
            except ValueError as exc:
                output_fn(f"ERROR: {exc}")
                continue

            try:
                keep_running = _dispatch_line(session, tokens, dispatch, output_fn)
            except ToolkitError as exc:
                output_fn(f"ERROR: {exc}")
                continue
            if not keep_running:
                return 0
