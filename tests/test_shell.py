"""Tests for FACT's interactive shell foundation."""

from __future__ import annotations

from pathlib import Path

import pytest

from fact.core.context import set_selected_case
from fact.core.project import create_case, initialise_project
from fact.errors import ToolkitError
from fact.shell.repl import _dispatch_line, run_shell
from fact.shell.session import ShellSession


def make_project(tmp_path: Path) -> tuple[Path, str]:
    """Create a small project suitable for shell-context tests."""

    root = tmp_path / "project"
    initialise_project(root, "P-1", "Project")
    case_id = create_case(root, "First case", "Comment")
    return root, case_id


def test_session_discovers_project_and_renders_context(tmp_path: Path) -> None:
    """Show project and selected-case context prominently in the prompt."""

    root, case_id = make_project(tmp_path)
    nested = root / "cases" / case_id / "acquisitions"
    session = ShellSession.from_start(nested)
    assert session.project_root == root
    assert session.prompt() == "P-1> "

    set_selected_case(root, case_id)
    assert session.prompt() == f"P-1 / {case_id}> "


def test_session_can_start_unbound_and_requires_explicit_project(tmp_path: Path) -> None:
    """Do not guess a project when the shell starts outside one."""

    session = ShellSession.from_start(tmp_path)
    assert session.prompt() == "fact> "
    with pytest.raises(ToolkitError, match="No FACT project is selected"):
        session.require_project()


def test_project_selection_and_clear_are_shell_context_operations(tmp_path: Path) -> None:
    """Bind and clear project context without invoking evidential handlers."""

    root, _ = make_project(tmp_path)
    session = ShellSession()
    output: list[str] = []
    dispatched: list[list[str]] = []

    assert _dispatch_line(
        session,
        ["select", "project", str(root)],
        lambda argv: dispatched.append(list(argv)) or 0,
        output.append,
    )
    assert session.project_root == root
    assert dispatched == []
    assert output[-1].startswith("Selected project: P-1")

    assert _dispatch_line(session, ["project", "clear"], lambda argv: 0, output.append)
    assert session.project_root is None


def test_project_commands_are_dispatched_with_selected_root(tmp_path: Path) -> None:
    """Reuse the ordinary CLI argument contract rather than a parallel shell API."""

    root, _ = make_project(tmp_path)
    session = ShellSession(project_root=root)
    calls: list[list[str]] = []

    assert _dispatch_line(
        session,
        ["acquire", "screenshot"],
        lambda argv: calls.append(list(argv)) or 0,
        lambda _: None,
    )
    assert calls == [["--root", str(root), "acquire", "screenshot"]]


def test_verify_is_available_without_project_context() -> None:
    """Archive verification does not require a selected working project."""

    session = ShellSession()
    calls: list[list[str]] = []
    assert _dispatch_line(
        session,
        ["verify", "evidence.7z"],
        lambda argv: calls.append(list(argv)) or 0,
        lambda _: None,
    )
    assert calls == [["verify", "evidence.7z"]]


def test_shell_help_context_parse_errors_interrupt_and_exit(tmp_path: Path) -> None:
    """Keep malformed input and Ctrl-C inside the shell and exit cleanly."""

    root, _ = make_project(tmp_path)
    events = iter([KeyboardInterrupt(), '"unterminated', "context", "help", "exit"])
    output: list[str] = []

    def fake_input(prompt: str) -> str:
        event = next(events)
        if isinstance(event, BaseException):
            raise event
        return event

    assert (
        run_shell(
            start=root,
            dispatch=lambda argv: 0,
            input_fn=fake_input,
            output_fn=output.append,
            show_banner=False,
        )
        == 0
    )
    assert "^C" in output
    assert any(line.startswith("ERROR:") for line in output)
    assert any(line.startswith("Project: P-1") for line in output)
    assert any("FACT interactive shell" in line for line in output)


def test_shell_eof_exits_cleanly(tmp_path: Path) -> None:
    """Treat EOF as a normal shell exit."""

    output: list[str] = []

    def eof(_: str) -> str:
        raise EOFError

    assert run_shell(start=tmp_path, dispatch=lambda argv: 0, input_fn=eof, output_fn=output.append) == 0


def test_nested_shell_is_refused() -> None:
    """Prevent accidental recursive REPL sessions."""

    with pytest.raises(ToolkitError, match="already active"):
        _dispatch_line(ShellSession(), ["shell"], lambda argv: 0, lambda _: None)


def test_stale_case_selection_is_visible_in_prompt(tmp_path: Path) -> None:
    """Expose invalid persisted case context instead of silently hiding it."""

    root, case_id = make_project(tmp_path)
    set_selected_case(root, case_id)
    from fact.core.project import retire_case

    retire_case(root, case_id, "done")
    session = ShellSession(project_root=root)
    assert session.prompt() == "P-1 / !invalid-case> "


def test_context_display_handles_stale_case_selection(tmp_path: Path) -> None:
    """Keep the shell usable when persisted case selection becomes stale."""

    root, case_id = make_project(tmp_path)
    set_selected_case(root, case_id)
    from fact.core.project import retire_case

    retire_case(root, case_id, "done")
    output: list[str] = []
    assert _dispatch_line(
        ShellSession(project_root=root),
        ["context"],
        lambda argv: 0,
        output.append,
    )
    assert output[-1] == "Case:    invalid selection; run 'case select'"
