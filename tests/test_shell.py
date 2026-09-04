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


def test_session_can_start_unbound_and_requires_explicit_project(
    tmp_path: Path,
) -> None:
    """Do not guess a project when the shell starts outside one."""

    session = ShellSession.from_start(tmp_path)
    assert session.prompt() == "fact> "
    with pytest.raises(ToolkitError, match="No FACT project is selected"):
        session.require_project()


def test_project_selection_and_clear_are_shell_context_operations(
    tmp_path: Path,
) -> None:
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

    assert (
        run_shell(
            start=tmp_path,
            dispatch=lambda argv: 0,
            input_fn=eof,
            output_fn=output.append,
        )
        == 0
    )


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


def test_project_registry_resolves_unique_registered_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Resolve a project ID only after an explicit path has registered it."""

    from fact.shell.registry import register_project, resolve_registered_project

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    root, _ = make_project(tmp_path)
    project_id, registered = register_project(root)
    assert project_id == "P-1"
    assert registered == root.resolve()
    assert resolve_registered_project("P-1") == root.resolve()


def test_project_registry_refuses_unknown_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Never guess a path for a project ID absent from validated local state."""

    from fact.shell.registry import resolve_registered_project

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    with pytest.raises(ToolkitError, match="No validated project"):
        resolve_registered_project("UNKNOWN")


def test_project_registry_refuses_ambiguous_duplicate_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Require an explicit path when two validated projects share an ID."""

    from fact.shell.registry import register_project, resolve_registered_project

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    first = tmp_path / "first"
    second = tmp_path / "second"
    initialise_project(first, "DUPLICATE", "First")
    initialise_project(second, "DUPLICATE", "Second")
    register_project(first)
    register_project(second)
    with pytest.raises(ToolkitError, match="ambiguous"):
        resolve_registered_project("DUPLICATE")


def test_shell_selects_registered_project_by_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Allow convenient project-ID selection after an explicit trusted encounter."""

    from fact.shell.registry import register_project

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    root, _ = make_project(tmp_path)
    register_project(root)
    session = ShellSession()
    output: list[str] = []
    assert _dispatch_line(
        session,
        ["project", "select", "P-1"],
        lambda argv: 0,
        output.append,
    )
    assert session.project_root == root.resolve()


def test_shell_projects_lists_validated_registry_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """List only locally registered project discovery hints."""

    from fact.shell.registry import register_project

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    root, _ = make_project(tmp_path)
    register_project(root)
    output: list[str] = []
    assert _dispatch_line(
        ShellSession(),
        ["projects"],
        lambda argv: 0,
        output.append,
    )
    assert output == [f"P-1\t{root.resolve()}"]


def test_command_specific_shell_help_uses_canonical_dispatcher() -> None:
    """Route contextual help to the same parser used by ordinary CLI calls."""

    calls: list[list[str]] = []
    assert _dispatch_line(
        ShellSession(),
        ["help", "acquire"],
        lambda argv: calls.append(list(argv)) or 0,
        lambda _: None,
    )
    assert calls == [["help", "acquire"]]


def test_history_filter_excludes_sensitive_commands() -> None:
    """Keep obvious secret-bearing commands out of persistent local history."""

    from fact.shell.interactive import should_retain_history

    assert should_retain_history("case list")
    assert not should_retain_history("   ")
    assert not should_retain_history("command --token abc")
    assert not should_retain_history("export-keypair")


def test_shell_operator_authentication_context_and_logout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Require and expose cryptographic operator context inside the interactive shell."""
    from fact.core.authority import AuthenticatedOperator
    from fact.shell import repl as repl_module

    root, _ = make_project(tmp_path)
    session = ShellSession(project_root=root)
    authenticated = AuthenticatedOperator("jane", "F" * 40, "2026-09-04T12:00:00Z", "a" * 64)
    output: list[str] = []

    assert _dispatch_line(session, ["whoami"], lambda argv: 0, output.append)
    assert output[-1] == "Operator: not authenticated"

    # Dataclass slot instances cannot have methods rebound in-place, so exercise
    # the command path with a small session subclass that preserves real state.
    class AuthenticatingSession(ShellSession):
        def authenticate(self):
            self.authenticated_operator = authenticated
            return authenticated

    session = AuthenticatingSession(project_root=root)
    assert _dispatch_line(session, ["auth"], lambda argv: 0, output.append)
    assert session.authenticated_operator == authenticated
    assert "Authenticated operator: jane" in output[-1]
    assert _dispatch_line(session, ["whoami"], lambda argv: 0, output.append)
    assert "Operator: jane" in output[-1]
    assert _dispatch_line(session, ["logout"], lambda argv: 0, output.append)
    assert session.authenticated_operator is None

    monkeypatch.setattr(repl_module, "authority_enabled", lambda project_root: True)
    with pytest.raises(ToolkitError, match="requires an authenticated operator"):
        _dispatch_line(
            ShellSession(project_root=root),
            ["acquire", "screenshot"],
            lambda argv: 0,
            output.append,
        )


def test_session_authenticate_uses_project_local_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bind shell authentication to the local signer and retained project identity."""
    from fact.core.authority import AuthenticatedOperator
    from fact.identity import OperatorIdentity
    from fact.shell import session as session_module

    root, _ = make_project(tmp_path)
    identity = OperatorIdentity(1, "jane", "Jane", None, None, None, "A" * 40, "B" * 40)
    expected = AuthenticatedOperator("jane", "B" * 40, "2026-09-04T12:00:00Z", "c" * 64)
    monkeypatch.setattr(
        session_module,
        "resolve_identity",
        lambda project_root, override: (identity, root / "operators/jane.json", "active"),
    )
    monkeypatch.setattr(
        session_module,
        "authenticate_operator_session",
        lambda project_root, operator: expected,
    )
    session = ShellSession(project_root=root)
    assert session.authenticate() == expected
    assert session.require_authenticated_operator() == expected
    session.logout_operator()
    with pytest.raises(ToolkitError, match="run 'auth' first"):
        session.require_authenticated_operator()
