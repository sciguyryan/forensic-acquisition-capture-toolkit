"""Tests for command-line argument parsing."""

from fact.cli import parser


def test_acquisition_context_and_comment_are_optional_at_parse_time() -> None:
    """Allow project/case context to supply identifiers and default comments."""
    args = parser().parse_args(["acquire", "youtube", "https://example.test"])
    assert args.case_id is None
    assert args.acquisition_comment is None
    assert args.operator_id is None


def test_explicit_operator_id_is_global_project_context() -> None:
    """Accept a project-retained operator identifier for signed operations."""
    args = parser().parse_args(
        ["--operator-id", "jane", "acquire", "youtube", "https://example.test"]
    )
    assert args.operator_id == "jane"


def test_project_init_arguments() -> None:
    """Parse signed project creation options through the current project command."""
    args = parser().parse_args(
        [
            "project",
            "init",
            "/evidence",
            "--project-id",
            "P-1",
            "--title",
            "Matter",
            "--test-key",
        ]
    )
    assert args.command == "project"
    assert args.project_command == "init"
    assert args.test_key is True


def test_explicit_youtube_collector_syntax() -> None:
    """Accept collector-oriented YouTube acquisition syntax."""
    args = parser().parse_args(
        ["acquire", "youtube", "https://youtu.be/abc", "--case-id", "CASE-1"]
    )
    assert args.source == "youtube"
    assert args.target == "https://youtu.be/abc"


def test_screenshot_collector_syntax_has_no_positional_target() -> None:
    """Accept interactive screenshot acquisition with a window target by default."""
    args = parser().parse_args(["acquire", "screenshot", "--case-id", "CASE-1"])
    assert args.source == "screenshot"
    assert args.target is None
    assert args.screenshot_target == "window"


def test_help_command_parses_topic() -> None:
    """Expose explicit command help alongside conventional --help syntax."""
    args = parser().parse_args(["help", "case", "select"])
    assert args.command == "help"
    assert args.topic == ["case", "select"]


def test_shell_no_history_option() -> None:
    """Allow operators to disable persistent shell history explicitly."""
    args = parser().parse_args(["shell", "--no-history"])
    assert args.command == "shell"
    assert args.no_history is True
