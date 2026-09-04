"""Tests for command-line argument parsing."""

from fact.cli import parser


def test_case_context_and_comment_are_optional_at_parse_time() -> None:
    """Allow project/case context to supply identifiers and default comments."""
    args = parser().parse_args(["acquire", "https://example.test"])
    assert args.case_id is None
    assert args.case_comment is None


def test_identity_override_available() -> None:
    """Accept a per-acquisition operator identity-file override."""
    args = parser().parse_args(
        [
            "acquire",
            "--case-id",
            "CASE-1",
            "--case-comment",
            "Purpose",
            "--identity-file",
            "jane.json",
            "https://example.test",
        ]
    )

    assert str(args.identity_file) == "jane.json"


def test_init_arguments() -> None:
    """Parse initialisation options supplied after the root directory."""
    args = parser().parse_args(["--root", "/evidence", "init", "--test-key"])

    assert args.command == "init"
    assert args.test_key is True


def test_explicit_youtube_collector_syntax() -> None:
    """Accept the new collector-oriented acquisition spelling."""

    args = parser().parse_args(
        [
            "acquire",
            "youtube",
            "https://youtu.be/abc",
            "--case-id",
            "CASE-1",
            "--case-comment",
            "Purpose",
        ]
    )
    assert args.source == "youtube"
    assert args.target == "https://youtu.be/abc"


def test_screenshot_collector_syntax_has_no_positional_target() -> None:
    """Accept interactive screenshot acquisition with a window target by default."""

    args = parser().parse_args(
        [
            "acquire",
            "screenshot",
            "--case-id",
            "CASE-1",
            "--case-comment",
            "Capture selected window",
        ]
    )
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
