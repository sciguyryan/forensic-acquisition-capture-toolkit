"""Tests for external command execution and transcript capture."""

import sys
from pathlib import Path

import pytest

from fact.errors import ToolkitError
from fact.models import ToolResult
from fact.services import commands
from fact.services.commands import run


def test_run_writes_stdout_stderr_and_exit_to_transcript(tmp_path: Path) -> None:
    """Record command output streams and exit status in the transcript."""
    transcript = tmp_path / "acquisition.log"
    result = run(
        [
            sys.executable,
            "-c",
            "import sys; print('out-line'); print('err-line', file=sys.stderr)",
        ],
        transcript=transcript,
    )

    assert result.returncode == 0
    text = transcript.read_text(encoding="utf-8")
    assert "[COMMAND]" in text
    assert "[STDOUT] out-line" in text
    assert "[STDERR] err-line" in text
    assert "[EXIT] 0" in text


def test_run_does_not_write_transcript_unless_requested(tmp_path: Path) -> None:
    """Avoid creating a transcript unless the caller explicitly requests one."""
    transcript = tmp_path / "acquisition.log"

    run([sys.executable, "-c", "print('quiet')"])

    assert not transcript.exists()


def test_require_resolves_commands_and_rejects_missing(monkeypatch) -> None:
    """Resolve required executables without retaining archive-specific policy."""
    monkeypatch.setattr(
        commands.shutil,
        "which",
        lambda command: f"/bin/{command}" if command == "tool" else None,
    )
    assert commands.require("tool") == "/bin/tool"
    with pytest.raises(ToolkitError, match="Required command not found"):
        commands.require("missing")


def test_version_handles_missing_and_empty_output(monkeypatch) -> None:
    """Return stable fallback text for absent or silent version commands."""
    from fact.services import commands

    monkeypatch.setattr(
        commands, "run", lambda *args, **kwargs: ToolResult([], 0, "", "")
    )
    assert commands.version("tool") == "unknown"
    monkeypatch.setattr(
        commands, "run", lambda *args, **kwargs: (_ for _ in ()).throw(OSError())
    )
    assert commands.version("tool") == "unknown"
