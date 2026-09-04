"""Run and inspect external command-line tools used by the toolkit.

The helpers in this module centralise executable discovery, subprocess
execution, error translation, version reporting, and timestamped command
transcripts.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from ..errors import ToolkitError
from ..models import ToolResult


def require(command: str) -> str:
    """Return the absolute path to a required executable."""
    path = shutil.which(command)
    if not path:
        raise ToolkitError(f"Required command not found: {command}")
    return path


def archive_tool() -> str:
    """Return the first supported 7-Zip executable found on PATH."""
    for name in ("7zz", "7z"):
        path = shutil.which(name)
        if path:
            return path
    raise ToolkitError("Required archive tool not found: 7zz or 7z")


def _utc_now() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _append_transcript(path: Path, argv: list[str], result: ToolResult) -> None:
    """Append a completed command invocation to a transcript file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(f"[{_utc_now()}] [COMMAND] {shlex.join(argv)}\n")
        for stream_name, text in (("STDOUT", result.stdout), ("STDERR", result.stderr)):
            if not text:
                continue
            for line in text.splitlines():
                fh.write(f"[{_utc_now()}] [{stream_name}] {line}\n")
        fh.write(f"[{_utc_now()}] [EXIT] {result.returncode}\n")


def run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
    input_text: str | None = None,
    transcript: Path | None = None,
) -> ToolResult:
    """Run an external command and return its captured result."""
    merged = os.environ.copy()
    if env:
        merged.update(env)
    proc = subprocess.run(
        argv,
        cwd=cwd,
        env=merged,
        input=input_text,
        text=True,
        capture_output=True,
        errors="replace",
    )
    result = ToolResult(argv, proc.returncode, proc.stdout, proc.stderr)
    if transcript is not None:
        _append_transcript(transcript, argv, result)
    if check and proc.returncode != 0:
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or [
            "unknown error"
        ]
        raise ToolkitError(
            f"Command failed ({proc.returncode}): {' '.join(argv)}: {tail[0]}"
        )
    return result


def version(command: str) -> str:
    """Return the first line of an executable's version output."""
    try:
        result = run([command, "--version"], check=False)
        text = (result.stdout or result.stderr).strip().splitlines()
        return text[0] if text else "unknown"
    except OSError:
        return "unknown"


class CommandRunner:
    """Reusable external-command service supplied to collectors.

    The class deliberately delegates to this module's ``run`` function.  Tests
    can replace the runner or the function without source collectors needing to
    know about ``subprocess`` directly, and future policy such as argument
    redaction can be centralised here.
    """

    def run(
        self,
        argv: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        input_text: str | None = None,
        transcript: Path | None = None,
    ) -> ToolResult:
        """Run a command using FACT's common transcript and error policy."""

        return run(
            argv,
            cwd=cwd,
            env=env,
            check=check,
            input_text=input_text,
            transcript=transcript,
        )

    def require(self, command: str) -> str:
        """Resolve a required executable using FACT's common policy."""

        return require(command)

    def version(self, command: str) -> str:
        """Return a tool version using FACT's common version probe."""

        return version(command)
