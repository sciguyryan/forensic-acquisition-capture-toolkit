"""Tests for the source-specific YouTube collector after generic refactoring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fact.collectors.youtube import collector as youtube
from fact.core.acquisition import (
    AcquisitionContext,
    AcquisitionWorkspace,
    ArtefactRegistry,
)
from fact.errors import ToolkitError
from fact.models import ToolResult


class FakeCommands:
    """In-memory command service used to exercise collector behaviour."""

    def __init__(self, fail_primary: bool = False) -> None:
        self.fail_primary = fail_primary
        self.calls: list[list[str]] = []

    def require(self, command: str) -> str:
        return command

    def version(self, command: str) -> str:
        return f"{command} 1"

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[0] == "yt-dlp" and "--skip-download" not in argv:
            if self.fail_primary:
                return ToolResult(list(argv), 1, "", "failed")
            output = Path(argv[argv.index("-o") + 1]).parent
            (output / "abc-title.mkv").write_bytes(b"media")
            (output / "abc-title.info.json").write_text(
                json.dumps(
                    {
                        "id": "abc",
                        "title": "Title",
                        "channel": "Channel",
                        "upload_date": "20260904",
                    }
                ),
                encoding="utf-8",
            )
            return ToolResult(list(argv), 0, "", "")
        if argv[0] == "ffprobe":
            return ToolResult(list(argv), 0, '{"streams": []}', "")
        return ToolResult(list(argv), 0, "", "")


def make_context(tmp_path: Path, commands: FakeCommands) -> AcquisitionContext:
    """Create a generic context suitable for direct collector tests."""

    workspace = AcquisitionWorkspace.create(tmp_path, "CASE-1", "ACQ-1")
    return AcquisitionContext(
        project_root=tmp_path,
        case_id="CASE-1",
        acquisition_id="ACQ-1",
        workspace=workspace,
        artefacts=ArtefactRegistry(workspace.stage),
        commands=commands,  # type: ignore[arg-type]
    )


def test_capture_returns_source_metadata_and_registered_outputs(
    tmp_path: Path, monkeypatch
) -> None:
    """YouTube-specific capture returns structured metadata without sealing."""

    # Disable optional curl/mediainfo branches so this test remains independent
    # of whichever utilities happen to exist on the test host.
    monkeypatch.setattr(youtube.shutil, "which", lambda command: None)
    commands = FakeCommands()
    context = make_context(tmp_path, commands)

    result = youtube.YouTubeCollector().capture(
        context,
        youtube.YouTubeRequest(url="https://youtu.be/abc", live_chat=False),
    )

    assert result.collector == "youtube"
    assert result.source["video_id"] == "abc"
    assert result.source["title"] == "Title"
    assert result.evidence["live_chat_status"] == "Skipped"
    assert any(item.path.endswith(".mkv") for item in context.artefacts.items())
    assert any("ffprobe" in item.path for item in context.artefacts.items())


def test_capture_stops_on_primary_failure(tmp_path: Path, monkeypatch) -> None:
    """Mandatory source acquisition failure is surfaced to the lifecycle."""

    monkeypatch.setattr(youtube.shutil, "which", lambda command: None)
    context = make_context(tmp_path, FakeCommands(fail_primary=True))
    with pytest.raises(ToolkitError, match="Primary yt-dlp acquisition failed"):
        youtube.YouTubeCollector().capture(
            context,
            youtube.YouTubeRequest(url="https://youtu.be/abc"),
        )


def test_video_id_parser() -> None:
    """YouTube URL parsing remains isolated within the source collector."""

    assert youtube.video_id("https://youtu.be/short") == "short"
    assert youtube.video_id("https://youtube.com/watch?v=watch") == "watch"
    assert youtube.video_id("https://example.test/") is None
