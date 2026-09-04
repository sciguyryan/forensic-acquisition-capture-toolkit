"""Extended tests for archive creation, listing, and extraction."""

from pathlib import Path

import pytest

from fact.errors import ToolkitError
from fact.models import ToolResult
from fact.services import archive


def test_create_archive_invokes_7zip(tmp_path: Path, monkeypatch) -> None:
    """Create the output directory and invoke 7-Zip with the staging directory."""
    staging = tmp_path / "stage"
    staging.mkdir()
    output = tmp_path / "out" / "case.7z"
    calls = []
    monkeypatch.setattr(archive, "archive_tool", lambda: "/usr/bin/7zz")
    monkeypatch.setattr(
        archive,
        "run",
        lambda argv, **kwargs: (
            calls.append((argv, kwargs)) or ToolResult(argv, 0, "", "")
        ),
    )

    archive.create_archive(staging, output)

    assert output.parent.is_dir()
    assert calls[0][0][:4] == ["/usr/bin/7zz", "a", "-t7z", "-mx=9"]
    assert calls[0][1]["cwd"] == staging


def test_create_archive_reports_tool_failure(tmp_path: Path, monkeypatch) -> None:
    """Raise a toolkit error when 7-Zip cannot create the archive."""
    monkeypatch.setattr(archive, "archive_tool", lambda: "7zz")
    monkeypatch.setattr(
        archive,
        "run",
        lambda argv, **kwargs: ToolResult(argv, 2, "", "disk full"),
    )

    with pytest.raises(ToolkitError, match="disk full"):
        archive.create_archive(tmp_path, tmp_path / "case.7z")


def test_list_members_ignores_archive_metadata(monkeypatch) -> None:
    """Parse only member paths appearing after the technical-list separator."""
    output = "\n".join(
        [
            "Path = archive.7z",
            "----------",
            "Path = evidence/video.mkv",
            "Size = 10",
            "Path = CASE_RECORD.json",
        ]
    )
    monkeypatch.setattr(archive, "archive_tool", lambda: "7zz")
    monkeypatch.setattr(archive, "run", lambda argv: ToolResult(argv, 0, output, ""))

    assert archive.list_members(Path("archive.7z")) == [
        "evidence/video.mkv",
        "CASE_RECORD.json",
    ]


def test_extract_invokes_7zip_with_destination(tmp_path: Path, monkeypatch) -> None:
    """Create the destination and pass its path to the extraction command."""
    calls = []
    monkeypatch.setattr(archive, "archive_tool", lambda: "7zz")
    monkeypatch.setattr(
        archive,
        "run",
        lambda argv: calls.append(argv) or ToolResult(argv, 0, "", ""),
    )
    destination = tmp_path / "extract"

    archive.extract(tmp_path / "case.7z", destination)

    assert destination.is_dir()
    assert f"-o{destination}" in calls[0]
