"""Tests for archive member path-safety validation."""

from pathlib import Path
from unittest.mock import patch

from fact.services.archive import unsafe_members


def test_rejects_traversal_and_absolute_members(tmp_path: Path) -> None:
    """Reject archive members that escape the intended extraction directory."""
    archive = tmp_path / "x.7z"
    archive.write_bytes(b"")

    members = ["evidence/a", "../escape", "/absolute"]
    with patch("fact.services.archive.list_members", return_value=members):
        assert unsafe_members(archive) == ["../escape", "/absolute"]
