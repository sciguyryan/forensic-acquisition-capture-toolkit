"""Create, inspect, validate, and extract 7-Zip evidence archives.

This module provides the archive operations used by the toolkit. It creates
compressed evidence packages, lists their members, identifies unsafe member
paths before extraction, and extracts verified archives to a destination.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..errors import ToolkitError
from .commands import archive_tool, run


def create_archive(staging: Path, archive: Path) -> None:
    """Create a compressed 7-Zip archive from a staging directory.

    The archive is created with maximum compression and includes every item
    beneath the staging directory.

    Args:
        staging: Directory containing the complete evidence set.
        archive: Destination path for the resulting 7-Zip archive.

    Raises:
        ToolkitError: If the archive utility reports a non-zero exit status.
    """

    archive.parent.mkdir(parents=True, exist_ok=True)
    tool = archive_tool()
    result = run(
        [tool, "a", "-t7z", "-mx=9", "-bb1", str(archive), "."],
        cwd=staging,
        check=False,
    )

    if result.returncode != 0:
        details = (result.stderr or result.stdout).strip()
        raise ToolkitError(f"Archive creation failed: {details}")


def list_members(archive: Path) -> list[str]:
    """Return the member paths recorded in a 7-Zip archive.

    Args:
        archive: Path to the archive to inspect.

    Returns:
        Archive member paths in the order reported by the archive utility.
    """

    result = run([archive_tool(), "l", "-slt", str(archive)])
    paths: list[str] = []
    seen_separator = False

    # In 7-Zip's technical listing, member records begin after the dashed
    # separator. Restricting parsing to that section avoids treating the
    # archive's own metadata as a member path.
    for line in result.stdout.splitlines():
        if line.startswith("----------"):
            seen_separator = True
            continue

        if seen_separator and line.startswith("Path = "):
            paths.append(line[7:])

    return paths


def unsafe_members(archive: Path) -> list[str]:
    """Return archive members that could escape an extraction destination.

    Absolute paths, Windows drive-qualified paths, and parent-directory
    traversal components are treated as unsafe.

    Args:
        archive: Path to the archive to inspect.

    Returns:
        A list of unsafe member paths. An empty list indicates that no unsafe
        paths were identified.
    """

    failures: list[str] = []
    drive_prefix = re.compile(r"^[A-Za-z]:")

    for member in list_members(archive):
        member_path = Path(member)
        if (
            member_path.is_absolute()
            or drive_prefix.match(member)
            or ".." in member_path.parts
        ):
            failures.append(member)

    return failures


def extract(archive: Path, destination: Path) -> None:
    """Extract a 7-Zip archive to the specified destination.

    Callers should validate the archive with :func:`unsafe_members` before
    extraction when the archive's provenance is not already trusted.

    Args:
        archive: Path to the archive to extract.
        destination: Directory into which archive members are written.
    """

    destination.mkdir(parents=True, exist_ok=True)
    run(
        [
            archive_tool(),
            "x",
            "-y",
            f"-o{destination}",
            str(archive),
        ]
    )
