"""Apply advisory filesystem protection to committed FACT payloads.

Filesystem permissions are a defence against accidental modification, not an
integrity boundary. FACT's authenticated catalogue and content digests remain
the mechanism that detects unauthorised changes to retained evidence.
"""

from __future__ import annotations

import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def protect_committed_file(path: Path) -> bool:
    """Best-effort protection for a committed regular file.

    Permission hardening must never become a second commit boundary after the
    catalogue transaction has succeeded. Unsupported filesystems therefore
    leave a verifiable warning condition rather than causing FACT to remove
    bytes whose catalogue commitment has already become authoritative.
    """
    try:
        path.chmod(stat.S_IRUSR)
    except OSError:
        return False
    return True


def is_read_only(path: Path) -> bool:
    """Return whether no filesystem write bit is set on a regular file."""
    return (
        path.is_file() and not path.is_symlink() and (path.stat().st_mode & 0o222) == 0
    )


@contextmanager
def temporarily_writable(path: Path) -> Iterator[None]:
    """Temporarily add owner-write permission and always restore prior mode.

    This helper is intended only for non-authoritative operational files that
    genuinely require in-place updates. Committed evidential payloads should
    instead receive a new immutable FILE identity or revision.
    """
    original = stat.S_IMODE(path.stat().st_mode)
    path.chmod(original | stat.S_IWUSR)
    try:
        yield
    finally:
        path.chmod(original)
