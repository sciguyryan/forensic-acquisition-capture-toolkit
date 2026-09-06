"""Filesystem protection tests for committed evidential payloads."""

import stat
from pathlib import Path

from fact.core.file_protection import is_read_only, temporarily_writable


def test_temporary_writable_restores_exact_mode(tmp_path: Path) -> None:
    path = tmp_path / "payload"
    path.write_bytes(b"evidence")
    path.chmod(0o400)
    with temporarily_writable(path):
        assert stat.S_IMODE(path.stat().st_mode) & stat.S_IWUSR
    assert stat.S_IMODE(path.stat().st_mode) == 0o400
    assert is_read_only(path)


def test_protection_failure_is_advisory(tmp_path: Path, monkeypatch) -> None:
    from fact.core.file_protection import protect_committed_file

    path = tmp_path / "payload"
    path.write_bytes(b"evidence")
    monkeypatch.setattr(
        Path,
        "chmod",
        lambda self, mode: (_ for _ in ()).throw(OSError("unsupported")),
    )
    assert protect_committed_file(path) is False
