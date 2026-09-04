"""Tests for complete archive verification workflows."""

import json
from pathlib import Path

from fact.core import verification as verify
from fact.services.hashing import digest, write_manifest
from fact.models import ToolResult


def test_verify_archive_happy_path(tmp_path: Path, monkeypatch) -> None:
    """Pass every verification stage for a complete evidence package."""
    archive = tmp_path / "archived" / "case.7z"
    archive.parent.mkdir()
    archive.write_bytes(b"archive")
    public_key = tmp_path / "pgp" / "evidence-public-key.asc"
    public_key.parent.mkdir()
    public_key.write_text("public", encoding="utf-8")
    Path(f"{archive}.sha256").write_text(
        f"{digest(archive, 'sha256')}  {archive.name}\n", encoding="ascii"
    )
    Path(f"{archive}.sha512").write_text(
        f"{digest(archive, 'sha512')}  {archive.name}\n", encoding="ascii"
    )
    Path(f"{archive}.asc").write_text("sig", encoding="utf-8")
    Path(f"{archive}.operator.asc").write_text("operator sig", encoding="utf-8")

    fingerprint = "B" * 40

    def fake_extract(_archive: Path, destination: Path) -> None:
        destination.mkdir(parents=True)
        for filename in (
            "acquisition.txt",
            "FILELIST.txt",
            "VERIFICATION.txt",
            "evidence-public-key.asc",
            "CASE_RECORD.json",
            "CASE_RECORD.md",
            "TOOLKIT.json",
            "operator-public-key.asc",
        ):
            (destination / filename).write_text(filename, encoding="utf-8")
        (destination / "operator-identity.json").write_text(
            json.dumps({"operator_signing_subkey_fingerprint": fingerprint}),
            encoding="utf-8",
        )
        write_manifest(destination, destination / "SHA256SUMS.txt", "sha256")
        write_manifest(destination, destination / "SHA512SUMS.txt", "sha512")

    def fake_run(argv, **kwargs):
        if "--status-fd" in argv:
            return ToolResult(argv, 0, f"[GNUPG:] VALIDSIG {fingerprint} 2026\n", "")
        return ToolResult(argv, 0, "", "")

    monkeypatch.setattr(verify, "require", lambda command: "/usr/bin/gpg")
    monkeypatch.setattr(verify, "run", fake_run)
    monkeypatch.setattr(verify, "unsafe_members", lambda path: [])
    monkeypatch.setattr(verify, "extract", fake_extract)
    monkeypatch.setattr(verify, "summary", lambda *args, **kwargs: None)
    report = tmp_path / "report.txt"

    result = verify.verify_archive(archive, public_key, report)

    assert result.passed is True
    assert "Overall result: PASS" in report.read_text(encoding="utf-8")
    assert all(stage.status == "PASS" for stage in result.stages)


def test_verify_archive_stops_for_unsafe_members(tmp_path: Path, monkeypatch) -> None:
    """Fail safely before extraction when an archive contains traversal paths."""
    archive = tmp_path / "case.7z"
    archive.write_bytes(b"archive")
    public_key = tmp_path / "key.asc"
    public_key.write_text("public", encoding="utf-8")
    for suffix, algorithm in (("sha256", "sha256"), ("sha512", "sha512")):
        Path(f"{archive}.{suffix}").write_text(
            f"{digest(archive, algorithm)}  {archive.name}\n", encoding="ascii"
        )
    Path(f"{archive}.asc").write_text("sig", encoding="utf-8")

    monkeypatch.setattr(verify, "require", lambda command: "/usr/bin/gpg")
    monkeypatch.setattr(
        verify, "run", lambda argv, **kwargs: ToolResult(argv, 0, "", "")
    )
    monkeypatch.setattr(verify, "unsafe_members", lambda path: ["../escape"])
    monkeypatch.setattr(verify, "summary", lambda *args, **kwargs: None)

    result = verify.verify_archive(archive, public_key)

    assert result.passed is False
    assert any(stage.name == "Archive path safety" for stage in result.stages)
