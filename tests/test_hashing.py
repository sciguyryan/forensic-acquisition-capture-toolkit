"""Tests for evidence manifest creation and verification."""

from pathlib import Path

from fact.services.hashing import verify_manifest, write_manifest


def test_transient_incomplete_is_never_manifested(tmp_path: Path) -> None:
    """Exclude the transient INCOMPLETE marker from evidence manifests."""
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "item.txt").write_text("evidence", encoding="utf-8")
    (tmp_path / "INCOMPLETE").write_text("temporary", encoding="utf-8")

    manifest = tmp_path / "SHA256SUMS.txt"
    write_manifest(tmp_path, manifest, "sha256")
    text = manifest.read_text(encoding="utf-8")

    assert "evidence/item.txt" in text
    assert "INCOMPLETE" not in text
    assert verify_manifest(tmp_path, manifest, "sha256") == []


def test_unicode_paths_verify(tmp_path: Path) -> None:
    """Create and verify manifests containing Unicode evidence paths."""
    target = tmp_path / "evidence" / "Pokémon evidence.txt"
    target.parent.mkdir()
    target.write_text("ok", encoding="utf-8")

    manifest = tmp_path / "SHA256SUMS.txt"
    write_manifest(tmp_path, manifest, "sha256")

    assert verify_manifest(tmp_path, manifest, "sha256") == []
