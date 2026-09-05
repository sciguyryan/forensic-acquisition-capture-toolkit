"""Tests for reusable acquisition context, workspace, and artefact records."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fact.collectors.registry import CollectorRegistry
from fact.core.acquisition import AcquisitionWorkspace, ArtefactRegistry, ArtefactRole


def test_workspace_creates_incomplete_marker_and_log(tmp_path: Path) -> None:
    """Generic staging begins in an explicitly incomplete state."""

    workspace = AcquisitionWorkspace.create(tmp_path, "CASE-000001", "ACQ-000001")
    assert workspace.incomplete_marker.is_file()
    workspace.note("INFO", "capture created")
    assert "capture created" in workspace.log_path.read_text(encoding="utf-8")


def test_registry_records_sorted_relative_artefacts(tmp_path: Path) -> None:
    """Artefacts are relative, deterministic, and preserve their evidential role."""

    stage = tmp_path / "stage"
    stage.mkdir()
    first = stage / "z.txt"
    second = stage / "a.png"
    first.write_text("z", encoding="utf-8")
    second.write_bytes(b"png")
    registry = ArtefactRegistry(stage)
    registry.register(first, role=ArtefactRole.SUPPORTING, media_type="text/plain")
    registry.register(second, role=ArtefactRole.PRIMARY, media_type="image/png")
    output = stage / "ARTEFACTS.json"
    registry.write(output)

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert [item["path"] for item in payload["artefacts"]] == ["a.png", "z.txt"]
    assert payload["artefacts"][0]["role"] == "primary"
    assert payload["artefacts"][0]["related_to"] is None


def test_registry_rejects_outside_and_symlink_paths(tmp_path: Path) -> None:
    """A collector cannot register host files or symlink targets as evidence."""

    stage = tmp_path / "stage"
    stage.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    registry = ArtefactRegistry(stage)
    with pytest.raises(ValueError, match="outside acquisition staging"):
        registry.register(outside, role=ArtefactRole.PRIMARY)

    target = stage / "target.txt"
    target.write_text("target", encoding="utf-8")
    link = stage / "link.txt"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="regular file"):
        registry.register(link, role=ArtefactRole.PRIMARY)


def test_collector_registry_is_explicit_and_deterministic() -> None:
    """Collectors register by stable names without a CLI dispatch chain."""

    registry = CollectorRegistry()
    one = object()
    two = object()
    registry.register("youtube", one)
    registry.register("file", two)
    assert registry.names() == ("file", "youtube")
    assert registry.get("youtube") is one
    with pytest.raises(ValueError):
        registry.register("youtube", object())
    with pytest.raises(KeyError, match="Unknown FACT collector"):
        registry.get("missing")


def test_registry_records_explicit_file_relationships(tmp_path: Path) -> None:
    """Retained collector files can describe relationships before check-in."""

    stage = tmp_path / "stage"
    stage.mkdir()
    original = stage / "original.png"
    metadata = stage / "capture.json"
    original.write_bytes(b"image")
    metadata.write_text("{}", encoding="utf-8")
    registry = ArtefactRegistry(stage)
    registry.register(original, role=ArtefactRole.PRIMARY)
    item = registry.register(
        metadata,
        role=ArtefactRole.METADATA,
        related_to=original,
        relationship="describes",
    )
    assert item.related_to == "original.png"
    assert item.relationship == "describes"

    with pytest.raises(ValueError, match="requires a relationship"):
        registry.register(metadata, role=ArtefactRole.METADATA, related_to=original)
    with pytest.raises(ValueError, match="requires a related artefact"):
        registry.register(metadata, role=ArtefactRole.METADATA, relationship="describes")
