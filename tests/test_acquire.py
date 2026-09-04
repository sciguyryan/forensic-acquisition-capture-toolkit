"""Tests for FACT's generic acquisition lifecycle around collectors."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fact import acquire as acquire_module
from fact.core.acquisition import AcquisitionResult, ArtefactRole
from fact.core import orchestration as orchestration_module
from fact.core import sealing as sealing_module
from fact.errors import ToolkitError
from fact.models import CaseInfo, VerificationSummary


def make_case() -> CaseInfo:
    """Return a complete case record suitable for acquisition tests."""

    return CaseInfo(
        "CASE-1",
        "Preserve source",
        {
            "schema_version": 1,
            "operator_id": "jane.doe",
            "name": "Jane Doe",
            "public_contact": None,
            "organisation": "Example Unit",
            "role": "Examiner",
            "operator_key_fingerprint": "A" * 40,
            "operator_signing_subkey_fingerprint": "B" * 40,
        },
        "active_profile",
        "c" * 64,
        "jane",
        None,
        None,
    )


class FakeCollector:
    """Small collector used to prove lifecycle/collector separation."""

    name = "youtube"

    def capture(self, context, request):
        evidence = context.workspace.stage / "evidence"
        reports = context.workspace.stage / "reports"
        http = context.workspace.stage / "http"
        for directory in (evidence, reports, http):
            directory.mkdir()
        media = evidence / "abc-title.mkv"
        media.write_bytes(b"media")
        info = evidence / "abc-title.info.json"
        info.write_text(json.dumps({"id": "abc", "title": "Title"}), encoding="utf-8")
        context.artefacts.register(media, role=ArtefactRole.PRIMARY)
        context.artefacts.register(info, role=ArtefactRole.SUPPORTING)
        context.metadata["tools"] = {"yt-dlp": "1"}
        return AcquisitionResult(
            collector="youtube",
            collector_version="test",
            source={"video_id": "abc", "title": "Title"},
            evidence={"live_chat_status": "Skipped"},
        )


class FailingCollector:
    """Collector that simulates a mandatory source failure."""

    name = "youtube"

    def capture(self, context, request):
        raise ToolkitError("Primary yt-dlp acquisition failed with exit 1")


def _patch_sealing(monkeypatch) -> None:
    """Replace crypto/archive operations while retaining lifecycle behaviour."""

    monkeypatch.setattr(orchestration_module, "ensure_key", lambda *args: "E" * 40)
    monkeypatch.setattr(
        orchestration_module,
        "export_public_key",
        lambda identity, output: output.write_text("operator key", encoding="utf-8"),
    )
    monkeypatch.setattr(
        sealing_module,
        "sign",
        lambda *args: Path(args[2]).write_text("signature", encoding="utf-8"),
    )
    monkeypatch.setattr(
        sealing_module,
        "sign_with_operator",
        lambda *args: Path(args[2]).write_text("operator signature", encoding="utf-8"),
    )
    monkeypatch.setattr(sealing_module, "summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        orchestration_module,
        "acquisition_id",
        lambda: "20260720-120000-deadbeef",
    )
    monkeypatch.setattr(
        sealing_module,
        "create_archive",
        lambda staging, archive: archive.write_bytes(b"sealed archive"),
    )

    def fake_verify(archive: Path, public_key: Path, report: Path):
        report.write_text("PASS\n", encoding="utf-8")
        return VerificationSummary(archive=archive)

    monkeypatch.setattr(sealing_module, "verify_archive", fake_verify)


def test_video_id_supports_watch_and_short_urls() -> None:
    """Retain the original helper while source parsing lives in the collector."""

    assert acquire_module._video_id("https://www.youtube.com/watch?v=abc123") == "abc123"
    assert acquire_module._video_id("https://youtu.be/xyz789") == "xyz789"
    assert acquire_module._video_id("https://example.test/video") is None


def test_acquire_happy_path(tmp_path: Path, monkeypatch) -> None:
    """Seal collector output through the reusable acquisition lifecycle."""

    _patch_sealing(monkeypatch)
    public_key = tmp_path / "pgp" / "evidence-public-key.asc"
    public_key.parent.mkdir(parents=True)
    public_key.write_text("evidence key", encoding="utf-8")

    archive = acquire_module.acquire(
        root=tmp_path,
        url="https://www.youtube.com/watch?v=abc",
        case=make_case(),
        live_chat=False,
        collector=FakeCollector(),
    )

    assert archive.is_file()
    assert Path(f"{archive}.sha256").is_file()
    assert Path(f"{archive}.operator.asc").is_file()
    staging = next((tmp_path / "archived").glob(".staging-*"))
    case_record = json.loads((staging / "CASE_RECORD.json").read_text(encoding="utf-8"))
    assert case_record["source"]["title"] == "Title"
    assert case_record["toolkit_name"].startswith("FACT")
    assert json.loads((staging / "ARTEFACTS.json").read_text())["artefacts"]
    assert not (staging / "INCOMPLETE").exists()


def test_acquire_retains_incomplete_state_on_collector_failure(tmp_path: Path, monkeypatch) -> None:
    """Retain a clearly marked workspace when mandatory capture fails."""

    monkeypatch.setattr(orchestration_module, "ensure_key", lambda *args: "E" * 40)
    monkeypatch.setattr(
        orchestration_module,
        "export_public_key",
        lambda identity, output: output.write_text("key", encoding="utf-8"),
    )
    public_key = tmp_path / "pgp" / "evidence-public-key.asc"
    public_key.parent.mkdir(parents=True)
    public_key.write_text("key", encoding="utf-8")

    with pytest.raises(ToolkitError, match="Primary yt-dlp acquisition failed"):
        acquire_module.acquire(
            root=tmp_path,
            url="https://youtu.be/abc",
            case=make_case(),
            collector=FailingCollector(),
        )

    staging = next((tmp_path / "archived").glob(".staging-*"))
    assert (staging / "INCOMPLETE").is_file()
    assert (staging / "CASE_RECORD.json").is_file()
