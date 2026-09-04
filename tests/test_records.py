"""Tests for machine-readable and human-readable case records."""

import json
from pathlib import Path

from fact.core.records import initial_record, write_record
from fact.models import CaseInfo


def test_case_comments_written_to_both_formats(tmp_path: Path) -> None:
    """Write case comments to both JSON and Markdown case records."""
    identity = {
        "schema_version": 1,
        "operator_id": "analyst",
        "name": "Analyst",
        "public_contact": None,
        "organisation": None,
        "role": None,
        "operator_key_fingerprint": "A" * 40,
        "operator_signing_subkey_fingerprint": "B" * 40,
    }
    comments = "What this acquisition is about."
    record = initial_record(
        CaseInfo(
            "CASE-1",
            comments,
            identity,
            "active_profile",
            "c" * 64,
            "login",
        ),
        "A-1",
        "https://example.test",
        {},
    )

    write_record(tmp_path, record)

    markdown = (tmp_path / "CASE_RECORD.md").read_text(encoding="utf-8")
    data = json.loads((tmp_path / "CASE_RECORD.json").read_text(encoding="utf-8"))
    assert comments in markdown
    assert data["case"]["comments"] == comments
