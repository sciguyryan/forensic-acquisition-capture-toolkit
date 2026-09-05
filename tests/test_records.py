"""Tests for structured acquisition provenance records."""

from fact.core.records import initial_record_for_source
from fact.models import CaseInfo


def test_case_comments_are_preserved_in_catalogue_record_material() -> None:
    """Keep case context in the structured record signed into the catalogue."""
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
    record = initial_record_for_source(
        CaseInfo("CASE-1", comments, identity, "login"),
        "ACQ-000001",
        {"submitted_url": "https://example.test"},
        {},
    )

    data = record.to_dict()
    assert data["schema_version"] == "3.0"
    assert data["case"]["comments"] == comments
    assert data["acquisition"]["acquisition_id"] == "ACQ-000001"
