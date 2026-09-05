"""Tests for FACT's everything-as-a-file evidence model."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from fact.core import authority, catalogue
from fact.core.authority import establish_project_genesis
from fact.core.catalogue import catalogue_path, issue_identifier, verify_chain
from fact.core.files import FileCandidate, commit_files, list_files
from fact.core.project import _initialise_project as initialise_project
from fact.core.project import create_case
from fact.errors import ToolkitError
from fact.identity import OperatorIdentity


def owner() -> OperatorIdentity:
    return OperatorIdentity(1, "owner", "Owner", None, None, None, "A" * 40, "a" * 40)


@pytest.fixture(autouse=True)
def fake_signatures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        authority,
        "sign_operator_payload",
        lambda identity, payload: f"SIG:{identity.operator_id}:{hashlib.sha256(payload).hexdigest()}",
    )
    monkeypatch.setattr(authority, "verify_operator_payload", lambda *args: None)
    monkeypatch.setattr(catalogue, "verify_operator_payload", lambda *args: None)


def project(root: Path) -> tuple[OperatorIdentity, str, str]:
    actor = owner()
    initialise_project(root, "P-FILES", "Everything as a file")
    establish_project_genesis(root, actor, "PUBLIC OWNER")
    case_id = create_case(root)
    acquisition_id = issue_identifier(root, "acquisition", "ACQ")
    return actor, case_id, acquisition_id


def test_batch_checkin_assigns_permanent_ids_and_preserves_exact_bytes(tmp_path: Path) -> None:
    actor, case_id, acquisition_id = project(tmp_path)
    source = tmp_path / "capture"
    source.mkdir()
    request = source / "request.txt"
    response = source / "response.bin"
    request.write_text("GET /evidence HTTP/1.1\nHost: example.test\n", encoding="utf-8")
    response.write_bytes(b"HTTP/1.1 200 OK\r\n\r\nbytes")

    committed = commit_files(
        tmp_path,
        case_id=case_id,
        acquisition_id=acquisition_id,
        actor_id=actor.operator_id,
        candidates=[
            FileCandidate(request, "network/request.txt", "network-request", "text/plain"),
            FileCandidate(response, "network/response.bin", "network-response"),
        ],
    )

    assert [row["file_id"] for row in committed] == ["FILE-000001", "FILE-000002"]
    rows = list_files(tmp_path, case_id=case_id)
    assert len(rows) == 2
    for row in rows:
        stored = tmp_path / str(row["storage_path"])
        assert stored.is_file()
        assert hashlib.sha256(stored.read_bytes()).hexdigest() == row["sha256"]
    assert verify_chain(tmp_path)["event_count"] >= 7


def test_identical_bytes_are_distinct_evidential_checkins(tmp_path: Path) -> None:
    actor, case_id, acquisition_id = project(tmp_path)
    first = tmp_path / "one.bin"
    second = tmp_path / "two.bin"
    first.write_bytes(b"same bytes")
    second.write_bytes(b"same bytes")
    rows = commit_files(
        tmp_path,
        case_id=case_id,
        acquisition_id=acquisition_id,
        actor_id=actor.operator_id,
        candidates=[
            FileCandidate(first, "first.bin", "primary"),
            FileCandidate(second, "second.bin", "primary"),
        ],
    )
    assert rows[0]["file_id"] != rows[1]["file_id"]
    assert rows[0]["sha256"] == rows[1]["sha256"]


def test_changed_or_missing_committed_file_is_a_sanctity_failure(tmp_path: Path) -> None:
    actor, case_id, acquisition_id = project(tmp_path)
    source = tmp_path / "source.txt"
    source.write_text("immutable", encoding="utf-8")
    row = commit_files(
        tmp_path,
        case_id=case_id,
        acquisition_id=acquisition_id,
        actor_id=actor.operator_id,
        candidates=[FileCandidate(source, "source.txt", "primary")],
    )[0]
    stored = tmp_path / str(row["storage_path"])
    stored.write_text("changed", encoding="utf-8")
    with pytest.raises(ToolkitError, match="bytes have changed"):
        verify_chain(tmp_path)
    stored.unlink()
    with pytest.raises(ToolkitError, match="missing from the authoritative tree"):
        verify_chain(tmp_path)


def test_catalogue_file_metadata_tampering_is_detected(tmp_path: Path) -> None:
    actor, case_id, acquisition_id = project(tmp_path)
    source = tmp_path / "source.txt"
    source.write_text("evidence", encoding="utf-8")
    commit_files(
        tmp_path,
        case_id=case_id,
        acquisition_id=acquisition_id,
        actor_id=actor.operator_id,
        candidates=[FileCandidate(source, "source.txt", "primary")],
    )
    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute("UPDATE files SET classification = 'forged'")
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="metadata differs from audit history"):
        verify_chain(tmp_path)


def test_failed_batch_commits_nothing_and_does_not_consume_file_ids(tmp_path: Path) -> None:
    actor, case_id, acquisition_id = project(tmp_path)
    source = tmp_path / "source.txt"
    source.write_text("evidence", encoding="utf-8")
    with pytest.raises(ToolkitError, match="Duplicate logical file path"):
        commit_files(
            tmp_path,
            case_id=case_id,
            acquisition_id=acquisition_id,
            actor_id=actor.operator_id,
            candidates=[
                FileCandidate(source, "same.txt", "primary"),
                FileCandidate(source, "same.txt", "metadata"),
            ],
        )
    assert list_files(tmp_path) == []
    assert issue_identifier(tmp_path, "file", "FILE") == "FILE-000001"


def test_checkin_rejects_unsafe_inputs_and_inactive_context(tmp_path: Path) -> None:
    actor, case_id, acquisition_id = project(tmp_path)
    source = tmp_path / "source.txt"
    source.write_text("evidence", encoding="utf-8")
    with pytest.raises(ToolkitError, match="Unsafe logical"):
        commit_files(
            tmp_path,
            case_id=case_id,
            acquisition_id=acquisition_id,
            actor_id=actor.operator_id,
            candidates=[FileCandidate(source, "../escape.txt", "primary")],
        )
    with pytest.raises(ToolkitError, match="Unknown FACT case"):
        commit_files(
            tmp_path,
            case_id="CASE-999999",
            acquisition_id=acquisition_id,
            actor_id=actor.operator_id,
            candidates=[FileCandidate(source, "source.txt", "primary")],
        )


def test_presentation_changes_and_relationships_append_without_erasing_files(tmp_path: Path) -> None:
    from fact.core.files import relate_files, set_file_presentation

    actor, case_id, acquisition_id = project(tmp_path)
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("original", encoding="utf-8")
    second.write_text("derived", encoding="utf-8")
    rows = commit_files(
        tmp_path,
        case_id=case_id,
        acquisition_id=acquisition_id,
        actor_id=actor.operator_id,
        candidates=[
            FileCandidate(first, "first.txt", "primary"),
            FileCandidate(second, "second.txt", "derived"),
        ],
    )
    relate_files(
        tmp_path,
        parent_file_id=str(rows[0]["file_id"]),
        child_file_id=str(rows[1]["file_id"]),
        relationship="derived-from",
    )
    set_file_presentation(
        tmp_path,
        str(rows[0]["file_id"]),
        state="retracted",
        reason="Excluded from presented record",
    )
    listed = list_files(tmp_path)
    assert listed[0]["presentation_state"] == "retracted"
    assert (tmp_path / str(listed[0]["storage_path"])).is_file()
    assert verify_chain(tmp_path)["event_count"] >= 1

    with pytest.raises(ToolkitError, match="cannot be related to itself"):
        relate_files(
            tmp_path,
            parent_file_id=str(rows[0]["file_id"]),
            child_file_id=str(rows[0]["file_id"]),
            relationship="derived-from",
        )
    with pytest.raises(ToolkitError, match="not supported"):
        set_file_presentation(tmp_path, str(rows[0]["file_id"]), state="deleted", reason="x")
