from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from fact.core import catalogue as catalogue_module
from fact.core.catalogue import (
    catalogue_path,
    fail_identifier,
    issue_identifier,
    list_identifiers,
    retire_identifier,
    verify_chain,
    verify_checkpoint,
    write_checkpoint,
)
from fact.core.project import _initialise_project as initialise_project
from fact.core.project import create_case, retire_case
from fact.errors import ToolkitError
from fact.models import ToolResult


def test_case_ids_are_monotonic_and_retired_ids_are_not_reused(tmp_path: Path) -> None:
    initialise_project(tmp_path, "P-1", "Test")
    first = create_case(tmp_path)
    second = create_case(tmp_path)
    retire_identifier(tmp_path, first, "test")
    third = create_case(tmp_path)
    assert (first, second, third) == ("CASE-000001", "CASE-000002", "CASE-000003")


def test_chain_detects_manual_event_tampering(tmp_path: Path) -> None:
    initialise_project(tmp_path, "P-1", "Test")
    create_case(tmp_path)
    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute(
        "UPDATE audit_events SET object_id = 'CASE-999999' WHERE event_sequence = 1"
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="event hash is invalid"):
        verify_chain(tmp_path)


def test_transaction_rollback_does_not_allocate_duplicate(tmp_path: Path) -> None:
    initialise_project(tmp_path, "P-1", "Test")
    assert issue_identifier(tmp_path, "case", "CASE") == "CASE-000001"
    assert issue_identifier(tmp_path, "case", "CASE") == "CASE-000002"


def test_project_refuses_overwrite(tmp_path: Path) -> None:
    initialise_project(tmp_path, "P-1", "Test")
    with pytest.raises(ToolkitError, match="already exists"):
        initialise_project(tmp_path, "P-2", "Other")


def test_list_and_retirement_errors(tmp_path: Path) -> None:
    initialise_project(tmp_path, "P-1", "Test")
    case_id = create_case(tmp_path, "Title", "Comment")
    rows = list_identifiers(tmp_path)
    assert rows[0]["identifier"] == case_id
    retire_case(tmp_path, case_id, "done")
    assert list_identifiers(tmp_path)[0]["state"] == "retired"
    with pytest.raises(ToolkitError, match="already retired"):
        retire_case(tmp_path, case_id)
    with pytest.raises(ToolkitError, match="Unknown FACT identifier"):
        retire_case(tmp_path, "CASE-999999")
    with pytest.raises(ToolkitError, match="Unknown identifier namespace"):
        issue_identifier(tmp_path, "unknown", "X")


def test_missing_catalogue_fails(tmp_path: Path) -> None:
    with pytest.raises(ToolkitError, match="does not exist"):
        verify_chain(tmp_path)


def test_chain_detects_discontinuity_and_previous_hash(tmp_path: Path) -> None:
    initialise_project(tmp_path, "P-1", "Test")
    create_case(tmp_path)
    path = catalogue_path(tmp_path)
    connection = sqlite3.connect(path)
    connection.execute(
        "UPDATE audit_events SET event_sequence = 7 WHERE event_sequence = 1"
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="discontinuous"):
        verify_chain(tmp_path)

    other = tmp_path / "other"
    initialise_project(other, "P-2", "Test")
    create_case(other)
    connection = sqlite3.connect(catalogue_path(other))
    connection.execute(
        "UPDATE audit_events SET previous_hash = ? WHERE event_sequence = 1",
        ("f" * 64,),
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="hash chain is broken"):
        verify_chain(other)


def test_checkpoint_write_and_verify_with_mocked_gpg(
    tmp_path: Path, monkeypatch
) -> None:
    initialise_project(tmp_path, "P-1", "Test")
    create_case(tmp_path)
    toolkit = tmp_path / "toolkit"
    home = toolkit / "pgp" / "keyring"
    home.mkdir(parents=True)
    monkeypatch.setattr(catalogue_module, "prepare_gnupg", lambda *a, **k: {})
    monkeypatch.setattr(catalogue_module, "fingerprint", lambda *a, **k: "FPR")

    def fake_sign(home, payload, signature, fpr):
        signature.write_text("signature", encoding="utf-8")

    monkeypatch.setattr(catalogue_module, "sign", fake_sign)
    checkpoint = write_checkpoint(tmp_path, toolkit)
    assert checkpoint.exists()

    public_key = tmp_path / "public.asc"
    public_key.write_text("key", encoding="utf-8")
    monkeypatch.setattr(
        catalogue_module,
        "run",
        lambda argv, **kwargs: ToolResult(argv, 0, "", ""),
    )
    assert verify_checkpoint(tmp_path, public_key)["event_count"] == 1

    create_case(tmp_path)
    with pytest.raises(ToolkitError, match="differs from signed checkpoint"):
        verify_checkpoint(tmp_path, public_key)


def test_checkpoint_requires_key_and_existing_checkpoint(
    tmp_path: Path, monkeypatch
) -> None:
    initialise_project(tmp_path, "P-1", "Test")
    toolkit = tmp_path / "toolkit"
    home = toolkit / "pgp" / "keyring"
    home.mkdir(parents=True)
    monkeypatch.setattr(catalogue_module, "prepare_gnupg", lambda *a, **k: {})
    monkeypatch.setattr(catalogue_module, "fingerprint", lambda *a, **k: None)
    with pytest.raises(ToolkitError, match="No evidence signing key"):
        write_checkpoint(tmp_path, toolkit)
    with pytest.raises(ToolkitError, match="no signed checkpoint"):
        verify_checkpoint(tmp_path, tmp_path / "missing.asc")


def test_project_id_validation_and_case_files(tmp_path: Path) -> None:
    with pytest.raises(ToolkitError, match="Project ID"):
        initialise_project(tmp_path / "bad", "bad id!", "Test")
    root = tmp_path / "good"
    initialise_project(root, "GOOD-1", 'A "quoted" title')
    case_id = create_case(root, 'A "case"', "line one\nline two")
    text = (root / "cases" / case_id / "CASE.toml").read_text(encoding="utf-8")
    assert '\\"case\\"' in text
    assert "\\n" in text


def test_chain_detects_live_state_and_counter_tampering(tmp_path: Path) -> None:
    initialise_project(tmp_path, "P-1", "Test")
    create_case(tmp_path)
    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute("UPDATE identifiers SET state = 'retired'")
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="current identifier state"):
        verify_chain(tmp_path)

    other = tmp_path / "counter"
    initialise_project(other, "P-2", "Test")
    create_case(other)
    connection = sqlite3.connect(catalogue_path(other))
    connection.execute(
        "UPDATE counters SET next_sequence = 99 WHERE namespace = 'case'"
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="counter does not match"):
        verify_chain(other)


def test_checkpoint_rejects_failed_public_key_import(
    tmp_path: Path, monkeypatch
) -> None:
    initialise_project(tmp_path, "P-1", "Test")
    toolkit = tmp_path / "toolkit"
    home = toolkit / "pgp" / "keyring"
    home.mkdir(parents=True)
    monkeypatch.setattr(catalogue_module, "prepare_gnupg", lambda *a, **k: {})
    monkeypatch.setattr(catalogue_module, "fingerprint", lambda *a, **k: "FPR")
    monkeypatch.setattr(
        catalogue_module, "sign", lambda h, p, s, f: s.write_text("sig")
    )
    write_checkpoint(tmp_path, toolkit)
    public_key = tmp_path / "public.asc"
    public_key.write_text("key")
    monkeypatch.setattr(
        catalogue_module, "run", lambda argv, **kwargs: ToolResult(argv, 1, "", "bad")
    )
    with pytest.raises(ToolkitError, match="Unable to import"):
        verify_checkpoint(tmp_path, public_key)


def test_acquisition_ids_are_sequential_and_failed_ids_are_not_reused(
    tmp_path: Path,
) -> None:
    initialise_project(tmp_path, "P-1", "Test")
    first = issue_identifier(tmp_path, "acquisition", "ACQ")
    fail_identifier(tmp_path, first, "operator cancelled")
    second = issue_identifier(tmp_path, "acquisition", "ACQ")
    assert (first, second) == ("ACQ-000001", "ACQ-000002")
    rows = list_identifiers(tmp_path, "acquisition")
    assert [row["state"] for row in rows] == ["failed", "active"]
    assert verify_chain(tmp_path)["event_count"] == 3


def test_missing_current_namespace_counter_fails_closed(tmp_path: Path) -> None:
    """Do not rewrite an incompatible or damaged catalogue during allocation."""
    initialise_project(tmp_path, "P-1", "Test")
    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute("DELETE FROM counters WHERE namespace = 'acquisition'")
    connection.commit()
    connection.close()

    with pytest.raises(
        ToolkitError, match="missing the required 'acquisition' identifier counter"
    ):
        issue_identifier(tmp_path, "acquisition", "ACQ")


def test_fail_identifier_rejects_unknown_and_non_active_ids(tmp_path: Path) -> None:
    initialise_project(tmp_path, "P-1", "Test")
    with pytest.raises(ToolkitError, match="Unknown FACT identifier"):
        fail_identifier(tmp_path, "ACQ-999999")
    identifier = issue_identifier(tmp_path, "acquisition", "ACQ")
    fail_identifier(tmp_path, identifier)
    with pytest.raises(ToolkitError, match="already failed"):
        fail_identifier(tmp_path, identifier)
