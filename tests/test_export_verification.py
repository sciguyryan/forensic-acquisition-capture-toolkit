"""Tests for immutable exports, export policy, verification and reports."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from fact.core import authority, catalogue
from fact.core.artefacts import create_acquisition_artefacts, list_artefacts
from fact.core.authority import establish_project_genesis, record_acquisition
from fact.core.catalogue import catalogue_path, issue_identifier, verify_chain
from fact.core.export_policy import get_export_policy, set_export_policy
from fact.core.exports import create_export, list_exports
from fact.core.files import FileCandidate, commit_files, set_file_presentation
from fact.core.project import _initialise_project as initialise_project
from fact.core.project import create_owned_case
from fact.core.reporting import render_report, write_report
from fact.core.verification import (
    verify_export,
    verify_external_file,
    verify_id,
    verify_structural,
)
from fact.errors import ToolkitError
from fact.identity import OperatorIdentity


def operator(operator_id: str, fingerprint_char: str = "A") -> OperatorIdentity:
    return OperatorIdentity(
        1,
        operator_id,
        operator_id.title(),
        f"{operator_id}@example.test",
        "Example Unit",
        "Investigator",
        fingerprint_char * 40,
        fingerprint_char.lower() * 40,
    )


@pytest.fixture(autouse=True)
def fake_signatures(monkeypatch: pytest.MonkeyPatch) -> None:
    def sign(identity: OperatorIdentity, payload: bytes) -> str:
        return f"TEST:{identity.operator_id}:{hashlib.sha256(payload).hexdigest()}"

    monkeypatch.setattr(authority, "sign_operator_payload", sign)
    monkeypatch.setattr(authority, "verify_operator_payload", lambda *args: None)
    monkeypatch.setattr(catalogue, "verify_operator_payload", lambda *args: None)


def project_with_acquisition(
    tmp_path: Path, *, chain_hash: str = "sha256", content_hash: str = "sha256"
):
    owner = operator("owner")
    initialise_project(
        tmp_path,
        "P-EXPORT",
        "Export project",
        chain_hash=chain_hash,
        content_hash=content_hash,
    )
    establish_project_genesis(tmp_path, owner, "PUBLIC OWNER")
    case_id = create_owned_case(tmp_path, owner, "Matter", "")
    acquisition_id = issue_identifier(tmp_path, "acquisition", "ACQ")
    first_source = tmp_path / "source-a.bin"
    second_source = tmp_path / "source-b.txt"
    first_source.write_bytes(b"alpha evidence")
    second_source.write_text("metadata", encoding="utf-8")
    committed = commit_files(
        tmp_path,
        case_id=case_id,
        acquisition_id=acquisition_id,
        actor_id=owner.operator_id,
        candidates=[
            FileCandidate(
                first_source, "source-a.bin", "primary", "application/octet-stream"
            ),
            FileCandidate(second_source, "source-b.txt", "metadata", "text/plain"),
        ],
    )
    artefacts = create_acquisition_artefacts(
        tmp_path,
        case_id=case_id,
        acquisition_id=acquisition_id,
        entries=[
            {
                "file_id": str(committed[0]["file_id"]),
                "role": "primary",
                "description": "Primary source",
            },
            {
                "file_id": str(committed[1]["file_id"]),
                "role": "metadata",
                "description": "Source metadata",
            },
        ],
    )
    record_acquisition(
        tmp_path,
        owner,
        acquisition_id=acquisition_id,
        case_id=case_id,
        collector="test",
        completed_utc="2026-09-05T12:00:00Z",
        file_ids=[str(item["file_id"]) for item in committed],
        record={"source": {"collector": "test"}},
    )
    return owner, case_id, acquisition_id, committed, artefacts


def test_default_and_changed_export_policy_is_authenticated(tmp_path: Path) -> None:
    owner, *_ = project_with_acquisition(tmp_path)
    policy = get_export_policy(tmp_path)
    assert policy["ordinary_export"] == "members"
    assert policy["broad_scope_export"] == "owner"

    changed = set_export_policy(
        tmp_path,
        owner,
        ordinary_export="owner",
        ciphertext_export="owner",
        broad_scope_export="members",
    )
    assert changed["ordinary_export"] == "owner"
    assert changed["broad_scope_export"] == "members"
    assert verify_chain(tmp_path)["event_count"] > 0

    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute(
        "UPDATE export_policy SET ordinary_export = 'members' WHERE policy_id = 'project'"
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="export policy"):
        verify_chain(tmp_path)


def test_directory_export_and_all_verification_entry_points(tmp_path: Path) -> None:
    owner, case_id, acquisition_id, committed, artefacts = project_with_acquisition(
        tmp_path
    )
    output = tmp_path.parent / "directory-export"
    exported = create_export(
        tmp_path,
        owner,
        scope_type="case",
        scope_id=case_id,
        output=output,
        output_format="directory",
    )
    assert exported["export_id"] == "EXPORT-000001"
    assert exported["file_count"] == 2
    assert (output / "FACT-EXPORT.json").is_file()
    assert list_exports(tmp_path)[0]["state"] == "completed"

    external = output / "files" / str(committed[0]["file_id"]) / "source-a.bin"
    file_result = verify_external_file(tmp_path, external)
    assert file_result["status"] == "verified"
    assert [item["file_id"] for item in file_result["matches"]] == [
        committed[0]["file_id"]
    ]

    assert (
        verify_structural(tmp_path, "file", str(committed[0]["file_id"]))["status"]
        == "verified"
    )
    assert (
        verify_structural(tmp_path, "artefact", str(artefacts[0]["artefact_id"]))[
            "status"
        ]
        == "verified"
    )
    assert (
        verify_structural(tmp_path, "acquisition", acquisition_id)["status"]
        == "verified"
    )
    assert verify_structural(tmp_path, "case", case_id)["status"] == "verified"
    project_result = verify_structural(tmp_path, "project")
    assert project_result["scope"]["project_chain"]["hashed_file_count"] == 2
    assert verify_id(tmp_path, str(committed[0]["file_id"]))["status"] == "verified"
    assert verify_id(tmp_path, str(artefacts[0]["artefact_id"]))["status"] == "verified"
    assert verify_id(tmp_path, acquisition_id)["status"] == "verified"
    assert verify_id(tmp_path, case_id)["status"] == "verified"
    assert verify_id(tmp_path, exported["export_id"])["status"] == "verified"

    export_result = verify_export(tmp_path, output)
    assert export_result["status"] == "verified"
    assert export_result["matches"][0]["export_id"] == exported["export_id"]


def test_external_file_reports_all_duplicate_byte_identities_and_unmatched(
    tmp_path: Path,
) -> None:
    owner, case_id, _, committed, _ = project_with_acquisition(tmp_path)
    duplicate = tmp_path / "duplicate.bin"
    duplicate.write_bytes(b"alpha evidence")
    duplicate_committed = commit_files(
        tmp_path,
        case_id=case_id,
        acquisition_id=None,
        actor_id=owner.operator_id,
        candidates=[FileCandidate(duplicate, "duplicate.bin", "supporting")],
    )[0]
    result = verify_external_file(tmp_path, duplicate)
    assert {item["file_id"] for item in result["matches"]} == {
        committed[0]["file_id"],
        duplicate_committed["file_id"],
    }

    unknown = tmp_path / "unknown.bin"
    unknown.write_bytes(b"not known")
    result = verify_external_file(tmp_path, unknown)
    assert result["status"] == "unmatched"
    assert result["matches"] == []


def test_presented_export_filters_retracted_file_and_selection_expands_ids(
    tmp_path: Path,
) -> None:
    owner, case_id, acquisition_id, committed, artefacts = project_with_acquisition(
        tmp_path
    )
    set_file_presentation(
        tmp_path,
        str(committed[1]["file_id"]),
        state="retracted",
        reason="presentation test",
    )
    presented = create_export(
        tmp_path,
        owner,
        scope_type="case",
        scope_id=case_id,
        output=tmp_path.parent / "presented",
        view_mode="presented",
    )
    assert presented["file_count"] == 1
    full = create_export(
        tmp_path,
        owner,
        scope_type="selection",
        selection_ids=[acquisition_id, str(artefacts[0]["artefact_id"])],
        output=tmp_path.parent / "full-selection",
        view_mode="full",
    )
    assert full["file_count"] == 2


def test_tar_export_verification_and_tamper_detection(tmp_path: Path) -> None:
    owner, _, _, committed, _ = project_with_acquisition(tmp_path)
    archive = tmp_path.parent / "single.fact-export.tar.gz"
    exported = create_export(
        tmp_path,
        owner,
        scope_type="file",
        scope_id=str(committed[0]["file_id"]),
        output=archive,
        output_format="tar",
    )
    assert exported["output"] == archive
    assert verify_export(tmp_path, archive)["status"] == "verified"

    archive.write_bytes(archive.read_bytes() + b"tamper")
    with pytest.raises(ToolkitError, match="digest differs"):
        verify_export(tmp_path, archive)


def test_directory_export_tamper_and_event_table_tamper_are_detected(
    tmp_path: Path,
) -> None:
    owner, _, _, committed, _ = project_with_acquisition(tmp_path)
    output = tmp_path.parent / "tamper-export"
    exported = create_export(
        tmp_path,
        owner,
        scope_type="file",
        scope_id=str(committed[0]["file_id"]),
        output=output,
    )
    payload = output / "files" / str(committed[0]["file_id"]) / "source-a.bin"
    payload.write_bytes(b"changed")
    with pytest.raises(ToolkitError, match="digest differs"):
        verify_export(tmp_path, output)

    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute(
        "UPDATE exports SET manifest_digest = ? WHERE export_id = ?",
        ("f" * 64, exported["export_id"]),
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="Export catalogue"):
        verify_chain(tmp_path)


def test_export_refuses_unsafe_or_unsupported_requests(tmp_path: Path) -> None:
    owner, case_id, _, committed, _ = project_with_acquisition(tmp_path)
    with pytest.raises(ToolkitError, match="Only native representation"):
        create_export(
            tmp_path,
            owner,
            scope_type="case",
            scope_id=case_id,
            representation="rendered",
        )
    with pytest.raises(ToolkitError, match="requires --format tar"):
        create_export(
            tmp_path,
            owner,
            scope_type="file",
            scope_id=str(committed[0]["file_id"]),
            encrypt_to=["recipient"],
        )
    existing = tmp_path.parent / "existing"
    existing.mkdir()
    (existing / "not-fact.txt").write_text("x")
    with pytest.raises(ToolkitError, match="already exists"):
        create_export(
            tmp_path,
            owner,
            scope_type="file",
            scope_id=str(committed[0]["file_id"]),
            output=existing,
        )


def test_reports_share_one_structured_result_and_render_all_formats(
    tmp_path: Path,
) -> None:
    _, _, _, committed, _ = project_with_acquisition(tmp_path)
    result = verify_structural(tmp_path, "file", str(committed[0]["file_id"]))
    text = render_report(result, format_name="text", detailed=True)
    html = render_report(result, format_name="html", detailed=True)
    json_bytes = render_report(result, format_name="json", detailed=False)
    pdf = render_report(result, format_name="pdf", detailed=True)
    assert b"FACT Verification Report" in text
    assert b"<!doctype html>" in html
    assert json.loads(json_bytes)["schema"] == "fact-verification-result/v1"
    assert pdf.startswith(b"%PDF-1.4")

    paths = []
    for format_name, suffix in (
        ("text", ".txt"),
        ("html", ".html"),
        ("json", ".json"),
        ("pdf", ".pdf"),
    ):
        path = write_report(
            result,
            format_name=format_name,
            output=tmp_path.parent / f"report{suffix}",
            detailed=True,
        )
        assert path.is_file()
        paths.append(path)
    assert len(paths) == 4
    with pytest.raises(ToolkitError, match="Unsupported verification report"):
        render_report(result, format_name="yaml")


def test_artefact_catalogue_listing_and_tamper_detection(tmp_path: Path) -> None:
    _, _, _, _, artefacts = project_with_acquisition(tmp_path)
    listed = list_artefacts(tmp_path)
    assert [item["artefact_id"] for item in listed] == [
        item["artefact_id"] for item in artefacts
    ]
    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.execute(
        "UPDATE artefacts SET role = 'changed' WHERE artefact_id = ?",
        (artefacts[0]["artefact_id"],),
    )
    connection.commit()
    connection.close()
    with pytest.raises(ToolkitError, match="Artefact catalogue"):
        verify_chain(tmp_path)


def test_policy_enforces_owner_only_export_for_contributor(tmp_path: Path) -> None:
    from fact.core.authority import accept_contributor, invite_contributor

    owner, _, _, committed, _ = project_with_acquisition(tmp_path)
    alice = operator("alice", "B")
    invite_contributor(tmp_path, owner, alice, "PUBLIC ALICE")
    accept_contributor(tmp_path, alice)
    with pytest.raises(ToolkitError, match="Only the current project owner"):
        set_export_policy(tmp_path, alice, ordinary_export="owner")
    set_export_policy(
        tmp_path,
        owner,
        ordinary_export="owner",
        broad_scope_export="owner",
    )
    with pytest.raises(ToolkitError, match="reserves ordinary export"):
        create_export(
            tmp_path,
            alice,
            scope_type="file",
            scope_id=str(committed[0]["file_id"]),
            output=tmp_path.parent / "denied",
        )
    with pytest.raises(ToolkitError, match="reserves broad scope export"):
        create_export(
            tmp_path,
            alice,
            scope_type="project",
            output=tmp_path.parent / "denied-project",
        )


def test_verify_id_supports_project_and_note_and_rejects_unknown(
    tmp_path: Path,
) -> None:
    from fact.core.notes import create_note

    owner, *_ = project_with_acquisition(tmp_path)
    note_id = create_note(tmp_path, owner, "Note", "Body")
    assert verify_id(tmp_path, "P-EXPORT")["verification_kind"] == "structural-project"
    assert verify_id(tmp_path, note_id)["verification_kind"] == "structural-note"
    with pytest.raises(ToolkitError, match="Unknown immutable FACT identifier"):
        verify_id(tmp_path, "FILE-999999")
    with pytest.raises(ToolkitError, match="Unknown FACT artefact"):
        verify_structural(tmp_path, "artefact", "ART-999999")
    with pytest.raises(ToolkitError, match="Unsupported FACT verification object type"):
        verify_structural(tmp_path, "widget", "W-1")


def test_confidential_note_exports_ciphertext_or_authorised_plaintext(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fact.core import exports as exports_module
    from fact.core import notes as notes_module
    from fact.core.authority import accept_contributor, invite_contributor
    from fact.core.notes import create_note

    owner, *_ = project_with_acquisition(tmp_path)
    alice = operator("alice", "B")
    invite_contributor(tmp_path, owner, alice, "PUBLIC ALICE")
    accept_contributor(tmp_path, alice)
    monkeypatch.setattr(
        notes_module,
        "encrypt_for_project_keys",
        lambda payload, keys: b"ENC:" + payload,
    )
    monkeypatch.setattr(
        notes_module,
        "decrypt_confidential_payload",
        lambda payload: payload[4:] if payload.startswith(b"ENC:") else payload,
    )
    monkeypatch.setattr(
        exports_module,
        "decrypt_confidential_payload",
        lambda payload: payload[4:] if payload.startswith(b"ENC:") else payload,
    )
    note_id = create_note(
        tmp_path,
        alice,
        "Secret",
        "Plaintext",
        visibility="confidential",
    )
    connection = sqlite3.connect(catalogue_path(tmp_path))
    file_id = connection.execute(
        "SELECT file_id FROM note_revisions WHERE note_id = ?", (note_id,)
    ).fetchone()[0]
    connection.close()

    ciphertext_export = create_export(
        tmp_path,
        alice,
        scope_type="file",
        scope_id=str(file_id),
        output=tmp_path.parent / "ciphertext-export",
    )
    assert ciphertext_export["file_count"] == 1

    plaintext_export = create_export(
        tmp_path,
        alice,
        scope_type="file",
        scope_id=str(file_id),
        output=tmp_path.parent / "plaintext-export",
        decrypt_confidential=True,
    )
    result = verify_export(tmp_path, plaintext_export["output"])
    assert result["status"] == "verified"
    assert result["warnings"]

    set_export_policy(tmp_path, owner, confidential_plaintext_export="owner")
    with pytest.raises(ToolkitError, match="Plaintext confidential export"):
        create_export(
            tmp_path,
            alice,
            scope_type="file",
            scope_id=str(file_id),
            output=tmp_path.parent / "plaintext-denied",
            decrypt_confidential=True,
        )


def test_cli_dispatches_new_verify_and_export_read_commands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from fact import cli

    project_with_acquisition(tmp_path)
    assert cli.main(["--root", str(tmp_path), "export", "policy", "show"]) == 0
    assert "ordinary_export=members" in capsys.readouterr().out
    assert cli.main(["--root", str(tmp_path), "export", "list"]) == 0
    assert cli.main(["--root", str(tmp_path), "verify", "project"]) == 0
    assert (
        cli.main(
            [
                "--root",
                str(tmp_path),
                "verify",
                "id",
                "P-EXPORT",
                "--detailed",
            ]
        )
        == 0
    )
    assert "FACT Verification Report" in capsys.readouterr().out


def test_export_verify_then_full_project_verify_preserves_provenance_chain(
    tmp_path: Path,
) -> None:
    """Exercise disclosure correspondence and exhaustive project verification together."""
    owner, case_id, _, committed, _ = project_with_acquisition(tmp_path)
    output = tmp_path.parent / "provenance-export"
    exported = create_export(
        tmp_path,
        owner,
        scope_type="case",
        scope_id=case_id,
        output=output,
        output_format="directory",
    )

    export_result = verify_export(tmp_path, output)
    assert export_result["status"] == "verified"
    assert export_result["matches"][0]["export_id"] == exported["export_id"]

    project_result = verify_structural(tmp_path, "project")
    assert project_result["status"] == "verified"
    assert project_result["scope"]["project_chain"]["hashed_file_count"] == len(
        committed
    )

    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        "SELECT event_type, actor_id, actor_uuid, credential_fingerprint "
        "FROM audit_events WHERE object_id = ? ORDER BY event_sequence",
        (exported["export_id"],),
    ).fetchall()
    connection.close()
    assert [row["event_type"] for row in rows] == [
        "IDENTIFIER_ISSUED",
        "EXPORT_STARTED",
        "EXPORT_COMPLETED",
    ]
    authoritative = [row for row in rows if row["event_type"] != "IDENTIFIER_ISSUED"]
    assert all(row["actor_id"] == owner.operator_id for row in authoritative)
    assert all(row["actor_uuid"] for row in authoritative)
    assert all(
        row["credential_fingerprint"] == owner.operator_signing_subkey_fingerprint
        for row in authoritative
    )
    assert rows[0]["actor_id"] is None
    assert rows[0]["actor_uuid"] is None


def test_sha3_512_project_export_verify_and_full_project_verify(tmp_path: Path) -> None:
    owner, case_id, _, committed, _ = project_with_acquisition(
        tmp_path, chain_hash="sha3-512", content_hash="sha3-512"
    )
    output = tmp_path.parent / "sha3-512-export"
    exported = create_export(
        tmp_path, owner, scope_type="case", scope_id=case_id, output=output
    )
    external = verify_export(tmp_path, output)
    assert external["status"] == "verified"
    verified = verify_chain(tmp_path)
    assert verified["hashed_file_count"] == len(committed)
    assert len(str(verified["chain_head"])) == 128
    connection = sqlite3.connect(catalogue_path(tmp_path))
    try:
        digest = connection.execute(
            "SELECT content_digest FROM files WHERE file_id = ?",
            (committed[0]["file_id"],),
        ).fetchone()[0]
        manifest = json.loads((output / "FACT-EXPORT.json").read_text(encoding="utf-8"))
    finally:
        connection.close()
    assert len(digest) == 128
    assert manifest["content_hash_algorithm"] == "sha3-512"
    assert exported["export_id"] == "EXPORT-000001"
