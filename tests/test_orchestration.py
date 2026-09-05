"""Tests for acquisition convergence onto the authoritative file catalogue."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pytest

from fact.core import authority, catalogue
from fact.core.acquisition import AcquisitionContext, AcquisitionResult, ArtefactRole
from fact.core.authority import assign_case_owner, establish_project_genesis
from fact.core.catalogue import catalogue_path, verify_chain
from fact.core.files import list_files
from fact.core.orchestration import run_collector_acquisition
from fact.core.project import _initialise_project as initialise_project
from fact.core.project import create_case
from fact.errors import ToolkitError
from fact.identity import OperatorIdentity
from fact.models import CaseInfo


def owner() -> OperatorIdentity:
    return OperatorIdentity(1, "owner", "Owner", None, None, None, "A" * 40, "a" * 40)


@pytest.fixture(autouse=True)
def fake_signatures(monkeypatch: pytest.MonkeyPatch) -> None:
    def sign(identity: OperatorIdentity, payload: bytes) -> str:
        return f"SIG:{identity.operator_id}:{hashlib.sha256(payload).hexdigest()}"

    monkeypatch.setattr(authority, "sign_operator_payload", sign)
    monkeypatch.setattr(authority, "verify_operator_payload", lambda *args: None)
    monkeypatch.setattr(catalogue, "verify_operator_payload", lambda *args: None)


def project(root: Path) -> tuple[OperatorIdentity, str, CaseInfo]:
    actor = owner()
    initialise_project(root, "P-ORCH", "Orchestration")
    establish_project_genesis(root, actor, "PUBLIC OWNER")
    case_id = create_case(root, "Case")
    assign_case_owner(root, case_id, actor)
    case = CaseInfo(
        case_id, "Purpose", actor.public_dict(), "tester", "Requestor", "Matter"
    )
    return actor, case_id, case


@dataclass
class RetainedCollector:
    name: str = "test"

    def capture(
        self, context: AcquisitionContext, request: object
    ) -> AcquisitionResult:
        original = context.workspace.stage / "original.bin"
        metadata = context.workspace.stage / "metadata.json"
        original.write_bytes(b"immutable source")
        metadata.write_text('{"source":"test"}\n', encoding="utf-8")
        context.artefacts.register(
            original,
            role=ArtefactRole.PRIMARY,
            media_type="application/octet-stream",
            description="Original source bytes",
        )
        context.artefacts.register(
            metadata,
            role=ArtefactRole.SOURCE_METADATA,
            media_type="application/json",
            description="Retained source metadata",
            related_to=original,
            relationship="describes",
        )
        context.metadata["tools"] = {"collector-test": "1.0"}
        return AcquisitionResult(
            collector=self.name,
            collector_version="1.0",
            source={"target": "test://source"},
            evidence={"capture": "complete"},
            observations=["Retained two source files."],
        )


@dataclass
class DirtyCollector:
    name: str = "dirty"

    def capture(
        self, context: AcquisitionContext, request: object
    ) -> AcquisitionResult:
        retained = context.workspace.stage / "retained.txt"
        retained.write_text("retained", encoding="utf-8")
        context.artefacts.register(retained, role=ArtefactRole.PRIMARY)
        (context.workspace.stage / "forgotten.tmp").write_text(
            "scratch", encoding="utf-8"
        )
        return AcquisitionResult(collector=self.name, collector_version="1.0")


def test_success_commits_only_retained_files_and_cleans_staging(tmp_path: Path) -> None:
    _, case_id, case = project(tmp_path)

    acquisition_id = run_collector_acquisition(
        root=tmp_path,
        case=case,
        collector=RetainedCollector(),
        request=object(),
        initial_source={"collector": "test"},
    )

    assert acquisition_id == "ACQ-000001"
    rows = list_files(tmp_path, case_id=case_id)
    assert {row["classification"] for row in rows} == {
        "primary",
        "source_metadata",
        "transcript",
    }
    assert all(row["acquisition_id"] == acquisition_id for row in rows)
    assert not (tmp_path / ".fact" / "staging" / "acquisitions").exists()
    assert not (tmp_path / "archived").exists()

    connection = sqlite3.connect(catalogue_path(tmp_path))
    connection.row_factory = sqlite3.Row
    try:
        event = connection.execute(
            "SELECT details_json FROM audit_events "
            "WHERE event_type = 'ACQUISITION_RECORDED' AND object_id = ?",
            (acquisition_id,),
        ).fetchone()
        relationship = connection.execute(
            "SELECT relationship FROM file_relationships"
        ).fetchone()
    finally:
        connection.close()
    data = json.loads(event["details_json"])["authority_transaction"]["data"]
    assert data["file_ids"] == [row["file_id"] for row in rows]
    assert data["record"]["source"]["target"] == "test://source"
    assert data["record"]["tools"] == {"collector-test": "1.0"}
    assert relationship["relationship"] == "describes"
    verify_chain(tmp_path)


def test_unregistered_leftover_is_not_silently_admitted_as_evidence(
    tmp_path: Path,
) -> None:
    _, _, case = project(tmp_path)

    with pytest.raises(ToolkitError, match="unregistered retained file"):
        run_collector_acquisition(
            root=tmp_path,
            case=case,
            collector=DirtyCollector(),
            request=object(),
            initial_source={"collector": "dirty"},
        )

    stage = (
        tmp_path
        / ".fact"
        / "staging"
        / "acquisitions"
        / ".staging-CASE-000001-ACQ-000001"
    )
    assert stage.is_dir()
    assert (stage / "INCOMPLETE").is_file()
    assert (stage / "forgotten.tmp").is_file()
    assert list_files(tmp_path) == []
    verify_chain(tmp_path)
