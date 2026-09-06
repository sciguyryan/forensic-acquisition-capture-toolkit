"""Run source-independent FACT acquisitions into the authoritative file catalogue.

Collectors own source capture only. The orchestration layer allocates the
acquisition, supplies mutable staging, commits every intentionally retained file
through the common file store, records acquisition provenance in the
authenticated catalogue, and verifies the complete project before successful
staging is discarded.

A successful acquisition does not create a second sealed archive of the same
bytes. Portable archives belong to project packaging/export. This keeps the
live project authoritative in one place: the catalogue and its committed files.
"""

from __future__ import annotations

import shutil
from contextlib import suppress
from pathlib import Path
from typing import Any

from ..collectors.base import Collector
from ..console import summary
from ..errors import ToolkitError
from ..identity import OperatorIdentity
from ..models import CaseInfo, iso_utc
from ..services.commands import CommandRunner
from .acquisition import AcquisitionContext, AcquisitionWorkspace, ArtefactRegistry
from .artefacts import create_acquisition_artefacts
from .authority import record_acquisition, require_registered_operator
from .catalogue import catalogue_path, fail_identifier, issue_identifier, verify_chain
from .files import FileCandidate, commit_files, relate_files
from .records import initial_record_for_source


def _retained_core_candidate(path: Path, stage: Path) -> FileCandidate | None:
    """Describe a collector-independent retained file, if it is authoritative.

    Collector-independent acquisition staging is intentionally sparse. The
    acquisition transcript is irreducible provenance and is therefore checked
    in. INCOMPLETE is a staging lifecycle marker and never crosses the evidence
    boundary. Other unregistered files are rejected instead of silently becoming
    evidence merely because an implementation happened to leave them in staging.
    """

    relative = path.relative_to(stage).as_posix()
    if relative == "INCOMPLETE":
        return None
    if relative == "acquisition.log":
        return FileCandidate(
            path=path,
            logical_path=relative,
            classification="transcript",
            media_type="text/plain",
            description="FACT acquisition lifecycle transcript",
        )
    return None


def _build_candidates(context: AcquisitionContext) -> list[FileCandidate]:
    """Build the complete authoritative file batch for one acquisition.

    Every registered collector artefact is retained. FACT-generated staging
    content is admitted only through the explicit core allow-list above. Any
    other regular file is an architectural error: silently sweeping it into the
    catalogue would blur the boundary between evidential material and temporary
    implementation state.
    """

    stage = context.workspace.stage
    candidates: list[FileCandidate] = []
    seen: set[str] = set()

    for artefact in context.artefacts.items():
        path = stage / artefact.path
        candidates.append(
            FileCandidate(
                path=path,
                logical_path=artefact.path,
                classification=artefact.role.value,
                media_type=artefact.media_type,
                description=artefact.description,
            )
        )
        seen.add(artefact.path)

    for path in sorted(stage.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(stage).as_posix()
        if relative in seen:
            continue
        candidate = _retained_core_candidate(path, stage)
        if candidate is not None:
            candidates.append(candidate)
            seen.add(relative)
            continue
        if relative == "INCOMPLETE":
            continue
        raise ToolkitError(
            "Acquisition staging contains an unregistered retained file: "
            f"{relative}. Collectors must explicitly register retained material; "
            "temporary working data must be removed before commitment."
        )

    return candidates


def run_collector_acquisition(
    *,
    root: Path,
    case: CaseInfo,
    collector: Collector[Any],
    request: Any,
    initial_source: dict[str, Any],
    initial_evidence: dict[str, Any] | None = None,
    commands: CommandRunner | None = None,
) -> str:
    """Capture and commit one acquisition, returning its permanent identifier.

    ``ACQ-######`` is consumed as soon as it is issued. Failed capture retains
    its private staging tree for diagnosis but does not check that transient
    material into the authoritative file catalogue. Successful capture commits
    the complete retained batch, records its provenance and exact file
    membership in the authenticated catalogue, verifies the resulting project,
    and only then removes the now-redundant staging tree.
    """

    root = root.resolve()
    if not catalogue_path(root).is_file():
        raise ToolkitError("FACT acquisitions require a current project catalogue")
    identity = OperatorIdentity(**case.operator_identity)
    require_registered_operator(root, identity)
    run_id = issue_identifier(root, "acquisition", "ACQ")

    try:
        workspace = AcquisitionWorkspace.create(root, case.case_id, run_id)
    except Exception:
        fail_identifier(root, run_id, "workspace creation failed")
        raise

    committed = False
    try:
        context = AcquisitionContext(
            project_root=root,
            case_id=case.case_id,
            acquisition_id=run_id,
            workspace=workspace,
            artefacts=ArtefactRegistry(workspace.stage),
            commands=commands or CommandRunner(),
        )
        workspace.note("INFO", f"Acquisition allocated: {run_id} in {case.case_id}")
        workspace.note(
            "INFO",
            (
                f"Operator identified as {identity.name!r} "
                f"({identity.operator_id}); login username: {case.operator_username}"
            ),
        )

        source = dict(initial_source)
        source.setdefault("collector", collector.name)
        record = initial_record_for_source(case, run_id, source, {})
        record.evidence.update(dict(initial_evidence or {}))

        result = collector.capture(context, request)
        record.acquisition["completed_utc"] = (
            record.acquisition.get("completed_utc") or iso_utc()
        )
        record.source.update(result.source)
        record.source["collector"] = result.collector
        record.evidence.update(result.evidence)
        record.tools = dict(context.metadata.get("tools", {}))
        record.observations.extend(result.observations)

        workspace.note("INFO", "Committing intentionally retained acquisition files")
        committed_files = commit_files(
            root,
            case_id=case.case_id,
            acquisition_id=run_id,
            actor_id=identity.operator_id,
            candidates=_build_candidates(context),
        )
        committed = True
        committed_by_path = {
            str(item["logical_path"]): str(item["file_id"]) for item in committed_files
        }
        for artefact in context.artefacts.items():
            if artefact.related_to is None or artefact.relationship is None:
                continue
            parent_id = committed_by_path.get(artefact.related_to)
            child_id = committed_by_path.get(artefact.path)
            if parent_id is None or child_id is None:
                raise ToolkitError(
                    "Registered artefact relationship was not committed with its files"
                )
            relate_files(
                root,
                parent_file_id=parent_id,
                child_file_id=child_id,
                relationship=artefact.relationship,
            )

        artefacts = create_acquisition_artefacts(
            root,
            case_id=case.case_id,
            acquisition_id=run_id,
            entries=[
                {
                    "file_id": committed_by_path[item.path],
                    "role": item.role.value,
                    "description": item.description,
                }
                for item in context.artefacts.items()
            ],
        )
        if artefacts:
            workspace.note(
                "INFO",
                f"Assigned {len(artefacts)} immutable ART identifiers to retained collector artefacts",
            )

        file_ids = [str(item["file_id"]) for item in committed_files]
        status = record_acquisition(
            root,
            identity,
            acquisition_id=run_id,
            case_id=case.case_id,
            collector=result.collector,
            completed_utc=str(record.acquisition["completed_utc"]),
            file_ids=file_ids,
            record=record.to_dict(),
        )
        verified = verify_chain(root)
        workspace.note(
            "INFO",
            (
                f"Acquisition authority state recorded as {status}: {run_id}; "
                f"catalogue verified at {verified['event_count']} events"
            ),
        )

        # Successful staging is now duplicate working state. The authoritative
        # copies live under FILE-###### storage and in the catalogue. Failed
        # staging is intentionally retained by the exception path below.
        shutil.rmtree(workspace.stage)
        parent = workspace.stage.parent
        if parent.exists() and not any(parent.iterdir()):
            parent.rmdir()

        summary(
            "EVIDENCE ACQUISITION COMMITTED",
            [
                ("Case ID", case.case_id, "INFO"),
                ("Acquisition ID", run_id, "INFO"),
                ("Collector", result.collector, "INFO"),
                ("Operator", identity.name, "INFO"),
                ("Operator ID", identity.operator_id, "INFO"),
                ("Committed files", str(len(committed_files)), "PASS"),
                ("Authority state", status, "PASS" if status == "approved" else "INFO"),
                ("Catalogue verification", "PASS", "PASS"),
            ],
            True,
        )
        return run_id
    except Exception as exc:
        if not committed:
            with suppress(Exception):
                fail_identifier(root, run_id, str(exc))
        raise
