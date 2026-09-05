"""Run source-independent FACT acquisitions from capture through sealing.

This module owns the common acquisition preparation that was historically tied
to the YouTube path: workspace allocation, evidence-key preparation, operator
binding, common records and final sealing.  A collector therefore receives a
prepared :class:`~fact.core.acquisition.AcquisitionContext` and can concentrate
solely on acquiring its source.
"""

from __future__ import annotations

import json
import shutil
from contextlib import suppress
from pathlib import Path
from typing import Any

from ..collectors.base import Collector
from ..errors import ToolkitError
from ..identity import OperatorIdentity, export_public_key
from ..keys import ensure_key
from ..models import CaseInfo
from ..services.commands import CommandRunner
from ..services.hashing import digest
from .acquisition import AcquisitionContext, AcquisitionWorkspace, ArtefactRegistry
from .authority import record_acquisition, require_registered_operator
from .catalogue import catalogue_path, fail_identifier, issue_identifier
from .files import FileCandidate, commit_files, relate_files
from .records import initial_record_for_source, write_record
from .sealing import seal_acquisition


def _core_record_classification(logical_path: str) -> str:
    """Classify collector-independent files retained by acquisition sealing."""

    name = Path(logical_path).name
    if name in {
        "SHA256SUMS.txt",
        "SHA512SUMS.txt",
        "EVIDENCESET-SHA256.txt",
        "FILELIST.txt",
    }:
        return "manifest"
    if name in {"evidence-public-key.asc", "operator-public-key.asc"}:
        return "verification_key"
    if name == "ARTEFACTS.json":
        return "artefact_registry"
    if name == "acquisition.log":
        return "transcript"
    if name in {"CASE.json", "operator-identity.json", "TOOLKIT.json"}:
        return "metadata"
    if name in {"acquisition.txt", "VERIFICATION.txt"}:
        return "record"
    return "record"


def _core_record_media_type(logical_path: str) -> str | None:
    """Return a conservative media type for FACT-generated retained records."""

    suffix = Path(logical_path).suffix.lower()
    if suffix == ".json":
        return "application/json"
    if suffix in {".txt", ".log"}:
        return "text/plain"
    if suffix == ".asc":
        return "application/pgp-keys"
    return None


def run_collector_acquisition(
    *,
    root: Path,
    case: CaseInfo,
    collector: Collector[Any],
    request: Any,
    initial_source: dict[str, Any],
    initial_evidence: dict[str, Any] | None = None,
    commands: CommandRunner | None = None,
) -> Path:
    """Prepare, capture, and seal one acquisition using a registered collector.

    The catalogue owns sequential acquisition identifiers for project-backed
    work. Once issued, an ``ACQ-######`` value is consumed permanently. Any
    subsequent preparation, capture, sealing, or verification failure therefore
    marks that identifier as failed while preserving the ``INCOMPLETE`` staging
    tree whenever one was created. Once sealing succeeds, the identifier remains
    active even if later catalogue authority recording fails, because FACT must
    not relabel already-sealed evidence as a failed acquisition.
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
        # Workspace creation may fail before there is any filesystem evidence of
        # the attempt. The catalogue still records the consumed identifier so it
        # can never later be reused for unrelated material.
        fail_identifier(root, run_id, "workspace creation failed")
        raise

    sealed = False
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

        pgp_dir = root / "pgp"
        pgp_dir.mkdir(parents=True, exist_ok=True)
        public_key = pgp_dir / "evidence-public-key.asc"
        fingerprint_file = pgp_dir / "evidence-key-fingerprint.txt"
        gnupg_home = pgp_dir / "keyring"
        fingerprint = ensure_key(gnupg_home, public_key, fingerprint_file)

        workspace.note(
            "INFO",
            (
                f"Operator identified as {identity.name!r} "
                f"({identity.operator_id}); "
                f"login username: {case.operator_username}"
            ),
        )

        source = dict(initial_source)
        source.setdefault("collector", collector.name)
        evidence = dict(initial_evidence or {})
        evidence["key_fingerprint"] = fingerprint
        record = initial_record_for_source(case, run_id, source, {})
        record.evidence.update(evidence)
        write_record(workspace.stage, record)

        # Public keys are evidence-package verification material. The
        # corresponding private keys remain outside staging and must never be
        # copied into evidence.
        shutil.copy2(public_key, workspace.stage / "evidence-public-key.asc")
        (workspace.stage / "operator-identity.json").write_text(
            json.dumps(identity.public_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        export_public_key(identity, workspace.stage / "operator-public-key.asc")

        result = collector.capture(context, request)
        record.source.update(result.source)
        record.source["collector"] = result.collector
        record.evidence.update(result.evidence)
        record.tools = dict(context.metadata.get("tools", {}))
        record.observations.extend(result.observations)

        archive = seal_acquisition(
            context=context,
            result=result,
            case=case,
            identity=identity,
            record=record,
            public_key=public_key,
            gnupg_home=gnupg_home,
            key_fingerprint=fingerprint,
        )
        sealed = True

        # Everything retained as evidential material is checked in as an
        # individually addressable immutable file. The collector registry gives
        # source-produced files richer classifications; sealing records and the
        # sealed archive are retained too rather than becoming invisible package
        # internals. This batch is all-or-nothing under normal failure handling.
        registered = {item.path: item for item in context.artefacts.items()}
        candidates: list[FileCandidate] = []
        for path in sorted(workspace.stage.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(workspace.stage).as_posix()
            item = registered.get(relative)
            candidates.append(
                FileCandidate(
                    path=path,
                    logical_path=relative,
                    classification=item.role.value
                    if item
                    else _core_record_classification(relative),
                    media_type=item.media_type
                    if item
                    else _core_record_media_type(relative),
                    description=item.description
                    if item
                    else "FACT-retained acquisition record",
                )
            )
        for path, classification, description in (
            (archive, "package", "Sealed acquisition archive"),
            (Path(f"{archive}.sha256"), "manifest", "Archive SHA-256 digest"),
            (Path(f"{archive}.sha512"), "manifest", "Archive SHA-512 digest"),
            (Path(f"{archive}.asc"), "signature", "Evidence-key detached signature"),
            (
                Path(f"{archive}.operator.asc"),
                "signature",
                "Operator detached signature",
            ),
            (
                Path(f"{archive}.verification.txt"),
                "verification",
                "Mandatory self-verification report",
            ),
        ):
            candidates.append(
                FileCandidate(
                    path=path,
                    logical_path=f"sealed/{path.name}",
                    classification=classification,
                    description=description,
                )
            )
        committed_files = commit_files(
            root,
            case_id=case.case_id,
            acquisition_id=run_id,
            actor_id=identity.operator_id,
            candidates=candidates,
        )
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
        workspace.note(
            "INFO",
            f"Individually committed {len(committed_files)} retained files for {run_id}",
        )

        status = record_acquisition(
            root,
            identity,
            acquisition_id=run_id,
            case_id=case.case_id,
            archive=archive,
            archive_sha256=digest(archive, "sha256"),
            collector=result.collector,
            completed_utc=str(record.acquisition["completed_utc"]),
        )
        workspace.note(
            "INFO",
            f"Acquisition authority state recorded as {status}: {run_id}",
        )
        return archive
    except Exception as exc:
        # The first exception is the evidentially useful failure. Catalogue
        # bookkeeping must not conceal it if marking the identifier also fails.
        if not sealed:
            with suppress(Exception):
                fail_identifier(root, run_id, str(exc))
        raise
