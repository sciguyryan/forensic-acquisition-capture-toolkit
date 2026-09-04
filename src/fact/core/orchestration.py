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
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..collectors.base import Collector
from ..identity import OperatorIdentity, export_public_key
from ..keys import ensure_key
from ..models import CaseInfo
from ..services.commands import CommandRunner
from .acquisition import AcquisitionContext, AcquisitionWorkspace, ArtefactRegistry
from .catalogue import catalogue_path, fail_identifier, issue_identifier
from .records import initial_record_for_source, write_record
from .sealing import seal_acquisition


def acquisition_id() -> str:
    """Return the historical non-catalogue acquisition ID format.

    This helper remains only for Python API compatibility. New acquisitions use
    the project's catalogue-owned ``ACQ-######`` sequence inside
    :func:`run_collector_acquisition`.
    """

    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return f"{timestamp}-{uuid.uuid4().hex[:8]}"


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
    tree whenever one was created.
    """

    root = root.resolve()
    catalogued = catalogue_path(root).is_file()
    run_id = (
        issue_identifier(root, "acquisition", "ACQ") if catalogued else acquisition_id()
    )

    try:
        workspace = AcquisitionWorkspace.create(root, case.case_id, run_id)
    except Exception:
        # Workspace creation may fail before there is any filesystem evidence of
        # the attempt. The catalogue still records the consumed identifier so it
        # can never later be reused for unrelated material.
        if catalogued:
            fail_identifier(root, run_id, "workspace creation failed")
        raise

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

        identity = OperatorIdentity(**case.operator_identity)
        workspace.note(
            "INFO",
            (
                f"Operator identified as {identity.name!r} "
                f"({identity.operator_id}) via {case.operator_source}; "
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

        return seal_acquisition(
            context=context,
            result=result,
            case=case,
            identity=identity,
            record=record,
            public_key=public_key,
            gnupg_home=gnupg_home,
            key_fingerprint=fingerprint,
        )
    except Exception as exc:
        # The first exception is the evidentially useful failure. Catalogue
        # bookkeeping must not conceal it if marking the identifier also fails.
        if catalogued:
            with suppress(Exception):
                fail_identifier(root, run_id, str(exc))
        raise
