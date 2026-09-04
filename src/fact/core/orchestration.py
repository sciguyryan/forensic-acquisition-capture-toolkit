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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..collectors.base import Collector
from ..identity import OperatorIdentity, export_public_key
from ..keys import ensure_key
from ..models import CaseInfo
from ..services.commands import CommandRunner
from .acquisition import AcquisitionContext, AcquisitionWorkspace, ArtefactRegistry
from .records import initial_record_for_source, write_record
from .sealing import seal_acquisition


def acquisition_id() -> str:
    """Return a collision-resistant acquisition identifier for current releases.

    Project-catalogue allocation for acquisition identifiers is a separate
    lifecycle change.  Until that migration is made, retain the established
    timestamp-plus-random-suffix format rather than silently changing existing
    archive naming semantics as part of a collector feature.
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

    The function deliberately writes the initial case record *before* invoking
    source-specific capture.  If the collector fails or the operator cancels a
    portal interaction, the retained ``INCOMPLETE`` staging tree still explains
    what FACT attempted and which operator initiated it.
    """

    root = root.resolve()
    run_id = acquisition_id()
    workspace = AcquisitionWorkspace.create(root, case.case_id, run_id)
    context = AcquisitionContext(
        project_root=root,
        case_id=case.case_id,
        acquisition_id=run_id,
        workspace=workspace,
        artefacts=ArtefactRegistry(workspace.stage),
        commands=commands or CommandRunner(),
    )

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

    # Public keys are evidence-package verification material.  The corresponding
    # private keys remain outside staging and must never be copied into evidence.
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
