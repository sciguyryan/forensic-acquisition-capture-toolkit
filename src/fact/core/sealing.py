"""Seal a completed collector result into a verified FACT evidence archive.

This module contains the collector-independent half of an acquisition.  Once a
collector has returned and registered its artefacts, sealing records provenance,
binds the registered payload to cryptographic manifests, creates signatures,
and performs mandatory self-verification.  Screenshot, file, web and future
collectors should all pass through this same boundary.
"""

from __future__ import annotations

import json
import platform
import shutil
import socket
from datetime import UTC, datetime
from pathlib import Path

from .. import __version__
from ..console import summary
from ..errors import ToolkitError
from ..identity import OperatorIdentity, sign_with_operator
from ..keys import sign
from ..models import CaseInfo, CaseRecord, iso_utc
from ..services.archive import create_archive
from ..services.hashing import digest, write_filelist, write_manifest
from .acquisition import AcquisitionContext, AcquisitionResult
from .records import write_record
from .verification import verify_archive


def _write_evidence_set_manifest(context: AcquisitionContext) -> tuple[Path, str]:
    """Hash precisely the source artefacts registered by the collector.

    The registry is the evidential boundary between capture and sealing.  Using
    it here prevents unrelated staging files from silently becoming part of the
    source payload and means every future collector follows the same rule.
    """

    manifest = context.workspace.stage / "EVIDENCESET-SHA256.txt"
    lines: list[str] = []
    for artefact in context.artefacts.items():
        path = context.workspace.stage / artefact.path
        lines.append(f"{digest(path, 'sha256')}  {artefact.path}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest, digest(manifest, "sha256")


def seal_acquisition(
    *,
    context: AcquisitionContext,
    result: AcquisitionResult,
    case: CaseInfo,
    identity: OperatorIdentity,
    record: CaseRecord,
    public_key: Path,
    gnupg_home: Path,
    key_fingerprint: str,
) -> Path:
    """Seal registered collector outputs and return the verified archive path."""

    stage = context.workspace.stage
    workspace = context.workspace
    record.acquisition["completed_utc"] = iso_utc()
    record.evidence["signature_status"] = "Pending"
    record.evidence["verification_status"] = "Pending"
    write_record(stage, record)

    workspace.note("INFO", "Finalising evidence records and internal manifests")
    shutil.copy2(workspace.log_path, stage / "acquisition.log")
    source_description = (
        record.source.get("submitted_url")
        or record.source.get("submitted_path")
        or record.source.get("target")
        or result.collector
    )
    (stage / "acquisition.txt").write_text(
        (
            f"Toolkit version: {__version__}\n"
            f"Collector: {result.collector}\n"
            f"Acquisition ID: {context.acquisition_id}\n"
            f"Case ID: {case.case_id}\n"
            f"Operator: {identity.name}\n"
            f"Operator ID: {identity.operator_id}\n"
            f"Operator source: {case.operator_source}\n"
            f"Operator profile SHA-256: {case.operator_profile_sha256}\n"
            "Operator signing key: "
            f"{identity.operator_signing_subkey_fingerprint}\n"
            f"Login username: {case.operator_username}\n"
            f"Source: {source_description}\n"
            f"Evidence-key fingerprint: {key_fingerprint}\n"
        ),
        encoding="utf-8",
    )

    toolkit_details = {
        "toolkit": "FACT - Forensic Acquisition & Capture Toolkit",
        "version": __version__,
        "collector": result.collector,
        "collector_version": result.collector_version,
        "python": platform.python_version(),
        "tools": record.tools,
        "runtime": {
            "operator_identity": case.operator_identity,
            "operator_source": case.operator_source,
            "operator_profile_sha256": case.operator_profile_sha256,
            "operator_username": case.operator_username,
            "hostname": socket.gethostname(),
        },
    }
    (stage / "TOOLKIT.json").write_text(
        json.dumps(toolkit_details, indent=2) + "\n",
        encoding="utf-8",
    )
    (stage / "VERIFICATION.txt").write_text(
        "Use fact verify ARCHIVE.7z to verify this package.\n",
        encoding="utf-8",
    )
    context.artefacts.write(stage / "ARTEFACTS.json")

    # Clearing INCOMPLETE here means collector capture completed.  A later
    # mandatory verification failure recreates the marker before the exception
    # escapes, so no failed archive can masquerade as a sealed acquisition.
    workspace.incomplete_marker.unlink(missing_ok=True)
    evidence_manifest, evidence_set_hash = _write_evidence_set_manifest(context)
    if not evidence_manifest.is_file():  # defensive invariant, normally impossible
        raise ToolkitError("Evidence-set manifest was not created")

    archive_date = datetime.now(UTC).strftime("%Y%m%d")
    archive = (
        context.project_root
        / "archived"
        / f"{case.case_id}_{archive_date}_{evidence_set_hash[:16]}.7z"
    )
    record.evidence["evidence_set_sha256"] = evidence_set_hash
    record.evidence["archive_filename"] = archive.name
    record.custody_events.append(
        {
            "utc": iso_utc(),
            "released_by": "",
            "received_by": identity.name,
            "purpose": "Initial acquisition and preservation",
            "media_seal_id": archive.name,
            "signature": "",
        }
    )
    write_record(stage, record)
    write_filelist(stage, stage / "FILELIST.txt")
    write_manifest(stage, stage / "SHA256SUMS.txt", "sha256")
    write_manifest(stage, stage / "SHA512SUMS.txt", "sha512")
    create_archive(stage, archive)

    sha256 = digest(archive, "sha256")
    sha512 = digest(archive, "sha512")
    Path(f"{archive}.sha256").write_text(
        f"{sha256}  {archive.name}\n", encoding="ascii"
    )
    Path(f"{archive}.sha512").write_text(
        f"{sha512}  {archive.name}\n", encoding="ascii"
    )

    signature = Path(f"{archive}.asc")
    sign(gnupg_home, archive, signature, key_fingerprint)
    operator_signature = Path(f"{archive}.operator.asc")
    sign_with_operator(identity, archive, operator_signature)

    verification_report = Path(f"{archive}.verification.txt")
    verified = verify_archive(archive, public_key, verification_report)
    if not verified.passed:
        workspace.incomplete_marker.write_text(
            "Mandatory self-verification failed.\n",
            encoding="utf-8",
        )
        raise ToolkitError(
            "Mandatory self-verification failed. Evidence retained but not "
            f"sealed: {archive}"
        )

    summary(
        "EVIDENCE ACQUISITION SEALED",
        [
            ("Case ID", case.case_id, "INFO"),
            ("Acquisition ID", context.acquisition_id, "INFO"),
            ("Collector", result.collector, "INFO"),
            ("Operator", identity.name, "INFO"),
            ("Operator ID", identity.operator_id, "INFO"),
            ("Operator signature", "PRESENT", "PASS"),
            ("Source", str(source_description), "INFO"),
            ("Archive", str(archive), "PASS"),
            ("Archive SHA-256", sha256, "PASS"),
            ("Archive SHA-512", sha512, "PASS"),
            ("Detached signature", "PRESENT", "PASS"),
            ("Self-verification", "PASS", "PASS"),
            ("Evidence sealed", "YES", "PASS"),
            ("Staging retained", str(stage), "INFO"),
            ("Verification report", str(verification_report), "INFO"),
        ],
        True,
    )
    return archive
