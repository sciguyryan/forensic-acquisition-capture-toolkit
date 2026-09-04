"""Create and serialise forensic case records.

Case records are written in both JSON and Markdown so that evidence packages
contain a machine-readable representation and a readily reviewable document.
"""

from __future__ import annotations

import json
import platform
import socket
from pathlib import Path
from typing import Any

from .. import __version__
from ..models import CaseInfo, CaseRecord, iso_utc


def render_markdown(record: CaseRecord) -> str:
    """Render a case record as a human-readable Markdown document."""
    c, a, s, e = record.case, record.acquisition, record.source, record.evidence
    observations = (
        "\n".join(f"- {item}" for item in record.observations) or "- None recorded."
    )
    custody = (
        "\n".join(
            f"| {x.get('utc', '')} | {x.get('released_by', '')} | {x.get('received_by', '')} | {x.get('purpose', '')} | {x.get('media_seal_id', '')} | {x.get('signature', '')} |"
            for x in record.custody_events
        )
        or "|  |  |  |  |  |  |"
    )
    return (
        f"""# Evidence Case Record

## Case

- Case ID: {c["case_id"]}
- Matter/title: {c.get("matter_title") or "Not supplied"}
- Operator: {c["operator_identity"]["name"]}
- Operator ID: {c["operator_identity"]["operator_id"]}
- Organisation: {c["operator_identity"].get("organisation") or "Not supplied"}
- Role: {c["operator_identity"].get("role") or "Not supplied"}
- Public contact: {c["operator_identity"].get("public_contact") or "Not supplied"}
- Operator source: {c.get("operator_source") or "Unspecified"}
- Operator profile SHA-256: {c.get("operator_profile_sha256") or "Unavailable"}
- Operator signing key: {c["operator_identity"]["operator_signing_subkey_fingerprint"]}
- Login username: {c.get("operator_username") or "Unavailable"}
- Requestor: {c.get("requestor") or "Not supplied"}

## Case purpose and comments

{c["comments"]}

## Acquisition

- Acquisition ID: {a["acquisition_id"]}
- Started (UTC): {a["started_utc"]}
- Completed (UTC): {a.get("completed_utc") or "Pending"}
- Hostname: {a["hostname"]}
- Platform: {a["platform"]}
- Toolkit version: {record.toolkit_version}

## Source

- Target: {s.get("submitted_url") or s.get("submitted_path") or s.get("target") or "Interactive/operator-selected source"}
- Effective URL: {s.get("effective_url") or "Unavailable"}
- Collector: {s.get("collector") or "Unavailable"}
- Capture type: {s.get("capture_type") or "Not applicable"}
- Video ID: {s.get("video_id") or "Unavailable"}
- Title: {s.get("title") or "Unavailable"}
- Channel: {s.get("channel") or "Unavailable"}
- Published date: {s.get("published_date") or "Unavailable"}

## Evidence package

- Archive filename: {e.get("archive_filename") or "Pending"}
- Evidence-set SHA-256: {e.get("evidence_set_sha256") or "Pending"}
- Archive SHA-256: {e.get("archive_sha256") or "Pending"}
- Archive SHA-512: {e.get("archive_sha512") or "Pending"}
- Evidence-key fingerprint: {e.get("key_fingerprint") or "Unavailable"}
- Detached signature: {e.get("signature_status") or "Pending"}
- Mandatory verification: {e.get("verification_status") or "Pending"}
- Live-chat capture: {e.get("live_chat_status") or "Not attempted"}
- Staging retained: Yes

## Tools

"""
        + "\n".join(
            f"- {name}: {value}" for name, value in sorted(record.tools.items())
        )
        + f"""

## Exceptions and observations

{observations}

## Chain of custody

| UTC date/time | Released by | Received by | Purpose/location | Media/seal ID | Signature |
|---|---|---|---|---|---|
{custody}
"""
    )


def initial_record_for_source(
    case: CaseInfo,
    acquisition_id: str,
    source: dict[str, Any],
    tools: dict[str, str],
) -> CaseRecord:
    """Create the initial case record for any FACT collector."""
    return CaseRecord(
        schema_version="2.0",
        toolkit_name="FACT - Forensic Acquisition & Capture Toolkit",
        toolkit_version=__version__,
        case={
            "case_id": case.case_id,
            "comments": case.comments,
            "operator_identity": case.operator_identity,
            "operator_source": case.operator_source,
            "operator_profile_sha256": case.operator_profile_sha256,
            "operator_username": case.operator_username,
            "requestor": case.requestor,
            "matter_title": case.matter_title,
        },
        acquisition={
            "acquisition_id": acquisition_id,
            "started_utc": iso_utc(),
            "completed_utc": None,
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        source=dict(source),
        evidence={},
        tools=tools,
        observations=[],
        custody_events=[],
    )


def initial_record(
    case: CaseInfo, acquisition_id: str, url: str, tools: dict[str, str]
) -> CaseRecord:
    """Create the legacy URL-oriented record used by older Python callers."""

    return initial_record_for_source(
        case, acquisition_id, {"submitted_url": url}, tools
    )


def write_record(root: Path, record: CaseRecord) -> None:
    """Write JSON and Markdown representations of a case record."""
    (root / "CASE_RECORD.json").write_text(
        json.dumps(record.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (root / "CASE_RECORD.md").write_text(render_markdown(record), encoding="utf-8")
