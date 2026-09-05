"""Construct structured acquisition provenance for authenticated catalogue events.

Historical FACT releases wrote duplicate JSON and Markdown case-record files into
every acquisition archive. The current catalogue is authoritative, so these
facts are now serialised directly into the signed ``ACQUISITION_RECORDED`` event
rather than being regenerated as additional evidential files.
"""

from __future__ import annotations

import platform
import socket
from typing import Any

from .. import __version__
from ..models import CaseInfo, CaseRecord, iso_utc


def initial_record_for_source(
    case: CaseInfo,
    acquisition_id: str,
    source: dict[str, Any],
    tools: dict[str, str],
) -> CaseRecord:
    """Create the structured provenance record populated during acquisition."""

    return CaseRecord(
        schema_version="3.0",
        toolkit_name="FACT - Forensic Acquisition & Capture Toolkit",
        toolkit_version=__version__,
        case={
            "case_id": case.case_id,
            "comments": case.comments,
            "operator_identity": case.operator_identity,
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
