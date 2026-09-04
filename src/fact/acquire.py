"""Compatibility orchestration for the first FACT source collector, YouTube.

The source interaction itself lives in :mod:`fact.collectors.youtube`; generic
workspace creation, artefact registration, and sealing live in FACT core.  This
module keeps the v2.2 public Python function intact while the CLI moves towards
explicit collector dispatch.
"""

from __future__ import annotations

import json
import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .collectors.youtube.collector import YouTubeCollector, YouTubeRequest, video_id
from .core.acquisition import AcquisitionContext, AcquisitionWorkspace, ArtefactRegistry
from .core.records import initial_record, write_record
from .core.sealing import seal_acquisition
from .identity import OperatorIdentity, export_public_key
from .keys import ensure_key
from .models import CaseInfo
from .services.commands import CommandRunner


def _id() -> str:
    """Return a timestamped identifier suitable for a legacy acquisition run."""

    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return f"{timestamp}-{uuid.uuid4().hex[:8]}"


def _video_id(url: str) -> str | None:
    """Compatibility helper retained for callers of the original module API."""

    return video_id(url)


def acquire(
    *,
    root: Path,
    url: str,
    case: CaseInfo,
    cookies: Path | None = None,
    subtitle_langs: str = "en.*,orig.*",
    live_chat: bool = True,
    sleep_requests: str = "3",
    sleep_subtitles: str = "8",
    min_sleep: str = "5",
    max_sleep: str = "12",
    rate_limit: str = "5M",
    collector: YouTubeCollector | None = None,
    commands: CommandRunner | None = None,
) -> Path:
    """Capture a YouTube source then pass the result to generic FACT sealing."""

    root = root.resolve()
    acquisition_id = _id()
    workspace = AcquisitionWorkspace.create(root, case.case_id, acquisition_id)
    context = AcquisitionContext(
        project_root=root,
        case_id=case.case_id,
        acquisition_id=acquisition_id,
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

    # Preserve an explanatory record before any external source command runs.
    # A failed collector therefore leaves useful provenance beside INCOMPLETE.
    record = initial_record(case, acquisition_id, url, {})
    record.source["collector"] = "youtube"
    record.source["video_id"] = _video_id(url)
    record.evidence["key_fingerprint"] = fingerprint
    record.evidence["live_chat_status"] = "Pending" if live_chat else "Skipped"
    write_record(workspace.stage, record)

    shutil.copy2(public_key, workspace.stage / "evidence-public-key.asc")
    (workspace.stage / "operator-identity.json").write_text(
        json.dumps(identity.public_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    export_public_key(identity, workspace.stage / "operator-public-key.asc")

    result = (collector or YouTubeCollector()).capture(
        context,
        YouTubeRequest(
            url=url,
            cookies=cookies,
            subtitle_langs=subtitle_langs,
            live_chat=live_chat,
            sleep_requests=sleep_requests,
            sleep_subtitles=sleep_subtitles,
            min_sleep=min_sleep,
            max_sleep=max_sleep,
            rate_limit=rate_limit,
        ),
    )
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
