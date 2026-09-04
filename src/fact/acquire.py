"""Compatibility wrapper for FACT's original YouTube Python acquisition API.

New collectors use :func:`fact.core.orchestration.run_collector_acquisition`.
This module preserves the original public ``acquire(...)`` function so external
callers do not break while the command-line interface becomes collector based.
"""

from __future__ import annotations

from pathlib import Path

from .collectors.youtube.collector import YouTubeCollector, YouTubeRequest, video_id
from .core.orchestration import acquisition_id, run_collector_acquisition
from .models import CaseInfo
from .services.commands import CommandRunner


def _id() -> str:
    """Compatibility alias for the established acquisition-ID helper."""

    return acquisition_id()


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
    """Capture YouTube material through FACT's generic acquisition lifecycle."""

    selected = collector or YouTubeCollector()
    return run_collector_acquisition(
        root=root,
        case=case,
        collector=selected,
        request=YouTubeRequest(
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
        initial_source={
            "submitted_url": url,
            "collector": "youtube",
            "video_id": _video_id(url),
        },
        initial_evidence={
            "live_chat_status": "Pending" if live_chat else "Skipped",
        },
        commands=commands,
    )
