"""YouTube source collector migrated from the original FACT acquisition path.

The collector is intentionally limited to source interaction and technical
inspection. It does not allocate IDs, create project keys, commit authority
state, package outputs, or perform final project verification.  Those evidential lifecycle
responsibilities belong to FACT core.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ... import __version__
from ...core.acquisition import (
    AcquisitionContext,
    AcquisitionResult,
    ArtefactRole,
)
from ...errors import ToolkitError
from ...models import iso_utc


@dataclass(slots=True, frozen=True)
class YouTubeRequest:
    """Source-specific options accepted by the YouTube collector."""

    url: str
    cookies: Path | None = None
    subtitle_langs: str = "en.*,orig.*"
    live_chat: bool = True
    sleep_requests: str = "3"
    sleep_subtitles: str = "8"
    min_sleep: str = "5"
    max_sleep: str = "12"
    rate_limit: str = "5M"


def video_id(url: str) -> str | None:
    """Extract a YouTube video identifier from a supported URL."""

    parsed = urlparse(url)
    if parsed.hostname == "youtu.be":
        return parsed.path.strip("/") or None
    return parse_qs(parsed.query).get("v", [None])[0]


class YouTubeCollector:
    """Capture YouTube media and source-specific supporting material."""

    name = "youtube"

    def _tool_versions(self, context: AcquisitionContext) -> dict[str, str]:
        """Record versions for source tools present on the acquisition host."""

        names = ["yt-dlp", "ffprobe", "mediainfo", "curl", "gpg"]
        return {
            name: context.commands.version(name) for name in names if shutil.which(name)
        }

    def capture(
        self,
        context: AcquisitionContext,
        request: YouTubeRequest,
    ) -> AcquisitionResult:
        """Capture source material into the generic FACT staging workspace."""

        for command in ("yt-dlp", "ffprobe", "gpg"):
            context.commands.require(command)

        stage = context.workspace.stage
        evidence_dir = stage / "evidence"
        reports_dir = stage / "reports"
        http_dir = stage / "http"
        for directory in (evidence_dir, reports_dir, http_dir):
            directory.mkdir()

        result = AcquisitionResult(
            collector=self.name,
            collector_version=__version__,
            source={
                "submitted_url": request.url,
                "video_id": video_id(request.url),
            },
            evidence={
                "live_chat_status": "Pending" if request.live_chat else "Skipped",
            },
        )
        context.metadata["tools"] = self._tool_versions(context)

        output = str(evidence_dir / "%(id)s-%(title)s.%(ext)s")
        ytdlp = [
            "yt-dlp",
            "--newline",
            "--no-progress",
            "--ignore-config",
            "--write-info-json",
            "--write-description",
            "--write-thumbnail",
            "--write-all-thumbnails",
            "--write-subs",
            "--write-auto-subs",
            "--sub-langs",
            request.subtitle_langs,
            "--write-comments",
            "--write-desktop-link",
            "--merge-output-format",
            "mkv",
            "--sleep-requests",
            request.sleep_requests,
            "--sleep-subtitles",
            request.sleep_subtitles,
            "--sleep-interval",
            request.min_sleep,
            "--max-sleep-interval",
            request.max_sleep,
            "--limit-rate",
            request.rate_limit,
            "--retries",
            "10",
            "--fragment-retries",
            "10",
            "--retry-sleep",
            "http:exp=2:60",
            "--retry-sleep",
            "fragment:exp=2:30",
            "-o",
            output,
        ]
        if request.cookies:
            ytdlp += ["--cookies", str(request.cookies)]

        context.workspace.note("INFO", "Starting primary yt-dlp acquisition")
        primary = context.commands.run(
            [*ytdlp, request.url],
            check=False,
            transcript=context.workspace.log_path,
        )
        primary_stdout = reports_dir / "yt-dlp-primary.stdout.txt"
        primary_stderr = reports_dir / "yt-dlp-primary.stderr.txt"
        primary_stdout.write_text(primary.stdout, encoding="utf-8")
        primary_stderr.write_text(primary.stderr, encoding="utf-8")
        context.artefacts.register(
            primary_stdout,
            role=ArtefactRole.TRANSCRIPT,
            media_type="text/plain",
            description="yt-dlp primary standard output",
        )
        context.artefacts.register(
            primary_stderr,
            role=ArtefactRole.TRANSCRIPT,
            media_type="text/plain",
            description="yt-dlp primary standard error",
        )
        if primary.returncode != 0:
            raise ToolkitError(
                f"Primary yt-dlp acquisition failed with exit {primary.returncode}"
            )

        if request.live_chat:
            self._capture_live_chat(context, request, result, output)

        self._capture_http(context, request, result)
        self._read_primary_metadata(context, result)
        self._inspect_media(context)
        self._register_evidence_files(context)
        context.workspace.note(
            "INFO", "Media acquisition and supplemental capture complete"
        )
        return result

    def _capture_live_chat(
        self,
        context: AcquisitionContext,
        request: YouTubeRequest,
        result: AcquisitionResult,
        output: str,
    ) -> None:
        """Attempt the source's optional live-chat replay without failing the acquisition."""

        chat = [
            "yt-dlp",
            "--ignore-config",
            "--skip-download",
            "--write-subs",
            "--sub-langs",
            "live_chat",
            "-o",
            output,
        ]
        if request.cookies:
            chat += ["--cookies", str(request.cookies)]

        context.workspace.note("INFO", "Starting best-effort live-chat acquisition")
        captured = context.commands.run(
            [*chat, request.url],
            check=False,
            transcript=context.workspace.log_path,
        )
        status = "Complete" if captured.returncode == 0 else "Partial or unavailable"
        result.evidence["live_chat_status"] = status
        report = context.workspace.stage / "reports" / "live-chat-capture.txt"
        report.write_text(
            (
                f"Status: {status}\n"
                f"Exit status: {captured.returncode}\n\n"
                f"STDOUT\n{captured.stdout}\n"
                f"STDERR\n{captured.stderr}\n"
            ),
            encoding="utf-8",
        )
        context.artefacts.register(
            report,
            role=ArtefactRole.TRANSCRIPT,
            media_type="text/plain",
            description="Best-effort YouTube live-chat capture report",
        )
        if captured.returncode != 0:
            result.observations.append(
                "Live-chat replay acquisition was partial or unavailable; retained output is best-effort evidence."
            )
            context.workspace.note(
                "WARN", "Live-chat replay was partial or unavailable"
            )

    def _capture_http(
        self,
        context: AcquisitionContext,
        request: YouTubeRequest,
        result: AcquisitionResult,
    ) -> None:
        """Capture supplemental HTTP material when curl is available."""

        curl = shutil.which("curl")
        if not curl:
            return
        http_dir = context.workspace.stage / "http"
        headers = http_dir / "response-headers.txt"
        page = http_dir / "watch-page.html"
        context.workspace.note("INFO", "Starting supplemental HTTP capture")
        captured = context.commands.run(
            [
                curl,
                "--location",
                "--silent",
                "--show-error",
                "--dump-header",
                str(headers),
                "--output",
                str(page),
                "--write-out",
                "%{url_effective}",
                request.url,
            ],
            check=False,
            transcript=context.workspace.log_path,
        )
        effective = http_dir / "effective-url.txt"
        retrieved = http_dir / "retrieved-utc.txt"
        effective.write_text(captured.stdout + "\n", encoding="utf-8")
        retrieved.write_text(iso_utc() + "\n", encoding="utf-8")
        result.source["effective_url"] = captured.stdout.strip() or None
        for path, media_type, description in (
            (headers, "text/plain", "Supplemental HTTP response headers"),
            (page, "text/html", "Supplemental YouTube watch page"),
            (effective, "text/plain", "Effective URL reported by curl"),
            (retrieved, "text/plain", "Supplemental HTTP retrieval time"),
        ):
            if path.is_file():
                context.artefacts.register(
                    path,
                    role=ArtefactRole.NETWORK,
                    media_type=media_type,
                    description=description,
                )

    def _read_primary_metadata(
        self,
        context: AcquisitionContext,
        result: AcquisitionResult,
    ) -> None:
        """Promote selected yt-dlp metadata into the common source record."""

        info_files = list((context.workspace.stage / "evidence").glob("*.info.json"))
        if not info_files:
            return
        try:
            info = json.loads(info_files[0].read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            result.observations.append(
                "Primary yt-dlp metadata JSON could not be parsed for the case record."
            )
            return
        result.source.update(
            {
                "title": info.get("title"),
                "channel": info.get("channel"),
                "published_date": info.get("upload_date"),
                "video_id": info.get("id"),
            }
        )

    def _inspect_media(self, context: AcquisitionContext) -> None:
        """Generate source-independent media inspection reports for captured video."""

        evidence = context.workspace.stage / "evidence"
        reports = context.workspace.stage / "reports"
        media_files = [
            path
            for suffix in ("*.mkv", "*.mp4", "*.webm")
            for path in evidence.glob(suffix)
        ]
        for media in media_files:
            probe = context.commands.run(
                [
                    "ffprobe",
                    "-v",
                    "quiet",
                    "-print_format",
                    "json",
                    "-show_format",
                    "-show_streams",
                    str(media),
                ],
                check=False,
            )
            probe_path = reports / f"{media.name}.ffprobe.json"
            probe_path.write_text(probe.stdout, encoding="utf-8")
            context.artefacts.register(
                probe_path,
                role=ArtefactRole.INSPECTION,
                media_type="application/json",
                description="ffprobe media inspection",
                related_to=media,
                relationship="inspects",
            )

            if shutil.which("mediainfo"):
                media_info = context.commands.run(
                    ["mediainfo", "--Output=JSON", str(media)],
                    check=False,
                )
                media_info_path = reports / f"{media.name}.mediainfo.json"
                media_info_path.write_text(media_info.stdout, encoding="utf-8")
                context.artefacts.register(
                    media_info_path,
                    role=ArtefactRole.INSPECTION,
                    media_type="application/json",
                    description="MediaInfo media inspection",
                    related_to=media,
                    relationship="inspects",
                )

    def _register_evidence_files(self, context: AcquisitionContext) -> None:
        """Register every retained yt-dlp output with a meaningful classification.

        yt-dlp may create many different source files depending on what the
        publisher exposes. Only files that remain after successful capture are
        retained. Temporary fragments and scratch files are not registered and
        therefore never cross FACT's evidential check-in boundary.
        """

        evidence = context.workspace.stage / "evidence"
        media_suffixes = {".mkv", ".mp4", ".webm", ".m4a", ".mp3", ".opus"}
        image_suffixes = {".jpg", ".jpeg", ".png", ".webp", ".gif"}
        subtitle_suffixes = {".vtt", ".srt", ".ass", ".lrc", ".ttml"}
        transient_suffixes = {".part", ".ytdl", ".tmp", ".temp"}
        retained: list[Path] = []
        for path in sorted(evidence.iterdir()):
            if not path.is_file() or path.is_symlink():
                continue
            if (
                path.suffix.lower() in transient_suffixes
                or ".part-frag" in path.name.lower()
            ):
                # Successful acquisition scratch is not evidential material. It
                # must not be retained merely because the source tool happened
                # to leave it in staging. Failed acquisitions retain their
                # incomplete workspace under the separate failure policy.
                path.unlink()
                continue
            retained.append(path)
        primary_media = next(
            (path for path in retained if path.suffix.lower() in media_suffixes),
            None,
        )
        for path in retained:
            suffix = path.suffix.lower()
            name = path.name.lower()
            related_to = (
                primary_media
                if primary_media is not None and path != primary_media
                else None
            )
            relationship = "supports" if related_to is not None else None
            if suffix in media_suffixes:
                role = ArtefactRole.PRIMARY
                media_type = None
                description = "Original YouTube media retained by yt-dlp"
            elif name.endswith(".info.json"):
                role = ArtefactRole.SOURCE_METADATA
                media_type = "application/json"
                description = "YouTube source metadata retained by yt-dlp"
                relationship = "describes" if related_to is not None else None
            elif suffix in subtitle_suffixes or "live_chat" in name:
                role = ArtefactRole.SUPPORTING
                media_type = "text/vtt" if suffix == ".vtt" else None
                description = "YouTube subtitle, caption, or live-chat material"
            elif suffix in image_suffixes:
                role = ArtefactRole.SUPPORTING
                media_type = (
                    f"image/{'jpeg' if suffix in {'.jpg', '.jpeg'} else suffix[1:]}"
                )
                description = "YouTube thumbnail or source image"
            elif suffix == ".description":
                role = ArtefactRole.SOURCE_METADATA
                media_type = "text/plain"
                description = "YouTube description retained by yt-dlp"
                relationship = "describes" if related_to is not None else None
            elif suffix == ".url":
                role = ArtefactRole.SOURCE_METADATA
                media_type = "text/plain"
                description = "YouTube source link retained by yt-dlp"
            else:
                role = ArtefactRole.SUPPORTING
                media_type = None
                description = "Retained YouTube collector output"
            context.artefacts.register(
                path,
                role=role,
                media_type=media_type,
                description=description,
                related_to=related_to,
                relationship=relationship,
            )
