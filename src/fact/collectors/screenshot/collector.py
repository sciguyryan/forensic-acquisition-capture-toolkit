"""FACT screenshot collector.

Capture is intentionally separate from review.  The original screenshot is
registered as PRIMARY evidence and is never annotated, redacted, resized or
re-encoded here.  Future review layers and rendered derivatives will reference
this immutable source rather than modifying it.
"""

from __future__ import annotations

import json
import platform
from dataclasses import dataclass

from ... import __version__
from ...capabilities.screenshot import CaptureTarget, LinuxScreenshotCapability
from ...core.acquisition import AcquisitionContext, AcquisitionResult, ArtefactRole
from ...errors import ToolkitError


@dataclass(slots=True, frozen=True)
class ScreenshotRequest:
    """Source-specific options accepted by the screenshot collector."""

    target: CaptureTarget = CaptureTarget.WINDOW
    backend: str = "auto"


class ScreenshotCollector:
    """Acquire an operator-selected screen source without transforming pixels."""

    name = "screenshot"

    def __init__(self, capability: LinuxScreenshotCapability | None = None) -> None:
        self._capability = capability

    def capture(
        self, context: AcquisitionContext, request: ScreenshotRequest
    ) -> AcquisitionResult:
        """Capture and register an immutable original plus capture metadata."""

        stage = context.workspace.stage
        evidence_dir = stage / "evidence"
        metadata_dir = stage / "metadata"
        evidence_dir.mkdir()
        metadata_dir.mkdir()

        capability = self._capability or LinuxScreenshotCapability(
            backend=request.backend
        )
        context.workspace.note(
            "INFO",
            f"Starting screenshot capture; requested target: {request.target.value}",
        )
        capture = capability.capture(evidence_dir, request.target)
        if capture.path.parent.resolve() != evidence_dir.resolve():
            raise ToolkitError("Screenshot backend returned evidence outside staging")

        media_type = str(
            capture.metadata.get("media_type") or "application/octet-stream"
        )
        context.artefacts.register(
            capture.path,
            role=ArtefactRole.PRIMARY,
            media_type=media_type,
            description="Immutable original screenshot returned by capture backend",
        )

        capture_metadata = {
            "schema": "fact-screenshot-capture/v1",
            "capture_type": "screenshot",
            "requested_target": request.target.value,
            "backend": capture.backend,
            "selection_method": capture.selection_method,
            "original_filename": capture.path.name,
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
            },
            "backend_metadata": capture.metadata,
        }
        metadata_path = metadata_dir / "screenshot-capture.json"
        metadata_path.write_text(
            json.dumps(capture_metadata, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        context.artefacts.register(
            metadata_path,
            role=ArtefactRole.METADATA,
            media_type="application/json",
            description="Screenshot capture environment and backend metadata",
        )

        portal_version = capture.metadata.get("portal_interface_version")
        if portal_version is not None:
            context.metadata["tools"] = {
                "xdg-desktop-portal Screenshot interface": f"v{portal_version}"
            }

        observations: list[str] = []
        if request.target is CaptureTarget.WINDOW:
            observations.append(
                "Window selection was mediated by the desktop capture backend; "
                "the backend did not expose a trusted window title to FACT."
            )
        if media_type == "application/octet-stream":
            observations.append(
                "The capture backend returned an image format FACT did not identify; "
                "the exact bytes were preserved without transformation."
            )

        context.workspace.note("INFO", "Screenshot capture complete")
        return AcquisitionResult(
            collector=self.name,
            collector_version=__version__,
            source={
                "target": f"operator-selected {request.target.value}",
                "capture_type": "screenshot",
                "screenshot_target": request.target.value,
                "selection_method": capture.selection_method,
                "capture_backend": capture.backend,
            },
            evidence={
                "original_filename": capture.path.name,
                "media_type": media_type,
                "pixel_width": capture.metadata.get("pixel_width"),
                "pixel_height": capture.metadata.get("pixel_height"),
            },
            observations=observations,
        )
