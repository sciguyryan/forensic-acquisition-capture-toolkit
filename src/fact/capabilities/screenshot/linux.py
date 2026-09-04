"""Arch/Linux screenshot capability and backend selection policy."""

from __future__ import annotations

import sys
from pathlib import Path

from ...errors import ToolkitError
from .base import CaptureTarget, ScreenshotBackend, ScreenshotCapture
from .portal import XdgDesktopPortalBackend


class LinuxScreenshotCapability:
    """Dispatch Linux screenshot capture to an explicit modular backend.

    Version 1 intentionally prefers XDG Desktop Portal.  A future X11 backend
    can implement the same ``ScreenshotBackend`` protocol and provide FACT-owned
    window enumeration without changing the screenshot collector or evidence
    model.  Windows and macOS adapters can follow the same boundary.
    """

    def __init__(
        self,
        *,
        backend: str = "auto",
        portal_backend: ScreenshotBackend | None = None,
    ) -> None:
        self.backend = backend
        self._portal_backend = portal_backend or XdgDesktopPortalBackend()

    def capture(self, destination_dir: Path, target: CaptureTarget) -> ScreenshotCapture:
        """Capture with the selected Linux backend or fail conservatively."""

        if not sys.platform.startswith("linux"):
            raise ToolkitError("The current screenshot capability targets Linux only")
        if self.backend not in {"auto", "portal"}:
            raise ToolkitError(f"Unknown Linux screenshot backend: {self.backend}")
        return self._portal_backend.capture(destination_dir, target)
