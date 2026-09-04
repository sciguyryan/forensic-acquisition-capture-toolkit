"""Platform-neutral models for screenshot capture.

The collector depends on this contract rather than a desktop implementation.
That boundary is deliberate: Wayland, X11, Windows and macOS have materially
different security models and capture APIs, but FACT's evidential lifecycle does
not need to know which backend supplied the pixels.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol


class CaptureTarget(StrEnum):
    """Kinds of screenshot source that a backend may expose."""

    WINDOW = "window"
    SCREEN = "screen"
    AREA = "area"
    ACTIVE_WINDOW = "active-window"


@dataclass(slots=True, frozen=True)
class ScreenshotCapture:
    """Describe one immutable screenshot file returned by a backend."""

    path: Path
    backend: str
    target: CaptureTarget
    selection_method: str
    metadata: dict[str, Any] = field(default_factory=dict)


class ScreenshotBackend(Protocol):
    """Minimal backend contract implemented by platform capture adapters."""

    name: str

    def capture(self, destination_dir: Path, target: CaptureTarget) -> ScreenshotCapture:
        """Capture a screenshot and return the preserved original file."""
        ...
