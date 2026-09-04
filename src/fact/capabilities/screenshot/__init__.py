"""Cross-platform screenshot capability interfaces and backend selection."""

from .base import CaptureTarget, ScreenshotBackend, ScreenshotCapture
from .linux import LinuxScreenshotCapability

__all__ = [
    "CaptureTarget",
    "LinuxScreenshotCapability",
    "ScreenshotBackend",
    "ScreenshotCapture",
]
