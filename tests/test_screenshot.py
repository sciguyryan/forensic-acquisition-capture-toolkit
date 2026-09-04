"""Tests for screenshot capture, immutable evidence, and Linux backend dispatch."""

from __future__ import annotations

import json
import struct
import sys
import types
from pathlib import Path

import pytest

from fact.capabilities.screenshot import CaptureTarget, LinuxScreenshotCapability
from fact.capabilities.screenshot.base import ScreenshotCapture
from fact.capabilities.screenshot.image import inspect_image
from fact.capabilities.screenshot.portal import XdgDesktopPortalBackend
from fact.collectors.screenshot.collector import ScreenshotCollector, ScreenshotRequest
from fact.core.acquisition import (
    AcquisitionContext,
    AcquisitionWorkspace,
    ArtefactRegistry,
)
from fact.errors import ToolkitError
from fact.services.commands import CommandRunner


def _png(width: int = 640, height: int = 480) -> bytes:
    """Return enough PNG structure for FACT's non-decoding metadata parser."""

    return (
        b"\x89PNG\r\n\x1a\n"
        + struct.pack(">I", 13)
        + b"IHDR"
        + struct.pack(">II", width, height)
        + b"\x08\x06\x00\x00\x00"
        + b"\x00\x00\x00\x00"
    )


class FakeScreenshotBackend:
    """Backend that writes deterministic image bytes into FACT staging."""

    name = "fake-screenshot"

    def capture(self, destination_dir: Path, target: CaptureTarget) -> ScreenshotCapture:
        path = destination_dir / "screenshot-original.png"
        path.write_bytes(_png(800, 600))
        return ScreenshotCapture(
            path=path,
            backend=self.name,
            target=target,
            selection_method="test-user-selection",
            metadata={
                "media_type": "image/png",
                "pixel_width": 800,
                "pixel_height": 600,
                "portal_interface_version": 3,
            },
        )


def _context(tmp_path: Path) -> AcquisitionContext:
    workspace = AcquisitionWorkspace.create(tmp_path, "CASE-1", "ACQ-1")
    return AcquisitionContext(
        project_root=tmp_path,
        case_id="CASE-1",
        acquisition_id="ACQ-1",
        workspace=workspace,
        artefacts=ArtefactRegistry(workspace.stage),
        commands=CommandRunner(),
    )


def test_screenshot_collector_preserves_original_and_registers_metadata(tmp_path: Path) -> None:
    """Register raw screenshot bytes separately from capture metadata."""

    context = _context(tmp_path)
    capability = LinuxScreenshotCapability(portal_backend=FakeScreenshotBackend())
    collector = ScreenshotCollector(capability)

    result = collector.capture(context, ScreenshotRequest())

    original = context.workspace.stage / "evidence" / "screenshot-original.png"
    assert original.read_bytes() == _png(800, 600)
    assert result.source["capture_type"] == "screenshot"
    assert result.source["screenshot_target"] == "window"
    assert result.evidence["pixel_width"] == 800
    artefacts = context.artefacts.items()
    assert [item.role.value for item in artefacts] == ["primary", "metadata"]
    metadata = json.loads(
        (context.workspace.stage / "metadata" / "screenshot-capture.json").read_text()
    )
    assert metadata["selection_method"] == "test-user-selection"
    assert "annotations" not in metadata
    assert result.observations


def test_screenshot_collector_rejects_backend_escape(tmp_path: Path) -> None:
    """Do not allow a capture backend to point evidence outside staging."""

    outside = tmp_path / "outside.png"
    outside.write_bytes(_png())

    class EscapingBackend:
        name = "escape"

        def capture(self, destination_dir, target):
            return ScreenshotCapture(outside, self.name, target, "test", {})

    context = _context(tmp_path / "project")
    collector = ScreenshotCollector(
        LinuxScreenshotCapability(portal_backend=EscapingBackend())
    )
    with pytest.raises(ToolkitError, match="outside staging"):
        collector.capture(context, ScreenshotRequest())


def test_linux_capability_validates_platform_and_backend(tmp_path: Path, monkeypatch) -> None:
    """Keep platform policy outside the screenshot collector."""

    backend = FakeScreenshotBackend()
    capability = LinuxScreenshotCapability(portal_backend=backend)
    capture = capability.capture(tmp_path, CaptureTarget.WINDOW)
    assert capture.backend == backend.name

    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(ToolkitError, match="targets Linux"):
        capability.capture(tmp_path, CaptureTarget.WINDOW)

    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(ToolkitError, match="Unknown Linux screenshot backend"):
        LinuxScreenshotCapability(backend="other").capture(tmp_path, CaptureTarget.WINDOW)


def test_image_inspection_reads_png_and_preserves_unknown(tmp_path: Path) -> None:
    """Inspect dimensions without re-encoding the evidential file."""

    png = tmp_path / "image"
    png.write_bytes(_png(123, 456))
    assert inspect_image(png) == {
        "media_type": "image/png",
        "extension": ".png",
        "pixel_width": 123,
        "pixel_height": 456,
    }
    unknown = tmp_path / "unknown"
    unknown.write_bytes(b"not an image")
    assert inspect_image(unknown)["extension"] == ".img"


def _install_fake_dbus(monkeypatch, source: Path, *, response: int = 0, version: int = 3, targets: int = 15):
    """Install a tiny dbus-next substitute exercising FACT's portal protocol."""

    class MessageType:
        METHOD_RETURN = "method-return"
        ERROR = "error"
        SIGNAL = "signal"

    class BusType:
        SESSION = "session"

    class Variant:
        def __init__(self, signature, value):
            self.signature = signature
            self.value = value

    class Message:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class Reply:
        def __init__(self, body, message_type=MessageType.METHOD_RETURN):
            self.body = body
            self.message_type = message_type
            self.error_name = None

    class FakeBus:
        unique_name = ":1.77"

        def __init__(self):
            self.handlers = []
            self.disconnected = False

        async def call(self, message):
            if message.interface == "org.freedesktop.DBus.Properties":
                value = version if message.body[1] == "version" else targets
                return Reply([Variant("u", value)])
            token = message.body[1]["handle_token"].value
            handle = f"/org/freedesktop/portal/desktop/request/1_77/{token}"
            import asyncio

            def emit():
                signal = types.SimpleNamespace(
                    message_type=MessageType.SIGNAL,
                    path=handle,
                    interface="org.freedesktop.portal.Request",
                    member="Response",
                    body=[
                        response,
                        {"uri": Variant("s", source.as_uri())} if response == 0 else {},
                    ],
                )
                for handler in list(self.handlers):
                    handler(signal)

            asyncio.get_running_loop().call_soon(emit)
            return Reply([handle])

        def add_message_handler(self, handler):
            self.handlers.append(handler)

        def remove_message_handler(self, handler):
            self.handlers.remove(handler)

        def disconnect(self):
            self.disconnected = True

    bus = FakeBus()

    class MessageBus:
        def __init__(self, **kwargs):
            pass

        async def connect(self):
            return bus

    module = types.ModuleType("dbus_next")
    module.BusType = BusType
    module.Message = Message
    module.MessageType = MessageType
    module.Variant = Variant
    aio = types.ModuleType("dbus_next.aio")
    aio.MessageBus = MessageBus
    monkeypatch.setitem(sys.modules, "dbus_next", module)
    monkeypatch.setitem(sys.modules, "dbus_next.aio", aio)
    return bus


def test_portal_backend_copies_exact_bytes_and_records_capabilities(tmp_path: Path, monkeypatch) -> None:
    """Use the portal request signal and preserve the exact returned file bytes."""

    source = tmp_path / "portal.png"
    source.write_bytes(_png(1920, 1080))
    bus = _install_fake_dbus(monkeypatch, source)
    destination = tmp_path / "evidence"

    capture = XdgDesktopPortalBackend().capture(destination, CaptureTarget.WINDOW)

    assert capture.path.read_bytes() == source.read_bytes()
    assert capture.path.name == "screenshot-original.png"
    assert capture.metadata["portal_interface_version"] == 3
    assert capture.metadata["pixel_height"] == 1080
    assert bus.disconnected is True


def test_portal_backend_reports_cancellation_and_target_support(tmp_path: Path, monkeypatch) -> None:
    """Fail conservatively when the operator cancels or window targeting is absent."""

    source = tmp_path / "portal.png"
    source.write_bytes(_png())
    _install_fake_dbus(monkeypatch, source, response=1)
    with pytest.raises(ToolkitError, match="cancelled"):
        XdgDesktopPortalBackend().capture(tmp_path / "cancel", CaptureTarget.WINDOW)

    _install_fake_dbus(monkeypatch, source, targets=1)
    with pytest.raises(ToolkitError, match="does not advertise"):
        XdgDesktopPortalBackend().capture(tmp_path / "unsupported", CaptureTarget.WINDOW)


def test_portal_backend_requires_v3_and_local_file_uri(tmp_path: Path, monkeypatch) -> None:
    """Require explicit-target semantics and reject non-local portal results."""

    source = tmp_path / "portal.png"
    source.write_bytes(_png())
    _install_fake_dbus(monkeypatch, source, version=2)
    with pytest.raises(ToolkitError, match="version 3"):
        XdgDesktopPortalBackend().capture(tmp_path / "old", CaptureTarget.WINDOW)

    with pytest.raises(ToolkitError, match="non-local"):
        XdgDesktopPortalBackend._file_uri_path("https://example.test/screenshot.png")


def test_image_inspection_reads_jpeg_dimensions_and_webp_type(tmp_path: Path) -> None:
    """Recognise common browser/desktop image containers without decoding them."""

    jpeg = tmp_path / "capture-jpeg"
    # SOI + baseline SOF0 segment.  The parser only needs the frame header and
    # deliberately does not decode image data.
    jpeg.write_bytes(
        b"\xff\xd8"
        + b"\xff\xe0\x00\x04ab"
        + b"\xff\xc0\x00\x08\x08"
        + struct.pack(">HH", 720, 1280)
        + b"\x03"
    )
    metadata = inspect_image(jpeg)
    assert metadata["media_type"] == "image/jpeg"
    assert metadata["pixel_width"] == 1280
    assert metadata["pixel_height"] == 720

    webp = tmp_path / "capture-webp"
    webp.write_bytes(b"RIFF" + b"\x00\x00\x00\x00" + b"WEBP" + b"payload")
    assert inspect_image(webp)["media_type"] == "image/webp"
