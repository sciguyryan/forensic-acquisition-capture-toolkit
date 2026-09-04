"""Linux Wayland/X11 screenshot capture through XDG Desktop Portal.

The portal is FACT's preferred Arch Linux backend because the compositor remains
in control of sensitive window selection.  Under Wayland this avoids attempting
to bypass the desktop security model or scraping compositor-specific private
interfaces.  Screenshot portal version 3 additionally lets FACT request a
specific target class such as an operator-selected window.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import uuid
from pathlib import Path
from urllib.parse import unquote, urlparse

from ...errors import ToolkitError
from .base import CaptureTarget, ScreenshotCapture
from .image import inspect_image

_PORTAL_DESTINATION = "org.freedesktop.portal.Desktop"
_PORTAL_PATH = "/org/freedesktop/portal/desktop"
_SCREENSHOT_INTERFACE = "org.freedesktop.portal.Screenshot"
_REQUEST_INTERFACE = "org.freedesktop.portal.Request"
_PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties"
_MIN_TARGET_PORTAL_VERSION = 3
_RESPONSE_TIMEOUT_SECONDS = 600

# XDG Screenshot portal target values are single enum-like bit values.  Keep
# this translation at the backend boundary so platform-neutral code never
# depends on D-Bus protocol constants.
_PORTAL_TARGETS = {
    CaptureTarget.SCREEN: 1,
    CaptureTarget.WINDOW: 2,
    CaptureTarget.AREA: 4,
    CaptureTarget.ACTIVE_WINDOW: 8,
}


class XdgDesktopPortalBackend:
    """Capture screenshots via the desktop's trusted XDG portal interface."""

    name = "xdg-desktop-portal"

    def capture(self, destination_dir: Path, target: CaptureTarget) -> ScreenshotCapture:
        """Run one portal interaction and copy its exact returned bytes to FACT."""

        try:
            return asyncio.run(self._capture(destination_dir, target))
        except RuntimeError as exc:
            if "asyncio.run() cannot be called" in str(exc):
                raise ToolkitError(
                    "The XDG screenshot backend requires a synchronous FACT CLI context"
                ) from exc
            raise

    async def _capture(
        self, destination_dir: Path, target: CaptureTarget
    ) -> ScreenshotCapture:
        try:
            from dbus_next import BusType, Message, MessageType, Variant
            from dbus_next.aio import MessageBus
        except ImportError as exc:
            raise ToolkitError(
                "Screenshot capture requires the optional 'dbus-next' dependency. "
                "Install FACT with the screenshot extra: pip install -e '.[screenshot]'"
            ) from exc

        destination_dir.mkdir(parents=True, exist_ok=True)
        bus = await MessageBus(bus_type=BusType.SESSION).connect()
        try:
            version = await self._property(bus, Message, MessageType, "version")
            if int(version) < _MIN_TARGET_PORTAL_VERSION:
                raise ToolkitError(
                    "The desktop Screenshot portal is too old for explicit window "
                    f"selection (reported version {version}; version 3+ required)"
                )
            available = await self._property(
                bus, Message, MessageType, "AvailableTargets"
            )
            portal_target = _PORTAL_TARGETS[target]
            if not int(available) & portal_target:
                raise ToolkitError(
                    f"The desktop Screenshot portal does not advertise target {target.value!r}"
                )

            # A predictable Request path lets us subscribe before invoking the
            # portal method, eliminating the response-signal race documented by
            # XDG Desktop Portal.  The token remains random to avoid collisions.
            token = f"fact_{uuid.uuid4().hex}"
            sender = bus.unique_name.removeprefix(":").replace(".", "_")
            expected_handle = f"{_PORTAL_PATH}/request/{sender}/{token}"
            loop = asyncio.get_running_loop()
            response_future: asyncio.Future[tuple[int, dict[str, object]]] = (
                loop.create_future()
            )

            def response_handler(message: object) -> bool:
                if (
                    getattr(message, "message_type", None) == MessageType.SIGNAL
                    and getattr(message, "path", None) == expected_handle
                    and getattr(message, "interface", None) == _REQUEST_INTERFACE
                    and getattr(message, "member", None) == "Response"
                ):
                    response, results = message.body
                    if not response_future.done():
                        response_future.set_result((int(response), results))
                    return True
                return False

            bus.add_message_handler(response_handler)
            try:
                options = {
                    "handle_token": Variant("s", token),
                    "interactive": Variant("b", True),
                    "target": Variant("u", portal_target),
                }
                reply = await bus.call(
                    Message(
                        destination=_PORTAL_DESTINATION,
                        path=_PORTAL_PATH,
                        interface=_SCREENSHOT_INTERFACE,
                        member="Screenshot",
                        signature="sa{sv}",
                        body=["", options],
                    )
                )
                self._raise_dbus_error(reply, MessageType)
                returned_handle = str(reply.body[0])
                if returned_handle != expected_handle:
                    # Very old/non-conforming portal implementations may return
                    # another handle.  Version 3 should not, and continuing would
                    # risk waiting on a signal that cannot be trusted to match.
                    raise ToolkitError(
                        "Screenshot portal returned an unexpected request handle"
                    )
                try:
                    response, results = await asyncio.wait_for(
                        response_future, timeout=_RESPONSE_TIMEOUT_SECONDS
                    )
                except TimeoutError as exc:
                    raise ToolkitError(
                        "Timed out waiting for screenshot selection from the desktop portal"
                    ) from exc
            finally:
                bus.remove_message_handler(response_handler)

            if response == 1:
                raise ToolkitError("Screenshot selection was cancelled by the operator")
            if response != 0:
                raise ToolkitError(
                    f"Screenshot portal ended without a capture (response {response})"
                )
            uri_value = results.get("uri")
            uri = getattr(uri_value, "value", None)
            if not isinstance(uri, str):
                raise ToolkitError("Screenshot portal did not return an image URI")
            source_path = self._file_uri_path(uri)
            if source_path.is_symlink() or not source_path.is_file():
                raise ToolkitError(
                    "Screenshot portal returned a path that is not a regular file"
                )

            # Copy bytes before inspecting them.  The portal's file may be
            # temporary; FACT must own an immutable staging copy before doing
            # any non-essential metadata work.
            temporary = destination_dir / ".screenshot-original.capture"
            shutil.copyfile(source_path, temporary)
            temporary.chmod(0o600)
            image = inspect_image(temporary)
            final_path = destination_dir / f"screenshot-original{image['extension']}"
            temporary.replace(final_path)
            return ScreenshotCapture(
                path=final_path,
                backend=self.name,
                target=target,
                selection_method="xdg-desktop-portal-user-selection",
                metadata={
                    "portal_interface_version": int(version),
                    "portal_available_targets": int(available),
                    "media_type": image["media_type"],
                    "pixel_width": image.get("pixel_width"),
                    "pixel_height": image.get("pixel_height"),
                    "session_type": os.environ.get("XDG_SESSION_TYPE") or None,
                    "desktop": os.environ.get("XDG_CURRENT_DESKTOP") or None,
                    "wayland_display": os.environ.get("WAYLAND_DISPLAY") or None,
                    "x11_display_present": bool(os.environ.get("DISPLAY")),
                },
            )
        finally:
            bus.disconnect()

    async def _property(self, bus: object, Message: object, MessageType: object, name: str) -> object:
        """Read one Screenshot portal property through standard D-Bus Properties."""

        reply = await bus.call(
            Message(
                destination=_PORTAL_DESTINATION,
                path=_PORTAL_PATH,
                interface=_PROPERTIES_INTERFACE,
                member="Get",
                signature="ss",
                body=[_SCREENSHOT_INTERFACE, name],
            )
        )
        self._raise_dbus_error(reply, MessageType)
        return reply.body[0].value

    @staticmethod
    def _raise_dbus_error(reply: object, MessageType: object) -> None:
        """Convert D-Bus method errors into operator-facing toolkit failures."""

        if reply.message_type == MessageType.ERROR:
            detail = str(reply.body[0]) if reply.body else str(reply.error_name)
            raise ToolkitError(f"Screenshot portal D-Bus request failed: {detail}")

    @staticmethod
    def _file_uri_path(uri: str) -> Path:
        """Resolve a local file URI returned by the Screenshot portal."""

        parsed = urlparse(uri)
        if parsed.scheme != "file" or parsed.netloc not in {"", "localhost"}:
            raise ToolkitError("Screenshot portal returned a non-local image URI")
        return Path(unquote(parsed.path))
