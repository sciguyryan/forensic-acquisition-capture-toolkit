"""Inspect common screenshot image formats without rewriting source bytes.

FACT intentionally does not open and re-save a screenshot merely to learn its
size: doing so would create a transformed image rather than preserving the exact
bytes returned by the capture backend.  These parsers therefore read only the
small amount of container structure needed for metadata.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_JPEG_SOI = b"\xff\xd8"


def inspect_image(path: Path) -> dict[str, Any]:
    """Return media type, dimensions when known, and a safe file extension."""

    with path.open("rb") as handle:
        header = handle.read(32)
        if header.startswith(_PNG_SIGNATURE) and header[12:16] == b"IHDR":
            width, height = struct.unpack(">II", header[16:24])
            return {
                "media_type": "image/png",
                "extension": ".png",
                "pixel_width": width,
                "pixel_height": height,
            }
        if header.startswith(_JPEG_SOI):
            dimensions = _jpeg_dimensions(path)
            return {
                "media_type": "image/jpeg",
                "extension": ".jpg",
                **dimensions,
            }
        if header.startswith(b"RIFF") and header[8:12] == b"WEBP":
            return {
                "media_type": "image/webp",
                "extension": ".webp",
            }
    return {"media_type": "application/octet-stream", "extension": ".img"}


def _jpeg_dimensions(path: Path) -> dict[str, int]:
    """Read JPEG frame dimensions without decoding or modifying the image."""

    with path.open("rb") as handle:
        if handle.read(2) != _JPEG_SOI:
            return {}
        while True:
            byte = handle.read(1)
            if not byte:
                return {}
            if byte != b"\xff":
                continue
            marker = handle.read(1)
            while marker == b"\xff":
                marker = handle.read(1)
            if not marker or marker in {b"\xd8", b"\xd9"}:
                continue
            if marker == b"\xda":
                return {}
            length_bytes = handle.read(2)
            if len(length_bytes) != 2:
                return {}
            segment_length = struct.unpack(">H", length_bytes)[0]
            if segment_length < 2:
                return {}
            marker_value = marker[0]
            if marker_value in {
                0xC0,
                0xC1,
                0xC2,
                0xC3,
                0xC5,
                0xC6,
                0xC7,
                0xC9,
                0xCA,
                0xCB,
                0xCD,
                0xCE,
                0xCF,
            }:
                frame = handle.read(segment_length - 2)
                if len(frame) >= 5:
                    height, width = struct.unpack(">HH", frame[1:5])
                    return {"pixel_width": width, "pixel_height": height}
                return {}
            handle.seek(segment_length - 2, 1)
