"""Structured review-layer models for immutable visual evidence.

Review data is intentionally separate from acquired evidence.  Geometry is
stored in normalised coordinates so the same layer can be rendered over an
image at any display scale without modifying or resampling the source image.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from ..errors import ToolkitError
from ..models import iso_utc


class AnnotationKind(StrEnum):
    """Initial visual primitives supported by the FACT review model."""

    RECTANGLE = "rectangle"
    ELLIPSE = "ellipse"
    ARROW = "arrow"
    LINE = "line"
    FREEHAND = "freehand"
    MARKER = "marker"
    TEXT = "text"
    HIGHLIGHT = "highlight"


@dataclass(slots=True, frozen=True)
class Point:
    """A point expressed relative to the original image dimensions."""

    x: float
    y: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.x <= 1.0 or not 0.0 <= self.y <= 1.0:
            raise ValueError("Review coordinates must be between 0 and 1")


@dataclass(slots=True, frozen=True)
class Box:
    """A normalised rectangular region used for shapes and redactions."""

    x: float
    y: float
    width: float
    height: float

    def __post_init__(self) -> None:
        values = (self.x, self.y, self.width, self.height)
        if any(value < 0.0 or value > 1.0 for value in values):
            raise ValueError("Review box values must be between 0 and 1")
        if self.width <= 0 or self.height <= 0:
            raise ValueError("Review boxes must have positive width and height")
        if self.x + self.width > 1.0 or self.y + self.height > 1.0:
            raise ValueError("Review box extends beyond the original image")


@dataclass(slots=True)
class Annotation:
    """One non-destructive operator annotation over visual evidence."""

    annotation_id: str
    kind: AnnotationKind
    geometry: dict[str, Any]
    note: str | None = None
    label: str | None = None


@dataclass(slots=True)
class ProposedRedaction:
    """One proposed redaction; a reason is mandatory by evidential policy."""

    redaction_id: str
    box: Box
    reason: str
    category: str | None = None

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError("Every proposed redaction must include a reason")


@dataclass(slots=True)
class ImageReviewLayers:
    """Review data bound to one immutable original image by SHA-256."""

    original_sha256: str
    original_width: int
    original_height: int
    annotations: list[Annotation] = field(default_factory=list)
    proposed_redactions: list[ProposedRedaction] = field(default_factory=list)
    created_utc: str = field(default_factory=iso_utc)
    schema: str = "fact-image-review/v1"

    def __post_init__(self) -> None:
        if len(self.original_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.original_sha256.lower()):
            raise ValueError("Review layers require a SHA-256 digest of the original image")
        if self.original_width <= 0 or self.original_height <= 0:
            raise ValueError("Original image dimensions must be positive")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serialisable review data while preserving enum values."""

        payload = asdict(self)
        for annotation in payload["annotations"]:
            kind = annotation["kind"]
            annotation["kind"] = kind.value if isinstance(kind, AnnotationKind) else str(kind)
        return payload

    def write(self, path: Path) -> None:
        """Write the review layer atomically enough for ordinary local use."""

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_review_layers(path: Path) -> dict[str, Any]:
    """Load review JSON for presentation, rejecting unsupported schemas."""

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolkitError(f"Unable to read FACT review layers: {path}") from exc
    if data.get("schema") != "fact-image-review/v1":
        raise ToolkitError("Unsupported FACT image review schema")
    return data
