from __future__ import annotations

import json
from pathlib import Path

import pytest

from fact.errors import ToolkitError
from fact.review import (
    Annotation,
    AnnotationKind,
    Box,
    ImageReviewLayers,
    Point,
    ProposedRedaction,
    load_review_layers,
    write_image_review_shell,
)

DIGEST = "a" * 64


def test_normalised_geometry_rejects_out_of_bounds_values() -> None:
    Point(0.0, 1.0)
    Box(0.1, 0.2, 0.3, 0.4)
    with pytest.raises(ValueError, match="between 0 and 1"):
        Point(-0.1, 0.5)
    with pytest.raises(ValueError, match="positive"):
        Box(0.1, 0.1, 0.0, 0.5)
    with pytest.raises(ValueError, match="beyond"):
        Box(0.8, 0.8, 0.3, 0.1)


def test_redaction_reason_is_mandatory() -> None:
    with pytest.raises(ValueError, match="must include a reason"):
        ProposedRedaction("R-0001", Box(0.1, 0.1, 0.2, 0.2), "   ")


def test_review_layers_write_and_load_without_modifying_original(
    tmp_path: Path,
) -> None:
    layers = ImageReviewLayers(
        original_sha256=DIGEST,
        original_width=1920,
        original_height=1080,
        annotations=[
            Annotation(
                "A-0001",
                AnnotationKind.ARROW,
                {"start": {"x": 0.1, "y": 0.1}, "end": {"x": 0.4, "y": 0.4}},
                note="Relevant control",
            )
        ],
        proposed_redactions=[
            ProposedRedaction(
                "R-0001",
                Box(0.5, 0.5, 0.2, 0.1),
                "Unrelated third-party telephone number",
            )
        ],
    )
    path = tmp_path / "review" / "layers.json"
    layers.write(path)
    loaded = load_review_layers(path)
    assert loaded["schema"] == "fact-image-review/v1"
    assert loaded["annotations"][0]["kind"] == "arrow"
    assert loaded["proposed_redactions"][0]["reason"].startswith("Unrelated")


def test_review_layers_validate_digest_dimensions_and_schema(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        ImageReviewLayers("short", 10, 10)
    with pytest.raises(ValueError, match="dimensions"):
        ImageReviewLayers(DIGEST, 0, 10)
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"schema": "other"}), encoding="utf-8")
    with pytest.raises(ToolkitError, match="Unsupported"):
        load_review_layers(path)
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(ToolkitError, match="Unable to read"):
        load_review_layers(path)


def test_browser_shell_embeds_layer_copy_and_uses_separate_assets(
    tmp_path: Path,
) -> None:
    review = {
        "schema": "fact-image-review/v1",
        "original_sha256": DIGEST,
        "original_width": 800,
        "original_height": 600,
        "annotations": [],
        "proposed_redactions": [],
    }
    index = write_image_review_shell(
        tmp_path / "browser",
        image="../evidence/screenshot-original.png",
        review_data=review,
    )
    html = index.read_text(encoding="utf-8")
    assert "../evidence/screenshot-original.png" in html
    assert "review_data" in html
    assert "https://" not in html
    assert (index.parent / "assets" / "fact-review.js").is_file()
    assert (index.parent / "assets" / "fact-review.css").is_file()
    assert "proposed_redactions" in html
