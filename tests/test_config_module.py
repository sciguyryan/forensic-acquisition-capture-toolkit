"""Tests for toolkit configuration-path helpers."""

from pathlib import Path

from fact.config import config_path


def test_config_path_resolves_root() -> None:
    """Return config.json beneath the resolved toolkit root."""
    root = Path("relative-root")

    assert config_path(root) == root.resolve() / "config.json"
