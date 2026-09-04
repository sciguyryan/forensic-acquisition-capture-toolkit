"""Explicit registry for FACT collectors.

The registry is intentionally small and local for now.  Keeping registration
separate from CLI dispatch avoids a future monolithic ``if/elif`` tree and gives
FACT a natural extension point without prematurely committing to third-party
plugin discovery.
"""

from __future__ import annotations

from typing import Any

from .base import Collector


class CollectorRegistry:
    """Map stable collector names to collector implementations."""

    def __init__(self) -> None:
        self._collectors: dict[str, Collector[Any]] = {}

    def register(self, name: str, collector: Collector[Any]) -> None:
        """Register a collector under a unique, user-facing name."""

        if not name or name in self._collectors:
            raise ValueError(f"Collector name is empty or already registered: {name!r}")
        self._collectors[name] = collector

    def get(self, name: str) -> Collector[Any]:
        """Return a registered collector or raise a clear lookup error."""

        try:
            return self._collectors[name]
        except KeyError as exc:
            raise KeyError(f"Unknown FACT collector: {name}") from exc

    def names(self) -> tuple[str, ...]:
        """Return collector names in deterministic order."""

        return tuple(sorted(self._collectors))


def default_registry() -> CollectorRegistry:
    """Return FACT's built-in collectors without importing them in CLI code.

    Imports are deliberately local so collector modules can later depend on
    optional platform capabilities without making unrelated FACT commands fail
    merely because those capabilities are unavailable.
    """

    from .youtube.collector import YouTubeCollector

    registry = CollectorRegistry()
    registry.register("youtube", YouTubeCollector())
    return registry
