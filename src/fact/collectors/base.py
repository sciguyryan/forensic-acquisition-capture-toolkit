"""Collector protocol used by source-specific FACT acquisition backends."""

from __future__ import annotations

from typing import Protocol, TypeVar

from ..core.acquisition import AcquisitionContext, AcquisitionResult

RequestT = TypeVar("RequestT", contravariant=True)


class Collector(Protocol[RequestT]):
    """Minimal contract implemented by every FACT collector.

    A collector captures source-specific material only.  It must not allocate
    project identifiers, sign packages, seal archives, or decide whether a
    project is valid.  Those responsibilities remain in reusable FACT core code.
    """

    name: str

    def capture(self, context: AcquisitionContext, request: RequestT) -> AcquisitionResult:
        """Capture source material into ``context.workspace.stage``."""
        ...
