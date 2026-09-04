"""Define the toolkit's core data models and UTC timestamp helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""
    return datetime.now(UTC)


def iso_utc(value: datetime | None = None) -> str:
    """Format a datetime as a whole-second UTC ISO 8601 string."""
    return (
        (value or utc_now())
        .astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


@dataclass(slots=True)
class CaseInfo:
    """Hold operator and matter details supplied for an acquisition."""

    case_id: str
    comments: str
    operator_identity: dict[str, Any]
    operator_source: str
    operator_profile_sha256: str
    operator_username: str | None = None
    requestor: str | None = None
    matter_title: str | None = None


@dataclass(slots=True)
class ToolResult:
    """Capture the result of an external command invocation."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str


@dataclass(slots=True)
class VerificationStage:
    """Describe one verification check and its outcome."""

    name: str
    status: str
    detail: str = ""


@dataclass(slots=True)
class VerificationSummary:
    """Collect verification stages for an evidence archive."""

    archive: Path
    stages: list[VerificationStage] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Return ``True`` when no verification stage has failed."""
        return all(stage.status != "FAIL" for stage in self.stages)

    def add(self, name: str, status: str, detail: str = "") -> None:
        """Append a verification stage to the summary."""
        self.stages.append(VerificationStage(name=name, status=status, detail=detail))


@dataclass(slots=True)
class CaseRecord:
    """Represent the complete machine-readable evidence case record."""

    schema_version: str
    toolkit_name: str
    toolkit_version: str
    case: dict[str, Any]
    acquisition: dict[str, Any]
    source: dict[str, Any]
    evidence: dict[str, Any]
    tools: dict[str, str]
    observations: list[str]
    custody_events: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        """Return the case record as a recursively serialisable dictionary."""
        return asdict(self)
