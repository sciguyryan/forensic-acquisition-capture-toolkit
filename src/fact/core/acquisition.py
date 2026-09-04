"""Generic acquisition lifecycle primitives shared by every FACT collector.

Collectors are deliberately kept away from project allocation, sealing, signing,
and verification.  This module owns the mutable staging workspace and the common
records that describe what a collector produced.  Source-specific collectors
receive an :class:`AcquisitionContext`, write only beneath its staging directory,
and register every artefact they intentionally create.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from ..console import log
from ..models import iso_utc
from ..services.commands import CommandRunner


class ArtefactRole(StrEnum):
    """Stable high-level roles used to distinguish evidence from later material."""

    PRIMARY = "primary"
    SUPPORTING = "supporting"
    METADATA = "metadata"
    TRANSCRIPT = "transcript"
    DERIVED = "derived"
    ANNOTATION = "annotation"
    REDACTION_REQUEST = "redaction_request"
    PREVIEW = "preview"


@dataclass(slots=True, frozen=True)
class Artefact:
    """Describe one file intentionally produced during an acquisition.

    Paths are stored relative to the acquisition staging root.  FACT never
    relies on absolute workstation paths as evidential identifiers because those
    paths are deployment-specific and would make packages unnecessarily brittle.
    """

    path: str
    role: ArtefactRole
    media_type: str | None = None
    description: str | None = None


class ArtefactRegistry:
    """Track collector-produced files using a common, explicit vocabulary."""

    def __init__(self, staging_root: Path) -> None:
        self._staging_root = staging_root.resolve()
        self._artefacts: dict[str, Artefact] = {}

    def register(
        self,
        path: Path,
        *,
        role: ArtefactRole,
        media_type: str | None = None,
        description: str | None = None,
    ) -> Artefact:
        """Register an existing regular file beneath the staging root.

        Registration rejects symlinks and paths outside the staging workspace.
        That boundary is important because a collector must not smuggle an
        unrelated host file into an evidence package merely by naming it.
        """

        resolved = path.resolve()
        try:
            relative = resolved.relative_to(self._staging_root)
        except ValueError as exc:
            raise ValueError(f"Artefact is outside acquisition staging: {path}") from exc
        if path.is_symlink() or not resolved.is_file():
            raise ValueError(f"Artefact must be an existing regular file: {path}")
        key = relative.as_posix()
        artefact = Artefact(key, role, media_type, description)
        self._artefacts[key] = artefact
        return artefact

    def items(self) -> list[Artefact]:
        """Return registered artefacts in deterministic path order."""

        return [self._artefacts[key] for key in sorted(self._artefacts)]

    def write(self, output: Path) -> None:
        """Write the registry as machine-readable acquisition metadata."""

        payload = {
            "schema": "fact-artefact-registry/v1",
            "artefacts": [
                {
                    **asdict(item),
                    "role": item.role.value,
                }
                for item in self.items()
            ],
        }
        output.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


@dataclass(slots=True)
class AcquisitionWorkspace:
    """Mutable staging workspace owned by the generic acquisition lifecycle."""

    root: Path
    stage: Path
    log_path: Path
    incomplete_marker: Path

    @classmethod
    def create(cls, root: Path, case_id: str, acquisition_id: str) -> "AcquisitionWorkspace":
        """Create the common staging and logging structure for an acquisition."""

        root = root.resolve()
        archive_dir = root / "archived"
        log_dir = root / "logs"
        archive_dir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)

        stage = archive_dir / f".staging-{case_id}-{acquisition_id}"
        stage.mkdir()
        marker = stage / "INCOMPLETE"
        marker.write_text(
            "Acquisition has not completed mandatory verification.\n",
            encoding="utf-8",
        )
        return cls(
            root=root,
            stage=stage,
            log_path=log_dir / f"{case_id}-{acquisition_id}.log",
            incomplete_marker=marker,
        )

    def note(self, level: str, text: str) -> None:
        """Write one lifecycle message to both the console and acquisition log."""

        log(level, text)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"[{iso_utc()}] [{level}] {text}\n")


@dataclass(slots=True)
class AcquisitionContext:
    """The source-agnostic services and state made available to a collector."""

    project_root: Path
    case_id: str
    acquisition_id: str
    workspace: AcquisitionWorkspace
    artefacts: ArtefactRegistry
    commands: CommandRunner
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AcquisitionResult:
    """Structured outcome returned by a collector to the generic lifecycle."""

    collector: str
    collector_version: str
    source: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    observations: list[str] = field(default_factory=list)
