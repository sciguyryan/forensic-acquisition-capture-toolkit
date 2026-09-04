"""Calculate evidence digests and create or verify checksum manifests.

Manifest generation deliberately excludes transient files, incomplete markers,
and verification workspaces so that checksums describe the sealed evidence set.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

EXCLUDED_NAMES = {
    "INCOMPLETE",
    "SHA256SUMS.txt",
    "SHA512SUMS.txt",
}
EXCLUDED_SUFFIXES = {".tmp"}


def digest(path: Path, algorithm: str) -> str:
    """Calculate a hexadecimal digest for a file."""
    h = hashlib.new(algorithm)
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def evidence_files(root: Path, *, include_manifests: bool = False) -> list[Path]:
    """Return the regular files that belong to the evidence set."""
    excluded = set() if include_manifests else EXCLUDED_NAMES
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root)
        if path.name in excluded or path.name == "INCOMPLETE":
            continue
        if any(path.name.endswith(suffix) for suffix in EXCLUDED_SUFFIXES):
            continue
        if any(part.startswith(".verification-work") for part in rel.parts):
            continue
        files.append(path)
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def write_filelist(root: Path, output: Path) -> None:
    """Write the canonical evidence file list."""
    lines = [p.relative_to(root).as_posix() for p in evidence_files(root)]
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_manifest(root: Path, output: Path, algorithm: str) -> None:
    """Write a checksum manifest for the evidence set."""
    lines: list[str] = []
    for path in evidence_files(root):
        rel = path.relative_to(root).as_posix()
        lines.append(f"{digest(path, algorithm)}  {rel}")
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_manifest(root: Path, manifest: Path, algorithm: str) -> list[str]:
    """Verify a checksum manifest and return human-readable failures."""
    failures: list[str] = []
    for lineno, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            expected, rel = raw.split("  ", 1)
        except ValueError:
            failures.append(f"line {lineno}: malformed manifest entry")
            continue
        target = root / rel
        if not target.is_file():
            failures.append(f"missing: {rel}")
        elif digest(target, algorithm) != expected:
            failures.append(f"digest mismatch: {rel}")
    return failures
