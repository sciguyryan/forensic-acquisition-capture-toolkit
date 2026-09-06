"""Project-selectable hashing profiles for FACT integrity operations."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

from ..errors import ToolkitError

DEFAULT_CHAIN_HASH = "sha256"
DEFAULT_CONTENT_HASH = "sha256"

SUPPORTED_HASHES = (
    "sha256",
    "sha512",
    "sha3-256",
    "sha3-512",
    "blake2b-256",
    "blake2b-512",
    "blake2s-256",
    "blake3-256",
)


def canonical_json_bytes(data: object) -> bytes:
    """Serialise integrity material using FACT's normative canonical JSON rules.

    Objects are encoded as UTF-8 JSON with recursively sorted object keys, no
    insignificant whitespace, JSON-native scalar spelling, and Unicode emitted
    directly rather than ASCII escaped. No trailing newline is added.
    """
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _blake3_factory() -> object:
    try:
        import blake3  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ToolkitError(
            "Hash algorithm blake3-256 is configured but the 'blake3' package is unavailable"
        ) from exc
    return blake3.blake3()


def _factory(name: str) -> Callable[[], object]:
    factories: dict[str, Callable[[], object]] = {
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
        "sha3-256": hashlib.sha3_256,
        "sha3-512": hashlib.sha3_512,
        "blake2b-256": lambda: hashlib.blake2b(digest_size=32),
        "blake2b-512": lambda: hashlib.blake2b(digest_size=64),
        "blake2s-256": lambda: hashlib.blake2s(digest_size=32),
        "blake3-256": _blake3_factory,
    }
    try:
        return factories[name]
    except KeyError as exc:
        raise ToolkitError(f"Unsupported FACT hash algorithm: {name}") from exc


def require_hash(name: str) -> str:
    """Validate a canonical FACT hash name and local implementation availability."""
    factory = _factory(name)
    factory()
    return name


def digest_bytes(name: str, payload: bytes) -> str:
    """Return the canonical hexadecimal digest for ``payload`` using ``name``."""
    hasher = _factory(name)()
    hasher.update(payload)  # type: ignore[attr-defined]
    return str(hasher.hexdigest())  # type: ignore[attr-defined]


def digest_file(name: str, path: Path) -> str:
    """Hash one file incrementally using the selected FACT hash profile."""
    hasher = _factory(name)()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)  # type: ignore[attr-defined]
    return str(hasher.hexdigest())  # type: ignore[attr-defined]


def digest_hex_length(name: str) -> int:
    """Return the hexadecimal digest length for one supported profile."""
    return len(digest_bytes(name, b""))


def genesis_hash(name: str) -> str:
    """Return the all-zero initial chain value matching the selected digest width."""
    return "0" * digest_hex_length(name)


def project_integrity(project_root: Path) -> tuple[str, str]:
    """Read and validate the immutable integrity policy from ``PROJECT.toml``."""
    import tomllib

    project_file = project_root / "PROJECT.toml"
    try:
        data = tomllib.loads(project_file.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ToolkitError(
            f"Unable to read FACT project integrity policy: {project_file}"
        ) from exc
    integrity = data.get("integrity")
    if not isinstance(integrity, dict):
        raise ToolkitError("FACT project record is missing the [integrity] policy")
    chain_hash = require_hash(str(integrity.get("chain_hash", "")))
    content_hash = require_hash(str(integrity.get("content_hash", "")))
    return chain_hash, content_hash


def project_content_hash(project_root: Path) -> str:
    """Return the configured evidential content hash for one project."""
    return project_integrity(project_root)[1]
