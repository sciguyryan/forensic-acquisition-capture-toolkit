"""Manage operator identities and operator signing keys.

This module validates public operator profiles, stores the active profile,
discovers usable GnuPG signing keys, and signs evidence with the selected
operator identity.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from .services.commands import require, run
from .errors import ToolkitError

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


@dataclass(frozen=True, slots=True)
class SigningKey:
    """Describe a usable secret signing key discovered in GnuPG."""

    primary_fingerprint: str
    signing_fingerprint: str
    uid: str
    algorithm: str
    created: str
    expires: str | None


@dataclass(frozen=True, slots=True)
class OperatorIdentity:
    """Represent the public operator identity embedded in evidence."""

    schema_version: int
    operator_id: str
    name: str
    public_contact: str | None
    organisation: str | None
    role: str | None
    operator_key_fingerprint: str
    operator_signing_subkey_fingerprint: str

    def public_dict(self) -> dict[str, object]:
        """Return the identity as a serialisable public dictionary."""
        return asdict(self)


def operators_dir(root: Path) -> Path:
    """Return the managed operator-profile directory."""
    return root.resolve() / "operators"


def config_path(root: Path) -> Path:
    """Return the toolkit configuration file path."""
    return root.resolve() / "config.json"


def _clean_optional(value: str | None) -> str | None:
    """Normalise an optional text field, returning ``None`` when blank."""
    if value is None:
        return None
    value = value.strip()
    return value or None


def validate_identity(data: dict[str, object]) -> OperatorIdentity:
    """Validate and normalise operator identity data."""
    required = (
        "operator_id",
        "name",
        "operator_key_fingerprint",
        "operator_signing_subkey_fingerprint",
    )
    for field in required:
        if not isinstance(data.get(field), str) or not str(data[field]).strip():
            raise ToolkitError(f"Operator identity field {field!r} is required")
    operator_id = str(data["operator_id"]).strip()
    if not _ID_RE.fullmatch(operator_id):
        raise ToolkitError(
            "operator_id must use 1-64 lowercase letters, digits, dots, underscores, or hyphens"
        )
    primary = re.sub(r"\s+", "", str(data["operator_key_fingerprint"])).upper()
    signing = re.sub(
        r"\s+", "", str(data["operator_signing_subkey_fingerprint"])
    ).upper()
    if not re.fullmatch(r"[0-9A-F]{40,64}", primary) or not re.fullmatch(
        r"[0-9A-F]{40,64}", signing
    ):
        raise ToolkitError(
            "Operator key fingerprints must be full hexadecimal fingerprints"
        )
    return OperatorIdentity(
        schema_version=1,
        operator_id=operator_id,
        name=str(data["name"]).strip(),
        public_contact=_clean_optional(
            data.get("public_contact")
            if isinstance(data.get("public_contact"), str)
            else None
        ),
        organisation=_clean_optional(
            data.get("organisation")
            if isinstance(data.get("organisation"), str)
            else None
        ),
        role=_clean_optional(
            data.get("role") if isinstance(data.get("role"), str) else None
        ),
        operator_key_fingerprint=primary,
        operator_signing_subkey_fingerprint=signing,
    )


def load_identity_file(path: Path) -> OperatorIdentity:
    """Load and validate an operator identity JSON file."""
    path = path.resolve()
    if path.is_symlink() or not path.is_file():
        raise ToolkitError(f"Operator identity is not a regular file: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolkitError(f"Unable to read operator identity {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ToolkitError("Operator identity must contain a JSON object")
    return validate_identity(data)


def save_identity(
    root: Path, identity: OperatorIdentity, *, force: bool = False
) -> Path:
    """Persist an operator profile and make it the active identity."""
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    directory = operators_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    path = directory / f"{identity.operator_id}.json"
    if path.exists() and not force:
        raise ToolkitError(f"Operator profile already exists: {path}")
    if path.is_symlink():
        raise ToolkitError(f"Refusing to replace symbolic-link profile: {path}")
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(identity.public_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    tmp.chmod(0o600)
    tmp.replace(path)
    path.chmod(0o600)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    config = {
        "schema_version": 2,
        "active_operator": identity.operator_id,
        "active_operator_sha256": digest,
    }
    cp = config_path(root)
    ctmp = cp.with_suffix(".json.tmp")
    ctmp.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    ctmp.chmod(0o600)
    ctmp.replace(cp)
    cp.chmod(0o600)
    readme = directory / "README.md"
    if not readme.exists():
        readme.write_text(
            "# Operator profiles\n\nManaged public identity profiles. Never place private-key material here. Fields are embedded in evidence packages.\n",
            encoding="utf-8",
        )
    return path


def active_identity(root: Path) -> tuple[OperatorIdentity, Path]:
    """Load the active identity and verify its pinned digest."""
    cp = config_path(root)
    if not cp.is_file():
        raise ToolkitError(
            "No active operator identity. Run youtube-forensic --root ROOT init."
        )
    data = json.loads(cp.read_text(encoding="utf-8"))
    operator_id = data.get("active_operator")
    if not isinstance(operator_id, str) or not _ID_RE.fullmatch(operator_id):
        raise ToolkitError("Toolkit configuration has no valid active_operator")
    path = operators_dir(root) / f"{operator_id}.json"
    identity = load_identity_file(path)
    expected = data.get("active_operator_sha256")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if expected != actual:
        raise ToolkitError("Active operator profile digest does not match config.json")
    return identity, path


def resolve_identity(
    root: Path, override: Path | None
) -> tuple[OperatorIdentity, Path, str]:
    """Resolve a per-acquisition override or the active identity."""
    if override is not None:
        path = override.resolve()
        return load_identity_file(path), path, "identity_file"
    identity, path = active_identity(root)
    return identity, path, "active_profile"


def discover_signing_keys() -> list[SigningKey]:
    """Discover usable signing keys in the system GnuPG keyring."""
    require("gpg")
    result = run(
        ["gpg", "--batch", "--with-colons", "--with-keygrip", "--list-secret-keys"],
        check=False,
    )
    if result.returncode not in (0, 2):
        raise ToolkitError(
            (result.stderr or result.stdout).strip()
            or "Unable to inspect system GnuPG keyring"
        )
    keys: list[SigningKey] = []
    primary_fpr = ""
    uid = ""
    primary_algo = ""
    primary_created = ""
    primary_expires: str | None = None
    pending_type: str | None = None
    pending_caps = ""
    pending_validity = ""
    for line in result.stdout.splitlines():
        p = line.split(":")
        rec = p[0]
        if rec in {"sec", "ssb"}:
            pending_type = rec
            pending_validity = p[1]
            primary_algo = p[3] if rec == "sec" else primary_algo
            pending_created = p[5]
            pending_expires = p[6] or None
            pending_caps = p[11]
            if rec == "sec":
                primary_fpr = ""
                uid = ""
                primary_created = pending_created
                primary_expires = pending_expires
        elif rec == "fpr" and pending_type:
            fpr = p[9]
            unusable = pending_validity in {"r", "e", "d"}
            if pending_type == "sec":
                primary_fpr = fpr
                if "s" in pending_caps.lower() and not unusable:
                    keys.append(
                        SigningKey(
                            fpr,
                            fpr,
                            uid,
                            primary_algo,
                            primary_created,
                            primary_expires,
                        )
                    )
            elif primary_fpr and "s" in pending_caps.lower() and not unusable:
                keys.append(
                    SigningKey(
                        primary_fpr,
                        fpr,
                        uid,
                        primary_algo,
                        primary_created,
                        primary_expires,
                    )
                )
            pending_type = None
        elif rec == "uid" and primary_fpr:
            uid = p[9]
            # Backfill UID on entries for this primary key.
            keys = [
                SigningKey(
                    k.primary_fingerprint,
                    k.signing_fingerprint,
                    uid if k.primary_fingerprint == primary_fpr else k.uid,
                    k.algorithm,
                    k.created,
                    k.expires,
                )
                for k in keys
            ]
    # Prefer signing subkeys over the primary when both exist.
    unique: dict[tuple[str, str], SigningKey] = {
        (k.primary_fingerprint, k.signing_fingerprint): k for k in keys
    }
    return list(unique.values())


def export_public_key(identity: OperatorIdentity, output: Path) -> None:
    """Export the operator public key in ASCII-armoured form."""
    result = run(
        ["gpg", "--batch", "--armor", "--export", identity.operator_key_fingerprint],
        check=False,
    )
    if result.returncode != 0 or "BEGIN PGP PUBLIC KEY BLOCK" not in result.stdout:
        raise ToolkitError(
            "Configured operator public key is unavailable in the system keyring"
        )
    output.write_text(result.stdout, encoding="utf-8")


def test_signing_key(identity: OperatorIdentity) -> None:
    """Create and verify a temporary signature with the operator key."""
    with tempfile.TemporaryDirectory(prefix="youtube-forensic-operator-test-") as td:
        payload = Path(td) / "nonce"
        signature = Path(td) / "nonce.asc"
        payload.write_text(os.urandom(32).hex() + "\n", encoding="ascii")
        sign_with_operator(identity, payload, signature)
        check = run(
            ["gpg", "--batch", "--verify", str(signature), str(payload)], check=False
        )
        if check.returncode != 0:
            raise ToolkitError("Operator test signature could not be verified")


def sign_with_operator(
    identity: OperatorIdentity, payload: Path, signature: Path
) -> None:
    """Create an ASCII-armoured detached operator signature."""
    result = run(
        [
            "gpg",
            "--local-user",
            identity.operator_signing_subkey_fingerprint + "!",
            "--armor",
            "--detach-sign",
            "--output",
            str(signature),
            str(payload),
        ],
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise ToolkitError(
            f"Operator signing failed: {detail[-1] if detail else 'unknown GnuPG error'}"
        )


def interactive_identity(
    root: Path, *, force: bool = False, test_key: bool = False
) -> tuple[OperatorIdentity, Path]:
    """Collect, validate, and save an operator identity interactively."""
    if not os.isatty(0):
        raise ToolkitError("Interactive init requires a terminal")
    name = input("Operator full name: ").strip()
    if not name:
        raise ToolkitError("Operator name is required")
    suggested = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:64]
    operator_id = input(f"Stable operator ID [{suggested}]: ").strip() or suggested
    organisation = input("Organisation [optional]: ").strip() or None
    role = input("Role [optional]: ").strip() or None
    public_contact = (
        input("Public contact email [optional; embedded in evidence]: ").strip() or None
    )
    keys = discover_signing_keys()
    if not keys:
        raise ToolkitError(
            "No usable secret signing keys were found in the system GnuPG keyring"
        )
    print("\nUsable operator signing keys:")
    for idx, key in enumerate(keys, 1):
        print(
            f"  {idx}. {key.uid or '(no user ID)'}\n     {key.signing_fingerprint}  algorithm={key.algorithm}  expires={key.expires or 'never'}"
        )
    raw = input("Select signing key number: ").strip()
    try:
        key = keys[int(raw) - 1]
    except (ValueError, IndexError):
        raise ToolkitError("Invalid signing-key selection") from None
    identity = validate_identity(
        {
            "operator_id": operator_id,
            "name": name,
            "organisation": organisation,
            "role": role,
            "public_contact": public_contact,
            "operator_key_fingerprint": key.primary_fingerprint,
            "operator_signing_subkey_fingerprint": key.signing_fingerprint,
        }
    )
    if test_key or input(
        "Test the selected signing key now? [y/N]: "
    ).strip().lower() in {"y", "yes"}:
        test_signing_key(identity)
    path = save_identity(root, identity, force=force)
    return identity, path
