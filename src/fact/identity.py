"""Manage operator identities and operator signing keys.

This module validates public operator identities, discovers usable GnuPG
signing keys, and signs evidence or project transactions with the selected
operator identity. Project identity itself is retained by the project catalogue.
"""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from .errors import ToolkitError
from .services.commands import require, run

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
    with tempfile.TemporaryDirectory(prefix="fact-operator-test-") as td:
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


def export_public_key_text(identity: OperatorIdentity) -> str:
    """Return the operator public key as an ASCII-armoured string.

    Project catalogues retain public verification material so historical
    signatures remain independently verifiable without relying on an external keyserver. Private key material
    never enters the project catalogue.
    """
    result = run(
        ["gpg", "--batch", "--armor", "--export", identity.operator_key_fingerprint],
        check=False,
    )
    if result.returncode != 0 or "BEGIN PGP PUBLIC KEY BLOCK" not in result.stdout:
        raise ToolkitError(
            "Configured operator public key is unavailable in the system keyring"
        )
    return result.stdout


def sign_operator_payload(identity: OperatorIdentity, payload: bytes) -> str:
    """Sign canonical project-transaction bytes with an operator key.

    FACT signs the exact transaction representation that will be bound into the
    catalogue chain. The temporary files exist only to interface with GnuPG and
    contain no private key material.
    """
    with tempfile.TemporaryDirectory(prefix="fact-operator-transaction-") as td:
        directory = Path(td)
        payload_path = directory / "transaction.json"
        signature_path = directory / "transaction.json.asc"
        payload_path.write_bytes(payload)
        sign_with_operator(identity, payload_path, signature_path)
        return signature_path.read_text(encoding="utf-8")


def verify_operator_payload(
    public_key: str,
    payload: bytes,
    signature: str,
    expected_fingerprint: str | None = None,
) -> None:
    """Verify a transaction and, when supplied, its exact historical signer."""
    with tempfile.TemporaryDirectory(prefix="fact-operator-verify-") as td:
        directory = Path(td)
        directory.chmod(0o700)
        payload_path = directory / "transaction.json"
        signature_path = directory / "transaction.json.asc"
        public_key_path = directory / "operator-public-key.asc"
        payload_path.write_bytes(payload)
        signature_path.write_text(signature, encoding="utf-8")
        public_key_path.write_text(public_key, encoding="utf-8")
        env = {"GNUPGHOME": str(directory / "gnupg")}
        Path(env["GNUPGHOME"]).mkdir(mode=0o700)
        imported = run(
            ["gpg", "--batch", "--import", str(public_key_path)],
            env=env,
            check=False,
        )
        if imported.returncode != 0:
            raise ToolkitError("Unable to import retained operator public key")
        verified = run(
            [
                "gpg",
                "--batch",
                "--status-fd",
                "1",
                "--verify",
                str(signature_path),
                str(payload_path),
            ],
            env=env,
            check=False,
        )
        if verified.returncode != 0:
            raise ToolkitError("Operator transaction signature is invalid")
        if expected_fingerprint is not None:
            valid_signers = {
                line.split()[2].upper()
                for line in verified.stdout.splitlines()
                if line.startswith("[GNUPG:] VALIDSIG ") and len(line.split()) >= 3
            }
            if expected_fingerprint.upper() not in valid_signers:
                raise ToolkitError(
                    "Operator transaction signature does not match the recorded signing key"
                )


def interactive_identity(*, test_key: bool = False) -> OperatorIdentity:
    """Collect and validate an operator identity from a local GnuPG key."""
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
    return identity
