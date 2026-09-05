"""Manage the toolkit's dedicated evidence-signing keyring.

The module prepares an isolated GnuPG home, creates and exports the project
evidence key, signs deliberately exported objects, and verifies key backups
before they are released.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from .errors import ToolkitError
from .services.commands import require, run

_PINENTRY_CANDIDATES = (
    "pinentry-curses",
    "pinentry-tty",
    "pinentry",
    "pinentry-gnome3",
    "pinentry-qt",
)


def _terminal_name() -> str | None:
    """Return a usable controlling terminal path, when one is available."""
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            if stream.isatty():
                return os.ttyname(stream.fileno())
        except (AttributeError, OSError, ValueError):
            continue
    return os.environ.get("GPG_TTY") or None


def _find_pinentry() -> str | None:
    """Return a suitable pinentry executable, if one is available."""
    for candidate in _PINENTRY_CANDIDATES:
        path = shutil.which(candidate)
        if path:
            return path
    return None


def _write_agent_config(gnupg_home: Path, pinentry: str) -> None:
    """Ensure the dedicated keyring has an explicit, usable pinentry helper."""
    config = gnupg_home / "gpg-agent.conf"
    existing: list[str] = []
    if config.exists():
        existing = config.read_text(encoding="utf-8", errors="replace").splitlines()
    filtered = [
        line for line in existing if not line.lstrip().startswith("pinentry-program")
    ]
    filtered.append(f"pinentry-program {pinentry}")
    config.write_text("\n".join(filtered) + "\n", encoding="utf-8")
    config.chmod(0o600)


def prepare_gnupg(gnupg_home: Path, *, interactive: bool) -> dict[str, str]:
    """Prepare an isolated GnuPG home and return environment additions for GPG.

    Existing keys can be listed and used without pinentry. Interactive key creation
    requires a controlling terminal and an installed pinentry implementation.
    """
    require("gpg")
    require("gpgconf")
    require("gpg-agent")

    gnupg_home.mkdir(parents=True, exist_ok=True)
    gnupg_home.chmod(0o700)

    env: dict[str, str] = {"GNUPGHOME": str(gnupg_home)}
    tty = _terminal_name()
    if tty:
        env["GPG_TTY"] = tty

    if interactive:
        if not tty:
            raise ToolkitError(
                "Evidence-key creation requires an interactive terminal. "
                "Run the acquisition directly in a terminal, not through a detached job."
            )
        pinentry = _find_pinentry()
        if not pinentry:
            raise ToolkitError(
                "No usable pinentry program was found. Install pinentry-curses "
                "(Debian/Ubuntu), pinentry (Fedora/Arch), or another GnuPG pinentry helper."
            )
        _write_agent_config(gnupg_home, pinentry)

    # Reload any old agent so configuration and socket state match this homedir.
    run(
        ["gpgconf", "--homedir", str(gnupg_home), "--kill", "gpg-agent"],
        env=env,
        check=False,
    )
    launched = run(
        ["gpgconf", "--homedir", str(gnupg_home), "--launch", "gpg-agent"],
        env=env,
        check=False,
    )
    if launched.returncode != 0:
        detail = (
            launched.stderr or launched.stdout
        ).strip() or "unknown gpg-agent error"
        raise ToolkitError(f"Unable to initialise the dedicated gpg-agent: {detail}")

    socket = run(
        ["gpgconf", "--homedir", str(gnupg_home), "--list-dirs", "agent-socket"],
        env=env,
        check=False,
    )
    socket_path = socket.stdout.strip()
    if socket.returncode != 0 or not socket_path:
        raise ToolkitError(
            "GnuPG did not report an agent socket for the dedicated keyring"
        )

    return env


def fingerprint(gnupg_home: Path, *, env: dict[str, str] | None = None) -> str | None:
    """Return the dedicated evidence key fingerprint, if present."""
    require("gpg")
    result = run(
        [
            "gpg",
            "--homedir",
            str(gnupg_home),
            "--batch",
            "--with-colons",
            "--list-secret-keys",
        ],
        env=env,
        check=False,
    )
    for line in result.stdout.splitlines():
        parts = line.split(":")
        if parts[0] == "fpr":
            return parts[9]
    return None


def ensure_key(gnupg_home: Path, public_key: Path, fingerprint_file: Path) -> str:
    # First prepare enough of GnuPG to inspect an existing key without requiring
    # pinentry. Only request the interactive setup if a new key must be created.
    """Return the evidence key fingerprint, creating the key when required."""
    env = prepare_gnupg(gnupg_home, interactive=False)
    fpr = fingerprint(gnupg_home, env=env)
    if not fpr:
        if not sys.stdin.isatty():
            raise ToolkitError(
                "No evidence signing key exists and interactive key generation is unavailable"
            )
        env = prepare_gnupg(gnupg_home, interactive=True)
        uid = "YouTube Forensic Evidence Key <evidence@localhost>"
        result = run(
            [
                "gpg",
                "--homedir",
                str(gnupg_home),
                "--yes",
                "--quick-generate-key",
                uid,
                "rsa4096",
                "sign",
                "0",
            ],
            env=env,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()
            message = detail[-1] if detail else "unknown GnuPG error"
            raise ToolkitError(f"Evidence-key generation failed: {message}")
        fpr = fingerprint(gnupg_home, env=env)
    if not fpr:
        raise ToolkitError("Evidence key fingerprint could not be determined")
    exported = run(
        ["gpg", "--homedir", str(gnupg_home), "--batch", "--armor", "--export", fpr],
        env=env,
    ).stdout
    public_key.parent.mkdir(parents=True, exist_ok=True)
    public_key.write_text(exported, encoding="utf-8")
    fingerprint_file.write_text(fpr + "\n", encoding="ascii")
    fingerprint_file.chmod(0o600)
    return fpr


def sign(gnupg_home: Path, target: Path, signature: Path, fpr: str) -> None:
    """Create a detached signature for an exported object with the project key."""
    env = prepare_gnupg(gnupg_home, interactive=True)
    result = run(
        [
            "gpg",
            "--homedir",
            str(gnupg_home),
            "--local-user",
            fpr,
            "--armor",
            "--detach-sign",
            "--output",
            str(signature),
            str(target),
        ],
        env=env,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        message = detail[-1] if detail else "unknown GnuPG error"
        raise ToolkitError(f"Signing failed: {message}")


def _write_export_checksums(directory: Path, names: list[str]) -> Path:
    """Write SHA-256 checksums for exported key-backup files."""
    lines: list[str] = []
    for name in sorted(names):
        path = directory / name
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}")
    output = directory / "SHA256SUMS.txt"
    output.write_text("\n".join(lines) + "\n", encoding="ascii")
    output.chmod(0o600)
    return output


def _export_failure(result, purpose: str) -> ToolkitError:
    """Convert a failed export command into a toolkit error."""
    detail = (result.stderr or result.stdout).strip().splitlines()
    message = detail[-1] if detail else "unknown GnuPG error"
    return ToolkitError(f"{purpose} failed: {message}")


def export_keypair(
    gnupg_home: Path,
    output_dir: Path,
    *,
    force: bool = False,
) -> dict[str, Path | str]:
    """Export and verify the dedicated evidence signing keypair.

    The output intentionally contains an unencrypted ASCII-armoured secret-key
    export. It is suitable only for deliberate, short-lived transfer into
    protected storage.
    """
    env = prepare_gnupg(gnupg_home, interactive=False)
    fpr = fingerprint(gnupg_home, env=env)
    if not fpr:
        raise ToolkitError("No evidence secret key exists in the dedicated keyring")

    if output_dir.is_symlink():
        raise ToolkitError(
            f"Key export destination must not be a symbolic link: {output_dir}"
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir.chmod(0o700)

    names = [
        "evidence-public-key.asc",
        "evidence-secret-key.asc",
        "evidence-ownertrust.txt",
        "evidence-key-fingerprint.txt",
        "KEY_BACKUP_README.txt",
        "MANIFEST.json",
        "SHA256SUMS.txt",
    ]
    existing = [output_dir / name for name in names if (output_dir / name).exists()]
    if existing and not force:
        listed = ", ".join(path.name for path in existing)
        raise ToolkitError(
            f"Key export files already exist in {output_dir}: {listed}. "
            "Use --force only after confirming they may be replaced."
        )

    # Secret-key export can require pinentry when the key is protected.
    env = prepare_gnupg(gnupg_home, interactive=True)
    public = run(
        ["gpg", "--homedir", str(gnupg_home), "--batch", "--armor", "--export", fpr],
        env=env,
        check=False,
    )
    if public.returncode != 0 or "BEGIN PGP PUBLIC KEY BLOCK" not in public.stdout:
        raise _export_failure(public, "Public-key export")

    secret = run(
        ["gpg", "--homedir", str(gnupg_home), "--armor", "--export-secret-keys", fpr],
        env=env,
        check=False,
    )
    if secret.returncode != 0 or "BEGIN PGP PRIVATE KEY BLOCK" not in secret.stdout:
        raise _export_failure(secret, "Secret-key export")

    trust = run(
        ["gpg", "--homedir", str(gnupg_home), "--export-ownertrust"],
        env=env,
        check=False,
    )
    if trust.returncode != 0:
        raise _export_failure(trust, "Ownertrust export")

    public_path = output_dir / "evidence-public-key.asc"
    secret_path = output_dir / "evidence-secret-key.asc"
    trust_path = output_dir / "evidence-ownertrust.txt"
    fingerprint_path = output_dir / "evidence-key-fingerprint.txt"
    readme_path = output_dir / "KEY_BACKUP_README.txt"
    manifest_path = output_dir / "MANIFEST.json"

    public_path.write_text(public.stdout, encoding="utf-8")
    secret_path.write_text(secret.stdout, encoding="utf-8")
    trust_path.write_text(trust.stdout, encoding="utf-8")
    fingerprint_path.write_text(fpr + "\n", encoding="ascii")

    created = (
        datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
    readme_path.write_text(
        "FACT - EVIDENCE KEY BACKUP\n"
        "================================================\n\n"
        "SECURITY WARNING\n"
        "----------------\n"
        "evidence-secret-key.asc contains private signing-key material in an\n"
        "unencrypted ASCII-armoured export. Retaining it in this format is not\n"
        "secure. Create this export only when required, move it promptly into\n"
        "encrypted and access-controlled offline storage, and securely remove\n"
        "the plaintext export from this directory afterwards.\n\n"
        f"Fingerprint: {fpr}\n"
        f"Exported:    {created}\n",
        encoding="utf-8",
    )
    manifest_path.write_text(
        json.dumps(
            {
                "schema": "fact-key-export/v1",
                "created_utc": created,
                "fingerprint": fpr,
                "contains_secret_key": True,
                "warning": "Plaintext ASCII-armoured secret-key export; protect and remove after use.",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    for path in (secret_path, trust_path, fingerprint_path, readme_path, manifest_path):
        path.chmod(0o600)
    public_path.chmod(0o644)

    # Verify imports and the secret-key fingerprint in a fresh isolated keyring.
    with tempfile.TemporaryDirectory(prefix="fact-keycheck-") as temp_name:
        verify_home = Path(temp_name) / "keyring"
        verify_env = prepare_gnupg(verify_home, interactive=False)
        imported_public = run(
            [
                "gpg",
                "--homedir",
                str(verify_home),
                "--batch",
                "--import",
                str(public_path),
            ],
            env=verify_env,
            check=False,
        )
        if imported_public.returncode != 0:
            raise _export_failure(imported_public, "Exported public-key verification")
        imported_secret = run(
            [
                "gpg",
                "--homedir",
                str(verify_home),
                "--batch",
                "--import",
                str(secret_path),
            ],
            env=verify_env,
            check=False,
        )
        if imported_secret.returncode != 0:
            raise _export_failure(imported_secret, "Exported secret-key verification")
        restored_fpr = fingerprint(verify_home, env=verify_env)
        if restored_fpr != fpr:
            raise ToolkitError(
                f"Export verification fingerprint mismatch: expected {fpr}, got {restored_fpr or 'none'}"
            )

    checksums_path = _write_export_checksums(
        output_dir,
        [
            path.name
            for path in (
                public_path,
                secret_path,
                trust_path,
                fingerprint_path,
                readme_path,
                manifest_path,
            )
        ],
    )
    return {
        "fingerprint": fpr,
        "output_dir": output_dir,
        "public_key": public_path,
        "secret_key": secret_path,
        "ownertrust": trust_path,
        "checksums": checksums_path,
    }
