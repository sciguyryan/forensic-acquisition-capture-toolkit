"""Maintain FACT project state in a tamper-evident SQLite catalogue."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

from .commands import run
from .errors import ToolkitError
from .keys import fingerprint, prepare_gnupg, sign

SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64
CATALOGUE_DIR = ".fact"
CATALOGUE_NAME = "catalogue.sqlite"
CHECKPOINT_NAME = "catalogue-checkpoint.json"
CHECKPOINT_SIGNATURE_NAME = "catalogue-checkpoint.json.asc"
PROJECT_NAME = "PROJECT.toml"


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical(data: object) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _event_hash(event: dict[str, object]) -> str:
    return hashlib.sha256(_canonical(event)).hexdigest()


def _state_digest(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        "SELECT namespace, sequence, identifier, state, issued_at, retired_at "
        "FROM identifiers ORDER BY namespace, sequence"
    ).fetchall()
    serialised = [dict(row) for row in rows]
    return hashlib.sha256(_canonical(serialised)).hexdigest()


def catalogue_path(project_root: Path) -> Path:
    return project_root / CATALOGUE_DIR / CATALOGUE_NAME


def _connect(project_root: Path) -> sqlite3.Connection:
    path = catalogue_path(project_root)
    if not path.exists():
        raise ToolkitError(f"FACT catalogue does not exist: {path}")
    connection = sqlite3.connect(path, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = FULL")
    return connection


def initialise_catalogue(project_root: Path, project_id: str) -> Path:
    fact_dir = project_root / CATALOGUE_DIR
    fact_dir.mkdir(parents=True, exist_ok=False)
    fact_dir.chmod(0o700)
    path = fact_dir / CATALOGUE_NAME
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        connection.executescript(
            """
            PRAGMA journal_mode = DELETE;
            PRAGMA synchronous = FULL;
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE counters (
                namespace TEXT PRIMARY KEY,
                next_sequence INTEGER NOT NULL CHECK(next_sequence > 0)
            );
            CREATE TABLE identifiers (
                namespace TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                identifier TEXT PRIMARY KEY,
                state TEXT NOT NULL CHECK(state IN ('active', 'retired', 'failed')),
                issued_at TEXT NOT NULL,
                retired_at TEXT,
                UNIQUE(namespace, sequence)
            );
            CREATE TABLE audit_events (
                event_sequence INTEGER PRIMARY KEY,
                occurred_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                object_type TEXT NOT NULL,
                object_id TEXT NOT NULL,
                details_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE
            );
            """
        )
        connection.execute("INSERT INTO metadata VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
        connection.execute("INSERT INTO metadata VALUES ('project_id', ?)", (project_id,))
        connection.execute("INSERT INTO counters VALUES ('case', 1)")
        _append_event(connection, "PROJECT_CREATED", "project", project_id, {"schema_version": SCHEMA_VERSION})
    finally:
        connection.close()
    path.chmod(0o600)
    return path


def _append_event(
    connection: sqlite3.Connection,
    event_type: str,
    object_type: str,
    object_id: str,
    details: dict[str, object],
) -> str:
    row = connection.execute(
        "SELECT event_sequence, event_hash FROM audit_events ORDER BY event_sequence DESC LIMIT 1"
    ).fetchone()
    sequence = 1 if row is None else int(row["event_sequence"]) + 1
    previous = GENESIS_HASH if row is None else str(row["event_hash"])
    occurred_at = _utc_now()
    details_json = _canonical(details).decode("utf-8")
    material = {
        "event_sequence": sequence,
        "occurred_at": occurred_at,
        "event_type": event_type,
        "object_type": object_type,
        "object_id": object_id,
        "details": details,
        "previous_hash": previous,
    }
    digest = _event_hash(material)
    connection.execute(
        "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (sequence, occurred_at, event_type, object_type, object_id, details_json, previous, digest),
    )
    return digest


@contextmanager
def _write_transaction(project_root: Path) -> Iterator[sqlite3.Connection]:
    connection = _connect(project_root)
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def issue_identifier(project_root: Path, namespace: str, prefix: str) -> str:
    """Atomically issue and permanently consume the next identifier."""
    with _write_transaction(project_root) as connection:
        row = connection.execute(
            "SELECT next_sequence FROM counters WHERE namespace = ?", (namespace,)
        ).fetchone()
        if row is None:
            raise ToolkitError(f"Unknown identifier namespace: {namespace}")
        sequence = int(row["next_sequence"])
        identifier = f"{prefix}-{sequence:06d}"
        issued_at = _utc_now()
        connection.execute(
            "INSERT INTO identifiers(namespace, sequence, identifier, state, issued_at) "
            "VALUES (?, ?, ?, 'active', ?)",
            (namespace, sequence, identifier, issued_at),
        )
        connection.execute(
            "UPDATE counters SET next_sequence = ? WHERE namespace = ?",
            (sequence + 1, namespace),
        )
        _append_event(connection, "IDENTIFIER_ISSUED", namespace, identifier, {"sequence": sequence})
    return identifier


def retire_identifier(project_root: Path, identifier: str, reason: str | None = None) -> None:
    """Retire an identifier without making it available for reuse."""
    with _write_transaction(project_root) as connection:
        row = connection.execute(
            "SELECT namespace, state FROM identifiers WHERE identifier = ?", (identifier,)
        ).fetchone()
        if row is None:
            raise ToolkitError(f"Unknown FACT identifier: {identifier}")
        if row["state"] != "active":
            raise ToolkitError(f"Identifier is already {row['state']}: {identifier}")
        retired_at = _utc_now()
        connection.execute(
            "UPDATE identifiers SET state = 'retired', retired_at = ? WHERE identifier = ?",
            (retired_at, identifier),
        )
        _append_event(
            connection,
            "IDENTIFIER_RETIRED",
            str(row["namespace"]),
            identifier,
            {"reason": reason},
        )


def list_identifiers(project_root: Path, namespace: str = "case") -> list[dict[str, object]]:
    connection = _connect(project_root)
    try:
        rows = connection.execute(
            "SELECT sequence, identifier, state, issued_at, retired_at FROM identifiers "
            "WHERE namespace = ? ORDER BY sequence",
            (namespace,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def verify_chain(project_root: Path) -> dict[str, object]:
    """Verify the complete audit chain and current-state consistency."""
    connection = _connect(project_root)
    try:
        rows = connection.execute("SELECT * FROM audit_events ORDER BY event_sequence").fetchall()
        previous = GENESIS_HASH
        expected_sequence = 1
        for row in rows:
            if int(row["event_sequence"]) != expected_sequence:
                raise ToolkitError(f"Catalogue audit sequence is discontinuous at event {expected_sequence}")
            if row["previous_hash"] != previous:
                raise ToolkitError(f"Catalogue hash chain is broken at event {expected_sequence}")
            details = json.loads(row["details_json"])
            material = {
                "event_sequence": expected_sequence,
                "occurred_at": row["occurred_at"],
                "event_type": row["event_type"],
                "object_type": row["object_type"],
                "object_id": row["object_id"],
                "details": details,
                "previous_hash": previous,
            }
            calculated = _event_hash(material)
            if calculated != row["event_hash"]:
                raise ToolkitError(f"Catalogue event hash is invalid at event {expected_sequence}")
            previous = calculated
            expected_sequence += 1

        issued: dict[str, dict[str, object]] = {}
        for row in rows:
            details = json.loads(row["details_json"])
            if row["event_type"] == "IDENTIFIER_ISSUED":
                issued[str(row["object_id"])] = {
                    "namespace": str(row["object_type"]),
                    "sequence": int(details["sequence"]),
                    "state": "active",
                }
            elif row["event_type"] == "IDENTIFIER_RETIRED":
                identifier = str(row["object_id"])
                if identifier not in issued:
                    raise ToolkitError(f"Catalogue retirement precedes issue: {identifier}")
                issued[identifier]["state"] = "retired"

        live_rows = connection.execute(
            "SELECT namespace, sequence, identifier, state FROM identifiers ORDER BY namespace, sequence"
        ).fetchall()
        live = {
            str(row["identifier"]): {
                "namespace": str(row["namespace"]),
                "sequence": int(row["sequence"]),
                "state": str(row["state"]),
            }
            for row in live_rows
        }
        if live != issued:
            raise ToolkitError("Catalogue current identifier state does not match its audit history")

        for counter in connection.execute("SELECT namespace, next_sequence FROM counters"):
            sequences = [
                int(item["sequence"])
                for item in issued.values()
                if item["namespace"] == counter["namespace"]
            ]
            expected_next = max(sequences, default=0) + 1
            if int(counter["next_sequence"]) != expected_next:
                raise ToolkitError(
                    f"Catalogue counter does not match audit history: {counter['namespace']}"
                )

        project_id = connection.execute("SELECT value FROM metadata WHERE key = 'project_id'").fetchone()[0]
        return {
            "project_id": project_id,
            "event_count": len(rows),
            "chain_head": previous,
            "state_digest": _state_digest(connection),
        }
    finally:
        connection.close()


def write_checkpoint(project_root: Path, toolkit_root: Path) -> Path:
    """Write and sign a deterministic catalogue checkpoint."""
    verified = verify_chain(project_root)
    checkpoint = {
        "schema_version": SCHEMA_VERSION,
        "project_id": verified["project_id"],
        "event_count": verified["event_count"],
        "chain_head": verified["chain_head"],
        "state_digest": verified["state_digest"],
        "created_at": _utc_now(),
    }
    fact_dir = project_root / CATALOGUE_DIR
    path = fact_dir / CHECKPOINT_NAME
    temp = fact_dir / f".{CHECKPOINT_NAME}.tmp"
    temp.write_text(json.dumps(checkpoint, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp.chmod(0o600)
    os.replace(temp, path)

    gnupg_home = toolkit_root / "pgp" / "keyring"
    fpr = fingerprint(gnupg_home, env=prepare_gnupg(gnupg_home, interactive=False))
    if not fpr:
        raise ToolkitError("No evidence signing key exists; run 'fact keygen' first")
    signature = fact_dir / CHECKPOINT_SIGNATURE_NAME
    if signature.exists():
        signature.unlink()
    sign(gnupg_home, path, signature, fpr)
    signature.chmod(0o600)
    return path


def verify_checkpoint(project_root: Path, public_key: Path) -> dict[str, object]:
    """Verify a signed checkpoint and ensure it matches current catalogue state."""
    verified = verify_chain(project_root)
    fact_dir = project_root / CATALOGUE_DIR
    checkpoint_path = fact_dir / CHECKPOINT_NAME
    signature_path = fact_dir / CHECKPOINT_SIGNATURE_NAME
    if not checkpoint_path.exists() or not signature_path.exists():
        raise ToolkitError("Catalogue has no signed checkpoint")
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    for field in ("project_id", "event_count", "chain_head", "state_digest"):
        if checkpoint.get(field) != verified[field]:
            raise ToolkitError(f"Catalogue differs from signed checkpoint: {field}")

    with tempfile.TemporaryDirectory(prefix="fact-catalogue-verify-") as temporary:
        home = Path(temporary)
        home.chmod(0o700)
        env = {"GNUPGHOME": str(home)}
        imported = run(["gpg", "--batch", "--import", str(public_key)], env=env, check=False)
        if imported.returncode != 0:
            raise ToolkitError("Unable to import catalogue verification public key")
        result = run(
            ["gpg", "--batch", "--verify", str(signature_path), str(checkpoint_path)],
            env=env,
            check=False,
        )
        if result.returncode != 0:
            raise ToolkitError("Catalogue checkpoint signature is invalid")
    return verified
