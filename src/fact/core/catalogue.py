"""Maintain FACT project state in a tamper-evident SQLite catalogue."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from ..errors import ToolkitError
from ..identity import verify_operator_payload
from ..keys import fingerprint, prepare_gnupg, sign
from ..services.commands import run

SCHEMA_VERSION = 2
GENESIS_HASH = "0" * 64
CATALOGUE_DIR = ".fact"
CATALOGUE_NAME = "catalogue.sqlite"
CHECKPOINT_NAME = "catalogue-checkpoint.json"
CHECKPOINT_SIGNATURE_NAME = "catalogue-checkpoint.json.asc"
PROJECT_NAME = "PROJECT.toml"


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical(data: object) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _event_hash(event: dict[str, object]) -> str:
    return hashlib.sha256(_canonical(event)).hexdigest()


def _state_digest(connection: sqlite3.Connection) -> str:
    """Digest current project state using stable table and row ordering.

    The digest deliberately covers authority state as well as identifiers. This
    makes signed checkpoints sensitive to ex post facto edits to operator
    identity, membership, ownership, transfer or approval records.
    """
    tables = {
        "identifiers": (
            "SELECT namespace, sequence, identifier, state, issued_at, retired_at "
            "FROM identifiers ORDER BY namespace, sequence"
        ),
        "operators": (
            "SELECT operator_id, name, public_contact, organisation, role_label, state, "
            "created_sequence FROM operators ORDER BY operator_id"
        ),
        "operator_keys": (
            "SELECT operator_id, primary_fingerprint, signing_fingerprint, public_key, state, "
            "valid_from_sequence, valid_until_sequence FROM operator_keys "
            "ORDER BY operator_id, signing_fingerprint"
        ),
        "project_memberships": (
            "SELECT operator_id, membership_role, state, added_sequence, resolved_sequence "
            "FROM project_memberships ORDER BY operator_id"
        ),
        "ownership": (
            "SELECT scope_type, scope_id, owner_id, effective_from_sequence FROM ownership "
            "ORDER BY scope_type, scope_id"
        ),
        "ownership_transfers": (
            "SELECT transfer_id, scope_type, scope_id, from_operator_id, to_operator_id, state, "
            "reason, proposed_sequence, resolved_sequence FROM ownership_transfers "
            "ORDER BY proposed_sequence, transfer_id"
        ),
        "record_authority": (
            "SELECT object_type, object_id, scope_type, scope_id, submitted_by, status, "
            "submitted_sequence, decided_by, decision_sequence, decision_reason, archive_sha256 "
            "FROM record_authority ORDER BY submitted_sequence, object_type, object_id"
        ),
    }
    serialised: dict[str, list[dict[str, object]]] = {}
    available = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    for table, query in tables.items():
        serialised[table] = (
            [dict(row) for row in connection.execute(query).fetchall()]
            if table in available
            else []
        )
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
            CREATE TABLE operators (
                operator_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                public_contact TEXT,
                organisation TEXT,
                role_label TEXT,
                state TEXT NOT NULL CHECK(state IN ('active', 'retired')),
                created_sequence INTEGER NOT NULL
            );
            CREATE TABLE operator_keys (
                operator_id TEXT NOT NULL,
                primary_fingerprint TEXT NOT NULL,
                signing_fingerprint TEXT NOT NULL,
                public_key TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('active', 'retired', 'revoked')),
                valid_from_sequence INTEGER NOT NULL,
                valid_until_sequence INTEGER,
                PRIMARY KEY(operator_id, signing_fingerprint),
                FOREIGN KEY(operator_id) REFERENCES operators(operator_id)
            );
            CREATE TABLE project_memberships (
                operator_id TEXT PRIMARY KEY,
                membership_role TEXT NOT NULL CHECK(membership_role IN ('owner', 'contributor')),
                state TEXT NOT NULL CHECK(state IN ('pending', 'active', 'rejected', 'removed')),
                added_sequence INTEGER NOT NULL,
                resolved_sequence INTEGER,
                FOREIGN KEY(operator_id) REFERENCES operators(operator_id)
            );
            CREATE TABLE ownership (
                scope_type TEXT NOT NULL CHECK(scope_type IN ('project', 'case')),
                scope_id TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                effective_from_sequence INTEGER NOT NULL,
                PRIMARY KEY(scope_type, scope_id),
                FOREIGN KEY(owner_id) REFERENCES operators(operator_id)
            );
            CREATE TABLE ownership_transfers (
                transfer_id TEXT PRIMARY KEY,
                scope_type TEXT NOT NULL CHECK(scope_type IN ('project', 'case')),
                scope_id TEXT NOT NULL,
                from_operator_id TEXT NOT NULL,
                to_operator_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('pending', 'accepted', 'rejected', 'cancelled')),
                reason TEXT NOT NULL,
                proposed_sequence INTEGER NOT NULL,
                resolved_sequence INTEGER,
                FOREIGN KEY(from_operator_id) REFERENCES operators(operator_id),
                FOREIGN KEY(to_operator_id) REFERENCES operators(operator_id)
            );
            CREATE TABLE record_authority (
                object_type TEXT NOT NULL,
                object_id TEXT NOT NULL,
                scope_type TEXT NOT NULL CHECK(scope_type IN ('project', 'case')),
                scope_id TEXT NOT NULL,
                submitted_by TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
                submitted_sequence INTEGER NOT NULL,
                decided_by TEXT,
                decision_sequence INTEGER,
                decision_reason TEXT,
                archive_sha256 TEXT,
                PRIMARY KEY(object_type, object_id),
                FOREIGN KEY(submitted_by) REFERENCES operators(operator_id),
                FOREIGN KEY(decided_by) REFERENCES operators(operator_id)
            );
            """
        )
        connection.execute(
            "INSERT INTO metadata VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),)
        )
        connection.execute(
            "INSERT INTO metadata VALUES ('project_id', ?)", (project_id,)
        )
        connection.execute(
            "INSERT INTO metadata VALUES ('authority_schema_version', '1')"
        )
        connection.execute(
            "INSERT INTO metadata VALUES ('authority_state', 'uninitialised')"
        )
        connection.execute("INSERT INTO counters VALUES ('case', 1)")
        connection.execute("INSERT INTO counters VALUES ('acquisition', 1)")
        _append_event(
            connection,
            "PROJECT_CREATED",
            "project",
            project_id,
            {"schema_version": SCHEMA_VERSION},
        )
    finally:
        connection.close()
    path.chmod(0o600)
    return path


def _current_event_context(connection: sqlite3.Connection) -> tuple[int, str]:
    """Return the sequence and chain head that the next event must consume."""
    row = connection.execute(
        "SELECT event_sequence, event_hash FROM audit_events "
        "ORDER BY event_sequence DESC LIMIT 1"
    ).fetchone()
    return (1, GENESIS_HASH) if row is None else (int(row["event_sequence"]) + 1, str(row["event_hash"]))


def _append_event(
    connection: sqlite3.Connection,
    event_type: str,
    object_type: str,
    object_id: str,
    details: dict[str, object],
    *,
    occurred_at: str | None = None,
    expected_sequence: int | None = None,
    expected_previous: str | None = None,
) -> str:
    sequence, previous = _current_event_context(connection)
    if expected_sequence is not None and sequence != expected_sequence:
        raise ToolkitError("Catalogue changed while a signed transaction was prepared")
    if expected_previous is not None and previous != expected_previous:
        raise ToolkitError("Catalogue chain head changed while a signed transaction was prepared")
    occurred_at = occurred_at or _utc_now()
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
        (
            sequence,
            occurred_at,
            event_type,
            object_type,
            object_id,
            details_json,
            previous,
            digest,
        ),
    )
    return digest


@contextmanager
def _write_transaction(project_root: Path) -> Iterator[sqlite3.Connection]:
    package_lock = project_root / CATALOGUE_DIR / "package.lock"
    if package_lock.exists():
        raise ToolkitError(
            "FACT project is currently being packaged; catalogue mutation is blocked"
        )
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
    """Atomically issue and permanently consume the next identifier.

    The acquisition namespace was introduced after the original catalogue
    schema shipped. Existing projects therefore initialise that one namespace
    lazily and record the migration in the audit chain before issuing its first
    sequential acquisition identifier. Unknown namespaces still fail closed.
    """
    known_prefixes = {"case": "CASE", "acquisition": "ACQ"}
    if namespace not in known_prefixes or known_prefixes[namespace] != prefix:
        raise ToolkitError(f"Unknown identifier namespace: {namespace}")
    with _write_transaction(project_root) as connection:
        row = connection.execute(
            "SELECT next_sequence FROM counters WHERE namespace = ?", (namespace,)
        ).fetchone()
        if row is None and namespace == "acquisition":
            connection.execute("INSERT INTO counters VALUES (?, 1)", (namespace,))
            _append_event(
                connection,
                "IDENTIFIER_NAMESPACE_INITIALISED",
                "catalogue",
                namespace,
                {"next_sequence": 1},
            )
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
        _append_event(
            connection,
            "IDENTIFIER_ISSUED",
            namespace,
            identifier,
            {"sequence": sequence},
        )
    return identifier


def retire_identifier(
    project_root: Path, identifier: str, reason: str | None = None
) -> None:
    """Retire an identifier without making it available for reuse."""
    with _write_transaction(project_root) as connection:
        row = connection.execute(
            "SELECT namespace, state FROM identifiers WHERE identifier = ?",
            (identifier,),
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


def fail_identifier(
    project_root: Path, identifier: str, reason: str | None = None
) -> None:
    """Mark a consumed identifier as failed without making it reusable."""
    with _write_transaction(project_root) as connection:
        row = connection.execute(
            "SELECT namespace, state FROM identifiers WHERE identifier = ?",
            (identifier,),
        ).fetchone()
        if row is None:
            raise ToolkitError(f"Unknown FACT identifier: {identifier}")
        if row["state"] != "active":
            raise ToolkitError(f"Identifier is already {row['state']}: {identifier}")
        connection.execute(
            "UPDATE identifiers SET state = 'failed' WHERE identifier = ?",
            (identifier,),
        )
        _append_event(
            connection,
            "IDENTIFIER_FAILED",
            str(row["namespace"]),
            identifier,
            {"reason": reason},
        )


def list_identifiers(
    project_root: Path, namespace: str = "case"
) -> list[dict[str, object]]:
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


def _verify_authority_state(
    connection: sqlite3.Connection, rows: list[sqlite3.Row]
) -> None:
    """Reconstruct signed authority state and compare it with the live tables.

    SQLite is deliberately treated as writable storage rather than a magic
    tamper-proof container. Authority tables must therefore be reproducible from
    the append-only event history, and every authority transaction must verify
    against the public key retained for its historical actor.
    """
    table_names = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    required = {
        "operators",
        "operator_keys",
        "project_memberships",
        "ownership",
        "ownership_transfers",
        "record_authority",
    }
    authority_state_row = connection.execute(
        "SELECT value FROM metadata WHERE key = 'authority_state'"
    ).fetchone()
    authority_state = str(authority_state_row[0]) if authority_state_row else "uninitialised"
    if not required.issubset(table_names):
        if authority_state == "active":
            raise ToolkitError("Catalogue authority schema is incomplete")
        return

    operators: dict[str, dict[str, object]] = {}
    keys: dict[tuple[str, str], dict[str, object]] = {}
    memberships: dict[str, dict[str, object]] = {}
    ownership: dict[tuple[str, str], dict[str, object]] = {}
    transfers: dict[str, dict[str, object]] = {}
    records: dict[tuple[str, str], dict[str, object]] = {}
    authority_events = 0

    for row in rows:
        details = json.loads(row["details_json"])
        transaction = details.get("authority_transaction")
        signature = details.get("authority_signature")
        if transaction is None and signature is None:
            continue
        authority_events += 1
        if not isinstance(transaction, dict) or not isinstance(signature, str):
            raise ToolkitError(
                f"Authority transaction envelope is malformed at event {row['event_sequence']}"
            )
        if transaction.get("schema") != "fact-authority-transaction/v1":
            raise ToolkitError(
                f"Unknown authority transaction schema at event {row['event_sequence']}"
            )
        expected = {
            "event_sequence": int(row["event_sequence"]),
            "occurred_at": str(row["occurred_at"]),
            "event_type": str(row["event_type"]),
            "object_type": str(row["object_type"]),
            "object_id": str(row["object_id"]),
            "previous_hash": str(row["previous_hash"]),
        }
        for field, value in expected.items():
            if transaction.get(field) != value:
                raise ToolkitError(
                    f"Authority transaction does not match catalogue event {row['event_sequence']}: {field}"
                )
        actor_id = transaction.get("actor_id")
        actor_key = transaction.get("actor_key_fingerprint")
        data = transaction.get("data")
        if not isinstance(actor_id, str) or not isinstance(actor_key, str) or not isinstance(data, dict):
            raise ToolkitError(
                f"Authority transaction identity is malformed at event {row['event_sequence']}"
            )

        event_type = str(row["event_type"])
        sequence = int(row["event_sequence"])
        if event_type == "AUTHORITY_BOOTSTRAPPED":
            identity = data.get("identity")
            public_key = data.get("public_key")
            if not isinstance(identity, dict) or not isinstance(public_key, str):
                raise ToolkitError("Authority bootstrap is missing retained operator identity")
            verification_key = public_key
        else:
            key_state = keys.get((actor_id, actor_key))
            if key_state is None or key_state["state"] != "active":
                raise ToolkitError(
                    f"Authority event was signed by an unrecognised historical key at event {sequence}"
                )
            verification_key = str(key_state["public_key"])
        verify_operator_payload(
            verification_key, _canonical(transaction), signature, actor_key
        )

        if event_type == "AUTHORITY_BOOTSTRAPPED":
            identity = data["identity"]
            assert isinstance(identity, dict)
            operator_id = str(identity["operator_id"])
            if actor_id != operator_id or actor_key != identity.get(
                "operator_signing_subkey_fingerprint"
            ):
                raise ToolkitError("Authority bootstrap signer does not match initial owner")
            operators[operator_id] = {
                "operator_id": operator_id,
                "name": identity["name"],
                "public_contact": identity.get("public_contact"),
                "organisation": identity.get("organisation"),
                "role_label": identity.get("role"),
                "state": "active",
                "created_sequence": sequence,
            }
            signing = str(identity["operator_signing_subkey_fingerprint"])
            keys[(operator_id, signing)] = {
                "operator_id": operator_id,
                "primary_fingerprint": identity["operator_key_fingerprint"],
                "signing_fingerprint": signing,
                "public_key": data["public_key"],
                "state": "active",
                "valid_from_sequence": sequence,
                "valid_until_sequence": None,
            }
            memberships[operator_id] = {
                "operator_id": operator_id,
                "membership_role": "owner",
                "state": "active",
                "added_sequence": sequence,
                "resolved_sequence": sequence,
            }
            ownership[("project", str(row["object_id"]))] = {
                "scope_type": "project",
                "scope_id": str(row["object_id"]),
                "owner_id": operator_id,
                "effective_from_sequence": sequence,
            }
        elif event_type == "CONTRIBUTOR_INVITED":
            identity = data.get("identity")
            if not isinstance(identity, dict):
                raise ToolkitError("Contributor invitation is missing retained identity")
            operator_id = str(identity["operator_id"])
            signing = str(identity["operator_signing_subkey_fingerprint"])
            operators[operator_id] = {
                "operator_id": operator_id,
                "name": identity["name"],
                "public_contact": identity.get("public_contact"),
                "organisation": identity.get("organisation"),
                "role_label": identity.get("role"),
                "state": "active",
                "created_sequence": sequence,
            }
            keys[(operator_id, signing)] = {
                "operator_id": operator_id,
                "primary_fingerprint": identity["operator_key_fingerprint"],
                "signing_fingerprint": signing,
                "public_key": data["public_key"],
                "state": "active",
                "valid_from_sequence": sequence,
                "valid_until_sequence": None,
            }
            memberships[operator_id] = {
                "operator_id": operator_id,
                "membership_role": "contributor",
                "state": "pending",
                "added_sequence": sequence,
                "resolved_sequence": None,
            }
        elif event_type in {"CONTRIBUTOR_ACCEPTED", "CONTRIBUTOR_REJECTED"}:
            if actor_id not in memberships:
                raise ToolkitError("Contributor decision precedes its invitation")
            memberships[actor_id]["state"] = (
                "active" if event_type == "CONTRIBUTOR_ACCEPTED" else "rejected"
            )
            memberships[actor_id]["resolved_sequence"] = sequence
        elif event_type == "CONTRIBUTOR_REMOVED":
            operator_id = str(row["object_id"])
            if operator_id not in memberships:
                raise ToolkitError("Contributor removal precedes membership")
            memberships[operator_id]["state"] = "removed"
            memberships[operator_id]["resolved_sequence"] = sequence
        elif event_type == "CASE_OWNERSHIP_ASSIGNED":
            ownership[("case", str(row["object_id"]))] = {
                "scope_type": "case",
                "scope_id": str(row["object_id"]),
                "owner_id": str(data["owner_id"]),
                "effective_from_sequence": sequence,
            }
        elif event_type == "OWNERSHIP_TRANSFER_PROPOSED":
            transfer_id = str(data["transfer_id"])
            transfers[transfer_id] = {
                "transfer_id": transfer_id,
                "scope_type": str(row["object_type"]),
                "scope_id": str(row["object_id"]),
                "from_operator_id": str(data["from_operator_id"]),
                "to_operator_id": str(data["to_operator_id"]),
                "state": "pending",
                "reason": str(data["reason"]),
                "proposed_sequence": sequence,
                "resolved_sequence": None,
            }
        elif event_type in {
            "OWNERSHIP_TRANSFER_ACCEPTED",
            "OWNERSHIP_TRANSFER_REJECTED",
            "OWNERSHIP_TRANSFER_CANCELLED",
        }:
            transfer_id = str(data["transfer_id"])
            if transfer_id not in transfers:
                raise ToolkitError("Ownership transfer decision precedes proposal")
            state = {
                "OWNERSHIP_TRANSFER_ACCEPTED": "accepted",
                "OWNERSHIP_TRANSFER_REJECTED": "rejected",
                "OWNERSHIP_TRANSFER_CANCELLED": "cancelled",
            }[event_type]
            transfers[transfer_id]["state"] = state
            transfers[transfer_id]["resolved_sequence"] = sequence
            if state == "accepted":
                transfer = transfers[transfer_id]
                scope = (str(transfer["scope_type"]), str(transfer["scope_id"]))
                ownership[scope] = {
                    "scope_type": scope[0],
                    "scope_id": scope[1],
                    "owner_id": str(transfer["to_operator_id"]),
                    "effective_from_sequence": sequence,
                }
                if scope[0] == "project":
                    memberships[str(transfer["from_operator_id"])][
                        "membership_role"
                    ] = "contributor"
                    memberships[str(transfer["to_operator_id"])]["membership_role"] = "owner"
                    memberships[str(transfer["to_operator_id"])]["state"] = "active"
        elif event_type == "ACQUISITION_RECORDED":
            status = str(data["status"])
            records[("acquisition", str(row["object_id"]))] = {
                "object_type": "acquisition",
                "object_id": str(row["object_id"]),
                "scope_type": "case",
                "scope_id": str(data["case_id"]),
                "submitted_by": actor_id,
                "status": status,
                "submitted_sequence": sequence,
                "decided_by": actor_id if status == "approved" else None,
                "decision_sequence": sequence if status == "approved" else None,
                "decision_reason": None,
                "archive_sha256": data.get("archive_sha256"),
            }
        elif event_type in {"RECORD_APPROVED", "RECORD_REJECTED"}:
            key = (str(row["object_type"]), str(row["object_id"]))
            if key not in records:
                raise ToolkitError("Record decision precedes submission")
            records[key]["status"] = (
                "approved" if event_type == "RECORD_APPROVED" else "rejected"
            )
            records[key]["decided_by"] = actor_id
            records[key]["decision_sequence"] = sequence
            records[key]["decision_reason"] = data.get("reason")

    live_sets = {
        "operators": (
            operators,
            {
                str(row["operator_id"]): dict(row)
                for row in connection.execute(
                    "SELECT operator_id, name, public_contact, organisation, role_label, state, "
                    "created_sequence FROM operators ORDER BY operator_id"
                ).fetchall()
            },
        ),
        "operator keys": (
            keys,
            {
                (str(row["operator_id"]), str(row["signing_fingerprint"])): dict(row)
                for row in connection.execute(
                    "SELECT operator_id, primary_fingerprint, signing_fingerprint, public_key, state, "
                    "valid_from_sequence, valid_until_sequence FROM operator_keys"
                ).fetchall()
            },
        ),
        "project memberships": (
            memberships,
            {
                str(row["operator_id"]): dict(row)
                for row in connection.execute(
                    "SELECT operator_id, membership_role, state, added_sequence, resolved_sequence "
                    "FROM project_memberships"
                ).fetchall()
            },
        ),
        "ownership": (
            ownership,
            {
                (str(row["scope_type"]), str(row["scope_id"])): dict(row)
                for row in connection.execute(
                    "SELECT scope_type, scope_id, owner_id, effective_from_sequence FROM ownership"
                ).fetchall()
            },
        ),
        "ownership transfers": (
            transfers,
            {
                str(row["transfer_id"]): dict(row)
                for row in connection.execute(
                    "SELECT transfer_id, scope_type, scope_id, from_operator_id, to_operator_id, state, "
                    "reason, proposed_sequence, resolved_sequence FROM ownership_transfers"
                ).fetchall()
            },
        ),
        "record authority": (
            records,
            {
                (str(row["object_type"]), str(row["object_id"])): dict(row)
                for row in connection.execute(
                    "SELECT object_type, object_id, scope_type, scope_id, submitted_by, status, "
                    "submitted_sequence, decided_by, decision_sequence, decision_reason, archive_sha256 "
                    "FROM record_authority"
                ).fetchall()
            },
        ),
    }
    for label, (historical, live) in live_sets.items():
        if historical != live:
            raise ToolkitError(
                f"Catalogue current {label} state does not match its audit history"
            )

    if authority_state == "active" and authority_events == 0:
        raise ToolkitError("Catalogue claims active authority without a signed authority root")
    if authority_state != "active" and authority_events:
        raise ToolkitError("Catalogue authority metadata does not match its audit history")


def verify_chain(project_root: Path) -> dict[str, object]:
    """Verify the complete audit chain and current-state consistency."""
    connection = _connect(project_root)
    try:
        rows = connection.execute(
            "SELECT * FROM audit_events ORDER BY event_sequence"
        ).fetchall()
        previous = GENESIS_HASH
        expected_sequence = 1
        for row in rows:
            if int(row["event_sequence"]) != expected_sequence:
                raise ToolkitError(
                    f"Catalogue audit sequence is discontinuous at event {expected_sequence}"
                )
            if row["previous_hash"] != previous:
                raise ToolkitError(
                    f"Catalogue hash chain is broken at event {expected_sequence}"
                )
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
                raise ToolkitError(
                    f"Catalogue event hash is invalid at event {expected_sequence}"
                )
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
            elif row["event_type"] in {"IDENTIFIER_RETIRED", "IDENTIFIER_FAILED"}:
                identifier = str(row["object_id"])
                if identifier not in issued:
                    raise ToolkitError(
                        f"Catalogue state change precedes issue: {identifier}"
                    )
                issued[identifier]["state"] = (
                    "retired" if row["event_type"] == "IDENTIFIER_RETIRED" else "failed"
                )

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
            raise ToolkitError(
                "Catalogue current identifier state does not match its audit history"
            )

        _verify_authority_state(connection, rows)

        for counter in connection.execute(
            "SELECT namespace, next_sequence FROM counters"
        ):
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

        project_id = connection.execute(
            "SELECT value FROM metadata WHERE key = 'project_id'"
        ).fetchone()[0]
        return {
            "project_id": project_id,
            "event_count": len(rows),
            "chain_head": previous,
            "state_digest": _state_digest(connection),
            "last_event_at": str(rows[-1]["occurred_at"]) if rows else None,
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
    temp.write_text(
        json.dumps(checkpoint, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
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
        imported = run(
            ["gpg", "--batch", "--import", str(public_key)], env=env, check=False
        )
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
