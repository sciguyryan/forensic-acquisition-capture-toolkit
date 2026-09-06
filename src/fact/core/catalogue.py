"""Maintain FACT project state in a tamper-evident SQLite catalogue."""

from __future__ import annotations

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
from .hashing import (
    digest_bytes,
    digest_file,
    genesis_hash,
    project_integrity,
    require_hash,
)

SCHEMA_VERSION = 10
AUDIT_EVENT_SCHEMA = "fact-audit-event/v3"
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


def _integrity_algorithm(connection: sqlite3.Connection, key: str) -> str:
    row = connection.execute(
        "SELECT value FROM metadata WHERE key = ?", (key,)
    ).fetchone()
    if row is None:
        raise ToolkitError(f"Catalogue is missing integrity policy: {key}")
    return require_hash(str(row["value"]))


def _chain_hash_algorithm(connection: sqlite3.Connection) -> str:
    return _integrity_algorithm(connection, "chain_hash")


def _content_hash_algorithm(connection: sqlite3.Connection) -> str:
    return _integrity_algorithm(connection, "content_hash")


def _event_hash(connection: sqlite3.Connection, event: dict[str, object]) -> str:
    return digest_bytes(_chain_hash_algorithm(connection), _canonical(event))


def _state_digest(connection: sqlite3.Connection) -> str:
    """Digest current project state using stable table and row ordering.

    The digest deliberately covers authority state as well as identifiers. This
    makes signed checkpoints sensitive to ex post facto edits to operator
    identity, membership, ownership, transfer or approval records.
    """
    tables = {
        "metadata": ("SELECT key, value FROM metadata ORDER BY key"),
        "identifiers": (
            "SELECT namespace, sequence, identifier, state, issued_at, retired_at "
            "FROM identifiers ORDER BY namespace, sequence"
        ),
        "operators": (
            "SELECT operator_id, operator_uuid, name, public_contact, organisation, role_label, state, "
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
            "submitted_sequence, decided_by, decision_sequence, decision_reason "
            "FROM record_authority ORDER BY submitted_sequence, object_type, object_id"
        ),
        "notes": (
            "SELECT note_id, visibility, author_id, case_id, subject_file_id, created_sequence, "
            "latest_revision, package_disclosure FROM notes ORDER BY note_id"
        ),
        "note_revisions": (
            "SELECT note_id, revision, file_id, revision_type, created_sequence, revised_by, reason "
            "FROM note_revisions ORDER BY note_id, revision"
        ),
        "files": (
            "SELECT file_id, case_id, acquisition_id, actor_id, logical_path, classification, "
            "media_type, description, content_digest, size_bytes, storage_path, committed_sequence, "
            "presentation_state FROM files ORDER BY committed_sequence, file_id"
        ),
        "artefacts": (
            "SELECT artefact_id, case_id, acquisition_id, role, description, created_sequence, "
            "presentation_state FROM artefacts ORDER BY created_sequence, artefact_id"
        ),
        "artefact_files": (
            "SELECT artefact_id, file_id, member_role, created_sequence FROM artefact_files "
            "ORDER BY created_sequence, artefact_id, file_id"
        ),
        "export_policy": (
            "SELECT policy_id, ordinary_export, ciphertext_export, confidential_plaintext_export, "
            "broad_scope_export, updated_sequence FROM export_policy ORDER BY policy_id"
        ),
        "confidential_authority": (
            "SELECT object_type, object_id, creator_id, authority_id, effective_sequence "
            "FROM confidential_authority ORDER BY object_type, object_id"
        ),
        "confidential_authority_transfers": (
            "SELECT transfer_id, from_operator_id, to_operator_id, scope_json, state, reason, "
            "proposed_sequence, resolved_sequence FROM confidential_authority_transfers "
            "ORDER BY proposed_sequence, transfer_id"
        ),
        "confidential_access_grants": (
            "SELECT operator_id, object_type, object_id, authority_basis, granted_sequence, "
            "revoked_sequence, grant_reason, revoke_reason FROM confidential_access_grants "
            "ORDER BY granted_sequence, operator_id, object_type, object_id, authority_basis"
        ),
        "exports": (
            "SELECT export_id, actor_id, scope_type, scope_id, view_mode, representation, "
            "output_format, output_digest, manifest_digest, state, policy_sequence, "
            "created_sequence, completed_sequence FROM exports ORDER BY created_sequence, export_id"
        ),
        "export_items": (
            "SELECT export_id, file_id, output_path, source_digest, output_digest, mode "
            "FROM export_items ORDER BY export_id, output_path, file_id"
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
    return digest_bytes(_chain_hash_algorithm(connection), _canonical(serialised))


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


def initialise_catalogue(
    project_root: Path,
    project_id: str,
    *,
    chain_hash: str,
    content_hash: str,
) -> Path:
    chain_hash = require_hash(chain_hash)
    content_hash = require_hash(content_hash)
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
                actor_kind TEXT NOT NULL CHECK(actor_kind IN ('system', 'operator')),
                actor_id TEXT,
                actor_uuid TEXT,
                credential_fingerprint TEXT,
                authority_basis TEXT,
                details_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE,
                CHECK(
                    (actor_kind = 'system' AND actor_id IS NULL AND actor_uuid IS NULL) OR
                    (actor_kind = 'operator' AND actor_id IS NOT NULL AND actor_uuid IS NOT NULL)
                )
            );
            CREATE TABLE operators (
                operator_id TEXT PRIMARY KEY,
                operator_uuid TEXT NOT NULL UNIQUE,
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
                PRIMARY KEY(object_type, object_id),
                FOREIGN KEY(submitted_by) REFERENCES operators(operator_id),
                FOREIGN KEY(decided_by) REFERENCES operators(operator_id)
            );
            CREATE TABLE files (
                file_id TEXT PRIMARY KEY,
                case_id TEXT,
                acquisition_id TEXT,
                actor_id TEXT NOT NULL,
                logical_path TEXT NOT NULL,
                classification TEXT NOT NULL,
                media_type TEXT,
                description TEXT,
                content_digest TEXT NOT NULL,
                size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
                storage_path TEXT NOT NULL UNIQUE,
                committed_sequence INTEGER NOT NULL UNIQUE,
                presentation_state TEXT NOT NULL DEFAULT 'presented'
                    CHECK(presentation_state IN ('presented', 'retracted', 'superseded')),
                FOREIGN KEY(actor_id) REFERENCES operators(operator_id)
            );
            CREATE TABLE file_relationships (
                parent_file_id TEXT NOT NULL,
                child_file_id TEXT NOT NULL,
                relationship TEXT NOT NULL,
                created_sequence INTEGER NOT NULL,
                PRIMARY KEY(parent_file_id, child_file_id, relationship),
                FOREIGN KEY(parent_file_id) REFERENCES files(file_id),
                FOREIGN KEY(child_file_id) REFERENCES files(file_id)
            );
            CREATE TABLE notes (
                note_id TEXT PRIMARY KEY,
                visibility TEXT NOT NULL CHECK(visibility IN ('project', 'confidential')),
                author_id TEXT NOT NULL,
                case_id TEXT,
                subject_file_id TEXT,
                created_sequence INTEGER NOT NULL,
                latest_revision INTEGER NOT NULL CHECK(latest_revision > 0),
                package_disclosure TEXT NOT NULL DEFAULT 'withheld'
                    CHECK(package_disclosure IN ('withheld', 'include')),
                FOREIGN KEY(author_id) REFERENCES operators(operator_id),
                FOREIGN KEY(subject_file_id) REFERENCES files(file_id)
            );
            CREATE TABLE note_revisions (
                note_id TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision > 0),
                file_id TEXT NOT NULL UNIQUE,
                revision_type TEXT NOT NULL CHECK(revision_type IN ('content', 'cryptographic')),
                created_sequence INTEGER NOT NULL,
                revised_by TEXT NOT NULL,
                reason TEXT,
                PRIMARY KEY(note_id, revision),
                FOREIGN KEY(note_id) REFERENCES notes(note_id),
                FOREIGN KEY(file_id) REFERENCES files(file_id),
                FOREIGN KEY(revised_by) REFERENCES operators(operator_id)
            );
            CREATE TABLE artefacts (
                artefact_id TEXT PRIMARY KEY,
                case_id TEXT,
                acquisition_id TEXT,
                role TEXT NOT NULL,
                description TEXT,
                created_sequence INTEGER NOT NULL UNIQUE,
                presentation_state TEXT NOT NULL DEFAULT 'presented'
                    CHECK(presentation_state IN ('presented', 'retracted', 'superseded'))
            );
            CREATE TABLE artefact_files (
                artefact_id TEXT NOT NULL,
                file_id TEXT NOT NULL,
                member_role TEXT NOT NULL DEFAULT 'member',
                created_sequence INTEGER NOT NULL,
                PRIMARY KEY(artefact_id, file_id),
                FOREIGN KEY(artefact_id) REFERENCES artefacts(artefact_id),
                FOREIGN KEY(file_id) REFERENCES files(file_id)
            );
            CREATE TABLE export_policy (
                policy_id TEXT PRIMARY KEY CHECK(policy_id = 'project'),
                ordinary_export TEXT NOT NULL CHECK(ordinary_export IN ('owner', 'members')),
                ciphertext_export TEXT NOT NULL CHECK(ciphertext_export IN ('owner', 'members')),
                confidential_plaintext_export TEXT NOT NULL
                    CHECK(confidential_plaintext_export IN ('owner', 'authority')),
                broad_scope_export TEXT NOT NULL CHECK(broad_scope_export IN ('owner', 'members')),
                updated_sequence INTEGER NOT NULL
            );
            CREATE TABLE confidential_authority (
                object_type TEXT NOT NULL CHECK(object_type IN ('file', 'note', 'artefact')),
                object_id TEXT NOT NULL,
                creator_id TEXT NOT NULL,
                authority_id TEXT NOT NULL,
                effective_sequence INTEGER NOT NULL,
                PRIMARY KEY(object_type, object_id),
                FOREIGN KEY(creator_id) REFERENCES operators(operator_id),
                FOREIGN KEY(authority_id) REFERENCES operators(operator_id)
            );
            CREATE TABLE confidential_access_grants (
                operator_id TEXT NOT NULL,
                object_type TEXT NOT NULL CHECK(object_type IN ('file', 'note', 'artefact')),
                object_id TEXT NOT NULL,
                authority_basis TEXT NOT NULL CHECK(authority_basis IN (
                    'object-owner', 'explicit-grant', 'project-owner', 'case-role',
                    'recovery-authority', 'system-policy'
                )),
                granted_sequence INTEGER NOT NULL,
                revoked_sequence INTEGER,
                grant_reason TEXT NOT NULL,
                revoke_reason TEXT,
                PRIMARY KEY(operator_id, object_type, object_id, authority_basis, granted_sequence),
                FOREIGN KEY(operator_id) REFERENCES operators(operator_id),
                CHECK(revoked_sequence IS NULL OR revoked_sequence > granted_sequence)
            );
            CREATE TABLE confidential_authority_transfers (
                transfer_id TEXT PRIMARY KEY,
                from_operator_id TEXT NOT NULL,
                to_operator_id TEXT NOT NULL,
                scope_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('pending', 'accepted', 'rejected', 'cancelled')),
                reason TEXT NOT NULL,
                proposed_sequence INTEGER NOT NULL,
                resolved_sequence INTEGER,
                FOREIGN KEY(from_operator_id) REFERENCES operators(operator_id),
                FOREIGN KEY(to_operator_id) REFERENCES operators(operator_id)
            );
            CREATE TABLE exports (
                export_id TEXT PRIMARY KEY,
                actor_id TEXT NOT NULL,
                scope_type TEXT NOT NULL CHECK(scope_type IN ('file', 'artefact', 'acquisition', 'case', 'project', 'selection')),
                scope_id TEXT,
                view_mode TEXT NOT NULL CHECK(view_mode IN ('full', 'presented')),
                representation TEXT NOT NULL,
                output_format TEXT NOT NULL,
                output_digest TEXT,
                manifest_digest TEXT,
                state TEXT NOT NULL CHECK(state IN ('preparing', 'completed', 'failed', 'cancelled')),
                policy_sequence INTEGER NOT NULL,
                created_sequence INTEGER NOT NULL,
                completed_sequence INTEGER,
                FOREIGN KEY(actor_id) REFERENCES operators(operator_id)
            );
            CREATE TABLE export_items (
                export_id TEXT NOT NULL,
                file_id TEXT NOT NULL,
                output_path TEXT NOT NULL,
                source_digest TEXT NOT NULL,
                output_digest TEXT NOT NULL,
                mode TEXT NOT NULL CHECK(mode IN ('native', 'derived')),
                PRIMARY KEY(export_id, output_path),
                FOREIGN KEY(export_id) REFERENCES exports(export_id),
                FOREIGN KEY(file_id) REFERENCES files(file_id)
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
            "INSERT INTO metadata VALUES ('chain_hash', ?)", (chain_hash,)
        )
        connection.execute(
            "INSERT INTO metadata VALUES ('content_hash', ?)", (content_hash,)
        )
        connection.execute(
            "INSERT INTO metadata VALUES ('authority_schema_version', '1')"
        )
        connection.execute(
            "INSERT INTO metadata VALUES ('authority_state', 'uninitialised')"
        )
        connection.execute("INSERT INTO counters VALUES ('case', 1)")
        connection.execute("INSERT INTO counters VALUES ('acquisition', 1)")
        connection.execute("INSERT INTO counters VALUES ('note', 1)")
        connection.execute("INSERT INTO counters VALUES ('file', 1)")
        connection.execute("INSERT INTO counters VALUES ('artefact', 1)")
        connection.execute("INSERT INTO counters VALUES ('export', 1)")
        connection.execute("INSERT INTO counters VALUES ('authority_transfer', 1)")
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
    return (
        (1, genesis_hash(_chain_hash_algorithm(connection)))
        if row is None
        else (int(row["event_sequence"]) + 1, str(row["event_hash"]))
    )


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
    actor_id: str | None = None,
    actor_uuid: str | None = None,
    credential_fingerprint: str | None = None,
    authority_basis: str | None = None,
) -> str:
    """Append one canonical audit event to the rolling provenance chain.

    Operator-attributed events bind the immutable project operator ID, globally
    unique operator UUID, active credential fingerprint and authority basis into
    the hash envelope. System events use an explicit system actor rather than an
    empty or ambiguous attribution.
    """
    sequence, previous = _current_event_context(connection)
    if expected_sequence is not None and sequence != expected_sequence:
        raise ToolkitError("Catalogue changed while a signed transaction was prepared")
    if expected_previous is not None and previous != expected_previous:
        raise ToolkitError(
            "Catalogue chain head changed while a signed transaction was prepared"
        )
    if actor_id is not None and (actor_uuid is None or credential_fingerprint is None):
        row = connection.execute(
            "SELECT p.operator_uuid, k.signing_fingerprint "
            "FROM operators p LEFT JOIN operator_keys k "
            "ON k.operator_id = p.operator_id AND k.state = 'active' "
            "WHERE p.operator_id = ?",
            (actor_id,),
        ).fetchone()
        if row is None:
            raise ToolkitError(f"Audit actor is not registered: {actor_id}")
        actor_uuid = actor_uuid or str(row["operator_uuid"])
        if credential_fingerprint is None and row["signing_fingerprint"] is not None:
            credential_fingerprint = str(row["signing_fingerprint"])
    actor_kind = "operator" if actor_id is not None else "system"
    if actor_kind == "system":
        actor_uuid = None
        credential_fingerprint = None
        authority_basis = authority_basis or "fact-system"
    occurred_at = occurred_at or _utc_now()
    details_json = _canonical(details).decode("utf-8")
    actor = {
        "kind": actor_kind,
        "operator_id": actor_id,
        "operator_uuid": actor_uuid,
        "credential_fingerprint": credential_fingerprint,
        "authority_basis": authority_basis,
    }
    material = {
        "schema": AUDIT_EVENT_SCHEMA,
        "hash_algorithm": _chain_hash_algorithm(connection),
        "event_sequence": sequence,
        "occurred_at": occurred_at,
        "event_type": event_type,
        "object_type": object_type,
        "object_id": object_id,
        "actor": actor,
        "details": details,
        "previous_hash": previous,
    }
    digest = _event_hash(connection, material)
    connection.execute(
        "INSERT INTO audit_events(event_sequence, occurred_at, event_type, object_type, "
        "object_id, actor_kind, actor_id, actor_uuid, credential_fingerprint, "
        "authority_basis, details_json, previous_hash, event_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            sequence,
            occurred_at,
            event_type,
            object_type,
            object_id,
            actor_kind,
            actor_id,
            actor_uuid,
            credential_fingerprint,
            authority_basis,
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

    Current-generation projects create every supported namespace at genesis.
    Missing counters therefore indicate an incompatible or damaged catalogue,
    not a migration opportunity. FACT fails closed rather than rewriting it.
    """
    known_prefixes = {
        "case": "CASE",
        "acquisition": "ACQ",
        "note": "NOTE",
        "file": "FILE",
        "artefact": "ART",
        "export": "EXPORT",
        "authority_transfer": "TRANSFER",
    }
    if namespace not in known_prefixes or known_prefixes[namespace] != prefix:
        raise ToolkitError(f"Unknown identifier namespace: {namespace}")
    with _write_transaction(project_root) as connection:
        row = connection.execute(
            "SELECT next_sequence FROM counters WHERE namespace = ?", (namespace,)
        ).fetchone()
        if row is None:
            raise ToolkitError(
                f"FACT catalogue is missing the required {namespace!r} identifier counter"
            )
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
    authority_state = (
        str(authority_state_row[0]) if authority_state_row else "uninitialised"
    )
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
        if transaction.get("schema") != "fact-authority-transaction/v2":
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
        actor_uuid = transaction.get("actor_uuid")
        actor_key = transaction.get("actor_key_fingerprint")
        data = transaction.get("data")
        if (
            not isinstance(actor_id, str)
            or not isinstance(actor_uuid, str)
            or not isinstance(actor_key, str)
            or not isinstance(data, dict)
        ):
            raise ToolkitError(
                f"Authority transaction identity is malformed at event {row['event_sequence']}"
            )
        if (
            row["actor_kind"] != "operator"
            or row["actor_id"] != actor_id
            or row["actor_uuid"] != actor_uuid
            or row["credential_fingerprint"] != actor_key
        ):
            raise ToolkitError(
                f"Authority transaction actor provenance does not match catalogue event {row['event_sequence']}"
            )

        event_type = str(row["event_type"])
        sequence = int(row["event_sequence"])
        if event_type == "PROJECT_GENESIS":
            identity = data.get("identity")
            public_key = data.get("public_key")
            if not isinstance(identity, dict) or not isinstance(public_key, str):
                raise ToolkitError(
                    "Project genesis is missing retained operator identity"
                )
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

        if event_type == "PROJECT_GENESIS":
            identity = data["identity"]
            assert isinstance(identity, dict)
            operator_id = str(identity["operator_id"])
            retained_uuid = data.get("operator_uuid")
            if not isinstance(retained_uuid, str) or retained_uuid != actor_uuid:
                raise ToolkitError("Project genesis operator UUID is inconsistent")
            if actor_id != operator_id or actor_key != identity.get(
                "operator_signing_subkey_fingerprint"
            ):
                raise ToolkitError(
                    "Project genesis signer does not match initial owner"
                )
            operators[operator_id] = {
                "operator_id": operator_id,
                "operator_uuid": actor_uuid,
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
                raise ToolkitError(
                    "Contributor invitation is missing retained identity"
                )
            operator_id = str(identity["operator_id"])
            invited_uuid = data.get("operator_uuid")
            if not isinstance(invited_uuid, str):
                raise ToolkitError("Contributor invitation is missing operator UUID")
            signing = str(identity["operator_signing_subkey_fingerprint"])
            operators[operator_id] = {
                "operator_uuid": invited_uuid,
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
                    memberships[str(transfer["to_operator_id"])]["membership_role"] = (
                        "owner"
                    )
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
                    "SELECT operator_id, operator_uuid, name, public_contact, organisation, role_label, state, "
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
                    "submitted_sequence, decided_by, decision_sequence, decision_reason "
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
        raise ToolkitError(
            "Catalogue claims active authority without a signed authority root"
        )
    if authority_state != "active" and authority_events:
        raise ToolkitError(
            "Catalogue authority metadata does not match its audit history"
        )


def _verify_note_sanctity(
    connection: sqlite3.Connection, rows: list[sqlite3.Row]
) -> None:
    """Verify immutable note identities and their file-backed revision lineage."""
    tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    if not {"notes", "note_revisions", "files"}.issubset(tables):
        return
    created: dict[str, dict[str, object]] = {}
    revision_events: dict[tuple[str, int], dict[str, object]] = {}
    latest: dict[str, int] = {}
    disclosure: dict[str, str] = {}
    for row in rows:
        if row["event_type"] not in {
            "NOTE_CREATED",
            "NOTE_REVISED",
            "NOTE_REENCRYPTED",
            "NOTE_DISCLOSURE_CHANGED",
        }:
            continue
        details = json.loads(row["details_json"])
        transaction = details.get("authority_transaction")
        if not isinstance(transaction, dict) or not isinstance(
            transaction.get("data"), dict
        ):
            raise ToolkitError(
                f"Note authority event is malformed at event {row['event_sequence']}"
            )
        data = transaction["data"]
        note_id = str(row["object_id"])
        if row["event_type"] == "NOTE_DISCLOSURE_CHANGED":
            if note_id not in created:
                raise ToolkitError("Note disclosure change precedes note creation")
            disclosure[note_id] = str(data["package_disclosure"])
            continue
        revision = int(data["revision"])
        revision_events[(note_id, revision)] = data
        latest[note_id] = revision
        if row["event_type"] == "NOTE_CREATED":
            created[note_id] = data
            disclosure[note_id] = str(data["package_disclosure"])
        elif note_id not in created:
            raise ToolkitError("Note revision precedes note creation")

    live_notes = {
        str(row["note_id"]): dict(row)
        for row in connection.execute(
            "SELECT note_id, visibility, author_id, case_id, subject_file_id, "
            "created_sequence, latest_revision, package_disclosure FROM notes"
        ).fetchall()
    }
    if set(live_notes) != set(created):
        raise ToolkitError(
            "Committed note tree does not match its signed creation history"
        )

    live_revisions = {
        (str(row["note_id"]), int(row["revision"])): dict(row)
        for row in connection.execute(
            "SELECT note_id, revision, file_id, revision_type, created_sequence, "
            "revised_by, reason FROM note_revisions"
        ).fetchall()
    }
    if set(live_revisions) != set(revision_events):
        raise ToolkitError(
            "Committed note revision tree does not match its signed history"
        )

    for note_id, data in created.items():
        live = live_notes[note_id]
        for field in ("visibility", "author_id", "case_id", "subject_file_id"):
            if live[field] != data.get(field):
                raise ToolkitError(f"Committed note metadata was altered: {note_id}")
        if int(live["latest_revision"]) != latest[note_id]:
            raise ToolkitError(
                f"Committed note revision pointer was altered: {note_id}"
            )
        if str(live["package_disclosure"]) != disclosure[note_id]:
            raise ToolkitError(
                f"Committed note disclosure state was altered: {note_id}"
            )

    file_rows = {
        str(row["file_id"]): dict(row)
        for row in connection.execute(
            "SELECT file_id, classification, content_digest FROM files"
        ).fetchall()
    }
    for key, live in live_revisions.items():
        data = revision_events[key]
        file_id = str(live["file_id"])
        if file_id != str(data.get("file_id")):
            raise ToolkitError(
                f"Committed note revision file pointer was altered: {key[0]}"
            )
        if str(live["revision_type"]) != str(data.get("revision_type")):
            raise ToolkitError(f"Committed note revision type was altered: {key[0]}")
        file_row = file_rows.get(file_id)
        if file_row is None:
            raise ToolkitError(
                f"Committed note revision file is missing from catalogue: {file_id}"
            )
        if str(file_row["content_digest"]) != str(data.get("payload_digest")):
            raise ToolkitError(
                f"Note revision hash differs from its signed history: {file_id}"
            )
        visibility = str(live_notes[key[0]]["visibility"])
        expected_classification = (
            "confidential-note-revision"
            if visibility == "confidential"
            else "note-revision"
        )
        if str(file_row["classification"]) != expected_classification:
            raise ToolkitError(
                f"Note revision file classification was altered: {file_id}"
            )


def _verify_file_sanctity(
    connection: sqlite3.Connection,
    project_root: Path,
    rows: list[sqlite3.Row],
    *,
    permitted_missing_file_ids: set[str] | None = None,
    file_ids_to_hash: set[str] | None = None,
) -> int:
    """Verify every committed file still exists with exactly its committed bytes."""
    permitted_missing_file_ids = permitted_missing_file_ids or set()
    hashed_count = 0
    committed_events: dict[str, dict[str, object]] = {}
    presentation: dict[str, str] = {}
    relationships: set[tuple[str, str, str, int]] = set()
    for row in rows:
        event_type = str(row["event_type"])
        file_id = str(row["object_id"])
        details = json.loads(row["details_json"])
        if event_type == "FILE_COMMITTED":
            committed_events[file_id] = details
            presentation[file_id] = "presented"
        elif event_type == "FILE_PRESENTATION_CHANGED":
            if file_id not in presentation:
                raise ToolkitError(
                    f"File presentation change precedes check-in: {file_id}"
                )
            if details.get("from") != presentation[file_id]:
                raise ToolkitError(
                    f"File presentation history is inconsistent: {file_id}"
                )
            presentation[file_id] = str(details["to"])
        elif event_type == "FILE_RELATIONSHIP_ADDED":
            relationships.add(
                (
                    str(details["parent_file_id"]),
                    file_id,
                    str(details["relationship"]),
                    int(row["event_sequence"]),
                )
            )
    file_rows = connection.execute(
        "SELECT * FROM files ORDER BY committed_sequence, file_id"
    ).fetchall()
    if len(file_rows) != len(committed_events):
        raise ToolkitError("Committed file catalogue does not match its audit history")
    for row in file_rows:
        file_id = str(row["file_id"])
        details = committed_events.get(file_id)
        if details is None:
            raise ToolkitError(f"Committed file has no audit event: {file_id}")
        expected = {
            "case_id": row["case_id"],
            "acquisition_id": row["acquisition_id"],
            "actor_id": str(row["actor_id"]),
            "logical_path": str(row["logical_path"]),
            "classification": str(row["classification"]),
            "media_type": row["media_type"],
            "content_digest": str(row["content_digest"]),
            "size_bytes": int(row["size_bytes"]),
            "storage_path": str(row["storage_path"]),
        }
        if details != expected:
            raise ToolkitError(
                f"Committed file metadata differs from audit history: {file_id}"
            )
        if str(row["presentation_state"]) != presentation[file_id]:
            raise ToolkitError(
                f"File presentation state differs from audit history: {file_id}"
            )
        if file_ids_to_hash is not None and file_id not in file_ids_to_hash:
            continue
        path = project_root / str(row["storage_path"])
        if path.is_symlink() or not path.is_file():
            if file_id in permitted_missing_file_ids:
                continue
            raise ToolkitError(
                f"Committed file is missing from the authoritative tree: {file_id}"
            )
        observed_digest = digest_file(_content_hash_algorithm(connection), path)
        if observed_digest != str(row["content_digest"]) or path.stat().st_size != int(
            row["size_bytes"]
        ):
            raise ToolkitError(f"Committed file bytes have changed: {file_id}")
        hashed_count += 1
    live_relationships = {
        (
            str(row["parent_file_id"]),
            str(row["child_file_id"]),
            str(row["relationship"]),
            int(row["created_sequence"]),
        )
        for row in connection.execute(
            "SELECT parent_file_id, child_file_id, relationship, created_sequence "
            "FROM file_relationships"
        ).fetchall()
    }
    if live_relationships != relationships:
        raise ToolkitError("File relationships do not match their audit history")
    return hashed_count


def _verify_acquisition_membership(
    connection: sqlite3.Connection, rows: list[sqlite3.Row]
) -> None:
    """Verify each acquisition event binds exactly its committed file set.

    This catalogue invariant replaces the historical EVIDENCESET and file-list
    manifests. Acquisition membership is authenticated once in the rolling
    history and independently cross-checked against the live file catalogue.
    """

    recorded: set[str] = set()
    for row in rows:
        if str(row["event_type"]) != "ACQUISITION_RECORDED":
            continue
        acquisition_id = str(row["object_id"])
        if acquisition_id in recorded:
            raise ToolkitError(
                f"Acquisition was recorded more than once: {acquisition_id}"
            )
        recorded.add(acquisition_id)
        details = json.loads(row["details_json"])
        transaction = details.get("authority_transaction")
        if not isinstance(transaction, dict) or not isinstance(
            transaction.get("data"), dict
        ):
            raise ToolkitError(
                f"Acquisition authority event is malformed: {acquisition_id}"
            )
        expected = [str(item) for item in transaction["data"].get("file_ids", [])]
        if not expected or len(expected) != len(set(expected)):
            raise ToolkitError(
                f"Acquisition has invalid committed file membership: {acquisition_id}"
            )
        live = [
            str(item["file_id"])
            for item in connection.execute(
                "SELECT file_id FROM files WHERE acquisition_id = ? "
                "ORDER BY committed_sequence",
                (acquisition_id,),
            ).fetchall()
        ]
        if live != expected:
            raise ToolkitError(
                f"Acquisition file membership differs from signed history: {acquisition_id}"
            )


def _verify_integrity_policy(
    project_root: Path, connection: sqlite3.Connection, rows: list[sqlite3.Row]
) -> None:
    """Require project record, catalogue metadata and signed genesis to agree."""
    project_chain, project_content = project_integrity(project_root)
    metadata_chain = _chain_hash_algorithm(connection)
    metadata_content = _content_hash_algorithm(connection)
    if (project_chain, project_content) != (metadata_chain, metadata_content):
        raise ToolkitError(
            "PROJECT.toml integrity policy differs from authenticated catalogue state"
        )
    genesis_rows = [row for row in rows if row["event_type"] == "PROJECT_GENESIS"]
    if genesis_rows:
        details = json.loads(genesis_rows[0]["details_json"])
        transaction = details.get("authority_transaction")
        data = transaction.get("data") if isinstance(transaction, dict) else None
        integrity = data.get("integrity") if isinstance(data, dict) else None
        expected = {"chain_hash": metadata_chain, "content_hash": metadata_content}
        if integrity != expected:
            raise ToolkitError("Project genesis integrity policy is inconsistent")


def verify_chain(
    project_root: Path,
    *,
    permitted_missing_file_ids: set[str] | None = None,
    file_ids_to_hash: set[str] | None = None,
) -> dict[str, object]:
    """Verify the complete audit chain and current-state consistency.

    ``permitted_missing_file_ids`` is reserved for constructing explicitly
    filtered package views. Normal project verification must leave it unset.
    """
    connection = _connect(project_root)
    try:
        rows = connection.execute(
            "SELECT * FROM audit_events ORDER BY event_sequence"
        ).fetchall()
        _verify_integrity_policy(project_root, connection, rows)
        previous = genesis_hash(_chain_hash_algorithm(connection))
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
            actor = {
                "kind": str(row["actor_kind"]),
                "operator_id": row["actor_id"],
                "operator_uuid": row["actor_uuid"],
                "credential_fingerprint": row["credential_fingerprint"],
                "authority_basis": row["authority_basis"],
            }
            material = {
                "schema": AUDIT_EVENT_SCHEMA,
                "hash_algorithm": _chain_hash_algorithm(connection),
                "event_sequence": expected_sequence,
                "occurred_at": row["occurred_at"],
                "event_type": row["event_type"],
                "object_type": row["object_type"],
                "object_id": row["object_id"],
                "actor": actor,
                "details": details,
                "previous_hash": previous,
            }
            calculated = _event_hash(connection, material)
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
        _verify_note_sanctity(connection, rows)
        hashed_file_count = _verify_file_sanctity(
            connection,
            project_root,
            rows,
            permitted_missing_file_ids=permitted_missing_file_ids,
            file_ids_to_hash=file_ids_to_hash,
        )
        _verify_acquisition_membership(connection, rows)
        from .integrity_state import verify_extended_state

        verify_extended_state(connection, rows)

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
            "hashed_file_count": hashed_file_count,
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
