"""Reconstruct extended catalogue state from append-only history.

This module keeps the main catalogue verifier readable while ensuring newer
logical objects remain derived from history rather than trusting mutable SQLite
rows. Signature validation for signed authority events is performed by the
catalogue authority verifier before these state projections are compared.
"""

from __future__ import annotations

import json
import sqlite3

from ..errors import ToolkitError


def _signed_data(row: sqlite3.Row) -> dict[str, object]:
    details = json.loads(row["details_json"])
    transaction = details.get("authority_transaction")
    if not isinstance(transaction, dict) or not isinstance(
        transaction.get("data"), dict
    ):
        raise ToolkitError(
            f"Signed extended-state event is malformed at event {row['event_sequence']}"
        )
    return transaction["data"]


def _verify_artefacts(connection: sqlite3.Connection, rows: list[sqlite3.Row]) -> None:
    expected: dict[str, dict[str, object]] = {}
    members: set[tuple[str, str, str, int]] = set()
    for row in rows:
        if str(row["event_type"]) != "ARTEFACT_CREATED":
            continue
        artefact_id = str(row["object_id"])
        if artefact_id in expected:
            raise ToolkitError(f"Artefact was created more than once: {artefact_id}")
        data = json.loads(row["details_json"])
        file_ids = data.get("file_ids")
        if not isinstance(file_ids, list) or not file_ids:
            raise ToolkitError(
                f"Artefact has no committed file membership: {artefact_id}"
            )
        sequence = int(row["event_sequence"])
        expected[artefact_id] = {
            "artefact_id": artefact_id,
            "case_id": data.get("case_id"),
            "acquisition_id": data.get("acquisition_id"),
            "role": data.get("role"),
            "description": data.get("description"),
            "created_sequence": sequence,
            "presentation_state": "presented",
        }
        for file_id in file_ids:
            members.add((artefact_id, str(file_id), "primary", sequence))

    live = {
        str(row["artefact_id"]): dict(row)
        for row in connection.execute(
            "SELECT artefact_id, case_id, acquisition_id, role, description, "
            "created_sequence, presentation_state FROM artefacts"
        ).fetchall()
    }
    if live != expected:
        raise ToolkitError("Artefact catalogue does not match its audit history")
    live_members = {
        (
            str(row["artefact_id"]),
            str(row["file_id"]),
            str(row["member_role"]),
            int(row["created_sequence"]),
        )
        for row in connection.execute(
            "SELECT artefact_id, file_id, member_role, created_sequence FROM artefact_files"
        ).fetchall()
    }
    if live_members != members:
        raise ToolkitError("Artefact file membership does not match its audit history")


def _verify_export_policy(
    connection: sqlite3.Connection, rows: list[sqlite3.Row]
) -> None:
    policy: dict[str, object] | None = None
    sequence: int | None = None
    for row in rows:
        event_type = str(row["event_type"])
        if event_type == "PROJECT_GENESIS":
            data = _signed_data(row)
            candidate = data.get("export_policy")
            if not isinstance(candidate, dict):
                raise ToolkitError("Project genesis is missing its export policy")
            policy = dict(candidate)
            sequence = int(row["event_sequence"])
        elif event_type == "EXPORT_POLICY_CHANGED":
            if policy is None:
                raise ToolkitError("Export policy change precedes project genesis")
            data = _signed_data(row)
            previous = data.get("previous")
            candidate = data.get("policy")
            if not isinstance(previous, dict) or not isinstance(candidate, dict):
                raise ToolkitError("Export policy event is malformed")
            if previous != policy:
                raise ToolkitError("Export policy history does not join cleanly")
            policy = dict(candidate)
            sequence = int(row["event_sequence"])
    live = connection.execute(
        "SELECT * FROM export_policy WHERE policy_id = 'project'"
    ).fetchone()
    if policy is None:
        if live is not None:
            raise ToolkitError(
                "Export policy exists without authenticated project genesis"
            )
        return
    if live is None:
        raise ToolkitError("Authenticated project export policy is missing")
    expected = {
        "policy_id": "project",
        "ordinary_export": policy["ordinary_export"],
        "ciphertext_export": policy["ciphertext_export"],
        "confidential_plaintext_export": policy["confidential_plaintext_export"],
        "broad_scope_export": policy["broad_scope_export"],
        "updated_sequence": sequence,
    }
    if dict(live) != expected:
        raise ToolkitError("Current export policy differs from authenticated history")


def _verify_confidential_authority(
    connection: sqlite3.Connection, rows: list[sqlite3.Row]
) -> None:
    authority: dict[tuple[str, str], dict[str, object]] = {}
    transfers: dict[str, dict[str, object]] = {}
    for row in rows:
        event_type = str(row["event_type"])
        sequence = int(row["event_sequence"])
        if event_type == "NOTE_CREATED":
            data = _signed_data(row)
            if data.get("visibility") == "confidential":
                note_id = str(row["object_id"])
                authority_id = data.get("confidential_authority_id")
                if not isinstance(authority_id, str):
                    raise ToolkitError(
                        f"Confidential note lacks authenticated authority: {note_id}"
                    )
                authority[("note", note_id)] = {
                    "object_type": "note",
                    "object_id": note_id,
                    "creator_id": str(data["author_id"]),
                    "authority_id": authority_id,
                    "effective_sequence": sequence,
                }
        elif event_type == "CONFIDENTIAL_AUTHORITY_TRANSFER_PROPOSED":
            data = _signed_data(row)
            transfer_id = str(row["object_id"])
            scope = data.get("scope")
            if not isinstance(scope, list):
                raise ToolkitError("Confidential authority transfer scope is malformed")
            transfers[transfer_id] = {
                "transfer_id": transfer_id,
                "from_operator_id": str(data["from_operator_id"]),
                "to_operator_id": str(data["to_operator_id"]),
                "scope_json": json.dumps(scope, sort_keys=True, separators=(",", ":")),
                "state": "pending",
                "reason": str(data["reason"]),
                "proposed_sequence": sequence,
                "resolved_sequence": None,
            }
        elif event_type in {
            "CONFIDENTIAL_AUTHORITY_TRANSFER_ACCEPTED",
            "CONFIDENTIAL_AUTHORITY_TRANSFER_REJECTED",
            "CONFIDENTIAL_AUTHORITY_TRANSFER_CANCELLED",
        }:
            transfer_id = str(row["object_id"])
            current = transfers.get(transfer_id)
            if current is None or current["state"] != "pending":
                raise ToolkitError(
                    "Confidential authority transfer resolution lacks proposal"
                )
            if event_type == "CONFIDENTIAL_AUTHORITY_TRANSFER_ACCEPTED":
                data = _signed_data(row)
                scope = data.get("scope")
                if not isinstance(scope, list):
                    raise ToolkitError("Accepted authority transfer scope is malformed")
                for item in scope:
                    if not isinstance(item, dict):
                        raise ToolkitError(
                            "Accepted authority transfer scope is malformed"
                        )
                    key = (str(item["object_type"]), str(item["object_id"]))
                    existing = authority.get(key)
                    if existing is None:
                        raise ToolkitError(
                            "Authority transfer refers to unknown confidential object"
                        )
                    if existing["authority_id"] != current["from_operator_id"]:
                        raise ToolkitError(
                            "Authority transfer history has stale source authority"
                        )
                    existing["authority_id"] = current["to_operator_id"]
                    existing["effective_sequence"] = sequence
                current["state"] = "accepted"
            elif event_type == "CONFIDENTIAL_AUTHORITY_TRANSFER_REJECTED":
                current["state"] = "rejected"
            else:
                current["state"] = "cancelled"
            current["resolved_sequence"] = sequence

    live_authority = {
        (str(row["object_type"]), str(row["object_id"])): dict(row)
        for row in connection.execute(
            "SELECT object_type, object_id, creator_id, authority_id, effective_sequence "
            "FROM confidential_authority"
        ).fetchall()
    }
    if live_authority != authority:
        raise ToolkitError(
            "Confidential authority state differs from authenticated history"
        )
    live_transfers = {
        str(row["transfer_id"]): dict(row)
        for row in connection.execute(
            "SELECT transfer_id, from_operator_id, to_operator_id, scope_json, state, reason, "
            "proposed_sequence, resolved_sequence FROM confidential_authority_transfers"
        ).fetchall()
    }
    if live_transfers != transfers:
        raise ToolkitError("Confidential authority transfer state differs from history")


def _verify_confidential_access(
    connection: sqlite3.Connection, rows: list[sqlite3.Row]
) -> None:
    """Reconstruct every grant/revocation from authenticated authority events."""

    grants: dict[tuple[str, str, str, str, int], dict[str, object]] = {}
    for row in rows:
        event_type = str(row["event_type"])
        if event_type not in {
            "CONFIDENTIAL_ACCESS_GRANTED",
            "CONFIDENTIAL_ACCESS_REVOKED",
        }:
            continue
        sequence = int(row["event_sequence"])
        data = _signed_data(row)
        operator_id = str(data["operator_id"])
        object_type = str(row["object_type"])
        object_id = str(row["object_id"])
        authority_basis = str(data["authority_basis"])
        if event_type == "CONFIDENTIAL_ACCESS_GRANTED":
            key = (operator_id, object_type, object_id, authority_basis, sequence)
            if key in grants:
                raise ToolkitError(
                    "Confidential access grant was recorded more than once"
                )
            grants[key] = {
                "operator_id": operator_id,
                "object_type": object_type,
                "object_id": object_id,
                "authority_basis": authority_basis,
                "granted_sequence": sequence,
                "revoked_sequence": None,
                "grant_reason": str(data["reason"]),
                "revoke_reason": None,
            }
            continue

        granted_sequence = data.get("granted_sequence")
        if not isinstance(granted_sequence, int):
            raise ToolkitError(
                "Confidential access revocation lacks its grant sequence"
            )
        key = (operator_id, object_type, object_id, authority_basis, granted_sequence)
        current = grants.get(key)
        if current is None or current["revoked_sequence"] is not None:
            raise ToolkitError(
                "Confidential access revocation lacks an active matching grant"
            )
        current["revoked_sequence"] = sequence
        current["revoke_reason"] = str(data["reason"])

    live = {
        (
            str(row["operator_id"]),
            str(row["object_type"]),
            str(row["object_id"]),
            str(row["authority_basis"]),
            int(row["granted_sequence"]),
        ): dict(row)
        for row in connection.execute(
            "SELECT operator_id, object_type, object_id, authority_basis, granted_sequence, "
            "revoked_sequence, grant_reason, revoke_reason FROM confidential_access_grants"
        ).fetchall()
    }
    if live != grants:
        raise ToolkitError(
            "Confidential access state differs from authenticated history"
        )


def _verify_exports(connection: sqlite3.Connection, rows: list[sqlite3.Row]) -> None:
    exports: dict[str, dict[str, object]] = {}
    items: set[tuple[str, str, str, str, str, str]] = set()
    for row in rows:
        event_type = str(row["event_type"])
        if event_type not in {"EXPORT_STARTED", "EXPORT_COMPLETED", "EXPORT_FAILED"}:
            continue
        export_id = str(row["object_id"])
        sequence = int(row["event_sequence"])
        data = _signed_data(row)
        if event_type == "EXPORT_STARTED":
            if export_id in exports:
                raise ToolkitError(f"Export was started more than once: {export_id}")
            exports[export_id] = {
                "export_id": export_id,
                "actor_id": str(
                    json.loads(row["details_json"])["authority_transaction"]["actor_id"]
                ),
                "scope_type": str(data["scope_type"]),
                "scope_id": data.get("scope_id"),
                "view_mode": str(data["view_mode"]),
                "representation": str(data["representation"]),
                "output_format": str(data["output_format"]),
                "output_digest": None,
                "manifest_digest": None,
                "state": "preparing",
                "policy_sequence": int(data["policy_sequence"]),
                "created_sequence": sequence,
                "completed_sequence": None,
            }
        else:
            current = exports.get(export_id)
            if current is None or current["state"] != "preparing":
                raise ToolkitError("Export completion/failure lacks a preparing export")
            if event_type == "EXPORT_FAILED":
                current["state"] = "failed"
                current["completed_sequence"] = sequence
                continue
            manifest_sha = str(data["manifest_digest"])
            output_sha = str(data["output_digest"])
            item_data = data.get("items")
            if not isinstance(item_data, list):
                raise ToolkitError("Completed export has malformed item membership")
            current["manifest_digest"] = manifest_sha
            current["output_digest"] = output_sha
            current["state"] = "completed"
            current["completed_sequence"] = sequence
            for item in item_data:
                if not isinstance(item, dict):
                    raise ToolkitError("Completed export item is malformed")
                items.add(
                    (
                        export_id,
                        str(item["file_id"]),
                        str(item["output_path"]),
                        str(item["source_digest"]),
                        str(item["output_digest"]),
                        str(item["mode"]),
                    )
                )
    live_exports = {
        str(row["export_id"]): dict(row)
        for row in connection.execute(
            "SELECT export_id, actor_id, scope_type, scope_id, view_mode, representation, "
            "output_format, output_digest, manifest_digest, state, policy_sequence, "
            "created_sequence, completed_sequence FROM exports"
        ).fetchall()
    }
    if live_exports != exports:
        raise ToolkitError("Export catalogue differs from authenticated export history")
    live_items = {
        (
            str(row["export_id"]),
            str(row["file_id"]),
            str(row["output_path"]),
            str(row["source_digest"]),
            str(row["output_digest"]),
            str(row["mode"]),
        )
        for row in connection.execute(
            "SELECT export_id, file_id, output_path, source_digest, output_digest, mode "
            "FROM export_items"
        ).fetchall()
    }
    if live_items != items:
        raise ToolkitError("Export item membership differs from authenticated history")


def verify_extended_state(
    connection: sqlite3.Connection, rows: list[sqlite3.Row]
) -> None:
    """Verify all post-v2.13 logical state against the event chain."""

    _verify_artefacts(connection, rows)
    _verify_export_policy(connection, rows)
    _verify_confidential_authority(connection, rows)
    _verify_confidential_access(connection, rows)
    _verify_exports(connection, rows)
