"""Normative test vectors for FACT's externally documented integrity format."""

from fact.core.hashing import canonical_json_bytes, digest_bytes, genesis_hash


def _event(algorithm: str) -> dict[str, object]:
    return {
        "schema": "fact-audit-event/v3",
        "hash_algorithm": algorithm,
        "event_sequence": 1,
        "occurred_at": "2026-09-06T12:00:00Z",
        "event_type": "EXAMPLE",
        "object_type": "project",
        "object_id": "AUDIT-EXAMPLE",
        "actor": {
            "kind": "system",
            "operator_id": None,
            "operator_uuid": None,
            "credential_fingerprint": None,
            "authority_basis": "fact-system",
        },
        "details": {"message": "café", "purpose": "normative-test-vector"},
        "previous_hash": genesis_hash(algorithm),
    }


def test_normative_sha256_audit_event_vector() -> None:
    payload = canonical_json_bytes(_event("sha256"))
    assert payload.endswith(b"}")
    assert not payload.endswith(b"\n")
    assert b"caf\xc3\xa9" in payload
    assert digest_bytes("sha256", payload) == (
        "a35b6665e9e904d28036064a2f35ea2ca1783117b286dd8811c400033435e567"
    )


def test_normative_sha3_512_audit_event_vector() -> None:
    payload = canonical_json_bytes(_event("sha3-512"))
    assert digest_bytes("sha3-512", payload) == (
        "0d8fd4057c06c25126bb84d2ab312f04fa256dddd0d421774a6dcdff780b90d5"
        "d666eddc03b46d6b0680269634ee62a0ac8aa2b7437478e2f4afacd31827c007"
    )
