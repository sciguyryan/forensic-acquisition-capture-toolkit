# Cryptographic integrity and the FACT hash chain

This document is the normative description of FACT's project hash construction. It is intended to make the integrity model independently reviewable and reproducible without trusting FACT's own verifier.

FACT does not rely on filesystem permissions as an integrity guarantee. Read-only committed payloads reduce accidental modification, while cryptographic digests, the authenticated event chain, current-state reconstruction and signatures are responsible for detecting unauthorised change.

## Integrity policy

Every project selects two immutable hash profiles at initialisation:

- `chain_hash` hashes audit events, state representations and authenticated chain material;
- `content_hash` hashes exact retained evidential file bytes.

The selected profiles are recorded in `PROJECT.toml`, catalogue metadata and the signed `PROJECT_GENESIS` authority transaction. Full verification requires all three representations to agree. Changing only one representation does not change the project's authenticated policy and causes verification to fail.

Supported profiles are `sha256`, `sha512`, `sha3-256`, `sha3-512`, `blake2b-256`, `blake2b-512`, `blake2s-256` and `blake3-256`.

The hash policy is immutable for the lifetime of the current project schema. A future authenticated transition mechanism, if ever required for unusually long-lived projects, must be designed explicitly rather than silently changing algorithms.

## Content hashing

FACT hashes the exact bytes stored as a committed `FILE-######` payload. Files are opened in binary mode and streamed into the selected `content_hash` implementation. FACT does not decode text, normalise Unicode, convert line endings, add a newline or otherwise transform the payload before calculating the content digest.

The digest is represented as lower-case hexadecimal. The file's digest, byte length, logical path, classification, media type, storage path, acquisition/case relationship and committing actor are bound into the authenticated `FILE_COMMITTED` event.

## Normative canonical JSON

Audit-event and state material is serialised to UTF-8 JSON using these rules:

1. Object keys are sorted recursively by JSON key name.
2. There is no insignificant whitespace. Separators are exactly `,` and `:`.
3. Unicode characters are emitted directly and encoded as UTF-8 rather than being forced into ASCII `\\uXXXX` escapes.
4. JSON scalars use the normal JSON spellings: `true`, `false` and `null`.
5. No byte-order mark or trailing newline is added.
6. Arrays retain their supplied order. Any collection whose order is semantically irrelevant must therefore be explicitly sorted by the producer before canonicalisation.
7. Timestamps are strings already normalised by the event producer. Current FACT audit timestamps use UTC ISO 8601 form such as `2026-09-06T12:00:00Z`.

The reference implementation is `fact.core.hashing.canonical_json_bytes`.

## Audit-event envelope

The current event schema is `fact-audit-event/v3`. Every event hash covers the complete canonical object below:

```json
{
  "schema": "fact-audit-event/v3",
  "hash_algorithm": "<project chain_hash>",
  "event_sequence": 1,
  "occurred_at": "<recorded UTC timestamp>",
  "event_type": "<event type>",
  "object_type": "<object type>",
  "object_id": "<object identifier>",
  "actor": {
    "kind": "system or operator",
    "operator_id": "<human-friendly project identity or null>",
    "operator_uuid": "<immutable UUID or null>",
    "credential_fingerprint": "<signing credential fingerprint or null>",
    "authority_basis": "<authenticated reason for authority>"
  },
  "details": {},
  "previous_hash": "<previous event hash>"
}
```

`details` is event-specific authenticated material. For signed authority events it includes the canonical signed authority transaction and signature. Consequently, the event chain binds not only the fact that an authority event occurred but the exact signed transaction FACT retained for that event.

`occurred_at` is part of the hashed material. Altering a recorded timestamp therefore changes that event hash and breaks every subsequent chain link. This makes the recorded timestamp tamper-evident; it does not independently prove that the host clock was correct when the event was created.

## Genesis value and rolling construction

Before the first event there is no preceding event digest. FACT therefore defines the predecessor as an all-zero hexadecimal string whose length matches the selected chain digest.

For SHA-256 this is 64 zeroes. For SHA-512 or SHA3-512 it is 128 zeroes.

For event `n`:

```text
canonical_n = canonical_json_bytes(event_n including previous_hash)
hash_n      = CHAIN_HASH(canonical_n)
```

The next event stores `hash_n` as its `previous_hash`:

```text
ZERO -> EVENT 1 -> HASH 1 -> EVENT 2 -> HASH 2 -> ... -> EVENT n -> HASH n
```

Verification starts again from the appropriate all-zero value, requires event sequences to be contiguous from 1, requires each stored `previous_hash` to equal the independently calculated predecessor, rebuilds every canonical event and recalculates every event digest.

Deletion, insertion, reordering or modification of an authenticated historical event therefore changes the chain from that point onwards.

## Normative test vector A: SHA-256

Logical event:

```json
{"schema":"fact-audit-event/v3","hash_algorithm":"sha256","event_sequence":1,"occurred_at":"2026-09-06T12:00:00Z","event_type":"EXAMPLE","object_type":"project","object_id":"AUDIT-EXAMPLE","actor":{"kind":"system","operator_id":null,"operator_uuid":null,"credential_fingerprint":null,"authority_basis":"fact-system"},"details":{"message":"café","purpose":"normative-test-vector"},"previous_hash":"0000000000000000000000000000000000000000000000000000000000000000"}
```

Exact canonical UTF-8 JSON, shown as text after key sorting:

```text
{"actor":{"authority_basis":"fact-system","credential_fingerprint":null,"kind":"system","operator_id":null,"operator_uuid":null},"details":{"message":"café","purpose":"normative-test-vector"},"event_sequence":1,"event_type":"EXAMPLE","hash_algorithm":"sha256","object_id":"AUDIT-EXAMPLE","object_type":"project","occurred_at":"2026-09-06T12:00:00Z","previous_hash":"0000000000000000000000000000000000000000000000000000000000000000","schema":"fact-audit-event/v3"}
```

Expected SHA-256 digest:

```text
a35b6665e9e904d28036064a2f35ea2ca1783117b286dd8811c400033435e567
```

The non-ASCII `é` is encoded as UTF-8 bytes `c3 a9`. The canonical representation contains no terminating newline.

## Normative test vector B: SHA3-512

Use the same logical event, change `hash_algorithm` to `sha3-512`, and use 128 zeroes for `previous_hash`.

Expected SHA3-512 digest:

```text
0d8fd4057c06c25126bb84d2ab312f04fa256dddd0d421774a6dcdff780b90d5d666eddc03b46d6b0680269634ee62a0ac8aa2b7437478e2f4afacd31827c007
```

These vectors are reproduced by automated tests so documentation and implementation cannot drift silently.

## Current-state digest

The rolling history proves the authenticated event sequence, but FACT also calculates a deterministic digest of current authoritative catalogue state. This catches direct database edits that might leave the historical event rows untouched.

The current state digest uses `chain_hash` over canonical JSON containing stable, explicitly ordered representations of these authoritative tables where present:

- project metadata;
- issued identifiers and lifecycle state;
- operators and immutable operator references/UUIDs;
- operator credentials;
- project memberships;
- ownership and ownership transfers;
- record authority;
- notes and note revisions;
- committed files;
- artefacts and artefact membership;
- export policy;
- confidential authority and confidential-authority transfers;
- confidential access grants and revocations;
- exports and export items.

Each SQL query specifies deterministic row ordering before canonical JSON serialisation. Verification additionally reconstructs critical live state from authenticated events and compares the reconstruction with the live catalogue. The state digest therefore complements, rather than replaces, semantic reconstruction checks.

## Signed checkpoints

A checkpoint records at least the project identifier, event count, current chain head, current state digest and checkpoint creation time. The checkpoint is signed with the configured FACT evidence-signing mechanism. Verification first authenticates the project and then requires the checkpoint's project identifier, event count, chain head and state digest to match current verified state before checking the detached signature.

A signed checkpoint can provide an independently retained anchor against some rollback scenarios. FACT does not claim that a locally stored checkpoint alone prevents an attacker who can replace the entire project and every local anchor with an older valid copy.

## Exports and package transport

Native FACT exports carry content and output digests according to their export schema and project integrity policy. Export verification checks the manifest/descriptor and relevant source/output material independently.

The project-package transport manifest deliberately uses SHA-256 as a transport checksum format. That checksum is separate from the project's immutable `chain_hash` and `content_hash` policy. It protects the package representation in transit; it does not redefine the project's evidential hash policy.

## Read-only filesystem protection

After a retained payload has been successfully committed, FACT attempts to remove all write bits from that payload. The current POSIX baseline is owner-readable mode `0400` with the containing project directories remaining owner-only/traversable as needed.

This is accidental-change protection only. A sufficiently privileged process or the file owner can change permissions. Full verification still recalculates content digests. If a committed payload remains byte-identical but has unexpectedly become writable, verification reports a warning rather than falsely declaring cryptographic compromise.

Committed evidential bytes should not normally be made writable in place. A legitimate evidential change creates a new FILE identity or revision. FACT's `temporarily_writable` helper exists for operational files that genuinely require an in-place update and always restores their previous mode in a `finally` path.

## Independent audit procedure

An independent implementation can audit FACT without importing FACT's verification code by:

1. reading the immutable hash policy from `PROJECT.toml`;
2. independently reading the catalogue metadata and signed genesis policy and requiring agreement;
3. reproducing the canonical JSON rules above;
4. replaying every audit event from the all-zero predecessor and comparing every digest/link;
5. validating signed authority transactions with the retained historical public keys;
6. reconstructing authoritative state from events and comparing it with current catalogue state;
7. hashing every retained `FILE-######` payload using `content_hash` and comparing digest and byte length;
8. independently rebuilding the current-state digest;
9. validating any signed checkpoint or independently retained anchor.

Reference implementation areas are intentionally separated for review:

- `src/fact/core/hashing.py`: hash profiles and normative canonical JSON;
- `src/fact/core/catalogue.py`: event construction, rolling chain, state digest and chain verification;
- `src/fact/core/files.py`: evidential file commitment;
- `src/fact/core/verification.py`: object/project verification reporting;
- `tests/test_integrity_specification.py`: normative cross-language test vectors.

## Security properties and limitations

A successful verification demonstrates internal consistency with FACT's authenticated record and detects modifications covered by the relevant digest/signature checks. It does not prove that a remote source was truthful, that the host clock was accurate, or that a previously authorised recipient did not retain plaintext elsewhere.

Hashing alone does not establish who authorised an event. FACT combines hashes with signed authority transactions and retained verification keys where human authority is evidentially meaningful.

Complete rollback remains a distinct threat: if an attacker can restore an older internally valid project together with all local anchors, the restored project can itself verify. Independently retained signed checkpoints, exports or future trusted temporal anchors strengthen resistance to that class of attack.

The design goal is not to ask auditors to trust an opaque integrity implementation. The canonical representation, included fields, algorithms, test vectors, limitations and verification process are documented so they can be reproduced and challenged independently.
