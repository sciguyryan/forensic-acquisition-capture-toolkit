# FACT projects and tamper-evident catalogue

## Purpose

FACT organises work as projects containing cases and, subsequently, acquisitions. Project state is separated from acquired evidence. Human-readable project and case metadata use TOML, while transactional identifier allocation and audit history use SQLite.

The catalogue is designed to make casual or accidental rewriting of project history detectable. It is not claimed to make a fully compromised host trustworthy.

## Project layout

```text
PROJECT.toml
.fact/
    catalogue.sqlite
    catalogue-checkpoint.json
    catalogue-checkpoint.json.asc
cases/
    CASE-000001/
        CASE.toml
        acquisitions/
```

`PROJECT.toml` contains stable, human-readable project metadata. `.fact/catalogue.sqlite` contains operational project state and the cryptographic audit journal. Case directories contain human-readable case records and future acquisition directories.

The `.fact` directory and catalogue are created with owner-only permissions where the host filesystem supports POSIX permissions.

## Identifier invariant

Once FACT issues an identifier, that identifier is permanently consumed within that project's namespace.

Retiring or deleting the object associated with an identifier must never make the identifier available again. Failed later work must likewise not rewind the counter. Gaps in the sequence are therefore legitimate and meaningful.

Case identifiers use six decimal digits, for example `CASE-000001`.

Allocation uses a SQLite `BEGIN IMMEDIATE` transaction. This serialises concurrent writers before the current sequence is read and advanced, preventing two FACT processes from being issued the same identifier.

## Logical retirement

FACT distinguishes retirement from deletion. Retirement changes the current state of an identifier but preserves its allocation record and audit history permanently.

The current implementation does not delete case material when a case is retired. Destructive evidence/project-data deletion requires a separately designed policy and must not be conflated with identifier retirement.

## Audit journal

Every catalogue-changing operation appends an audit event. Events include their sequence, UTC timestamp, event type, affected object, canonical JSON details, the previous event hash, and their own SHA-256 hash.

The first event refers to a fixed all-zero genesis hash. Every later event cryptographically commits to the previous event. Altering, deleting, inserting or reordering historical events therefore breaks verification unless the attacker reconstructs the subsequent chain.

FACT never silently repairs a broken chain. A chain-verification failure is an integrity failure requiring explicit investigation and recovery.

## State digest

The audit chain protects logical history. Signed checkpoints additionally contain a deterministic SHA-256 digest of the identifier registry's current state. This allows FACT to detect direct changes to the live identifier table even if the audit journal itself was left untouched.

## Signed checkpoints

A checkpoint records:

- checkpoint schema version;
- project ID;
- audit event count;
- current audit-chain head;
- current-state digest; and
- checkpoint creation time.

The checkpoint is detached-signed with FACT's dedicated evidence-signing key. Verification imports the supplied public key into a temporary isolated GnuPG home before verifying the signature.

A checkpoint describes an exact catalogue state. After legitimate catalogue mutation, the previous checkpoint is intentionally stale until a new checkpoint is signed. This distinction must not be mistaken for corruption: chain verification can still validate the internal journal, while checkpoint verification requires the checkpoint to match the current state exactly.

## Rollback limitation

A self-contained signed catalogue cannot by itself detect replacement with an older catalogue and its matching older valid checkpoint. This is a rollback attack.

Future sealed FACT acquisition packages should cryptographically bind the relevant project ID, catalogue event sequence and chain-head hash. Once such a package has been independently retained, it becomes an external anchor against silent rollback of the local project catalogue. Additional external checkpoint publication or protected backup can provide stronger anchoring where required.

## Threat model

The catalogue is intended to detect accidental edits and make casual manual tampering substantially more difficult. It protects against common attempts such as changing an issued identifier, removing a retirement event, rewriting current state without updating history, or modifying a checkpoint without the signing key.

It does not claim to defeat an attacker who simultaneously controls the host, FACT process, signing credentials, all historical checkpoints and every externally retained evidence package.

## Encryption

The catalogue is not encrypted by default. Encryption provides confidentiality, whereas the immediate requirement is tamper evidence and integrity. Database encryption may be added later as an optional protection for sensitive project metadata, using an established implementation rather than bespoke cryptography.

## Operational commands

Create a project:

```bash
fact project init --project-id EXAMPLE-2026 --title "Example investigation" /path/to/project
```

Create the next case ID:

```bash
fact --root /path/to/project case create --title "Example case"
```

Retire a case without reusing its ID:

```bash
fact --root /path/to/project case retire CASE-000003 --reason "Created in error"
```

Verify the internal hash chain:

```bash
fact --root /path/to/project catalogue verify
```

Create a signed checkpoint:

```bash
fact --root /path/to/project catalogue checkpoint --toolkit-root /path/to/fact-installation
```

Verify the signed checkpoint:

```bash
fact --root /path/to/project catalogue verify --checkpoint --public-key /path/to/evidence-public-key.asc
```
