# FACT project packages

## Purpose

`fact package` exports a complete, self-contained representation of the FACT-managed state of a project. The package is intended for preservation, controlled transfer, backup and independent later examination without weakening the catalogue integrity model.

Project packaging is separate from source acquisition. Acquisition records what FACT obtained from a source. Packaging records and protects a selected FACT project state.

Version 2.2 implements project-scope packages. Case-scope and acquisition-scope packages are part of the intended architecture but are not yet implemented.

## Security properties

A successful project package provides the following properties:

- the live project catalogue passed full hash-chain and state-consistency verification before packaging;
- the catalogue included in the archive is a consistent SQLite snapshot rather than a file copied while SQLite may be writing it;
- the package descriptor records the project ID, catalogue event count, catalogue chain head and catalogue state digest;
- package contents are covered by an internal SHA-256 manifest;
- the completed canonical archive has an external SHA-256 checksum;
- the canonical archive is detached-signed using FACT's evidence-signing key;
- FACT verifies the completed internal manifest and newly created detached signature before reporting packaging success; and
- optional encryption is applied after the canonical archive has been created, hashed and signed.

These properties make exported packages useful external anchors against later rollback of the live project catalogue. An independently retained package containing catalogue chain head `H` is evidence that the project catalogue had reached at least that cryptographically committed state.

## Package scope and allow-list

FACT does not recursively archive arbitrary files from the project directory. Project packaging uses an explicit allow-list:

```text
PROJECT.toml
.fact/
    catalogue.sqlite
    catalogue-checkpoint.json          # when present
    catalogue-checkpoint.json.asc      # when present
files/
    FILE-######/...                    # project-scoped committed files
cases/
    CASE-######/
        CASE.toml
        files/
            FILE-######/...            # case-scoped committed files
FACT-PACKAGE/
    PACKAGE.json
    MANIFEST.sha256
    evidence-public-key.asc
    evidence-key-fingerprint.txt
```

The `.fact/catalogue.sqlite` member is produced through SQLite's backup API so that the package receives a transactionally consistent database snapshot. Acquisition staging under `.fact/staging/` is not included. Failed acquisition working state remains project-local diagnostic material, not authoritative package evidence.

FACT no longer includes per-acquisition `.7z` bundles or their checksum/signature sidecars. Successful acquisitions are already represented by their individually committed `FILE-######` payloads and authenticated acquisition records, so embedding a second archive of the same bytes would duplicate rather than strengthen the authoritative record.

The allow-list prevents unrelated working files, prior package outputs, caches, local configuration and private keyrings from being swept into an evidential package merely because they are present below the project directory.

Private keys are never included by the project packager.

## Symbolic links

The current project package format rejects symbolic links anywhere in included authoritative file or case material.

This is a conservative first-version rule. It prevents links from ambiguously referring to material outside the package and avoids extraction-time path substitution. If a future acquisition source needs to preserve a symbolic link as evidence, FACT should represent that link explicitly as acquisition metadata rather than silently dereferencing it during project packaging.

## Canonical archive

Project packages use a gzip-compressed POSIX tar archive with the suffix:

```text
.fact.tar.gz
```

FACT normalises archive-level metadata to reduce host-specific variation:

- members are ordered lexicographically by their package path;
- numeric owner and group IDs are set to zero;
- owner and group names are empty;
- archive member modification times are set to zero;
- directory permissions are normalised to `0755`;
- regular-file permissions are normalised to `0644`; and
- the gzip header modification time and filename are normalised.

`FACT-PACKAGE/PACKAGE.json` uses the timestamp of the catalogue state it represents rather than the wall-clock time at which the packaging command happened. As a result, packaging an unchanged FACT project state with the same FACT version and signing public key produces the same canonical archive bytes.

Detached signatures are intentionally outside the deterministic archive. OpenPGP signature packets may legitimately contain their own signature creation time and therefore are not expected to be byte-for-byte reproducible.

## Package descriptor

`FACT-PACKAGE/PACKAGE.json` currently contains:

- package schema identifier;
- package type;
- project ID;
- FACT version;
- catalogue event count;
- catalogue chain-head digest and selected chain-hash profile;
- catalogue state digest;
- catalogue checkpoint status;
- evidence-signing key fingerprint;
- catalogue state timestamp; and
- the project roots included by the package format.

The package schema identifier is:

```text
fact-project-package/v1
```

Consumers must not infer support for future fields or package types from this version.

## Catalogue checkpoints

A project may have no signed catalogue checkpoint, a checkpoint matching the current catalogue state, or a valid older checkpoint that became stale after legitimate catalogue mutation.

When checkpoint files are present, FACT verifies their detached signature before packaging them. The package descriptor records the resulting checkpoint status as `absent`, `current` or `stale`.

A stale but correctly signed checkpoint does not make the catalogue compromised. It records an earlier legitimate catalogue state. A missing half of a checkpoint pair or an invalid checkpoint signature causes normal packaging to fail.

The project package's own detached signature and embedded current catalogue chain head provide an additional external anchor independent of whether a current catalogue checkpoint was created immediately before packaging.

## Output artefacts

For a project named `EXAMPLE-2026`, the default canonical package output is created in the project directory's parent:

```text
EXAMPLE-2026.fact.tar.gz
EXAMPLE-2026.fact.tar.gz.sha256
EXAMPLE-2026.fact.tar.gz.asc
EXAMPLE-2026.fact.tar.gz.public-key.asc
EXAMPLE-2026.fact.tar.gz.fingerprint.txt
```

The archive itself is the canonical project package. The checksum, detached signature, public key and fingerprint are transport and verification sidecars.

The default output location is outside the project so that successive packaging operations do not recursively include earlier package exports.

FACT refuses to overwrite any planned output by default. `--force` permits deliberate replacement.

## Packaging command

When the current directory is the FACT source installation containing its evidence keyring:

```bash
fact \
    --root /mnt/storage/Forensic/projects/example \
    package
```

If the project is elsewhere and FACT cannot infer the key location from the current working directory, specify the toolkit root explicitly:

```bash
fact \
    --root /mnt/storage/Forensic/projects/example \
    package \
    --toolkit-root /mnt/storage/GitHub/forensic-acquisition-capture-toolkit
```

An explicit destination may be supplied:

```bash
fact \
    --root /mnt/storage/Forensic/projects/example \
    package \
    --toolkit-root /mnt/storage/GitHub/forensic-acquisition-capture-toolkit \
    --output /mnt/storage/Forensic/exports/example.fact.tar.gz
```

## Encryption

Encryption is optional and is an outer confidentiality layer rather than part of canonical package identity.

The order of operations is:

```text
verified project state
        |
        v
canonical package
        |
        v
SHA-256 checksum
        |
        v
OpenPGP detached signature
        |
        v
optional OpenPGP encrypted copy
```

A recipient can therefore decrypt the encrypted copy and recover the same canonical package that was hashed and signed before encryption.

Encrypt to one recipient:

```bash
fact \
    --root /mnt/storage/Forensic/projects/example \
    package \
    --toolkit-root /mnt/storage/GitHub/forensic-acquisition-capture-toolkit \
    --encrypt-to 0123456789ABCDEF0123456789ABCDEF01234567
```

Multiple `--encrypt-to` options may be supplied:

```bash
fact \
    --root /mnt/storage/Forensic/projects/example \
    package \
    --toolkit-root /mnt/storage/GitHub/forensic-acquisition-capture-toolkit \
    --encrypt-to INVESTIGATOR_FINGERPRINT \
    --encrypt-to ORGANISATIONAL_RECOVERY_FINGERPRINT
```

The recipient keys must already be available to the GnuPG keyring FACT is using. The resulting encrypted copy has an additional `.gpg` suffix.

FACT retains the unencrypted canonical package when encryption is requested. This prevents encryption from becoming the only surviving representation of the evidence and avoids accidental permanent loss if all recipient private keys are later unavailable. A future explicit encrypted-only workflow would require a separately documented recovery policy rather than silently deleting the canonical package.

## Confidentiality limits

The encrypted `.gpg` copy protects the contents of the canonical archive. The normal package filename, detached signature, checksum, public key and fingerprint remain outside that encrypted envelope. Operators who require metadata-hiding transport should place the complete package and sidecar set inside an additional approved secure transport mechanism.

Encryption does not replace access controls on the live FACT project.

## Package locking

FACT creates `.fact/package.lock` while it is constructing the snapshot. Catalogue-writing operations cooperate with this lock and refuse mutation while packaging is active.

If a process is forcibly terminated, a stale lock can remain. FACT intentionally does not silently delete a pre-existing lock because doing so could defeat a real concurrent packaging operation. The operator should first establish that no FACT packaging process is active and then remove the stale lock manually.

This lock protects cooperative FACT operations. It cannot prevent an administrator or another program from directly altering project files on the host.

## Failure behaviour

Normal packaging fails rather than producing a package claimed to be valid when any mandatory integrity condition fails. Examples include:

- catalogue hash-chain failure;
- catalogue live-state or counter inconsistency;
- mismatch between `PROJECT.toml` and the catalogue project ID;
- invalid or incomplete existing checkpoint material;
- symbolic links in included material;
- failure to export the evidence public key;
- package manifest self-verification failure;
- detached-signature creation or verification failure;
- encryption failure when encryption was requested; or
- an existing output that was not explicitly authorised for replacement.

FACT never repairs catalogue history as a side effect of packaging.

## Signing-key location

In version 2.2 the packaging command needs the directory containing FACT's existing `pgp/keyring` evidence-signing keyring. During development this is normally the toolkit repository root and is supplied with `--toolkit-root` when it differs from the current working directory.

This is transitional architecture. Key ownership and reusable acquisition infrastructure are expected to be revisited during FACT's source-agnostic refactoring. Package semantics should remain independent of where the implementation ultimately stores or resolves signing credentials.

## Threat model

Project packaging is intended to make ordinary corruption, accidental changes and unsophisticated evidence rewriting detectable. It also makes later catalogue rollback more difficult once a package has been independently retained.

It cannot make a fully compromised host trustworthy. An attacker who controls the running FACT process, all signing credentials, every package copy, all recipient keys and all external records can potentially construct a replacement history. Independent retention of signed packages, protected signing keys and appropriate organisational controls remain important.

## Retained note disclosure

Retained notes are excluded from external project packages by default. Because each note revision is now an ordinary committed file, packaging does not null a database payload. Instead, the filtered package view omits the revision-file bytes for notes whose disclosure policy is `withheld`, while the catalogue snapshot still retains the note identity, revision lineage, `FILE-######` identity, content digest and provenance showing that the material exists in the authoritative project. The authoritative project catalogue is never rewritten by packaging.

The current project owner may explicitly mark an individual note for inclusion. Project-visible revision files are then included as their committed bytes. Confidential revision files remain encrypted ciphertext and are never decrypted by the packaging path.

A project package is therefore allowed to be physically missing only the exact note revision file IDs that the package disclosure selection deliberately withheld. Package construction verifies the staged tree with that explicit omission set. An unrelated missing committed file still fails verification. This prevents note disclosure filtering from becoming a general mechanism for overlooking damaged or missing evidence.
