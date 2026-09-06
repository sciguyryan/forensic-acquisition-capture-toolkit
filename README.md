# FACT

**Forensic Acquisition & Capture Toolkit**

FACT is a source-agnostic digital evidence acquisition toolkit for collecting, preserving and independently verifying online and digital material while maintaining provenance and evidential integrity.

FACT is designed around a simple principle: acquisition should preserve what was obtained, document how it was obtained, and provide the information necessary for another party to verify the resulting project evidence independently.

The toolkit is intended to support multiple acquisition sources and evidence types. YouTube is the first supported acquisition source, inherited from the original YouTube Forensics project.

## Status

FACT is currently in transition from the original YouTube-specific forensic acquisition toolkit into a general-purpose acquisition framework.

At present, FACT supports YouTube acquisition and an initial screenshot collector for Linux desktop environments using XDG Desktop Portal. The existing YouTube functionality remains the behavioural baseline while additional source-independent acquisition capabilities are developed.

Support for a source should not be inferred merely because FACT is designed to accommodate it. Only explicitly documented acquisition sources should be considered supported.

## Design principles

FACT is built around several core forensic principles:

- **Preserve acquired material.** Original acquired media and other source artefacts should not be unnecessarily transformed or modified.
- **Record provenance.** The project record should describe what was acquired, when it was acquired, how it was acquired, and which tools participated in the process.
- **Preserve acquisition records.** Relevant command execution, output, errors, metadata and supporting information should be retained where appropriate.
- **Separate evidence from interpretation.** Acquired material and observable source data should remain distinguishable from subsequently generated documentation, analysis or conclusions.
- **Fail conservatively.** An incomplete or unsuccessful acquisition must not be presented as successfully committed evidence.
- **Make integrity verifiable.** Committed files and authenticated catalogue state should retain the integrity information required for verification.
- **Bind evidence to its operator.** Operator identity and signing material should provide an auditable relationship between an acquisition and the person responsible for it.
- **Verify independently.** Verification should not depend upon trusting the originating machine or its normal cryptographic environment.
- **Retain useful failure state.** Failed acquisition staging data should remain available where doing so assists investigation, diagnosis or recovery.
- **Prefer established tools.** FACT should orchestrate mature acquisition and cryptographic utilities rather than unnecessarily reimplementing them.

These principles form part of FACT's intended evidence model and should be preserved as support for additional acquisition sources is introduced.

## Evidence lifecycle

At a high level, FACT follows this lifecycle:

```text
Source
  |
  v
Acquisition
  |
  v
Staging
  |
  +--> Retained source files
  +--> Source metadata
  +--> Acquisition transcript
  +--> Operator context
  |
  v
Immutable file check-in
  |
  v
Authenticated acquisition record
  |
  v
Project verification
  |
  v
Committed project state
```

An acquisition is not considered successful merely because source material was downloaded. Retention, immutable check-in, authenticated recording and verification are separate stages. Packaging and export operate later on verified project state rather than forming part of acquisition commitment.

## Acquisition sources

FACT is intended to support multiple independently implemented acquisition sources.

### YouTube

**Status: supported**

The current YouTube acquisition capability preserves the functionality developed by the original YouTube Forensics project.

Depending on the source and available material, acquisition can include:

- original media;
- source metadata;
- thumbnails and associated material;
- subtitles or captions;
- live chat where available;
- acquisition command transcripts;
- tool and inspection information; and
- retained source or network capture material where available.

Original downloaded media is preserved without transcoding.

Every retained YouTube output crosses the same ordinary file check-in boundary as other FACT evidence. Media, source metadata, subtitles/captions, thumbnails, retained source links, network capture material, command transcripts and inspection reports are individually classified and committed as `FILE-######` objects when present. Explicit relationships connect descriptive and inspection records to their retained primary media. Temporary download fragments and scratch files are working state, not evidence: they are removed after successful capture and do not receive file identifiers merely because an acquisition tool created them.

Some source acquisition is inherently best-effort. For example, material that is unavailable at acquisition time cannot be reconstructed by FACT. Such conditions should be recorded rather than silently treated as successful acquisition.

### Screenshot

**Status: supported on Linux through XDG Desktop Portal**

FACT can acquire an operator-selected window, screen, area, or active window through the desktop screenshot portal. Window capture is the default. The exact returned image bytes are preserved as primary evidence and are not resized, re-encoded, annotated, or redacted during acquisition.

On Wayland, FACT deliberately uses the compositor-mediated selector instead of attempting to enumerate or bypass other applications' windows. This means window selection is presented by the trusted desktop portal rather than by a FACT-owned window list.

Install the optional screenshot dependency with:

```bash
python -m pip install -e '.[screenshot]'
```

A typical acquisition is:

```bash
fact acquire screenshot --acquisition-comment "Capture selected window"
```

Detailed platform behaviour, dependencies, failure semantics, metadata, and future backend design are documented in `docs/SCREENSHOT_CAPTURE.md`.

Additional source types will be introduced as FACT's generic acquisition architecture develops.

### Collector architecture

FACT now uses an explicit collector boundary. Source-specific collectors receive a generic acquisition context and register the files they intentionally retain; project management, staging policy, immutable file check-in, authenticated acquisition records, relationships and final project verification remain source-independent core responsibilities.

The canonical Python package and command are both `fact`. Legacy package and console aliases are not part of the current codebase.

For YouTube, the preferred collector-oriented command form is:

```bash
fact acquire youtube URL --acquisition-comment "Purpose"
```

Detailed module boundaries, collector responsibilities and artefact-registry rules are documented in `docs/ARCHITECTURE.md`.

## Everything as a file

FACT treats every retained byte-bearing evidential object as an individually checked-in file. Primary media, screenshots, network request and response material, source metadata, retained diagnostics, acquisition transcripts and retained note revisions receive independent immutable file identities and hashes. Acquisitions, notes and later artefact groupings organise and explain those files rather than replacing them as the atomic evidential objects.

Once committed, file bytes and hashes are never rewritten. Later corrections, derivations, cryptographic re-encryption, retractions and presentation decisions create new files, records or state transitions while preserving the original history. This is the project's **no change left behind** rule. See `docs/EVERYTHING_AS_A_FILE.md` for the data model, examples and verification behaviour.

## Evidence staging

FACT uses private project-local staging under `.fact/staging/acquisitions/` while an acquisition is in progress.

An `INCOMPLETE` marker identifies a staging tree that has not successfully completed authoritative file commitment and catalogue verification. Staging files are not evidence merely because FACT or an external acquisition tool touched them. Only intentionally retained material crosses the check-in boundary and receives a `FILE-######` identity.

If acquisition fails, the staging tree is retained for diagnosis and recovery, but remains explicitly unauthoritative. On success, registered collector artefacts and the acquisition transcript are checked in through the ordinary immutable file store, the authenticated acquisition event binds the exact committed file set and provenance, the project catalogue is verified, and the now-duplicate staging tree is removed.

FACT no longer creates a second per-acquisition evidence archive. Portable archival representations belong to project packaging and the general export subsystem.

## Retained notes

FACT projects can retain attributable notes as part of the project record. Every note revision is an ordinary immutable `FILE-######` object. Project-visible notes are stored as canonical note files and can be read by active authenticated project members. Confidential note revision files contain ciphertext only. Their immutable creator attribution is separate from current access authority: FACT evaluates the operator's active authenticated confidential-access grants before protected decryption. SQLite retains note lineage, access authority and file references rather than a mutable note-body BLOB.

Notes are withheld from external project packages by default. Withholding omits their committed revision-file bytes from the filtered package view while retaining their identities and hashes in catalogue history. The project owner may explicitly include selected notes; confidential notes remain encrypted even when included. Confidential access changes are append-only authority events. Project ownership transfer revokes only access derived from the outgoing `project-owner` basis and grants the corresponding basis to the incoming owner, while independent surviving access bases remain intact. See `docs/NOTES.md` and `docs/CONFIDENTIAL_ACCESS.md` for examples and the security and failure model.

## Evidence packages

FACT does not create a standalone archive for every acquisition. The live project itself is the authoritative record: the authenticated catalogue plus individually committed `FILE-######` payloads.

When a portable representation is required, project packaging creates a canonical self-contained package from verified project state. Package-time manifests, human-readable descriptors, public verification material, outer checksums and signatures are transport and verification representations of the authoritative project. They are not recursively checked back into the project merely because packaging generated them.

### Project packages

FACT can package the current state of a project into a canonical project archive. Project packaging verifies the tamper-evident catalogue and every committed file before export, embeds the catalogue event count and chain head as an external rollback anchor, writes an internal package SHA-256 transport manifest (independent of the project-selected provenance/content policy), creates a detached OpenPGP signature and archive checksum, and verifies the generated package before reporting success.

The canonical package remains unencrypted so its package identity is independent of its recipients. Optional OpenPGP encryption creates a separate encrypted envelope without replacing the signed canonical package. Private signing keys and local operational secrets are never included.

Detailed package-format, encryption and recovery documentation is provided in `docs/PROJECT_PACKAGES.md`.


## Export policy and confidential access authority

Each project carries an authenticated export policy. The policy separately controls ordinary export, ciphertext export, confidential plaintext export and broad case/project export. Policy changes are owner-authorised append-only events, so a later `EXPORT-######` can be evaluated against the policy that was actually in force when it occurred.

Confidential authorship and current access authority are different concepts. Creator attribution never changes. A confidential object may carry several independent authenticated access bases for the same operator, such as `object-owner`, `explicit-grant` and `project-owner`. Revoking one basis does not erase another surviving basis, and access history is retained through append-only `CONFIDENTIAL_ACCESS_GRANTED` and `CONFIDENTIAL_ACCESS_REVOKED` events.

This distinction also governs decryption and export. Cryptographic possession is necessary but is not treated as sufficient current authority. FACT checks authenticated confidential-access state before protected decryption, and project policy separately controls whether an authorised operator may export confidential plaintext. The current GnuPG representation does not provide cryptographic erasure: a revoked operator who retained plaintext, a private key or an external copy may still possess that information outside FACT. Revocation limits future access through FACT's normal infrastructure rather than rewriting or invalidating historical disclosure.

## Cryptographic integrity

FACT's live integrity model is catalogue-centred. Every project declares immutable chain and evidential-content hash profiles in `PROJECT.toml`. Every committed file has its own digest under the selected content profile and immutable metadata, and those file-commit events participate in the authenticated rolling catalogue history. Each recorded acquisition additionally binds the exact ordered set of committed `FILE-######` identifiers to its source, tool, operator and observation provenance.

The former per-acquisition `EVIDENCESET-SHA256.txt`, `FILELIST.txt`, `SHA256SUMS.txt`, `SHA512SUMS.txt`, archive checksum sidecars and detached acquisition-archive signatures are no longer part of the live project model. Maintaining parallel inventories and duplicate integrity layers would create additional representations that could drift from the authoritative catalogue without strengthening the underlying chain of custody.

Signed catalogue authority transactions, signed checkpoints and signed portable project packages still serve distinct authentication and external-anchor purposes. Private signing keys are not evidence artefacts and must not be included in ordinary project packages or general exports.

## Operator identity

FACT maintains an operator identity system for associating project activity with the operator responsible for performing or authorising it. Each operator receives a randomly generated immutable UUID when first admitted to project authority, alongside the human-friendly project-local operator ID. The UUID is independent of any one signing credential, so later key rotation can preserve operator identity while retaining exact credential history. Project-relevant identity, public signing-key material, contributor membership, ownership and approval state are retained inside the tamper-evident project catalogue rather than relying on mutable local operator JSON as project authority.

FACT does not maintain local operator profile files. Project-relevant identity and public signing-key material are retained directly in the project catalogue. Private keys, passphrases and GnuPG agent state remain outside the project catalogue and under the operator's control.

FACT supports a curated hash registry rather than an arbitrary algorithm string. New projects may select `sha256`, `sha512`, `sha3-256`, `sha3-512`, `blake2b-256`, `blake2b-512`, `blake2s-256` or `blake3-256` independently for the rolling provenance chain and retained evidential content. SHA-256 remains the default. The selected policy is immutable for the lifetime of the current project schema, is included in signed project genesis, and must agree with `PROJECT.toml` and catalogue metadata during verification. FACT fails closed if a configured implementation is unavailable and never substitutes another algorithm.

Authority-changing catalogue events are individually signed and also enter the rolling hash chain. The versioned audit-event envelope hashes the event sequence, recorded UTC timestamp, event/object identity, actor kind, project-local operator ID, immutable operator UUID, signing credential fingerprint, authority basis, event details and previous chain hash. Signed authority transactions separately bind the same operator UUID and signing fingerprint, and verification cross-checks those representations. This allows verification to detect unauthorised changes to identity, attribution, ownership, contributor membership or approval state while preserving the original historical sequence. Detailed behaviour and limitations are documented in [`docs/AUTHORITY_AND_IDENTITY.md`](docs/AUTHORITY_AND_IDENTITY.md).

Signing credentials should be protected appropriately for the environment in which FACT is deployed.

## Export and independent verification

Verification is a first-class part of FACT rather than an optional afterthought. The command family makes the claim being tested explicit:

```bash
fact verify file /path/to/external/file
fact verify artefact ART-000001
fact verify acquisition ACQ-000001
fact verify case CASE-000001
fact verify project
fact verify export /path/to/export
fact verify id FILE-000001
```

`verify file` is correspondence verification. It hashes an external file, reports every matching committed `FILE-######` identity, and validates the authenticated project state supporting those matches. Identical bytes may legitimately map to several file identities because independent captures have independent provenance.

Structural verification starts with an authoritative FACT object. It verifies the selected object's descendant file payloads and the authenticated catalogue path that gives the object meaning. `verify project` remains exhaustive and rehashes every committed file. A narrower case, acquisition or artefact verification does not claim that unrelated sibling payloads were rehashed.

FACT exports selected authoritative material through `fact export`. Every export attempt receives a never-reused `EXPORT-######` and is recorded in authenticated history. A completed export binds its actor, scope, project export policy, selected `FILE-######` identities, representation, view, output paths and digests. A generated `FACT-EXPORT.json` describes the portable representation but does not become project evidence merely because FACT generated it. `verify export` maps that representation back to its exact recorded export event and source files.

The current export implementation supports native directory and deterministic tar representations, explicit multi-selection, full or presented views, confidential-note ciphertext by default, authorised confidential-note plaintext derivation, and optional OpenPGP protection of tar output. Rendered and archival representations are deliberately deferred until their transformation semantics can be defined and verified without overstating byte identity.

Verification results can be emitted as text, HTML, JSON or PDF with `--report`, written with `--output`, and expanded with `--detailed`. All formats are rendered from the same structured verification result. Reports state both what was verified and relevant limitations; generating a report does not silently check it back into FACT.

Portable project packages retain their separate package-level manifest, checksum and signature verification. Packaging is a canonical project transport operation; general export is a policy-controlled disclosure operation. Neither recreates the retired per-acquisition archive verifier.

## Requirements

FACT requires Python 3.11 or later.

The Python runtime is intentionally dependency-light. FACT primarily orchestrates established external tools used for acquisition, media inspection and cryptographic operations. Screenshot capture uses the optional `dbus-next` dependency to communicate with XDG Desktop Portal.

The current YouTube acquisition implementation requires appropriate versions of tools including:

- `yt-dlp`;
- `ffmpeg` and associated media utilities where required; and
- GnuPG.

Exact requirements should be checked against the current project configuration and release documentation.

## Installation

Clone the repository and install FACT into a Python environment:

```bash
python -m pip install .
```

For development:

```bash
python -m pip install -e '.[dev]'
```

The installed command-line interface is intended to be exposed as:

```text
fact
```

FACT also provides an interactive operator shell:

```bash
fact shell
```

Explicit command help is also available with `fact help [command ...]`, alongside the conventional `--help` form.

When the shell is started inside a FACT project it displays the selected project and case directly in the prompt, allowing routine operations such as `acquire screenshot` without repeatedly transcribing project paths or case identifiers. Detailed shell behaviour is documented in [`docs/SHELL.md`](docs/SHELL.md).

During the transition from the original YouTube Forensics project, command names and package structure may change as the generic FACT architecture is introduced.

## Development

The test suite uses `pytest`.

After installing the project in development mode:

```bash
python -m pytest
```

The current source layout can also be tested without installation by exposing `src` explicitly:

```bash
PYTHONPATH=src python -m pytest
```

Linting and formatting are checked with Ruff:

```bash
ruff check .
ruff format --check .
```

The project's continuous-integration configuration should be treated as the authoritative definition of supported Python versions and automated quality checks for a particular release.

## Forensic limitations

FACT assists with acquisition, preservation, provenance and integrity verification. It does not by itself establish the legal admissibility, authenticity, meaning or evidential weight of acquired material.

A valid FACT project or verified portable representation can demonstrate properties such as file integrity, authenticated project history and cryptographic provenance. It cannot prove that material published by a third-party source was truthful, that an account was controlled by a particular real-world individual, or that an online service supplied historically complete information.

Remote digital sources can also change or disappear without notice. FACT can preserve material available to it during acquisition, but it cannot recover information that the source no longer exposes.

Investigators remain responsible for using FACT in accordance with applicable law, organisational policy, evidential procedure and the requirements of the relevant jurisdiction.

## Security

Forensic acquisition software operates on potentially hostile external input.

FACT therefore treats source content, metadata, filenames, archives and externally generated output as untrusted data.

Security-sensitive behaviour should favour explicit validation, conservative failure and preservation of evidence over convenience.

Sensitive configuration and private cryptographic material must not be committed to source control or included in ordinary project distributions.

Security issues should be reported privately to the project maintainers rather than disclosed through public issue reports before a fix can be prepared.

## Project direction

FACT is evolving from a specialised YouTube acquisition utility into a modular forensic acquisition framework.

The intended architecture will allow source-specific acquisition capabilities to coexist behind a common evidence lifecycle without weakening the forensic guarantees already provided by the existing implementation.

Future expansion may introduce additional source and evidence types, but new capabilities should continue to satisfy the same fundamental requirements:

**acquire faithfully, preserve provenance, protect integrity, and make the result independently verifiable.**

## History

FACT originated as **YouTube Forensics**, a specialised toolkit for forensic acquisition of YouTube material.

The project was renamed and broadened to **FACT - Forensic Acquisition & Capture Toolkit** as its scope expanded beyond a single online service.

The original YouTube acquisition implementation forms FACT's first source-specific acquisition capability and provides the behavioural and forensic baseline for the wider framework.

## Licence

See the repository's licence information for the terms under which FACT is distributed.

## Projects and catalogue

FACT projects use a human-readable `PROJECT.toml`, per-case `CASE.toml` records, and a tamper-evident SQLite catalogue under `.fact/`. The catalogue owns never-reused case, acquisition, note, file, artefact, export and authority-transfer identifiers (`CASE-######`, `ACQ-######`, `NOTE-######`, `FILE-######`, `ART-######`, `EXPORT-######` and `TRANSFER-######`), records lifecycle and authority events in the project-selected authenticated hash chain, retains project operator identities and public verification material, tracks contributor membership, confidential access authority and ownership, and supports signed checkpoints for independent verification.

The project owner is the human authority represented by this ledger. The SQLite catalogue is not intended to make a writable project impossible to alter; it is intended to make unauthorised modification detectable. Signed authority transactions and state reconstruction prevent changes to operator identity, ownership, membership or approval status from being silently accepted merely because somebody has edited the database.

Routine acquisitions no longer require operators to retype a case identifier. FACT can infer the current case from the working directory, use the project's selected case, automatically use the sole active case, or present an interactive numbered selector when a choice is required. New cases are allocated sequentially and selected automatically.

Detailed design and operational behaviour are documented in [`docs/EVERYTHING_AS_A_FILE.md`](docs/EVERYTHING_AS_A_FILE.md), [`docs/PROJECTS_AND_CATALOGUE.md`](docs/PROJECTS_AND_CATALOGUE.md), [`docs/AUTHORITY_AND_IDENTITY.md`](docs/AUTHORITY_AND_IDENTITY.md), [`docs/CONFIDENTIAL_ACCESS.md`](docs/CONFIDENTIAL_ACCESS.md), [`docs/NOTES.md`](docs/NOTES.md), and [`docs/WORKFLOW_CONTEXT.md`](docs/WORKFLOW_CONTEXT.md). The interactive workflow is described in [`docs/SHELL.md`](docs/SHELL.md), while accepted future workflow work is recorded in [`docs/TODO.md`](docs/TODO.md). The non-destructive image review and future closed-project browser foundation is described in [`docs/REVIEW_LAYERS.md`](docs/REVIEW_LAYERS.md).
