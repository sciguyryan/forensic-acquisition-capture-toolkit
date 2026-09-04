# FACT

**Forensic Acquisition & Capture Toolkit**

FACT is a source-agnostic digital evidence acquisition toolkit for collecting, preserving, sealing, and independently verifying online and digital material while maintaining provenance and evidential integrity.

FACT is designed around a simple principle: acquisition should preserve what was obtained, document how it was obtained, and provide the information necessary for another party to verify the resulting evidence package independently.

The toolkit is intended to support multiple acquisition sources and evidence types. YouTube is the first supported acquisition source, inherited from the original YouTube Forensics project.

## Status

FACT is currently in transition from the original YouTube-specific forensic acquisition toolkit into a general-purpose acquisition framework.

At present, FACT supports YouTube acquisition and an initial screenshot collector for Linux desktop environments using XDG Desktop Portal. The existing YouTube functionality remains the behavioural baseline while additional source-independent acquisition capabilities are developed.

Support for a source should not be inferred merely because FACT is designed to accommodate it. Only explicitly documented acquisition sources should be considered supported.

## Design principles

FACT is built around several core forensic principles:

- **Preserve acquired material.** Original acquired media and other source artefacts should not be unnecessarily transformed or modified.
- **Record provenance.** An evidence package should describe what was acquired, when it was acquired, how it was acquired, and which tools participated in the process.
- **Preserve acquisition records.** Relevant command execution, output, errors, metadata and supporting information should be retained where appropriate.
- **Separate evidence from interpretation.** Acquired material and observable source data should remain distinguishable from subsequently generated documentation, analysis or conclusions.
- **Fail conservatively.** An incomplete or unsuccessful acquisition must not be presented as successfully sealed evidence.
- **Make integrity verifiable.** Evidence packages should contain cryptographic manifests and associated integrity information.
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
  +--> Acquired artefacts
  +--> Source metadata
  +--> Acquisition records
  +--> Operator information
  |
  v
Manifest
  |
  v
Evidence package
  |
  +--> Cryptographic hashes
  +--> Toolkit signature
  +--> Operator signature
  |
  v
Independent verification
  |
  v
Sealed evidence
```

An acquisition is not considered successfully sealed merely because source material was downloaded. Collection, packaging, integrity protection and verification are separate stages.

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
- tool information;
- evidence manifests; and
- cryptographic integrity and signature material.

Original downloaded media is preserved without transcoding.

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

FACT now uses an explicit collector boundary. Source-specific collectors receive a generic acquisition context and register the artefacts they intentionally produce; project management, staging state, evidence-set manifests, signing, sealing and mandatory verification remain source-independent core responsibilities.

The canonical Python package is `fact`. The historical `youtube_forensics` package and `youtube-forensics` console command are compatibility aliases and do not contain a second copy of evidential logic.

For YouTube, the preferred collector-oriented command form is:

```bash
fact acquire youtube URL --acquisition-comment "Purpose"
```

The v2.2 `fact acquire URL` spelling remains accepted during migration. Detailed module boundaries, collector responsibilities and artefact-registry rules are documented in `docs/ARCHITECTURE.md`.

## Evidence staging

FACT uses a staging area while an acquisition is in progress.

An `INCOMPLETE` marker identifies evidence that has not successfully completed the acquisition and sealing process. This prevents partially acquired material from being confused with completed evidence.

If acquisition fails, staging material is retained rather than automatically destroyed. This can preserve useful forensic and diagnostic information about what occurred before the failure.

Successful acquisition proceeds through finalisation and evidence-package creation.

## Evidence packages

FACT packages completed acquisitions into self-contained evidence archives.

An evidence package is intended to contain sufficient information to establish:

- the acquired material;
- relevant source information;
- acquisition provenance;
- the tools and commands involved;
- the responsible operator;
- the relationship between packaged files through cryptographic manifests; and
- the integrity and authenticity information required for subsequent verification.

The archive itself is cryptographically hashed and signed after creation.

Generated records should not be confused with independently acquired evidence. FACT should make that distinction clear wherever generated documentation, summaries or other derived material are introduced.

### Project packages

FACT can package the current state of a project into a canonical project archive. Project packaging verifies the tamper-evident catalogue before export, embeds the catalogue event count and chain head as an external rollback anchor, writes an internal SHA-256 manifest, creates a detached OpenPGP signature and archive checksum, and verifies the generated package before reporting success.

The canonical package remains unencrypted so its evidential identity is independent of its recipients. Optional OpenPGP encryption creates a separate encrypted envelope without replacing the signed canonical package. Private signing keys and local operational secrets are never included.

Detailed package-format, encryption and recovery documentation is provided in `docs/PROJECT_PACKAGES.md`.

## Cryptographic integrity

FACT uses cryptographic hashes and OpenPGP signatures to protect completed evidence packages.

The signing model distinguishes between toolkit signing material and operator identity.

This allows an evidence package to demonstrate both that it was produced through the FACT sealing process and that an identified operator cryptographically authorised the acquisition.

Private signing keys are not evidence artefacts and must not be included in distributable source packages or evidence intended for third parties.

## Operator identity

FACT maintains an operator identity system for associating acquisitions with the person responsible for performing them.

Operator information is cryptographically bound through signing keys and recorded fingerprints rather than relying solely upon textual identity fields.

Signing credentials should be protected appropriately for the environment in which FACT is deployed.

## Independent verification

Verification is a first-class part of FACT rather than an optional afterthought.

The verifier checks the structure and integrity of an evidence package and validates its cryptographic signatures.

Signature verification is performed using an isolated temporary GnuPG environment rather than implicitly trusting the user's ordinary keyring.

Archive extraction and inspection are also treated defensively. Unsafe archive paths, traversal attempts and inappropriate symbolic links must not be trusted simply because an archive carries a recognised FACT structure.

The objective is that a recipient can verify a FACT evidence package independently of the machine on which the acquisition was originally performed.

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

A valid FACT evidence package can demonstrate properties such as package integrity and cryptographic provenance. It cannot prove that material published by a third-party source was truthful, that an account was controlled by a particular real-world individual, or that an online service supplied historically complete information.

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

FACT projects use a human-readable `PROJECT.toml`, per-case `CASE.toml` records, and a tamper-evident SQLite catalogue under `.fact/`. The catalogue owns never-reused case and acquisition identifiers, records lifecycle events in a SHA-256 hash chain, and supports signed checkpoints for independent verification.

Routine acquisitions no longer require operators to retype a case identifier. FACT can infer the current case from the working directory, use the project's selected case, automatically use the sole active case, or present an interactive numbered selector when a choice is required. New cases are allocated sequentially and selected automatically.

Detailed design and operational behaviour are documented in [`docs/PROJECTS_AND_CATALOGUE.md`](docs/PROJECTS_AND_CATALOGUE.md) and [`docs/WORKFLOW_CONTEXT.md`](docs/WORKFLOW_CONTEXT.md). The non-destructive image review and future closed-project browser foundation is described in [`docs/REVIEW_LAYERS.md`](docs/REVIEW_LAYERS.md).
