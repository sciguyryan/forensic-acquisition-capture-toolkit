# Changelog

## 2.10.0 - File Foundations

- Established individually committed files as FACT's atomic evidential objects, with never-reused `FILE-######` identifiers, SHA-256 hashes, provenance, classifications and stable storage paths.
- Added all-or-nothing ordinary file check-in batches with private preparation staging and byte-for-byte validation before catalogue commitment.
- Added file sanctity verification so missing or changed committed bytes fail catalogue verification instead of being silently accepted.
- Added append-only file relationships and presentation-state transitions so retraction or supersession does not erase historical existence.
- Integrated successful acquisitions with individual check-in of collector output, generated acquisition records, the sealed package and its retained verification sidecars.
- Bumped the current unreleased project schema boundary to version 4. No compatibility migration is provided for earlier development schemas.
- Changed confidential-note ownership cycling to append a new immutable encrypted revision instead of rewriting historical ciphertext.
- Documented the everything-as-a-file and no-change-left-behind architecture, including network evidence, note revision convergence, filtered presentation and the future encrypted-artefact model.

## 2.9.0 - Notes and Confidentiality

- Added retained project and confidential notes with never-reused note identifiers and append-only revision history.
- Added confidential-note encryption before the SQLite boundary so persistent project state receives ciphertext only.
- Restricted confidential-note plaintext to its author and the current project owner while retaining project-visible note metadata.
- Integrated confidential-note recipient cycling into project ownership acceptance before ownership flags change, with ciphertext-only temporary staging, cardinality checks and complete transaction rollback on failure.
- Added note sanctity verification for missing committed records, missing revisions, altered metadata, altered revision pointers, disclosure-state changes and payload digest mismatches.
- Added package disclosure controls that withhold note payloads by default while retaining note existence and payload digests in package catalogue snapshots.
- Bumped the current FACT project schema boundary to version 3; active projects created under earlier trust/schema versions remain with the FACT version that created them rather than being migrated in place.
- Added confidential-persistence boundary tests that reject plaintext crossing into SQLite parameters and scan project/package artefacts, failure logs and GnuPG invocation paths for sentinel plaintext.

## 2.8.0 - Clean Authority Architecture

- Added project-retained operator identity, public signing-key records, contributor membership, project and case ownership, ownership transfers, and evidential approval state to the tamper-evident catalogue.
- Added signed authority transactions bound to the rolling catalogue chain and exact historical operator signing fingerprint.
- Added authenticated shell operator sessions while retaining per-transaction signatures for authority-changing actions.
- Added two-sided contributor admission and signed project/case ownership transfer workflows.
- Added pending, approved and rejected acquisition authority states without rewriting original acquisition metadata or deleting rejected records.
- Extended catalogue verification and checkpoint state digests to detect direct tampering with identity, key, membership, ownership, transfer and approval state.
- Established signed project authority at genesis and deliberately refused in-place migration of active projects created under older trust models.
- Prevented authority records from being attached to invented or inactive acquisition identifiers.
- Preserved already sealed evidence as an active acquisition if later authority recording fails instead of falsely marking the sealed acquisition as failed.
- Removed obsolete local operator-profile/configuration paths, legacy FACT compatibility import wrappers, and in-place catalogue migration behaviour that no longer matches the current trust model.

## 2.7.1 - Ruff Repair

- Repair repository-wide Ruff 0.16.6 lint failures exposed by the GitHub runner.
- Normalise import ordering in canonical and compatibility modules and tests.
- Apply selected modern typing and simplification rules without weakening the lint configuration.
- Preserve the completed interactive-shell behaviour from 2.7.0.

## 2.7.0 - Interactive Shell Completion

- Completed the interactive shell foundation with explicit command help, safe local history, tab completion, and validated project-ID selection.
- Added a local non-evidential project registry that revalidates project records and refuses ambiguous duplicate IDs.
- Added `fact help [command ...]` while preserving conventional `--help` behaviour.
- Prevented non-interactive shell callers from reading or writing local command history.
- Corrected Ruff-visible import, simplification, and formatting issues across the shell work and pre-existing lint hotspots.
- Retired the completed shell-foundation items from the development TODO.

## 2.6.0 - Interactive Shell Foundation

- Added `fact shell` as a thin in-process REPL over the existing FACT command handlers and core services.
- Added project-aware and case-aware prompts so the current evidential context remains visible before commands are executed.
- Added safe project selection by path, project-context clearing, case-selection aliases, context display, help, clean EOF/exit handling, and non-fatal `Ctrl-C` input cancellation.
- Added conservative stale-case handling that displays an invalid-context marker rather than silently selecting another case.
- Preserved archive verification outside project context and prevented accidental nested FACT shells.
- Added detailed shell architecture and usage documentation in `docs/SHELL.md`.
- Added `docs/TODO.md` as the canonical list of accepted ownership, notes, case lifecycle, review-layer, and project-browser follow-on work.
- Adopted the user-reviewed `.gitignore` baseline, added the generated `coverage.xml` report, and continued excluding generated `*.egg-info/` metadata and sensitive runtime material from source releases.

## 2.5.0 - Context and Review Foundation

- Added automatic project and case context discovery so routine acquisitions no longer require operators to retype case identifiers.
- Added persistent numbered case selection, automatic selection of newly created cases, and safe sole-case inference.
- Added catalogue-owned sequential `ACQ-######` identifiers with non-reuse and failed-acquisition state recording.
- Added an audit-compatible lazy acquisition-namespace migration for projects created before 2.5.0.
- Added the first structured image annotation and proposed-redaction layer models with normalised coordinates and mandatory redaction reasons.
- Added a dependency-free static image review shell with independent annotation and proposed-redaction SVG overlays.
- Added detailed workflow and review-layer documentation under `docs/`.
- Corrected project packaging so complete sealed acquisition archives and their sidecars are included while mutable `.staging-*` trees remain excluded.
- Restored the README `Projects and catalogue` section and linked the new detailed documents.
- Ignored setuptools-generated `*.egg-info/` metadata and removed generated package metadata from the release tree.

## 2.4.0 - 2026-09-04

- Added the first screenshot collector, initially targeting Linux desktop environments through XDG Desktop Portal.
- Added a modular screenshot capability/backend boundary so future X11, Windows, and macOS implementations do not change collector evidential semantics.
- Added explicit screenshot targets for window, screen, area, and active-window capture, with window capture as the default.
- Added conservative portal version and advertised-target checks before capture.
- Preserved the exact screenshot bytes returned by the capture backend without resizing, re-encoding, annotation, or redaction.
- Added screenshot capture metadata covering backend, selection method, portal capabilities, session information, media type, and pixel dimensions where safely readable.
- Added generic collector orchestration so key preparation, operator binding, initial records, staging, and sealing are no longer owned by the YouTube wrapper.
- Generalised case-record source rendering so non-URL collectors do not inherit YouTube-specific assumptions.
- Added optional `dbus-next` screenshot dependency and detailed Arch/Linux screenshot documentation in `docs/SCREENSHOT_CAPTURE.md`.
- Added automated coverage for screenshot collector behaviour, backend isolation, portal success/cancellation/target checks, and exact-byte image preservation.

## 2.3.0 - 2026-09-04

- Renamed the canonical internal Python package from `youtube_forensics` to `fact`, retaining thin compatibility aliases rather than duplicate implementations.
- Added a generic acquisition context and staging workspace with explicit `INCOMPLETE` lifecycle handling.
- Added a first-class artefact registry with evidential roles and path/symlink safety checks.
- Added an explicit collector protocol and registry, and migrated YouTube source interaction into `collectors/youtube/`.
- Added an injectable command-runner service for collector command execution and transcripts.
- Extracted collector-independent sealing, manifests, signing and mandatory self-verification into `core/sealing.py`.
- Changed evidence-set identity generation to hash explicitly registered collector artefacts rather than relying on hard-coded payload directories.
- Added `ARTEFACTS.json` to new acquisitions as a machine-readable description of intentional collector outputs.
- Added the preferred collector-oriented CLI form `fact acquire youtube URL` while preserving the v2.2 URL-only spelling during migration.
- Added detailed architecture, collector-boundary, artefact-registry and review-boundary documentation in `docs/ARCHITECTURE.md`.

## 2.2.0 - 2026-09-04

- Added canonical project-scope packaging with `fact package`.
- Added deterministic `tar.gz` package generation with normalised archive metadata.
- Added an internal SHA-256 manifest plus external archive checksum, detached OpenPGP signature, public-key sidecar and fingerprint sidecar.
- Added package self-verification before successful completion.
- Bound project packages to the tamper-evident catalogue event count, chain head and state digest to provide an external rollback anchor.
- Added consistent SQLite catalogue snapshots using the SQLite backup API.
- Added cooperative package locking that blocks catalogue mutation during package creation.
- Added optional multi-recipient OpenPGP encryption as a separate outer envelope after hashing and signing.
- Added strict package allow-listing and symbolic-link rejection to prevent accidental inclusion or unsafe path semantics.
- Added detailed package-format, encryption, failure and threat-model documentation under `docs/PROJECT_PACKAGES.md`.

## 2.0.0

- Initial full release.

## 2.0.0-rc9

- Added explicit operator identity resolution with precedence: command line, environment, toolkit configuration, then system username fallback.
- Added `init` to store a persistent default operator in `ROOT/config.json` with mode `0600`.
- Added a prominent warning whenever the toolkit must fall back to the current login username.
- Added `operator_source` and `operator_username` to case records, and mirrored runtime identity and hostname in `TOOLKIT.json`.
- Added operator identity to the acquisition log, acquisition summary, and `acquisition.txt`.
- Added regression tests for precedence, fallback, configuration permissions, and CLI parsing.
- Added interactive `init` wizard for name, stable ID, organisation, role, public contact, and system-keyring signing-key selection.
- Added full primary/signing-subkey fingerprint validation and optional test signing.
- Added active-profile digest pinning in `config.json` and per-acquisition `--identity-file` override.
- Added operator identity/public-key snapshots and mandatory personal detached archive signatures.
- Extended verification to validate the operator signature and exact signing fingerprint.

## 2.0.0-rc7

- Fixed acquisition logging so primary yt-dlp, live-chat, and supplemental curl command output is appended to the main acquisition log.
- Main command transcripts now record the invoked command, stdout, stderr, and exit status with UTC timestamps.
- Retained exact unmodified command output in the existing dedicated report files.
- Added finalization-stage log messages and regression tests for transcript capture.

## 2.0.0-rc5

- Verification summaries now size the label column dynamically so every detail value remains aligned, including long document names.
- Added a regression test for summary-column alignment.

## 2.0.0-rc4

- Prepare and validate the dedicated GnuPG environment before first-run key generation.
- Detect a controlling terminal and configure an available pinentry helper automatically.
- Reload and launch `gpg-agent`, then require a reported agent socket before invoking key generation.
- Preserve existing evidence keys without requiring pinentry during the inspection phase.
- Improve actionable errors for missing terminal, pinentry, agent, or socket initialization.
- Document public-key export, protected secret-key backup, ownertrust export, and restoration into a fresh dedicated keyring.

## 2.0.0-rc3

- Made direct `PYTHONPATH=src python3 -m youtube_forensic` execution the primary first-run path.
- Added separate activation instructions for Bash/Zsh and fish.
- Documented the fish `activate.fish` requirement.
- Added distro-specific guidance for installing `venv` and `pip`.
- Clarified that runtime execution has no third-party Python package dependencies.

## 2.0.0-rc2 - 2026-07-19

- Removed the ambiguous extensionless source-tree shell launcher.
- Retained the standard `pyproject.toml` console entry point, which installs `youtube-forensic`.
- Documented explicit source-tree execution with `PYTHONPATH=src python3 -m youtube_forensic`.
- Added copy/paste acquisition and verification examples using case `CASE-0031`.

## 2.0.0-rc1 - 2026-07-19

- Reimplemented toolkit orchestration and verification in Python 3.11+.
- Added mandatory case comments and optional matter title/requestor fields.
- Added generated canonical `CASE_RECORD.json` and human-readable `CASE_RECORD.md`.
- Added `TOOLKIT.json` with Python, platform, and external-tool versions.
- Added explicit transactional finalization and isolated mandatory verification.
- Added a canonical acquired-payload manifest, `EVIDENCESET-SHA256.txt`.
- Categorically excluded transient `INCOMPLETE` state from inventories and manifests.
- Retained dedicated passphrase-protected RSA-4096 GPG signing keys.
- Retained best-effort, separately reported live-chat acquisition.
- Added automated tests for transient-state exclusion, Unicode paths, case records, CLI requirements, and archive path safety.
