# FACT development TODO

This document records accepted future work that has not yet been implemented. Items are architectural commitments or investigation targets rather than promises that a particular interface is final.


## Provenance and temporal assurance

- Add optional external trusted timestamping or independently retained temporal anchors for projects that require evidence of real-world time rather than only tamper-evident recorded host time.
- Add conservative temporal sanity checks such as detecting backwards event-time movement or implausible clock discontinuities without pretending those checks provide trusted wall-clock proof.
- Decide whether a future project schema needs authenticated hash-algorithm transition epochs for exceptionally long-lived projects. The current integrity policy remains immutable from project genesis to closure.

## Identity and key lifecycle

- Define operator UUID provisioning in the onboarding/initialisation framework so stable operator identity can be reused deliberately across projects without reviving mutable local operator-profile authority.
- Add auditable operator signing-key rotation without invalidating historical signatures or rewriting the key that represented an operator at an earlier catalogue sequence.
- Add explicit signing-key revocation and compromised or lost-key recovery with conservative, highly visible exceptional transactions rather than making recovery appear to be an ordinary key rotation.
- Design exceptional ownership recovery for situations in which the current owner cannot participate. Recovery must never masquerade as a consensual ownership transfer and must retain the reason, authority and recovery path in project history.
- Improve contributor public-key import and selection ergonomics while preserving the rule that project-retained identity cannot be silently redefined by local keyring state.
- Continue extending individually signed authority semantics to later structural lifecycle operations where attribution is evidentially meaningful.

## Notes follow-on

- Add optional direct acquisition association to retained notes once acquisition-level review workflows need it.
- Add note-level retraction/presentation controls using append-only state transitions rather than deletion.
- Keep note rendering, searching and future disclosure controls layered on the ordinary file model rather than introducing a second payload store.


## Generalised evidence export

The v2.14 foundation implements authenticated export policy, immutable `EXPORT-######` events, native directory/tar export, full/presented views, multi-selection, export verification and confidential-note ciphertext/plaintext handling. Remaining expansion work is:

- Add rendered/flattened, structured and archival representations with deterministic transformation/provenance descriptions and verification semantics.
- Add first-class layered image/review export after annotation and proposed-redaction layers exist.
- Extend recipient-encryption UX and key selection while preserving output protection as a choice independent from source confidentiality.
- Implement a generic encrypted file/artefact payload format and authenticated streaming/chunk cryptography before enabling cryptographic authority transfer or plaintext export for large generic encrypted artefacts.
- Expand export receipts/summary presentation where useful without checking generated descriptors back into evidence automatically.
- If an exported/rendered result is deliberately checked back into FACT, admit it as a new immutable derivative file with explicit provenance.

## Operator onboarding and project-local cryptographic bootstrap

- Add an interactive, convenient operator setup workflow. It should guide an operator through defining project-relevant identity, discovering suitable existing signing keys from the operator's ordinary/global keyring, displaying fingerprints clearly, validating key suitability and performing a test signature where appropriate.
- Do not create operator/global-keyring keys. FACT may discover, select and validate externally managed operator keys, but project setup must not silently generate, rotate, import private material into, or otherwise mutate the user's personal/global GnuPG keyring.
- Integrate operator setup smoothly with project creation. If a new project requires an operator and no usable setup is available, the interactive project-creation flow should be able to launch or embed operator onboarding rather than ending at an opaque prerequisite error. Preserve explicit non-interactive options for automation.
- Add project-local cryptographic bootstrap during project creation for cryptographic material that belongs to FACT itself and is scoped to that project. FACT may offer to generate those project-local keys automatically after the architecture determines which such keys are still necessary.
- Store every project-owned configuration, key, public material, metadata and related operational state beneath the project and its correct protected subdirectories. Do not scatter project-owned state into unrelated global locations.
- Keep project-local cryptographic material clearly separated from operator identity keys in naming, storage, documentation and lifecycle. Project creation must make this boundary obvious to the operator.
- Apply restrictive permissions, explicit purpose metadata, fingerprint validation, creation rollback and recovery/backup guidance to generated project-local keys.
- Ensure project-local private key material is excluded from ordinary source distributions, general exports and project packages unless a future narrowly defined backup/recovery operation explicitly requires otherwise.
- Fold project-local key rotation, revocation, recovery and eventual retirement into the same lifecycle design rather than treating automatic creation as a one-off key-generation command.

## Audit timeline and contribution queries

- Add a chronological project timeline derived from the canonical signed catalogue event stream.
- Add operator contribution queries, including filtering by operator, case, acquisition, event type and time range.
- Distinguish performed, authored, approved or rejected, owned, and otherwise affected relationships rather than collapsing all activity into a single meaning.
- Add a readable terminal renderer and later reuse the verified query layer for a richer HTML/SVG project-closing timeline.
- Keep timeline presentation derived from authoritative catalogue history; it must never become another source of truth.

## Case lifecycle

- Add case audit as an integrity and completeness inspection operation.
- Add case verification as a structural and cryptographic validation operation.
- Add case sealing as an explicit lifecycle transition that binds the responsible owner and verified state.
- Add case packaging as a transport/export operation distinct from sealing.

## Collector convergence follow-on

- Continue auditing source collectors as their capabilities expand so every intentionally retained evidential output is individually classified and checked in, while transient working data remains outside the authoritative record.
- Extend explicit file relationships when collectors gain richer source-specific context rather than encoding those relationships only in filenames or prose.
- Keep future image annotations, proposed redactions and rendered derivatives on the ordinary file/relationship foundation established by screenshot/image acquisition.

## Screenshot review and presentation

- Continue the generic review subsystem with editable structured annotations and auditable revision history.
- Support common screenshot-style annotation shapes including arrows, rectangles, circles/ellipses, lines, highlights, markers, text, and freehand paths.
- Preserve the immutable original image. Annotation geometry remains in normalised coordinates and is rendered as separate scalable layers.
- Add proposed redactions as a separate layer with a mandatory reason for every redaction.
- Keep requested/proposed redactions distinct from destructively flattened redacted derivatives.
- Build a minimal self-contained HTML/SVG review application around the existing review-layer foundation.
- On project closure, generate a self-contained static HTML media browser for project evidence, derivatives, provenance, review layers, and other appropriate retained records.


## Encrypted artefacts

- Extend the now-completed file-backed confidential-note model to general encrypted artefacts, using ordinary immutable file/check-in machinery with special classification and access policy rather than a separate evidence store.
- Design authenticated streaming or chunk encryption for large artefacts so owner-only confidentiality remains practical without whole-file memory requirements.
- Treat ownership transfer as an all-or-nothing transition across every affected encrypted note revision and encrypted artefact. Decrypt, re-encrypt, validate and stage the complete set before committing any new ownership state.
- Never permit a non-owner to export an encrypted artefact in decrypted form. Ordinary exports may exclude it or retain only its encrypted committed representation according to disclosure policy.
- Preserve every historical encrypted representation and hash. Re-encryption creates a new immutable representation rather than rewriting the old one.

## File-store hardening

- Add a durable crash-recovery journal for the narrow filesystem/SQLite commit boundary so abrupt process or machine failure can be diagnosed and recovered conservatively without silently adopting unexplained files.
- Extend file relationships and presentation-state verification as derivation, review, retraction and filtered export workflows are implemented.
