# FACT development TODO

This document records accepted future work that has not yet been implemented. Items are architectural commitments or investigation targets rather than promises that a particular interface is final.

## Current agreed implementation order

1. Project initialisation, mandatory owner bootstrap and project-local keyring.
2. Recovery foundations and finite threshold-share configuration.
3. Operator enrolment and signing/encryption credential lifecycle.
4. Complete user-facing revocable-authority workflows beyond the current multi-basis foundation.
5. Extend operator-removal and object-specific revocation consequences beyond the current ownership-transfer behaviour.
6. File-store crash hardening across filesystem/catalogue boundaries.
7. Generic encrypted artefacts and reviewed envelope-encryption implementation.
8. Notes and provenance-relationship follow-on.
9. Version and state comparison.
10. Operator activity, change attribution, provenance graphing and timeline queries.
11. Case lifecycle.
12. Generalised export expansion.
13. Cross-project operator identity and credential management.
14. Screenshot review/presentation and remaining assurance work.

Collector correctness fixes continue whenever discovered; formal collector-convergence expansion remains a later programme. Simple temporal sanity checks may land opportunistically before the larger trusted-time work.


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


## Revocable confidential access and cryptographic lifecycle

The v2.17 foundation records independent confidential-access bases, retains grant and revocation history, applies explicit `project-owner` access consequences during ownership transfer, and checks current authenticated access before FACT-mediated protected decryption. Revoking one basis does not erase another surviving basis. The remaining work is:

- Replace the transitional confidential-note recipient encryption with a reviewed FACT-owned envelope format built around a fresh per-payload DEK, authenticated encryption and independently managed access envelopes. Do not invent cryptographic primitives or protocols; select established constructions only after explicit review.
- Minimise durable standalone decryption capability beyond the current FACT-mediated access check so possession of historical ciphertext and an old recipient key does not remain sufficient for future cryptographic access where forward exclusion is required.
- Add the remaining user-facing grant and specific-operator revocation workflows for files, notes and artefacts, including bulk project-removal handling. Project membership removal should revoke role-derived access while preserving direct object ownership or other surviving explicit authority.
- Add forward cryptographic exclusion for cases that require it by generating a fresh DEK and immutable replacement ciphertext representation that excludes revoked recipients. Preserve every historical encrypted representation and access event.
- Distinguish ordinary access revocation, lost credentials and compromised credentials. Compromise may require wider re-encryption and review than an ordinary role change.
- Extend explicit access consequences to later authority transitions and object classes without collapsing independent surviving bases.
- Design the project operational encryption capability separately from the exceptional project recovery key if mediated decryption requires a routinely available project-side component.
- Add a unique project recovery credential with finite configurable k-of-n threshold recovery shares. Recovery trustees must not become shadow owners or routine decryption recipients.
- Record recovery-policy creation and changes authentically. If fewer than k valid shares survive, recovery is impossible; do not create recursive recovery-for-recovery mechanisms.
- Add auditable owner-recovery workflows that distinguish consensual transfer from exceptional recovery and preserve failed/rejected recovery attempts.
- State the unavoidable disclosure limitation clearly: revocation cannot erase plaintext, keys or exports already retained outside FACT by a previously authorised operator.

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

- Build the interactive project-initialisation framework around a mandatory owner. Additional operators may be enrolled during initialisation or later through the same underlying authority framework.
- Formalise a project-local immutable `OPERATOR-######` identity alongside the operator UUID and a separate human-friendly alias/display handle. Preserve the UUID independently of credential rotation.
- Separate signing credentials from encryption credentials in FACT semantics and lifecycle even where a future backend can technically derive or store both beneath one identity.
- Create a protected project keyring for project-scoped operator and FACT cryptographic material. Do not silently mutate or depend on the user's ordinary/global GnuPG keyring as project authority state.
- Keep the architecture ready for a future cross-project operator keyring, but do not make that future facility a prerequisite for project-local initialisation.
- Add project-local cryptographic bootstrap during project creation for the operational and recovery material that the reviewed architecture requires. Store all project-owned configuration, public material, metadata and operational state beneath protected project directories.
- Use non-echoing passphrase prompts. Never accept human private-key passphrases as plaintext command-line arguments or retain them in SQLite, `PROJECT.toml`, audit details, logs or crash diagnostics.
- Validate every created or imported credential before committing initialisation: fingerprint/public-key inspection, signing challenge and verification, plus encryption/decryption self-test where applicable.
- Make initialisation transactional and fail closed: prepare privately, validate prerequisites and cryptography, build the catalogue, sign genesis, perform full verification, then promote the project to active state. Failed initialisation must not leave an apparently usable ownerless or partially authoritative project.
- Apply restrictive permissions, explicit purpose metadata, fingerprint validation, rollback and deliberate backup/recovery guidance to project-local keys. Never include project private key material in ordinary source distributions, exports or project packages.
- Add credential rotation, revocation, loss, compromise, recovery and retirement as lifecycle operations rather than treating bootstrap as one-off key generation.


## Version and state comparison

- Add file-, note-, artefact- and case-state comparison using approved system or library diff backends where appropriate.
- Normalise backend results into a FACT-owned comparison model and support raw unified terminal output, structured machine-readable output and an accessible graphical viewer.
- Resolve stable identities and lineage before comparison so case-state diffing reports object additions, removals, revisions and state changes rather than concatenating unrelated text.
- Enforce confidential-access boundaries before comparison and never allow diff tooling to become a decryption bypass.
- Keep comparisons transient and non-authoritative by default. If deliberately retained, check the result in as a new derivative FILE with provenance to both compared inputs.

## Operator activity, change attribution, provenance graphing and timeline queries

- Add operator activity interrogation across the entire project or a selected case or artefact, from project inception, since a recorded date, within a recorded date range, or between audit-sequence boundaries.
- Attribute direct authenticated actions separately from consequential state changes. Derived consequences must never be presented as though the operator explicitly performed an action they did not perform.
- Walk the relevant provenance and relationship graph where necessary so changes to a FILE revision can be attributed into its NOTE, artefact, case or project context without relying on filenames or denormalised prose.
- Add `--explain` output that gives the authenticated provenance path responsible for an attribution and can answer why FACT says a particular operator affected an object or scope.
- Add `--graph` output for the same verified query result. Support a readable ASCII terminal graph and self-contained HTML/SVG rendering rather than visualising the entire database indiscriminately.
- Add graph filters including depth limits, direct-only attribution, optional consequential changes, event-type filtering and object-type filtering. Keep the first CLI surface conservative while ensuring the query model can express these filters.
- Make HTML/SVG graph output accessible: colour must not be the sole relationship signal, edges and nodes need meaningful labels, interactive views need keyboard operation, and a textual/tabular representation should accompany the visual graph.
- Add a chronological project timeline derived from the canonical signed catalogue event stream and reuse the same verified query layer for richer project-closing HTML/SVG presentation.
- Support filtering by operator, case, artefact, acquisition, event type, object type, recorded time and audit sequence. Recorded date/time filters must be described as tamper-evident host-recorded time unless independently trusted timestamping is later available.
- Distinguish performed, authored, approved or rejected, owned, granted, revoked, transferred and otherwise affected relationships rather than collapsing all activity into a single meaning.
- Keep all reporting and graph presentation derived from authoritative catalogue history; none of these views becomes another source of truth.


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

## Cross-project operator identity and credential management

- Provide an explicitly managed FACT operator identity/keyring outside individual projects so stable operator UUIDs and authorised credentials can be reused deliberately without relying on the user's general-purpose GnuPG keyring.
- Keep cross-project identity state separate from project authority state. Enrolment into a project must remain explicit and auditable.
- Include privacy/linkability controls, credential rotation and revocation, backup/recovery and conservative trust boundaries.
- Do not implement this by reviving mutable local operator-profile authority or by silently mutating a user's ordinary/global keyring.
