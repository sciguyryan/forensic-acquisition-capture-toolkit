# FACT development TODO

This document records accepted future work that has not yet been implemented. Completed work belongs in the changelog, release documentation, tests and repository history rather than remaining as checked-off TODO entries.

## Current ideal implementation order

The cryptographic constitution, complete current-capability project initialisation workflow, normative hash-chain specification and committed-file read-only baseline are implemented. The remaining work order is:

1. Recovery foundations and finite threshold-share configuration.
2. Operator signing/encryption credential lifecycle and project-local secret-key workflows.
3. Full revocable-authority workflows and decryption preflight.
4. Ownership-transfer, operator-removal and object-specific revocation consequences.
5. File-store crash hardening across filesystem/catalogue boundaries.
6. Generic encrypted artefacts and reviewed envelope-encryption implementation.
7. Notes and provenance-relationship follow-on.
8. Version and state comparison.
9. Operator activity, change attribution, provenance graphing and timeline queries.
10. Case lifecycle.
11. Generalised export expansion.
12. Cross-project operator identity and credential management.
13. Screenshot review/presentation and remaining assurance work.

Collector correctness fixes continue whenever discovered; formal collector-convergence expansion remains a later programme. Simple temporal sanity checks may land opportunistically before the larger trusted-time work.

## Provenance and temporal assurance

- Add optional external trusted timestamping or independently retained temporal anchors for projects that require evidence of real-world time rather than only tamper-evident recorded host time.
- Add conservative temporal sanity checks such as detecting backwards event-time movement or implausible clock discontinuities without pretending those checks provide trusted wall-clock proof.
- Decide whether a future project schema needs authenticated hash-algorithm transition epochs for exceptionally long-lived projects. The current integrity policy remains immutable from project genesis to closure.

## Identity and credential lifecycle

- Define deliberate operator UUID provisioning/reuse for future cross-project identity without reviving mutable local operator-profile authority.
- Separate signing credentials from encryption credentials in FACT semantics and lifecycle even where a backend can technically derive or store both beneath one identity.
- Extend the protected `.fact/crypto/` area into project-local private signing/encryption credential handling only through an explicit secure creation/import workflow. Never silently copy or mutate the user's ordinary/global GnuPG keyring.
- Use non-echoing passphrase prompts and secure secret-provider mechanisms. Never accept human private-key passphrases as plaintext command-line arguments or retain them in SQLite, `PROJECT.toml`, audit details, logs or crash diagnostics.
- Validate every created or imported credential before activation using fingerprint/public-key inspection, signing challenge/verification and encryption/decryption self-tests where applicable.
- Add auditable signing- and encryption-key rotation without invalidating historical signatures or rewriting the credential that represented an operator at an earlier catalogue sequence.
- Add explicit credential revocation, retirement, loss and compromise handling with conservative, highly visible exceptional transactions.
- Improve contributor public-key import and selection ergonomics while preserving the rule that project-retained identity cannot be silently redefined by local keyring state.
- Apply restrictive permissions, explicit purpose metadata, fingerprint validation, rollback and deliberate backup/recovery guidance to project-local keys. Never include project private key material in ordinary source distributions, exports or project packages.
- Extend individually signed authority semantics to later structural lifecycle operations where attribution is evidentially meaningful.

## Recovery foundations and exceptional recovery

- Add a unique project recovery credential separate from ordinary signing credentials and, if the final architecture requires it, separate from routinely available operational encryption capability.
- Protect the project recovery private capability with a finite configurable k-of-n threshold scheme using reviewed established cryptographic constructions. Trustees must not become shadow owners or routine decryption recipients.
- Provide sensible threshold validation and secure recovery-share/package generation. If fewer than k valid shares survive, recovery is impossible; do not create recursive recovery-for-recovery mechanisms.
- Record recovery-policy creation and later healthy rotation authentically. Support explicit no-recovery mode only with a recorded warning that loss of required credentials can permanently lock confidential material.
- Design reconstruction to minimise the lifetime and exposure of reconstructed private material.
- Integrate recovery configuration into the existing fail-closed project setup workflow once the recovery primitives are implemented.
- Add auditable exceptional owner recovery that cannot masquerade as consensual ownership transfer and preserves the reason, authority path and failed/rejected recovery attempts.

## Revocable confidential access and cryptographic lifecycle

- Replace transitional confidential-note recipient encryption with a reviewed FACT-owned envelope format built around a fresh per-payload DEK, authenticated encryption and independently managed access envelopes. Do not invent cryptographic primitives or protocols.
- Minimise durable standalone decryption capability. A valid credential must remain necessary but not sufficient: current authenticated authority must be checked before every protected decryption operation.
- Add user-facing per-object confidential access grant and revocation workflows using independent authority bases. Revoking one basis must not erase another surviving basis for the same operator and object.
- Add specific-operator revocation for files, notes and artefacts, including bulk project-removal handling. Project membership removal should revoke role-derived access while preserving direct object ownership or other surviving explicit authority.
- Add forward cryptographic exclusion where required by generating a fresh DEK and immutable replacement ciphertext representation that excludes revoked recipients. Preserve every historical encrypted representation and access event.
- Distinguish ordinary access revocation, lost credentials and compromised credentials. Compromise may require wider re-encryption and review than an ordinary role change.
- Make ownership transfer append explicit object-level access consequences. Access inherited only through `project-owner` must end when ownership changes; `object-owner`, `explicit-grant` and other independent surviving bases must remain.
- Design project operational encryption separately from the exceptional recovery key if mediated decryption requires a routinely available project-side component.
- State the unavoidable disclosure limitation clearly: revocation cannot erase plaintext, keys or exports already retained outside FACT by a previously authorised operator.

## File-store hardening

- Add a durable crash-recovery journal for the narrow filesystem/SQLite commit boundary so abrupt process or machine failure can be diagnosed and recovered conservatively without silently adopting unexplained files.
- Extend read-only protection auditing where platform-specific behaviour warrants it, while preserving the rule that permissions are advisory protection rather than the cryptographic integrity boundary.
- Investigate optional stronger platform-specific immutable-file attributes only as an explicitly supported hardening layer, never as a portability requirement or substitute for verification.
- Extend file relationships and presentation-state verification as derivation, review, retraction and filtered export workflows are implemented.

## Notes follow-on

- Add optional direct acquisition association to retained notes once acquisition-level review workflows need it.
- Add note-level retraction/presentation controls using append-only state transitions rather than deletion.
- Keep note rendering, searching and future disclosure controls layered on the ordinary file model rather than introducing a second payload store.

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
- Add `--graph` output for the same verified query result. Support readable ASCII terminal graphs and self-contained HTML/SVG rendering rather than visualising the entire database indiscriminately.
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

## Generalised evidence export

The v2.14 foundation implements authenticated export policy, immutable `EXPORT-######` events, native directory/tar export, full/presented views, multi-selection, export verification and confidential-note ciphertext/plaintext handling. Remaining expansion work is:

- Add rendered/flattened, structured and archival representations with deterministic transformation/provenance descriptions and verification semantics.
- Add first-class layered image/review export after annotation and proposed-redaction layers exist.
- Extend recipient-encryption UX and key selection while preserving output protection as a choice independent from source confidentiality.
- Implement a generic encrypted file/artefact payload format and authenticated streaming/chunk cryptography before enabling cryptographic authority transfer or plaintext export for large generic encrypted artefacts.
- Expand export receipts/summary presentation where useful without checking generated descriptors back into evidence automatically.
- If an exported/rendered result is deliberately checked back into FACT, admit it as a new immutable derivative file with explicit provenance.

## Cross-project operator identity and credential management

- Provide an explicitly managed FACT operator identity/keyring outside individual projects so stable operator UUIDs and authorised credentials can be reused deliberately without relying on the user's general-purpose GnuPG keyring.
- Keep cross-project identity state separate from project authority state. Enrolment into a project must remain explicit and auditable.
- Include privacy/linkability controls, credential rotation and revocation, backup/recovery and conservative trust boundaries.
- Do not implement this by reviving mutable local operator-profile authority or by silently mutating a user's ordinary/global keyring.

## Collector convergence follow-on

- Continue auditing source collectors as their capabilities expand so every intentionally retained evidential output is individually classified and checked in, while transient working data remains outside the authoritative record.
- Extend explicit file relationships when collectors gain richer source-specific context rather than encoding those relationships only in filenames or prose.
- Keep future image annotations, proposed redactions and rendered derivatives on the ordinary file/relationship foundation established by screenshot/image acquisition.

## Screenshot review and presentation

- Continue the generic review subsystem with editable structured annotations and auditable revision history.
- Support common screenshot-style annotation shapes including arrows, rectangles, circles/ellipses, lines, highlights, markers, text and freehand paths.
- Preserve the immutable original image. Annotation geometry remains in normalised coordinates and is rendered as separate scalable layers.
- Add proposed redactions as a separate layer with a mandatory reason for every redaction.
- Keep requested/proposed redactions distinct from destructively flattened redacted derivatives.
- Build a minimal self-contained HTML/SVG review application around the existing review-layer foundation.
- On project closure, generate a self-contained static HTML media browser for project evidence, derivatives, provenance, review layers and other appropriate retained records.

## Encrypted artefacts

- Extend the file-backed confidential-note model to general encrypted artefacts using ordinary immutable file/check-in machinery with special classification and access policy rather than a separate evidence store.
- Design authenticated streaming or chunk encryption for large artefacts so confidential handling remains practical without whole-file memory requirements.
- Treat ownership transfer as an all-or-nothing transition across every affected encrypted note revision and encrypted artefact. Decrypt, re-encrypt, validate and stage the complete set before committing any new ownership state.
- Never permit a non-authorised operator to export an encrypted artefact in decrypted form. Ordinary exports may exclude it or retain only its encrypted committed representation according to disclosure policy.
- Preserve every historical encrypted representation and hash. Re-encryption creates a new immutable representation rather than rewriting the old one.
