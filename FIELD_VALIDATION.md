# FACT v2.19.0 Setup Stewardship field validation

This candidate completes the current-capability project initialisation workflow, publishes the normative hash-chain specification and test vectors, and adds advisory read-only protection for committed evidential payloads. Recovery and separate encryption-credential provisioning remain intentionally unimplemented until their dedicated reviewed phases; when implemented, they must extend the same fail-closed setup boundary rather than create a second setup path.

## Required local Arch checks

```fish
python -m ruff check src tests
python -m ruff format --check src tests
python -m pytest
```

Ruff is not installed in the assistant validation environment, so both Ruff commands are mandatory local acceptance checks.

## Complete setup workflow

1. Run `fact project init /tmp/fact-setup-test` without `--project-id` or `--title` from a real terminal. Confirm the guided workflow prompts for both values. Repeat non-interactively without those options and confirm FACT fails closed rather than inventing values.
2. Select the mandatory owner and a real signing credential. Confirm setup exercises the selected signing key before project creation can become active.
3. Choose to add at least one additional locally available operator. Confirm that operator signs their own acceptance during the same setup and becomes an active contributor with the next immutable `OPERATOR-######` reference.
4. Repeat with `--no-additional-operators` and confirm setup completes with only the owner.
5. Confirm `.fact-initialising` exists during an intentionally interrupted setup and that project discovery refuses to treat that directory as active.
6. Force an owner-signing, contributor-enrolment or final-verification failure in a disposable test. Confirm the setup-created `PROJECT.toml`, `.fact/`, `cases/` and `files/` state is unwound and the failed project is not discoverable as active.
7. On a successful setup, run `fact --root /tmp/fact-setup-test verify project` and confirm exhaustive verification succeeds.

## Cryptographic integrity specification

1. Review `docs/CRYPTOGRAPHIC_INTEGRITY.md` independently of the implementation. Confirm it specifies exact content-byte hashing, canonical JSON rules, all `fact-audit-event/v3` fields, all-zero genesis predecessor construction, rolling linkage, current-state digest coverage, checkpoint semantics, package/export distinction and limitations.
2. Independently reproduce normative vector A using SHA-256. The expected digest is `a35b6665e9e904d28036064a2f35ea2ca1783117b286dd8811c400033435e567`.
3. Independently reproduce normative vector B using SHA3-512. The expected digest is `0d8fd4057c06c25126bb84d2ab312f04fa256dddd0d421774a6dcdff780b90d5d666eddc03b46d6b0680269634ee62a0ac8aa2b7437478e2f4afacd31827c007`.
4. Confirm the UTF-8 word `café` is represented with bytes `c3 a9`, object keys are sorted, insignificant whitespace is absent and no newline is included in canonical material.
5. Confirm `docs/PROJECTS_AND_CATALOGUE.md` describes the live chain using the project-selected chain-hash profile, schema 11 and `fact-audit-event/v3`.

## Read-only committed payload protection

1. Commit ordinary evidence and inspect each authoritative payload. On the normal Arch/POSIX filesystem it should have mode `0400`; containing project directories remain owner-only and traversable as required.
2. Confirm `fact verify project` succeeds and reports no writable committed payloads.
3. In a disposable copy, `chmod 600` one committed payload without changing its bytes. Full verification should still verify the bytes but report that the committed payload is unexpectedly writable.
4. Alter the bytes of that writable payload. Verification must fail as changed evidence rather than merely issuing the permission warning.
5. Restore or recreate the test project. Confirm a legitimate evidence change is represented by a new FILE/revision rather than by FACT making the committed payload writable in place.
6. If testing on a filesystem where permission hardening is unsupported, confirm evidence commitment remains authoritative and verification exposes the weakened protection posture rather than leaving a half-committed database/filesystem state.

---

## v2.17 cryptographic-constitution candidate

## v2.18.0 Identity Inception candidate

Assistant-side validation for this candidate covers the schema-11 operator-reference and bootstrap changes. The complete automated suite passes with 197 tests and 80.63% branch-aware coverage; `python -m compileall -q src tests` also passes. The normal owner bootstrap now remains marked incomplete until signed genesis and exhaustive project verification succeed. `OPERATOR-######` references are included in authenticated reconstructed operator state, and tests cover lookup by project reference/UUID plus direct reference tampering. The protected `.fact/crypto/` directory is a structural foundation only; this candidate does not copy private operator keys into the project.

Required local Arch checks remain:

```fish
python -m ruff check src tests
python -m ruff format --check src tests
python -m pytest
```


The v2.17 candidate introduces authenticated multi-basis confidential access state and changes project/catalogue schema to version 10. Before accepting the candidate on Arch Linux, run the complete test and Ruff validation suite and exercise a real confidential-note ownership transfer with the configured local cryptographic tooling.

Required checks:

```fish
python -m ruff check src tests
python -m ruff format --check src tests
python -m pytest
```

Confirm that an outgoing project owner loses access to confidential material they held only through the `project-owner` basis, while retaining access to confidential material for which they retain an independent `object-owner` basis. Confirm that the incoming owner can read the re-encrypted current revision and that `fact verify project` succeeds afterwards.

The new access-authority foundation does not yet implement the planned DEK/envelope-encryption, mediated decryption or threshold-recovery mechanisms. Do not interpret v2.17 as providing cryptographic erasure of access already exercised outside FACT.

# FACT v2.15.0 field validation

This release hardens FACT's provenance spine by assigning each retained operator an immutable UUID and binding operator identity, credential attribution and authority context directly into the versioned rolling-hash event envelope. It preserves the v2.14 export, verification and confidential-authority architecture. Field validation should concentrate on UUID persistence, audit-envelope tamper detection, export-to-history correspondence, exhaustive project verification and regression of acquisition, packaging and confidential authority.


## Provenance-spine checks

1. Create a fresh disposable project and inspect `.fact/catalogue.sqlite`. Confirm the initial owner has both the human-friendly project-local `operator_id` and a non-empty unique `operator_uuid`. Invite and accept another operator and confirm the two UUID values differ.
2. Inspect the `PROJECT_GENESIS` and contributor acceptance audit rows. Operator-authored rows must contain `actor_kind = operator`, the project-local actor ID, the retained immutable operator UUID, the signing fingerprint used for that authority transaction and a non-empty authority basis. Identifier-allocation rows should instead be explicit system events.
3. Inspect the signed authority transaction nested in an operator-authored event. Confirm its `actor_uuid` matches the outer audit row UUID and its signing fingerprint matches the outer credential fingerprint.
4. In a disposable database copy, change only `audit_events.actor_uuid` for one signed event and run `fact verify project` or `fact catalogue verify`. Verification must fail because the changed UUID is part of the rolling event hash.
5. Restore the valid project, then change only `operators.operator_uuid` directly. Verification must fail because reconstructed signed authority state and checkpoint state digest no longer agree with the live operator table.
6. Perform a native export and run `fact verify export /path/to/export`, followed by `fact verify project`. Both must succeed. Inspect `EXPORT_STARTED` and `EXPORT_COMPLETED`: both must bind the exporting operator's project ID, immutable UUID and signing fingerprint.
7. Confirm full project verification remains exhaustive and rehashes every committed `FILE-######` payload after the export. Exported bytes and verification reports must remain external representations rather than silently becoming project evidence.

## Collector convergence checks

### YouTube retained-file boundary

1. Run a successful disposable YouTube acquisition with a source that exposes several kinds of material, such as media, source metadata, a thumbnail and captions where available.
2. Inspect the acquisition's committed `FILE-######` entries. Confirm each retained source item and each retained FACT acquisition record has its own file identity.
3. Confirm the primary media is classified `primary`, yt-dlp `.info.json` material is `source_metadata`, HTTP capture material is `network`, and ffprobe/MediaInfo reports are `inspection`.
4. Confirm descriptive and inspection files that have a primary media target carry explicit file relationships rather than relying only on matching filenames.
5. Confirm successful acquisition state contains no yt-dlp `.part`, `.ytdl`, `.tmp`, `.temp` or fragment scratch files. Such transient working material must not receive `FILE-######` identities. Successful `.fact/staging/acquisitions/` state should be removed after commitment and verification.

### Screenshot/image retained-file boundary

1. Capture a disposable screenshot through the supported image acquisition path.
2. Confirm the exact original image bytes are committed as a `primary` file and `screenshot-capture.json` is committed separately as `metadata`.
3. Confirm the metadata file has a `describes` relationship to the original image file.
4. Verify the catalogue, then alter a committed screenshot byte and confirm verification detects the changed file. Restore the disposable project or repeat with a fresh capture before further testing.
5. Confirm no annotation or redaction file is invented by acquisition. Those remain later review-layer work built on the immutable original.


## Sealing and integrity convergence checks

1. Create a disposable successful acquisition and inspect the project root. Confirm no `archived/CASE-....7z` acquisition package or acquisition hash/signature sidecars are created.
2. Confirm there is no retained `EVIDENCESET-SHA256.txt`, `FILELIST.txt`, `SHA256SUMS.txt`, `SHA512SUMS.txt`, `CASE_RECORD.json`, `CASE_RECORD.md`, `TOOLKIT.json`, `VERIFICATION.txt`, `operator-identity.json` or copied acquisition public-key file unless a collector independently and explicitly retained a file with a different evidential purpose.
3. Inspect `.fact/catalogue.sqlite`. The `ACQUISITION_RECORDED` authority transaction must contain the exact ordered `file_ids` list for the acquisition and the structured source/tool/observation record.
4. Compare that list with `files.acquisition_id = ACQ-######`. They must agree exactly. Directly alter the signed event or the live file association in a disposable copy and confirm verification rejects the mismatch.
5. Confirm `acquisition.log` is checked in once as a `transcript` file and there is no second successful `logs/` copy.
6. Confirm the successful `.fact/staging/acquisitions/.staging-...` directory is removed only after catalogue verification succeeds.
7. Force a collector failure or leave an unregistered scratch file in staging. FACT must refuse successful commitment, retain the `INCOMPLETE` staging tree for diagnosis, and not assign `FILE-######` identities to that unauthoritative material.
8. Run `fact --root /path/to/project verify project` and `fact --root /path/to/project catalogue verify`. Both should validate the authoritative project model rather than requiring an acquisition archive.



## Export, authority and verification checks

1. Authenticate as the project owner and run `fact export policy show`. Confirm the policy is read from authenticated project state. Change one policy value with `fact export policy set`, verify the project, and confirm the policy change remains visible. In a disposable database copy, edit the policy row directly and confirm verification fails.
2. Perform a native directory export of a file, artefact, acquisition and case. Confirm each attempt receives a distinct never-reused `EXPORT-######` and that the completed event records the actor, scope, policy sequence, view, source file identities, output paths and digests.
3. Inspect `FACT-EXPORT.json`. Confirm it describes the exported representation but is not checked back into the project's `FILE-######` store. Generate a verification report and confirm the report likewise remains external unless deliberately admitted by a separate future check-in workflow.
4. Run `fact verify export /path/to/export`. Confirm it identifies the exact `EXPORT-######`, validates the descriptor and output hashes, and maps the export back to the committed source file identities. Add, alter or remove an exported file in a disposable copy and confirm export verification fails.
5. Copy one committed payload outside the project and run `fact verify file /path/to/copy`. Confirm every matching `FILE-######` is reported. If two independent file identities contain identical bytes, both must appear. Alter the copy and confirm it reports no correspondence rather than blessing the altered bytes.
6. Run `fact verify artefact ART-######`, `fact verify acquisition ACQ-######`, `fact verify case CASE-######`, `fact verify id FILE-######`, and `fact verify project`. Confirm narrow structural verification states that unrelated sibling payloads were not rehashed, while project verification is exhaustive.
7. Produce text, HTML, JSON and PDF reports with `--report`, `--output` and `--detailed`. Confirm each carries the same result/status semantics, identifies its verification scope and limitations, and does not create a project file identity.
8. Authenticate as a non-owner active member. Exercise ordinary and broad-scope export under both permissive and owner-only policies. Confirm policy enforcement is fail-closed and a denied operator cannot obtain a successful export merely by selecting a narrower CLI path.
9. Create a confidential note. Confirm ordinary export emits its committed ciphertext. Confirm plaintext export requires both project export permission and current authenticated confidential access and is recorded as a derived export output rather than byte-identical evidence.
10. As project owner, propose a `TRANSFER-######` for the confidential note to another active member. Confirm the outgoing authority holder cannot accept it. Have the nominated incoming member accept it and verify that immutable creator attribution is unchanged, a new cryptographic note revision is committed, current authority changes only after successful re-encryption, and the former authority holder can no longer decrypt through FACT.
11. Repeat with rejection and owner cancellation. Confirm the proposal and outcome remain in authenticated history. Attempt a generic encrypted file/artefact authority transfer and confirm FACT refuses it until the generic encrypted-payload cryptographic transition is implemented rather than pretending authority moved.
12. For a tar export protected to a recipient key, confirm the encrypted envelope's digest corresponds to the recorded export. `fact verify export` may establish exact envelope correspondence without decryption, but must clearly state that the internal plaintext representation was not independently inspected.

## Fresh environment

From the extracted release directory on Arch Linux with fish:

```fish
python -m venv .venv
source .venv/bin/activate.fish
python -m pip install -e '.[dev,screenshot]'
```

Run the release gates without modifying the tree:

```fish
python -m ruff check src tests
python -m ruff format --check src tests
python -m pytest
```

All three must pass before the release candidate is promoted.

## Initial owner and project creation

Create a disposable project. FACT will collect the initial owner identity and signing key directly during project genesis:

```fish
fact project init /tmp/fact-authority-test --project-id FACT-AUTHORITY-TEST --title "FACT authority test"
```

Expected behaviour:

1. The operator must sign the initial authority transaction.
2. FACT reports the project creation and initial owner.
3. `fact --root /tmp/fact-authority-test authority status` reports authority as active and names the retained owner.
4. `fact --root /tmp/fact-authority-test catalogue verify` succeeds.

If signing the initial authority transaction is cancelled or fails, FACT should remove the incomplete newly created project state rather than leave an apparently usable ownerless project.

## Legacy project boundary

Use a disposable project created by an older FACT build to confirm that current FACT recognises the project as belonging to a different schema and refuses to mutate it in place. Do not import profile data, create a current authority root, or rewrite the older project. Active legacy projects remain on the FACT version under which they were created until they are closed.

## Shell authentication

Start the shell in the test project:

```fish
fact --root /tmp/fact-authority-test shell
```

Run:

```text
context
auth OWNER-ID
whoami
```

The authentication step should invoke the active operator signing key and the shell should then display the authenticated operator. `logout` must clear that identity. Selecting or clearing another project must also clear it.

Before `auth`, attempt a protected mutation such as `case create`. The shell should refuse it and direct the operator to authenticate. Read-only inspection such as `catalogue verify`, `authority status`, `contributor list`, and `record list` should remain available as appropriate.

## Contributor admission

Using a second disposable operator identity whose public key is available to the local GnuPG environment, have the owner record an invitation:

```fish
fact --root /tmp/fact-authority-test --operator-id OWNER-ID contributor invite CONTRIBUTOR-ID --name "Contributor Name" --key-fingerprint PRIMARY-FINGERPRINT --signing-fingerprint SIGNING-FINGERPRINT
fact --root /tmp/fact-authority-test contributor list
```

The contributor should initially appear as `pending` and must not be allowed to submit project work merely because the owner invited them.

Accept the invitation using the contributor's project-retained operator ID and corresponding signing key:

```fish
fact --root /tmp/fact-authority-test --operator-id CONTRIBUTOR-ID contributor accept
```

The acceptance must be signed by the invited contributor's registered key. `contributor list` should then show the contributor as active.

Also test rejection with another disposable invitation. The rejected identity should remain represented historically rather than disappearing.

## Ownership transfer

As the current owner, propose a transfer to an active contributor:

```fish
fact --root /tmp/fact-authority-test owner transfer CONTRIBUTOR-ID --reason "Field validation handover"
```

`owner current` must still report the original owner until the transferee accepts. Switch to the incoming operator and run:

```fish
fact --root /tmp/fact-authority-test owner accept
fact --root /tmp/fact-authority-test owner current
fact --root /tmp/fact-authority-test catalogue verify
```

The incoming operator should become owner only after their signed acceptance. Repeat with disposable transfers to exercise signed rejection and owner cancellation. Historical ownership must not be rewritten.

## Case responsibility and contributor acquisition

Create and select a disposable case as the current project owner. The case should receive signed initial ownership automatically.

Switch to an active contributor, authenticate in the shell, and perform a screenshot acquisition:

```text
PROJECT-ID / CASE-000001> auth CONTRIBUTOR-ID
PROJECT-ID / CASE-000001> acquire screenshot --acquisition-comment "Pending contributor acquisition"
```

The acquisition should commit its retained files, record the authenticated acquisition event, pass full project verification and then appear in:

```text
record list
```

with status `pending` because the contributor is not the responsible case owner. The committed file set, original acquisition timestamp, operator attribution and provenance must already be fixed and must not change when the owner later decides the record.

As the responsible owner, approve the acquisition:

```text
record approve ACQ-000001
```

For another contributor acquisition, reject it with a reason:

```text
record reject ACQ-000002 --reason "Outside agreed evidential scope"
```

Both acquisitions must remain listed. The second should be retained as `rejected`, not deleted or made to appear never to have existed.

## Tamper detection

Make a backup of the disposable test project before this section. Direct database changes are intentionally destructive to the test copy.

With the project in a valid state, confirm:

```fish
fact --root /tmp/fact-authority-test catalogue verify
```

Then use an SQLite client against `.fact/catalogue.sqlite` to alter one current-state authority field without creating the corresponding signed event. Suitable disposable tests include changing an operator name, replacing retained public-key text, changing an active contributor to removed, substituting a case owner, or changing a pending record to approved.

Run catalogue verification again. FACT must reject the altered state because reconstruction from signed history no longer matches the live authority tables.

Restore the valid backup before testing another tamper scenario. Do not treat a successful direct SQL write as a FACT-supported mutation.

Also modify one committed `FILE-######` payload and confirm `fact verify project` or `fact catalogue verify` fails. These tests demonstrate the intended security property: FACT cannot prevent a sufficiently privileged user from writing different bytes, but unauthorised modification must not silently verify as legitimate project history.

## Regression checks

Run representative owner and contributor screenshot acquisitions and one representative YouTube acquisition. Confirm each successful acquisition leaves only individually committed retained files plus authenticated catalogue state. There must be no per-acquisition `.7z`, `EVIDENCESET-SHA256.txt`, `FILELIST.txt`, internal SHA-256/SHA-512 manifest, archive checksum sidecar, detached acquisition signature or acquisition verification report.

Create a project package and confirm catalogue verification occurs before export. Confirm the package retains `PROJECT.toml`, the catalogue snapshot, project/case committed file trees and package-specific verification metadata while excluding private signing keys, passphrases, local GnuPG agent state, acquisition staging and any legacy `archived/` directory that happens to exist.

The release tree should not contain generated `*.egg-info/`, `coverage.xml`, `.coverage`, `__pycache__/`, `.pytest_cache/` or other development output.


## File-backed notes and confidential transfer

1. Create a project-visible note with no case association. Inspect the catalogue and project tree. Revision 1 must point to a `FILE-######` row and its bytes must live below `files/FILE-######/`, not inside a note payload BLOB in SQLite. Confirm another active contributor can read it.
2. Revise the note with a reason. Confirm revision 2 has a different `FILE-######` identity and that the revision 1 file still exists unchanged and remains readable by explicitly selecting revision 1.
3. Create a case-level note. Its revision file must live below `cases/CASE-######/files/`. If the note is associated with an existing committed file, inspect `file_relationships` and confirm an explicit `note-about` relationship connects the subject file to the note revision file.
4. Create a confidential note and confirm the author and current project owner can read it while another active contributor is denied. Inspect the corresponding committed revision file directly: the title and body must not appear in plaintext, the file classification must be `confidential-note-revision`, and its digest under the project-selected content-hash profile must match the `files` table.
5. Propose a project ownership transfer to an active contributor and accept it. Confirm the previous confidential revision file remains present, a new `FILE-######` cryptographic revision is appended, the note's current revision advances, and ownership changes only after the complete confidential transition succeeds.
6. Inject or simulate a failure during confidential-note re-encryption. Confirm the ownership transfer remains pending, the old owner remains authoritative, no new authoritative note revision remains committed, and the previous ciphertext file is untouched.
7. Package the project without changing note disclosure. Confirm withheld note revision bytes are absent from the package while their note IDs, file IDs, hashes and lineage remain represented in the catalogue snapshot. Mark a project note for inclusion and confirm its committed file appears. Mark a confidential note for inclusion and confirm the package contains ciphertext rather than decrypted plaintext.
8. Alter one note revision file byte and run `fact catalogue verify`. Verification must fail as a committed-file byte change. Restore from the disposable backup, remove the revision file, and confirm verification reports a missing committed file. FACT must not repair either condition by blessing replacement bytes or deleting history.

## Everything-as-a-file checks

After creating a disposable project, case and successful acquisition, inspect `cases/CASE-000001/files/`. Every retained acquisition file should have its own `FILE-######` directory and immutable payload copy. The catalogue `files` table should contain the same file IDs, logical paths, sizes and configured content-digest values.

Run `fact --root /path/to/project catalogue verify`. Verification must pass before tampering. Change one committed payload byte and run verification again. FACT must report that the committed file bytes changed. Restore the original test project rather than asking FACT to accept the changed bytes. In a second disposable project, remove one committed payload and confirm verification reports a missing committed file.

Where the collector captures network material, confirm request, response, header, body, metadata or diagnostic files that the collector intentionally retained are independently checked in rather than represented only as opaque acquisition metadata.

A failed multi-file check-in must not leave a partial set represented as committed. File identifiers already committed in successful history must never be reused.


## Project hash-agility checks

Create disposable projects using at least the default SHA-256 profile and one 512-bit alternative such as SHA3-512. Confirm `PROJECT.toml` records both `[integrity].chain_hash` and `[integrity].content_hash`, and confirm signed project genesis records the same policy. For the SHA3-512 project, commit representative evidence, create an export, verify the external export, then run exhaustive project verification. The rolling chain head and committed content digests should be 128 hexadecimal characters and verification must rehash every committed file successfully.

Repeat project creation for the supported standard-library profiles (`sha256`, `sha512`, `sha3-256`, `sha3-512`, `blake2b-256`, `blake2b-512`, `blake2s-256`). Test `blake3-256` with the packaged `blake3` dependency installed. FACT must reject a selected algorithm if its implementation is unavailable rather than falling back to another digest.

In a disposable project, change only `PROJECT.toml` so its integrity policy differs from the catalogue, then run full project verification. Verification must fail. Restore the project, then alter the catalogue integrity metadata without corresponding signed genesis/history and confirm verification also fails. Hash policy is selected at project genesis and is not an in-place mutable setting.
