# FACT v2.14.0 field validation

This release adds authenticated export/disclosure history, project export policy, confidential-authority transfer, immutable artefact identities, scoped verification and multi-format verification reports on top of the everything-as-a-file catalogue architecture. Field validation should concentrate on export-to-history correspondence, exact file matching, verification scope, policy enforcement, confidential-note authority changes and regression of acquisition, packaging and whole-project integrity.

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
9. Create a confidential note. Confirm ordinary export emits its committed ciphertext. Confirm plaintext export requires the current project owner or current confidential authority holder according to policy and is recorded as a derived export output rather than byte-identical evidence.
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
4. Create a confidential note and confirm the author and current project owner can read it while another active contributor is denied. Inspect the corresponding committed revision file directly: the title and body must not appear in plaintext, the file classification must be `confidential-note-revision`, and its SHA-256 must match the `files` table.
5. Propose a project ownership transfer to an active contributor and accept it. Confirm the previous confidential revision file remains present, a new `FILE-######` cryptographic revision is appended, the note's current revision advances, and ownership changes only after the complete confidential transition succeeds.
6. Inject or simulate a failure during confidential-note re-encryption. Confirm the ownership transfer remains pending, the old owner remains authoritative, no new authoritative note revision remains committed, and the previous ciphertext file is untouched.
7. Package the project without changing note disclosure. Confirm withheld note revision bytes are absent from the package while their note IDs, file IDs, hashes and lineage remain represented in the catalogue snapshot. Mark a project note for inclusion and confirm its committed file appears. Mark a confidential note for inclusion and confirm the package contains ciphertext rather than decrypted plaintext.
8. Alter one note revision file byte and run `fact catalogue verify`. Verification must fail as a committed-file byte change. Restore from the disposable backup, remove the revision file, and confirm verification reports a missing committed file. FACT must not repair either condition by blessing replacement bytes or deleting history.

## Everything-as-a-file checks

After creating a disposable project, case and successful acquisition, inspect `cases/CASE-000001/files/`. Every retained acquisition file should have its own `FILE-######` directory and immutable payload copy. The catalogue `files` table should contain the same file IDs, logical paths, sizes and SHA-256 values.

Run `fact --root /path/to/project catalogue verify`. Verification must pass before tampering. Change one committed payload byte and run verification again. FACT must report that the committed file bytes changed. Restore the original test project rather than asking FACT to accept the changed bytes. In a second disposable project, remove one committed payload and confirm verification reports a missing committed file.

Where the collector captures network material, confirm request, response, header, body, metadata or diagnostic files that the collector intentionally retained are independently checked in rather than represented only as opaque acquisition metadata.

A failed multi-file check-in must not leave a partial set represented as committed. File identifiers already committed in successful history must never be reused.
