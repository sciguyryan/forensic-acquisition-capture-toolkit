# FACT v2.10.0 field validation

This release establishes individually committed files as FACT's atomic evidential objects and strengthens catalogue verification around immutable file identity, storage paths, sizes and hashes. Field validation should concentrate on file check-in, all-or-nothing multi-file commits, missing or altered payload detection, never-reused file identifiers, richer collector-retained evidence, and regression of the existing authority, acquisition, note and packaging behaviour.

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

The acquisition should seal through the normal acquisition path and then appear in:

```text
record list
```

with status `pending` because the contributor is not the responsible case owner. The archive, original acquisition timestamp, operator attribution and cryptographic provenance must already be fixed and must not change when the owner later decides the record.

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

Also modify a copied evidence archive or other digest-bound evidence file and confirm its normal evidence verification fails. These tests demonstrate the intended security property: FACT cannot prevent a sufficiently privileged user from writing different bytes, but unauthorised modification should not silently verify as legitimate project history.

## Regression checks

Run representative owner and contributor screenshot acquisitions and one representative YouTube acquisition. Confirm successful evidence still follows the accepted sealing, detached-signature and self-verification process.

Create a project package and confirm catalogue verification occurs before export. Confirm the package retains the catalogue and sealed acquisition bundles while excluding private signing keys, passphrases, local GnuPG agent state, mutable staging directories and other operational material that does not belong in an evidential package.

The release tree should not contain generated `*.egg-info/`, `coverage.xml`, `.coverage`, `__pycache__/`, `.pytest_cache/` or other development output.


## Retained notes and confidential transfer

1. Create a project-visible note and confirm another active contributor can read it. Revise it with a reason and confirm the earlier revision remains readable.
2. Create a confidential note and confirm the author and current project owner can read it while another active contributor is denied. Inspect the catalogue and confirm the confidential title/body do not appear in the stored payload.
3. Propose a project ownership transfer to an active contributor and accept it. Confirm all confidential revisions are cycled before ownership changes, the new owner can read them, and the former owner cannot read a note unless they are its author.
4. Inject or simulate a failure during confidential-note re-encryption. Confirm the ownership transfer remains pending, the old owner remains authoritative, and all live confidential ciphertext remains in its pre-transfer state.
5. Package the project without changing note disclosure and confirm note payloads are absent from the package catalogue snapshot while note metadata and payload hashes remain. Explicitly include a confidential note and confirm the package still contains ciphertext rather than plaintext.
6. Remove or alter a committed note/revision in a disposable test project and confirm `fact catalogue verify` reports a sanctity violation rather than repairing or deleting history.

## Everything-as-a-file checks

After creating a disposable project, case and successful acquisition, inspect `cases/CASE-000001/files/`. Every retained acquisition file should have its own `FILE-######` directory and immutable payload copy. The catalogue `files` table should contain the same file IDs, logical paths, sizes and SHA-256 values.

Run `fact --root /path/to/project catalogue verify`. Verification must pass before tampering. Change one committed payload byte and run verification again. FACT must report that the committed file bytes changed. Restore the original test project rather than asking FACT to accept the changed bytes. In a second disposable project, remove one committed payload and confirm verification reports a missing committed file.

Where the collector captures network material, confirm request, response, header, body, metadata or diagnostic files that the collector intentionally retained are independently checked in rather than represented only as opaque acquisition metadata.

A failed multi-file check-in must not leave a partial set represented as committed. File identifiers already committed in successful history must never be reused.
