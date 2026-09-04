# FACT v2.8.0 field validation

This release establishes FACT's project identity, authority and tamper-detection foundation. Field validation should concentrate on signed initial ownership, project-retained identity, contributor admission, ownership transfer, pending/approved/rejected acquisition state, authenticated shell context, catalogue tamper detection, and regression of existing acquisition and packaging behaviour.

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

Create a disposable signing key in the local GnuPG environment and note its full fingerprint. Then create a disposable project while supplying the initial owner identity explicitly:

```fish
fact project init /tmp/fact-authority-test --project-id FACT-AUTHORITY-TEST --title "FACT authority test" --owner-id OWNER-ID --owner-key OWNER-FINGERPRINT
```

Expected behaviour:

1. The operator must sign the initial authority transaction.
2. FACT reports the project creation and initial owner.
3. `fact --root /tmp/fact-authority-test authority status` reports authority as active and names the retained owner.
4. `fact --root /tmp/fact-authority-test catalogue verify` succeeds.

If signing the initial authority transaction is cancelled or fails, FACT should remove the incomplete newly created project state rather than leave an apparently usable ownerless project.

## Legacy authority bootstrap

For a disposable project created by an older FACT build, run:

```fish
fact --root /path/to/legacy-project authority status
fact --root /path/to/legacy-project authority bootstrap --operator-id OWNER-ID --signing-key OWNER-FINGERPRINT
fact --root /path/to/legacy-project catalogue verify
```

The first command should report uninitialised authority. Bootstrap should require a valid operator signature. Earlier catalogue events must remain historically earlier than the authority root and must not be retroactively attributed to the bootstrap operator.

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

The authentication step should resolve the owner's project-retained fingerprint, invoke the matching private key from the local GnuPG environment, and then display the authenticated operator. `logout` must clear that identity. Selecting or clearing another project must also clear it.

Before `auth`, attempt a protected mutation such as `case create`. The shell should refuse it and direct the operator to authenticate. Read-only inspection such as `catalogue verify`, `authority status`, `contributor list`, and `record list` should remain available as appropriate.

## Contributor admission

Create a second disposable signing key and export only its public key for admission to the project. Have the owner record an invitation using the contributor's explicit operator ID and public verification key:

```fish
gpg --armor --export CONTRIBUTOR-FINGERPRINT > /tmp/contributor-public-key.asc
fact --root /tmp/fact-authority-test contributor invite --operator-id CONTRIBUTOR-ID --public-key /tmp/contributor-public-key.asc
fact --root /tmp/fact-authority-test contributor list
```

The contributor should initially appear as `pending` and must not be allowed to submit project work merely because the owner invited them.

Accept the invitation as that operator by selecting the project-retained contributor identity explicitly:

```fish
fact --root /tmp/fact-authority-test contributor accept --operator-id CONTRIBUTOR-ID
```

The acceptance must be signed by the invited contributor's registered key. `contributor list` should then show the contributor as active.

Also test rejection with another disposable invitation. The rejected identity should remain represented historically rather than disappearing.

## Ownership transfer

As the current owner, propose a transfer to an active contributor:

```fish
fact --root /tmp/fact-authority-test owner transfer CONTRIBUTOR-ID --reason "Field validation handover"
```

`owner current` must still report the original owner until the transferee accepts. Use the incoming operator's project-retained identity and run:

```fish
fact --root /tmp/fact-authority-test owner accept --operator-id CONTRIBUTOR-ID
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

Create a project package and confirm catalogue verification occurs before export. Confirm the package retains the catalogue, project-retained public verification material and sealed acquisition bundles while excluding private signing keys, passphrases, local GnuPG agent state, mutable staging directories and other ignored operational material. Confirm no `operators/` profile directory or active-profile configuration is created by the 2.8 workflow.

The release tree should not contain generated `*.egg-info/`, `coverage.xml`, `.coverage`, `__pycache__/`, `.pytest_cache/` or other development output.
