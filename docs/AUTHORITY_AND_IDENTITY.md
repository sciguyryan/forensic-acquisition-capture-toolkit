# Authority, identity and project integrity

FACT treats operator identity, project membership, ownership and approval state as part of the evidential meaning of a project. These records are therefore retained inside the same tamper-evident SQLite catalogue that records project identifiers and lifecycle events. FACT does not maintain a separate mutable operator-profile database. Private signing capability remains outside the project, while the public identity and verification material needed to interpret project history remain inside the catalogue.

The design has two related goals. FACT should be able to establish which project identity performed or authorised an action at the point it occurred, and it should make later unauthorised alteration of that attribution detectable. FACT does not attempt to make a writable filesystem physically immune to tampering.

A useful summary of the security model is:

> FACT does not prevent all tampering. It is designed to make unauthorised modification detectable.

## Project authority

Every newly created FACT project must establish an initial owner before the project is considered usable. Project creation through the normal CLI therefore creates the project and its signed authority genesis as one operation. If the initial owner cannot sign the genesis transaction, FACT removes the incomplete empty project rather than leaving an apparently usable ownerless project behind.

The signed project genesis is the first hash-chained authority event. The initial owner is not an editable field in `PROJECT.toml` and cannot be replaced by changing unrelated local state.

Projects created under an older FACT trust model are not upgraded in place. An active legacy project should remain on the FACT version and project schema under which it was created until it is closed. Current FACT may recognise an incompatible project and refuse to mutate it, but it does not import old profile state, manufacture ownership history, reinterpret old signatures, or otherwise imply interoperability between incompatible authority models.

Check the current authority state with:

```bash
fact --root /path/to/project authority status
```

## Operator identity and signing keys

A project-retained operator identity includes a human-friendly project-local operator ID, a randomly generated immutable operator UUID, public descriptive fields, full signing-key fingerprints and the public OpenPGP key material required to verify signed authority transactions. The UUID is created once when the operator first enters project authority and is not derived from a key, name, email address or other mutable attribute. Private keys, passphrases, GnuPG agent state and session authentication secrets are never stored in the catalogue.

FACT has no persistent local operator-profile file. When a new project is created, the proposed owner supplies their public identity details and selects a usable secret signing key from the local GnuPG keyring. FACT retains the resulting public identity, full signing fingerprints and exported public key inside the new project catalogue. Subsequent project operations identify the operator by the project-retained operator ID and verify signatures against the retained public key material.

Historical public verification material is retained with the project so that a later verifier does not have to rely on the originating workstation or an external keyserver merely to understand which key signed a historical project transaction.

A valid cryptographic signature demonstrates control of the private key associated with the retained operator identity at that point in project history. It does not prove that a particular biological person personally operated the keyboard. Key custody, workstation security, hardware-token policy and compromise response remain important operational controls outside the cryptographic claim FACT can make.

A UUID identifies the retained operator across credential changes. A signing fingerprint identifies the credential used at a particular point in history. FACT deliberately keeps these concepts separate so future key rotation can append credential history without rewriting earlier attribution or changing the operator's UUID.

## Signed authority transactions

Authority-changing events use a canonical signed transaction before they are appended to the rolling catalogue chain. The signed payload binds the transaction to the project, event type, object, actor, actor signing-key fingerprint, intended event sequence, previous chain head, timestamp and event-specific data.

FACT immediately verifies the new signature against the project-retained public key and the exact historical signing fingerprint before appending the event. Catalogue verification later reconstructs the authority state from those signed events and checks the signatures again.

The rolling hash and transaction signature provide different assurances. The versioned `fact-audit-event/v2` envelope protects event ordering and commits the event timestamp, event/object identity, actor kind, project-local operator ID, immutable operator UUID, credential fingerprint, authority basis, event details and previous hash. The `fact-authority-transaction/v2` signature independently binds the operator UUID and signing fingerprint to the authority transaction. Verification cross-checks the signed transaction against the outer event attribution. The rolling chain therefore detects later alteration of provenance fields, while the operator signature demonstrates control of the corresponding registered signing key for the exact signed transaction. Neither mechanism is treated as a substitute for the other.

## Session authentication

The interactive FACT shell supports an authenticated operator context. Run:

```text
PROJECT-ID> auth OPERATOR-ID
```

FACT generates a fresh project-scoped challenge containing the project identity, operator identity, signing fingerprint, timestamp, purpose and a random nonce. The local operator signs that challenge and FACT verifies it against the project-retained public key before the shell marks the operator as authenticated.

Use:

```text
PROJECT-ID> whoami
PROJECT-ID> logout
```

Session authentication is deliberately not sufficient on its own for authority-changing project transactions. Consequential authority events still receive their own transaction signature. The session establishes who is currently operating the shell; the transaction signature binds that operator to the exact mutation entered into project history.

Changing the selected project clears the authenticated shell identity. A new project therefore requires a new authentication challenge.

## Contributors

The project owner controls contributor admission, but contributor membership is not created solely by the owner's assertion. A normal contributor relationship has two stages.

The owner first records a signed invitation:

```bash
fact --root /path/to/project --operator-id OWNER-ID contributor invite CONTRIBUTOR-ID --name "Contributor Name" --key-fingerprint PRIMARY-FINGERPRINT --signing-fingerprint SIGNING-FINGERPRINT
```

The invited operator must then use their own registered signing key to accept:

```bash
fact --root /path/to/project --operator-id CONTRIBUTOR-ID contributor accept
```

Until acceptance, the membership remains `pending` and the operator cannot submit project work as an active contributor. The invited operator can instead reject the invitation. An active contributor can later be removed by the owner with a mandatory reason. Invitations, acceptance, rejection and removal remain in project history rather than being erased.

Current membership can be inspected with:

```bash
fact --root /path/to/project contributor list
```

The initial authority model deliberately keeps roles small. FACT currently distinguishes the responsible owner from contributors rather than introducing a general-purpose access-control hierarchy before concrete project operations require one.

## Project and case ownership

The project owner is the human authority represented by the project ledger. Cases also have a responsible owner. A newly created case is assigned to the current project owner through a signed case-ownership event, so there is no ordinary ownerless interval between case creation and responsibility assignment.

Ownership history is append-only. A normal transfer is proposed by the current owner and does not become effective until the intended incoming owner accepts using their own registered signing key.

For example:

```bash
fact --root /path/to/project owner transfer operator-id --reason "Handover"
fact --root /path/to/project owner accept
```

The same model can be applied to a case by supplying `--case-id`.

A proposed transfer may be rejected by the transferee or cancelled by the current owner. Rejection and cancellation require reasons and remain visible in the transaction history. A later transfer does not rewrite who owned the project or case at an earlier catalogue sequence.

This historical distinction is important. If an operator creates or approves material before transferring ownership, the transfer cannot make that earlier work appear to have belonged to the incoming owner.

## Recorded material and owner decisions

A successfully committed acquisition is recorded in the authority ledger immediately after its retained `FILE-######` set has been checked in. The record is therefore part of the same rolling history whether the acquisition was performed by the owner or by a contributor.

When the responsible case owner performs the acquisition, the authority status is `approved` immediately. When an active contributor performs it, the status begins as `pending`. The responsible owner can later approve or reject the record:

```bash
fact --root /path/to/project record list
fact --root /path/to/project record approve ACQ-000123
fact --root /path/to/project record reject ACQ-000123 --reason "Outside agreed scope"
```

Approval or rejection changes the authority state of the recorded acquisition. It does not change the acquisition's original collection time, operator, provenance, committed file membership or position in the historical chain. Rejected material remains historically recorded rather than being deleted or made to appear never to have existed.

This distinction allows FACT to preserve both facts at once: a contributor really did collect and submit particular material, and the responsible owner either accepted or rejected it as part of the authoritative project record.

## Catalogue integrity and tamper detection

The catalogue contains project-relevant operator records, retained public keys, contributor membership, current ownership, ownership-transfer state and record approval state in separate relational tables alongside the existing identifier and audit structures. These current-state tables are conveniences for safe queries and relational consistency. Their authority comes from the signed append-only event history from which they can be reconstructed.

`fact catalogue verify` reconstructs identity and authority state from the event chain, verifies signed authority transactions and compares the reconstructed result with the live SQLite tables. Directly editing an operator name, substituting retained public-key material, altering contributor membership, changing ownership or flipping a record from `pending` to `approved` without the corresponding valid history therefore causes verification to fail.

The same principle applies to evidence bytes through their cryptographic digests. FACT cannot stop a sufficiently privileged attacker from writing different bytes to a project directory or SQLite file. It aims to ensure that doing so produces an integrity discrepancy rather than a silently accepted new history.

Signed catalogue checkpoints and sealed packages provide stronger external anchors against rollback. An attacker who controls the entire project directory may be able to restore an older internally consistent copy of project state. They cannot make that older state match an independently retained later signed checkpoint without the relevant signing authority. This limitation should be considered when deciding how and where checkpoints or sealed packages are retained.

## Current limitations and future key lifecycle work

FACT 2.8 establishes the signed identity and authority foundation but does not yet implement the complete operator-key lifecycle. Auditable signing-key rotation, explicit revocation, compromised or lost-key recovery, and exceptional administrative ownership recovery require their own conservative transaction designs. Historical verification must remain possible when those capabilities are added.

Until that work is implemented, operators should treat the signing key registered with a project as durable project identity material and protect its private counterpart appropriately. FACT must never silently replace a project-retained key merely because the local system keyring has changed.

## Confidential-note authority

The project catalogue already retains each registered operator's public OpenPGP key material. FACT uses that retained public material for confidential-note encryption; it does not create a second mutable identity database for note access.

Confidential note content is authorised to the note author and current project owner. Project ownership acceptance therefore includes a ciphertext-recipient transition before ownership flags change. The signed ownership-transfer event records the completed transition as an aggregate consequence of the transfer rather than creating one authority event for every re-encrypted revision.

Private decryption keys remain outside project authority. A transfer that cannot complete the confidential-note transition fails closed and leaves the previous ownership state authoritative.
