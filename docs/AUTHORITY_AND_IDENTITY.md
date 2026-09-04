# Authority, identity and project integrity

FACT treats operator identity, project membership, ownership and approval state as part of the evidential meaning of a project. These records are therefore retained inside the same tamper-evident SQLite catalogue that records project identifiers and lifecycle events. FACT does not maintain a separate local operator-profile authority layer. Project identity is resolved from the project-retained record, while private signing capability remains in the operator's local GnuPG environment.

The design has two related goals. FACT should be able to establish which project identity performed or authorised an action at the point it occurred, and it should make later unauthorised alteration of that attribution detectable. FACT does not attempt to make a writable filesystem physically immune to tampering.

A useful summary of the security model is:

> FACT does not prevent all tampering. It is designed to make unauthorised modification detectable.

## Project authority

Every newly created FACT project must establish an initial owner before the project is considered usable. Project creation through the normal CLI therefore combines ordinary project initialisation with a signed authority bootstrap. If the initial owner cannot sign the bootstrap transaction, FACT removes the incomplete empty project rather than leaving an apparently usable ownerless project behind.

The initial owner becomes part of the rolling catalogue history. The owner assignment is not an editable field in `PROJECT.toml` and cannot be substituted later by changing local configuration or selecting a different signing key.

Older projects created before the authority model can be migrated explicitly with:

```bash
fact --root /path/to/project authority bootstrap
```

This operation establishes authority from that point forward. FACT does not retroactively claim that the bootstrap operator owned or authorised project activity that predates the signed authority root. Earlier history remains honestly pre-authority.

Check the current authority state with:

```bash
fact --root /path/to/project authority status
```

## Operator identity and signing keys

A project-retained operator identity includes the operator ID, public descriptive fields, full signing-key fingerprints and the public OpenPGP key material required to verify signed authority transactions. Private keys, passphrases, GnuPG agent state and session authentication secrets are never stored in the catalogue.

FACT no longer uses local operator JSON profiles or an active-profile selection mechanism. For an authority-enabled project, the retained operator record supplies the operator ID and exact signing fingerprint. FACT asks the local GnuPG environment to use that exact fingerprint when a private-key operation is required, and refuses the operation if the matching private key is unavailable.

During initial authority bootstrap, the operator ID and signing fingerprint are supplied explicitly. FACT exports and retains the corresponding public key only after confirming that the fingerprint matches the selected local signing key. Contributor invitations likewise import explicit public verification material rather than consuming another installation's private operator profile.

Historical public verification material is retained with the project so that a later verifier does not have to rely on the originating workstation or an external keyserver merely to understand which key signed a historical project transaction.

A valid cryptographic signature demonstrates control of the private key associated with the retained operator identity at that point in project history. It does not prove that a particular biological person personally operated the keyboard. Key custody, workstation security, hardware-token policy and compromise response remain important operational controls outside the cryptographic claim FACT can make.

## Signed authority transactions

Authority-changing events use a canonical signed transaction before they are appended to the rolling catalogue chain. The signed payload binds the transaction to the project, event type, object, actor, actor signing-key fingerprint, intended event sequence, previous chain head, timestamp and event-specific data.

FACT immediately verifies the new signature against the project-retained public key and the exact historical signing fingerprint before appending the event. Catalogue verification later reconstructs the authority state from those signed events and checks the signatures again.

The rolling hash and transaction signature provide different assurances. The rolling hash protects event ordering and detects changes to the chain. The operator signature demonstrates that the corresponding registered signing key authorised the exact authority transaction. Neither mechanism is treated as a substitute for the other.

## Session authentication

The interactive FACT shell supports an authenticated operator context. Run:

```text
PROJECT-ID> auth OPERATOR-ID
```

FACT generates a fresh project-scoped challenge containing the project identity, operator identity, signing fingerprint, timestamp, purpose and a random nonce. The operator selects a retained project identity, FACT asks the local GnuPG environment for the matching private key by exact fingerprint, and the resulting signature is verified against the project-retained public key before the shell marks that operator as authenticated.

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
fact --root /path/to/project contributor invite --operator-id OPERATOR-ID --public-key /path/to/operator-public-key.asc
```

The invited operator must then use their own registered signing key to accept:

```bash
fact --root /path/to/project contributor accept --operator-id OPERATOR-ID
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

A sealed acquisition is recorded in the authority ledger immediately. The record is therefore part of the same rolling history whether the acquisition was performed by the owner or by a contributor.

When the responsible case owner performs the acquisition, the authority status is `approved` immediately. When an active contributor performs it, the status begins as `pending`. The responsible owner can later approve or reject the record:

```bash
fact --root /path/to/project record list
fact --root /path/to/project record approve ACQ-000123
fact --root /path/to/project record reject ACQ-000123 --reason "Outside agreed scope"
```

Approval or rejection changes the authority state of the recorded acquisition. It does not change the acquisition's original collection time, operator, provenance, archive digest or position in the historical chain. Rejected material remains historically recorded rather than being deleted or made to appear never to have existed.

This distinction allows FACT to preserve both facts at once: a contributor really did collect and submit particular material, and the responsible owner either accepted or rejected it as part of the authoritative project record.

## Catalogue integrity and tamper detection

The catalogue contains project-relevant operator records, retained public keys, contributor membership, current ownership, ownership-transfer state and record approval state in separate relational tables alongside the existing identifier and audit structures. These current-state tables are conveniences for safe queries and relational consistency. Their authority comes from the signed append-only event history from which they can be reconstructed.

`fact catalogue verify` reconstructs identity and authority state from the event chain, verifies signed authority transactions and compares the reconstructed result with the live SQLite tables. Directly editing an operator name, substituting retained public-key material, altering contributor membership, changing ownership or flipping a record from `pending` to `approved` without the corresponding valid history therefore causes verification to fail.

The same principle applies to evidence bytes through their cryptographic digests. FACT cannot stop a sufficiently privileged attacker from writing different bytes to a project directory or SQLite file. It aims to ensure that doing so produces an integrity discrepancy rather than a silently accepted new history.

Signed catalogue checkpoints and sealed packages provide stronger external anchors against rollback. An attacker who controls the entire project directory may be able to restore an older internally consistent copy of project state. They cannot make that older state match an independently retained later signed checkpoint without the relevant signing authority. This limitation should be considered when deciding how and where checkpoints or sealed packages are retained.

## Current limitations and future key lifecycle work

FACT 2.8 establishes the signed identity and authority foundation but does not yet implement the complete operator-key lifecycle. Auditable signing-key rotation, explicit revocation, compromised or lost-key recovery, and exceptional administrative ownership recovery require their own conservative transaction designs. Historical verification must remain possible when those capabilities are added.

Until that work is implemented, operators should treat the signing key registered with a project as durable project identity material and protect its private counterpart appropriately. FACT must never silently replace a project-retained key merely because the local GnuPG keyring has changed or another signing key is available.
