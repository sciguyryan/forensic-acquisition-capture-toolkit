# Retained notes and confidentiality

FACT notes are part of the retained project record. They are not disposable comments and they are never silently overwritten or deleted after commitment. Each note receives a never-reused `NOTE-######` identifier and revisions append to the existing history.

## Note classes

FACT supports two note classes.

`project` notes are readable by any active authenticated project member. They are retained inside the project catalogue but are withheld from external project packages by default.

`confidential` notes are encrypted before their content crosses the SQLite boundary. Their plaintext is readable only by the note author and the current project owner. Other authenticated contributors can see that the note record exists but cannot read its content.

The word "project" in this context means project-visible, not automatically public outside FACT. Package disclosure is a separate decision.

## Confidentiality boundary

Confidential note title and body are serialised together and encrypted through GnuPG before SQLite receives the payload. SQLite stores ciphertext and a SHA-256 digest of that ciphertext. FACT never deliberately writes confidential-note plaintext to a database table, temporary table, temporary file, package staging area, transcript, log, audit event or exception message.

Decryption and re-encryption use process-memory buffers and pipes. Python and the operating system can make copies of process memory and FACT cannot promise deterministic zeroisation of every interpreter or library buffer. Systems requiring stronger memory-confidentiality guarantees should use encrypted swap or disable swap and should apply appropriate operating-system hardening.

The automated confidentiality tests instrument FACT's SQLite write boundary with a known plaintext sentinel, scan generated project and package artefacts for that sentinel, exercise both successful and failed confidential operations, and verify that GnuPG receives plaintext only through process stdin and returns decrypted plaintext only through captured stdout. These tests verify FACT's persistence behaviour; they do not claim authority over transient copies made by Python, GnuPG, the kernel, swap, crash-dump facilities or other operating-system mechanisms outside FACT's persistence model.

Private OpenPGP keys remain outside the project. The project catalogue retains each operator's public key material, which allows FACT to encrypt confidential material for registered recipients without creating a parallel identity database.

## Ownership transfer

A project ownership transfer is indivisible from confidential-note recipient transition. When the incoming owner accepts a pending project transfer, FACT first cycles every retained confidential revision before changing ownership flags.

For each confidential revision FACT reads old ciphertext, decrypts it in memory, immediately re-encrypts it for the note author and incoming project owner, verifies the replacement, and writes only replacement ciphertext to a connection-scoped SQLite temporary staging table. The live note rows are not changed until every expected revision has been staged successfully.

FACT checks that the selected, staged and activated revision counts agree. It then activates the replacement ciphertext, records the single signed ownership-transfer acceptance event, changes ownership and membership state, validates the transaction and commits. The transfer event records the number of confidential revisions cycled and an aggregate digest of the replacement ciphertext set rather than emitting one audit event per note.

Any failure before commit rolls back the complete operation. The outgoing owner remains owner, the pending transfer remains pending, and the old ciphertext remains authoritative. Temporary staging records disappear when the database connection closes. They contain ciphertext only.

The access invariant is therefore:

```text
confidential note recipients = note author + current project owner
```

If the author is also the owner, the recipient is naturally represented once.

Cryptography cannot make a former owner forget plaintext they previously read or destroy copies they independently retained. The ownership transition controls future access through FACT and future decryptability of the authoritative ciphertext.

## Revisions and sanctity

Only the author may revise a note. A revision requires a reason and creates a new retained revision rather than replacing the previous one. Catalogue verification checks the signed creation/revision history against the live note tree and treats missing committed notes, missing revisions, altered metadata, altered revision pointers, altered disclosure state, or ciphertext/payload digest mismatches as sanctity violations.

Committed project and case records are never cleanup candidates. FACT may automatically discard only unauthoritative temporary transfer staging state.

## Package disclosure

Every note starts with package disclosure set to `withheld`. Only the current project owner may explicitly mark a note for inclusion. Project packaging operates on a catalogue snapshot and removes the payload of withheld notes from that snapshot while preserving the note metadata and payload digest. The authoritative project catalogue is never modified by packaging.

An explicitly included project-visible note is packaged with its plaintext payload. An explicitly included confidential note remains encrypted. Packaging never decrypts confidential notes.
