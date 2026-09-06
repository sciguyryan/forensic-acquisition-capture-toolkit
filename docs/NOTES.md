# Retained notes and confidentiality

FACT notes are ordinary evidential files with additional note semantics. They do not live in a separate mutable note store and they are not disposable comments attached to otherwise more important evidence.

Every note receives a never-reused `NOTE-######` identity. Every revision of that note receives its own ordinary `FILE-######` identity, immutable bytes, content digest, provenance and storage path. SQLite records the note lineage and points each revision to its committed file. It does not store the note body as a note payload BLOB.

This is the note form of FACT's two governing rules:

> **Everything as a file.**
>
> **No change left behind.**

## Note identity and file identity

A note identity groups a sequence of immutable file representations.

For example:

```text
NOTE-000001
├── revision 1 -> FILE-000014  content
├── revision 2 -> FILE-000021  content
└── revision 3 -> FILE-000044  cryptographic
```

`NOTE-000001` means "the same continuing note". `FILE-000014`, `FILE-000021` and `FILE-000044` identify the exact stored bytes that represented that note at particular points in its history.

Changing the wording does not replace `FILE-000014`. It creates `FILE-000021`. Re-encrypting the same confidential text for a new project owner does not replace the old ciphertext either. It creates `FILE-000044` as a cryptographic revision.

This distinction lets FACT answer both questions:

```text
What is the current version of NOTE-000001?
```

and:

```text
What exact bytes represented NOTE-000001 before the correction or ownership transfer?
```

without rewriting history to answer the first question.

## Storage scope

Project-level note revisions are project-level files and are stored under the project file tree:

```text
PROJECT/
├── files/
│   └── FILE-000014/
│       └── revision-000001.json
└── .fact/
    └── catalogue.sqlite
```

A note associated with a case is stored as a case-level file:

```text
PROJECT/
└── cases/
    └── CASE-000003/
        └── files/
            └── FILE-000021/
                └── revision-000002.json
```

FACT does not create a fake case merely to give a project note somewhere to live. The physical location reflects the note's real evidential scope.

A note may also explicitly concern another committed file. In that situation FACT records a `note-about` file relationship. For example:

```text
FILE-000031  screenshot.png
└── note-about -> FILE-000032  revision-000001.json
                  └── NOTE-000007
```

The note remains independently addressable evidence. The relationship explains what it describes.

## Note classes

FACT currently supports two note classes.

A `project` note is readable by active authenticated project members. Its revision file contains the canonical JSON note representation in plaintext because the project itself is the access boundary for that note class.

A `confidential` note is readable through FACT only when the authenticated operator has at least one active confidential-access grant for that note. Its committed revision file contains ciphertext, not plaintext. Access may arise through independent bases such as direct `object-owner` authority or the current `project-owner` role.

The word `project` means project-visible. It does not mean automatically disclosed outside the project. Package and export disclosure are separate decisions.

## Confidential files

For a confidential note, FACT serialises the title and body into the canonical note representation and encrypts those bytes before they enter the file staging area or SQLite parameters.

A confidential revision therefore looks conceptually like:

```text
NOTE-000008
└── revision 1 -> FILE-000040
                  classification: confidential-note-revision
                  media type: application/pgp-encrypted
                  content_digest: HASH(ciphertext bytes under project content profile)
```

The ciphertext is the authoritative stored representation. Its content digest is handled exactly like the hash of any other committed file.

FACT does not deliberately persist confidential-note plaintext in:

- the catalogue;
- file-check-in staging;
- the final project file tree;
- package staging;
- command transcripts;
- audit events;
- logs; or
- exception messages.

Decryption necessarily produces plaintext in process memory. Python, GnuPG and the operating system may make transient copies that FACT cannot deterministically zeroise. Systems with stronger memory-confidentiality requirements should apply appropriate host hardening, including suitable swap and crash-dump policy.

The confidentiality tests use a known sentinel to check FACT-managed persistence boundaries. They instrument SQLite writes, inspect project and package files, exercise successful and failed operations, and verify that the GnuPG integration passes plaintext through process input/output rather than named plaintext files. These tests establish FACT's persistence behaviour, not a claim that plaintext can never exist transiently in RAM.

## Content revisions

Only the note author may create a semantic revision. A reason is mandatory.

Suppose the original note is:

```text
NOTE-000012
revision 1
"Vehicle entered the north gate at 14:03."
```

If the author later establishes that the timestamp should have been 14:05, FACT does not edit revision 1. The author creates revision 2 with a reason such as `Corrected timestamp after reviewing source clock`.

The resulting history is:

```text
NOTE-000012
├── revision 1 -> FILE-000071  content
└── revision 2 -> FILE-000083  content
```

Both files remain committed. The note's current-revision pointer moves to revision 2 through an authenticated catalogue event.

## Cryptographic revisions

A cryptographic revision changes the stored encrypted representation without asserting that the semantic note text changed.

This distinction is important during project ownership transfer. If the required confidential-note recipient set changes so the incoming project owner must be able to decrypt the current representation, FACT creates a new ciphertext file and records the revision type as `cryptographic`.

For example:

```text
NOTE-000020
├── revision 1 -> FILE-000101  content
│                 encrypted for authority holder + Owner A
└── revision 2 -> FILE-000122  cryptographic
                  encrypted for authority holder + Owner B
```

`FILE-000101` is not rewritten or deleted. Its existence demonstrates what encrypted representation was authoritative before the transfer.

FACT deliberately does not store an ordinary plaintext digest merely to prove that both ciphertexts contain the same semantic text. Low-entropy confidential text could make such a digest useful for offline guessing. Semantic continuity is instead established by the authenticated re-encryption process: FACT decrypts the current authoritative representation, re-encrypts those same bytes for the new recipient set, round-trip verifies the replacement, and commits the transition as part of the ownership transaction.

## Ownership transfer is all or nothing

Project ownership cannot change while only some confidential notes have been transitioned.

FACT first processes every affected current confidential revision. Each must:

1. exist as the expected committed file;
2. pass its stored size and configured content-digest checks;
3. decrypt successfully;
4. re-encrypt for the author and incoming owner;
5. decrypt back to the same plaintext in validation; and
6. produce a valid staged replacement file.

Only after the complete set succeeds does FACT append the new `FILE-######` representations and cryptographic note revisions inside the ownership-transfer transaction.

The transfer can then commit the new ownership state. If any part fails, the catalogue transaction rolls back, the outgoing owner remains owner, the transfer remains pending, and filesystem representations created solely by the failed transaction are removed rather than becoming orphan authoritative files.

This provides the normal failure invariant:

```text
ALL confidential transitions + ownership change
                    OR
NONE of them
```

A future file-store hardening phase will add a durable recovery journal for abrupt machine/process failure across the filesystem/SQLite boundary. FACT must remain conservative around unexplained files and must never silently adopt them as committed evidence.

## Reading and verification

Reading a note resolves the selected note revision to its `FILE-######` record. FACT checks that the file exists, that its size and configured content digest still match the committed values, verifies the authenticated operator has current confidential access where required, and then decodes or decrypts the stored bytes as appropriate.

Normal catalogue verification independently checks the complete file tree. If a note revision file is changed or removed, this is a file sanctity violation just as it would be for a video, screenshot or captured network response.

For example:

```text
NOTE-000030 revision 1 -> FILE-000200
catalogue content digest -> abcdef...
current content digest   -> 123456...
```

FACT rejects the project state. It does not update the catalogue to accept the new bytes.

Verification also checks that note metadata, current-revision pointers, revision types, file pointers and disclosure state still agree with authenticated note history.

## Package disclosure

Every note starts with package disclosure set to `withheld`. Only the current project owner may explicitly mark a note for inclusion.

Because note content is now a normal file, withholding no longer means nulling a database BLOB. Instead, project packaging retains the note and file identities in the catalogue snapshot but omits the selected revision file bytes from the filtered package view.

Conceptually:

```text
Authoritative project:
NOTE-000001 -> FILE-000010 -> bytes present

Filtered package:
NOTE-000001 -> FILE-000010 -> bytes intentionally withheld
```

The omission is a presentation/disclosure decision. It is not deletion from the project record. Package construction explicitly permits only the known withheld note file IDs to be absent while verifying the staged package view.

An included project note is packaged as its committed plaintext revision file. An included confidential note is packaged as its committed ciphertext revision file. Project packaging never decrypts confidential notes.

The later generalised export subsystem will provide richer selection, full-record versus presented-record views, owner-authorised decrypted export, layered rendering and optional output encryption. Packaging remains a distinct self-contained archival operation rather than becoming the only export mechanism.

## Retraction

The general architecture distinguishes committed existence from presentation. Retraction therefore must never mean deleting a note or a revision file.

When note-level retraction is exposed through the user interface, it will be an append-only presentation transition. A full historical export will be able to include the note and all revisions. A presented/filtered export may omit retracted material, but it must identify itself as a filtered view rather than a complete authoritative record.

## Confidential access authority

The operator who created a confidential note remains its immutable creator in provenance. Current access authority is separate and may have several independent bases for the same operator and note. FACT records each basis separately so changing a role does not silently erase unrelated direct authority.

Project ownership transfer revokes the outgoing owner's `project-owner` grants and adds the corresponding grants for the incoming owner. An `object-owner` or other independent surviving basis remains active. Access changes are append-only `CONFIDENTIAL_ACCESS_GRANTED` and `CONFIDENTIAL_ACCESS_REVOKED` events; historical grants are not deleted or rewritten.

The current GnuPG ciphertext representation still requires cryptographic transitions where ownership changes the recipient set. Those transitions create new immutable cryptographic revision files rather than rewriting historical ciphertext. FACT checks current authenticated access before its protected decryption path, so an operator whose last active basis has been revoked can no longer decrypt through FACT even if an old credential remains technically capable of decrypting a historical ciphertext outside FACT.

This is not retroactive cryptographic erasure. FACT cannot revoke plaintext, private keys, screenshots, exports or other material that an operator retained while authorised. See `CONFIDENTIAL_ACCESS.md` for the current access model and its cryptographic boundary.
