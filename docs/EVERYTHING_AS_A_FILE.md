# Everything as a file

FACT uses one simple evidential rule: **if FACT retains a byte-bearing object as evidence or as part of the evidential record, FACT treats it as a file.**

This rule applies regardless of where the bytes came from or whether a human would normally think of them as a document. A downloaded video is a file, but so is a captured HTTP request, a response body, a header transcript, a JSON metadata response, a screenshot, a command transcript, a certificate record, a generated verification report, a manifest and a sealed package.

The purpose is not to create files for their own sake. It is to make every retained component independently identifiable, hashable, attributable, verifiable and exportable.

## Atomic evidential identity

Every committed file receives a never-reused identifier such as:

```text
FILE-000001
FILE-000002
FILE-000003
```

A file identifier identifies one check-in event and one immutable byte sequence. It is not a content-addressing shortcut. If the same bytes are captured twice, FACT records two file identities because the two captures have different provenance even though their SHA-256 values happen to match.

For example:

```text
PROJECT PANDA
└── CASE-000001
    └── ACQ-000001
        ├── FILE-000001  video.mkv
        ├── FILE-000002  request.txt
        ├── FILE-000003  response-headers.txt
        ├── FILE-000004  response-body.json
        └── FILE-000005  yt-dlp.stderr.txt
```

`ACQ-000001` explains how these files entered FACT. It is not a replacement for their individual identities.

## Acquisition, artefact and file

FACT distinguishes three ideas that were historically easy to conflate.

An **acquisition** is an event or process. It records what the operator attempted to collect, from where, using which collector and under which case context.

An **artefact** is a logical evidential concept or grouping. An artefact may be represented by one file or by several related files. Artefact classification gives files meaning but does not make the grouping the atomic evidence object.

A **file** is the immutable byte-bearing object that FACT actually checks in.

For a web capture, one logical artefact might include a request transcript, response headers, response body and TLS observations. FACT can present those together while still preserving each file independently.

## Network evidence is file evidence

Network activity is not special-cased into opaque catalogue fields when FACT retains its byte-bearing representation. The more useful context FACT can faithfully preserve, the stronger the resulting evidential record can be.

Depending on the collector and what the source exposes, a capture may therefore retain files representing:

- requests and request bodies;
- responses and response bodies;
- request and response headers;
- redirect information;
- source metadata;
- DNS or certificate observations where available and appropriate;
- timing and collector diagnostics;
- command transcripts; and
- the primary content returned by the source.

FACT must not invent information that was unavailable. Rich capture means preserving what was actually observed, together with enough provenance to explain how it was observed.

## No change left behind

FACT's second rule follows from the first:

> Once an authoritative representation has been committed, FACT does not rewrite or erase that representation. A change is another record.

A committed file's bytes and hash are invariant. If different bytes need to be retained, those bytes receive a new file identity. Relationships such as `derived-from`, `supersedes`, `annotation-for` or future domain-specific relationships can connect the new file to existing material without rewriting history.

The same principle separates **existence** from **presentation**. A file may later be marked retracted or superseded for presentation purposes, but the original file, its identifier, its hash and the event that committed it remain in the authoritative record.

This distinction is important. Retraction means "do not present this as part of the current evidential view". It does not mean "pretend this never existed".

## Check-in and all-or-nothing batches

Collectors work in mutable staging because a partially completed capture must not masquerade as committed evidence. Once capture and mandatory sealing succeed, FACT prepares the retained files for check-in, validates their hashes and commits the batch to the project file store and catalogue.

For ordinary handled failures, a batch is all or nothing. FACT must not report half of an intended check-in as a successful complete acquisition. Prepared temporary material is unauthoritative and may be removed when the batch fails.

The filesystem and SQLite do not provide a shared native transaction. FACT therefore uses private staging, byte-for-byte hash validation, guarded catalogue transactions and conservative failure handling. A future crash-recovery journal may strengthen recovery across abrupt process or machine failure. FACT must never silently adopt unexplained files into the authoritative record merely because they appear on disk.

## Verification and sanctity

Catalogue verification checks more than the rolling event hashes. For every committed file, FACT expects the recorded storage path to exist as a regular file and expects its current size and SHA-256 to match the committed values.

Changing a committed file is therefore a verification failure. Removing it is also a verification failure.

For example, if the catalogue says:

```text
FILE-000042
SHA-256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
```

but the stored bytes no longer produce that digest, FACT reports that the committed file bytes have changed. It does not update the catalogue to bless the replacement.

This is the project's sanctity rule in practical form: **missing history is evidence of a problem, not an invitation to rewrite history.**

## Notes

Notes follow the same conceptual model, with a stable note identity and immutable revisions. A note is not edited in place. A correction, clarification or cryptographic re-encryption creates another revision beneath the same never-reused note ID.

Conceptually:

```text
NOTE-000001
├── REVISION-000001  initial representation
├── REVISION-000002  clarification
└── REVISION-000003  re-encrypted after ownership transfer
```

A confidential revision is hashed over its stored encrypted representation. Re-encryption therefore creates a new immutable representation and a new hash rather than changing the historical revision's ciphertext.

A note may be retracted from the presented record, but neither its identity nor any committed revision disappears from the authoritative history. Full-record export can include the complete lineage, while a presented-record export may omit material currently marked retracted. The latter must identify itself as a filtered presentation rather than as the complete record.

The current note subsystem predates the unified file store and is being converged onto the same file-backed machinery. Until that convergence is complete, its append-only note identity and revision semantics remain mandatory and must not be weakened by compatibility work.

## Encrypted artefacts

Encrypted artefacts are a planned extension of the same model rather than a separate evidence system. The encrypted bytes will themselves be the committed file representation and therefore have ordinary file IDs and hashes.

Ownership transfer must be all or nothing for encrypted material. FACT must successfully decrypt, re-encrypt, validate and stage every affected confidential note representation and encrypted artefact before the new ownership state is committed. No partial transfer may become authoritative.

Large encrypted files may require chunked or streaming authenticated encryption so that confidentiality does not require loading an entire artefact into memory. That cryptographic design is intentionally deferred until the ordinary immutable file model is established.

## What this model does and does not prove

A larger, internally coherent evidence tree increases the amount of history that would need to be fabricated consistently in order to substitute a convincing false project state. Individual hashes, relationships, provenance and the rolling catalogue history reinforce one another.

This does not make fabrication impossible and a hash alone does not establish who performed an action. FACT's integrity chain, authenticated operator model and signed authority anchors/checkpoints have distinct roles. Documentation and user interfaces must not collapse those claims into an assertion that hashing alone proves real-world authenticity or legal admissibility.
