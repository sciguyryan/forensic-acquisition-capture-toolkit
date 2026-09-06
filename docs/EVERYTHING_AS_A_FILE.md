# Everything as a file

FACT uses one deliberately simple evidential rule: **if FACT retains a byte-bearing object as evidence or as part of the evidential record, FACT treats it as a file.**

This rule applies regardless of where the bytes came from or whether a human would normally think of them as a document. A downloaded video is a file, but so is a captured HTTP request, a response body, a header transcript, a JSON metadata response, a screenshot, a command transcript or a certificate record. Package-time manifests and verification descriptors are different: they describe an exported representation and are not automatically admitted back into the live project as evidence.

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

An **artefact** is a logical evidential concept or grouping with a never-reused `ART-######` identity. An artefact may be represented by one file or by several related files. Artefact identity gives those files a stable logical boundary but does not make the grouping the atomic byte-bearing evidence object.

A **file** is the immutable byte-bearing object that FACT actually checks in.

For a web capture, one logical artefact might include a request transcript, response headers, response body and TLS observations. FACT can present those together while still preserving each file independently.

## Network evidence is file evidence

Network activity is not special-cased into opaque catalogue fields when FACT deliberately retains its byte-bearing representation. The more useful context FACT can faithfully preserve, the stronger the resulting evidential record can be.

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

Collectors work in mutable staging because a partially completed capture must not masquerade as committed evidence. Once capture has produced its intentional retained set, FACT rejects unexplained leftover files, prepares the registered files and acquisition transcript for check-in, validates their bytes and commits the batch to the project file store and catalogue. The authenticated acquisition event then binds the exact committed `FILE-######` set and provenance, and full project verification must pass before successful staging is removed.

For ordinary handled failures, a batch is all or nothing. FACT must not report half of an intended check-in as a successful complete acquisition. Prepared temporary material is unauthoritative and may be removed when the batch fails.

The filesystem and SQLite do not provide a shared native transaction. FACT therefore uses private staging, byte-for-byte hash validation, guarded catalogue transactions and conservative failure handling. A future crash-recovery journal may strengthen recovery across abrupt process or machine failure. FACT must never silently adopt unexplained files into the authoritative record merely because they appear on disk.

## Acquisition membership without duplicate manifests

Older FACT development builds created per-acquisition `EVIDENCESET-SHA256.txt`, `FILELIST.txt`, SHA-256/SHA-512 manifests and a second sealed archive. Those representations are no longer part of the live project model.

The authoritative acquisition membership is now the exact ordered `FILE-######` list in the authenticated `ACQUISITION_RECORDED` transaction. Catalogue verification compares that list with the files actually associated with the acquisition. Each file's SHA-256 remains in the file catalogue and its `FILE_COMMITTED` history. This avoids maintaining a second checksum or inventory system that could drift from the authoritative record.

A project package may still generate its own manifest, descriptor, checksum and detached signature because a portable copy needs self-contained verification material. Those package artefacts describe the export. They do not become live-project evidence unless a later deliberate workflow checks them back in as new derivative files.

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

This convergence is now implemented. Every note revision is an ordinary committed `FILE-######` object. Project notes live in the project file store, case notes live in the corresponding case file store, and a note about another file is connected through an explicit `note-about` relationship. The note tables retain logical lineage and authority state rather than duplicating mutable payload bytes in SQLite.


## Exported representations are not automatic evidence

An export is a recorded disclosure event, not an automatic file check-in. `EXPORT-######` records who exported what, under which policy and representation, and binds the resulting output digests. The generated export directory/archive, `FACT-EXPORT.json` descriptor and verification reports remain outside the authoritative file tree unless an operator deliberately checks a resulting representation back in through a future derivative workflow.

This keeps two statements simultaneously true: the chain can prove that an export occurred and what it contained, while FACT does not recursively turn its own presentation/transport records into new evidence merely because it generated them.

## Encrypted artefacts

Encrypted artefacts are a planned extension of the same model rather than a separate evidence system. The encrypted bytes will themselves be the committed file representation and therefore have ordinary file IDs and hashes.

Ownership transfer must be all or nothing for encrypted material. FACT must successfully decrypt, re-encrypt, validate and stage every affected confidential note representation and encrypted artefact before the new ownership state is committed. No partial transfer may become authoritative.

Large encrypted files may require chunked or streaming authenticated encryption so that confidentiality does not require loading an entire artefact into memory. That cryptographic design is intentionally deferred until the ordinary immutable file model is established.

## What this model does and does not prove

A larger, internally coherent evidence tree increases the amount of history that would need to be fabricated consistently in order to substitute a convincing false project state. Individual hashes, relationships, provenance and the rolling catalogue history reinforce one another.

This does not make fabrication impossible and a hash alone does not establish who performed an action. FACT's integrity chain, authenticated operator model and signed authority anchors/checkpoints have distinct roles. Documentation and user interfaces must not collapse those claims into an assertion that hashing alone proves real-world authenticity or legal admissibility.

## Collector retention boundary

Everything-as-a-file does not mean that every temporary byte touched by an acquisition tool becomes evidence. The boundary is intentional retention. A file that FACT retains as part of the authoritative acquisition record receives a `FILE-######` identity, hash, classification and provenance. Temporary fragments, scratch files, intermediate buffers and other working material that are discarded after successful acquisition never enter the catalogue.

For example, a completed YouTube download may retain the original media, yt-dlp source metadata, captions, thumbnails, HTTP capture material and media-inspection reports. Each retained object is checked in separately. A `.part` fragment used only while downloading is not retained and receives no file identity. Failed acquisition staging remains governed by the separate incomplete-acquisition policy and must not be confused with successfully committed evidence.

The screenshot/image collector follows the same rule. The exact captured image is the primary file and the retained capture-environment metadata is a separate file related to it with a `describes` relationship. Future annotation and redaction layers will become additional retained files and relationships; they will not rewrite the original image.
