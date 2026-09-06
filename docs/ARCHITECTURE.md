# FACT architecture

FACT is structured so that source-specific capture logic remains separate from the authoritative evidential lifecycle around that capture. Adding a collector must not require reimplementing project management, identifier allocation, immutable file check-in, authority, verification, packaging or disclosure policy.

## Architectural rule

A collector acquires a source. FACT core decides which intentionally retained files cross into the authoritative record, commits them individually, records their provenance and verifies the resulting project.

The current lifecycle is:

```text
project/case context
        |
        v
private acquisition staging + INCOMPLETE marker
        |
        v
collector capture
        |
        v
explicit retained-file registry
        |
        v
remove transient/scratch output
        |
        v
immutable FILE-###### check-in
        |
        v
file relationships
        |
        v
authenticated ACQUISITION_RECORDED event
  - exact committed file IDs
  - source and acquisition provenance
  - operator and case context
  - tool versions and observations
        |
        v
full catalogue/file verification
        |
        v
successful staging removed
```

The `INCOMPLETE` marker belongs to unauthoritative working state. It remains with failed acquisition staging for diagnosis, but it is never itself checked in as evidence. A successful staging tree is removed only after the committed files, acquisition authority event and complete project verification are successful.

## One authoritative inventory

The live FACT project has one authoritative inventory: the `files` catalogue table and the corresponding `FILE_COMMITTED` events in the authenticated rolling history.

FACT no longer creates a second per-acquisition 7-Zip archive or the historical `EVIDENCESET-SHA256.txt`, `FILELIST.txt`, `SHA256SUMS.txt` and `SHA512SUMS.txt` files. It also no longer creates per-acquisition archive hash sidecars, detached archive signatures or archive-verification reports.

Those mechanisms belonged to an older architecture in which the acquisition archive itself was the primary evidential object. Under everything-as-a-file, maintaining a second list or hash manifest of the same committed files would create parallel representations that can drift without adding a distinct authority property.

This does not mean portable packages lack verification material. Project packaging deliberately generates a package descriptor, package manifest, outer SHA-256 checksum, public verification material and detached package signature. Those are representations of a selected verified project state for portability. They are not recursively committed back into the live project merely because FACT generated them.

## Source layout

The canonical Python package is `fact`.

```text
src/fact/
├── core/
│   ├── acquisition.py
│   ├── authority.py
│   ├── catalogue.py
│   ├── files.py
│   ├── notes.py
│   ├── orchestration.py
│   ├── packaging.py
│   ├── project.py
│   └── records.py
├── services/
│   └── commands.py
├── collectors/
│   ├── base.py
│   ├── registry.py
│   ├── screenshot/
│   └── youtube/
├── review/
├── shell/
├── cli.py
├── identity.py
├── keys.py
└── models.py
```

## Acquisition context

Collectors receive an `AcquisitionContext`. It contains the acquisition ID, case ID, private staging workspace, artefact registry and command service needed to perform capture.

Collectors must not allocate project or case identifiers, create project cryptographic keys, commit catalogue authority state, package the project or decide whether project verification has passed.

The context is also the boundary through which reusable services are supplied. This keeps source collectors testable without moving generic evidential policy into source-specific code.

## Collector contract

A collector implements the small `Collector` protocol and returns an `AcquisitionResult`.

Conceptually:

```python
class Collector:
    name = "example"

    def capture(self, context, request) -> AcquisitionResult:
        ...
```

A collector is responsible for:

- validating the source-specific target;
- invoking source-specific acquisition mechanisms;
- writing working material beneath its staging workspace;
- deliberately registering every file that should be retained as evidence;
- removing successful temporary fragments and scratch files that should not be retained;
- attaching useful classifications, media types, descriptions and relationships to retained files;
- returning structured source metadata, observations and source-specific evidence state.

A collector is not responsible for:

- permanent project, case, acquisition, note, file, artefact, export or authority-transfer identifier allocation;
- authoritative file storage;
- catalogue hashing or authority transactions;
- project membership or ownership decisions;
- project packaging or export;
- project-local signing-key lifecycle;
- final project integrity verification.

## The retention boundary

Everything-as-a-file applies only after intentional retention.

A temporary downloader fragment, scratch file, response buffer, conversion intermediate or staging helper does not become evidence merely because FACT touched it. If it is removed after successful capture and is not deliberately retained, it receives no `FILE-######`, no permanent hash and no catalogue event.

Conversely, anything FACT deliberately retains as evidential material must cross the ordinary file check-in boundary. The core refuses an unexplained regular file left in successful staging rather than silently sweeping implementation debris into the authoritative record. This fail-closed behaviour forces collectors to make retention explicit.

Failed acquisition staging is different. It may preserve incomplete working material for diagnosis or recovery, but that tree is explicitly unauthoritative and must not be confused with committed evidence.

## File commitment and relationships

Each retained file receives a never-reused `FILE-######` identifier. FACT records its case and acquisition association, actor, logical path, classification, media type, description, content digest, size, storage path, commitment sequence and presentation state.

Committed bytes are immutable. A changed representation is a new file. Retraction and supersession are append-only presentation transitions and do not erase committed existence.

Relationships such as `describes`, `derived-from` and `note-about` are append-only catalogue events connecting immutable files. Future image annotation, proposed-redaction and rendered-derivative layers should use the same relationship machinery rather than introducing a parallel evidence store.

## Acquisition membership

A successful `ACQUISITION_RECORDED` authority transaction contains the exact ordered set of `FILE-######` identifiers committed for that acquisition. It also retains the structured acquisition record containing case context, source facts, completion time, tool versions, observations and collector-specific evidence state.

Catalogue verification reconstructs that authenticated acquisition event and confirms its file list exactly matches the files currently associated with the acquisition in the catalogue. This is the authoritative replacement for the historical evidence-set and file-list manifests.

The file hashes themselves remain in the file catalogue and `FILE_COMMITTED` history. They are not copied into an additional acquisition checksum manifest.

## Acquisition transcript

The lifecycle transcript is one collector-independent file that remains worth retaining because it contains historical information that cannot necessarily be reconstructed from final catalogue state. It lives inside acquisition staging while work is in progress and, on success, is checked in once as an ordinary `transcript` file.

There is no separate successful `logs/` copy after commitment. The checked-in `FILE-######` is the authoritative retained transcript.

## Verification

`verify_chain()` verifies the rolling event chain and current state derived from it. It also checks operator and ownership state, notes, committed files, file relationships, presentation state and recorded acquisition membership.

Every present committed file is checked directly against its recorded size and configured content digest. Missing or altered bytes therefore fail project verification without requiring a separate per-acquisition checksum file.

Filtered package construction may explicitly permit selected withheld note files to be absent from the staged package view. This exception is narrow and does not weaken normal live-project verification.

## Packaging is not acquisition sealing

Project packaging is an output operation over verified project state. It snapshots the catalogue, copies the selected authoritative file tree, applies explicit disclosure filtering, writes package-specific metadata and a package manifest, creates a deterministic `.fact.tar.gz`, hashes and signs that package, and verifies the resulting transport representation.

Package artefacts are not automatically checked back into FACT. If a future workflow deliberately admits an exported or rendered result back into the project, it must be checked in as a new immutable derivative with explicit provenance.

## Cryptographic boundaries

Operator signing identities authenticate authority-changing transactions. Project-local FACT keys are a separate future bootstrap/lifecycle concern and must remain beneath the project in protected purpose-specific subdirectories. FACT must not create or mutate an operator's global GnuPG identity as part of project creation.

Hashing and authentication have distinct roles. The project-selected content profile identifies committed bytes, the selected chain profile links catalogue history, and signatures and signed checkpoints provide actor attribution and external anchoring. Removing duplicate archive hashes does not remove those distinct authentication properties.

## No change left behind

Once something enters the authoritative FACT record, its committed representation is immutable. New facts and changed representations are appended. Presentation is a view over that history, not a replacement for it.

This rule applies to files, note revisions, cryptographic re-encryption, relationships, ownership changes, acquisition decisions and future review layers.

## Artefact identities

Retained collector artefacts now receive never-reused `ART-######` identities. An artefact is a logical evidential grouping and may own one or more member files; it does not replace the immutable byte identity of any `FILE-######`. Collector staging paths are resolved to committed file identities before the artefact is created, and the authenticated `ARTEFACT_CREATED` event binds the grouping. This gives structural verification and later review/export workflows a stable object boundary without weakening everything-as-a-file.

## Export authority and recorded disclosure

General export is a disclosure operation over verified project state, distinct from canonical project packaging. Each project has an authenticated export policy controlling ordinary export, ciphertext export, confidential plaintext export and broad case/project scope. Policy changes require the project owner and are retained as signed append-only events.

Every export attempt receives a never-reused `EXPORT-######`. FACT records `EXPORT_STARTED` before building in private temporary space and `EXPORT_COMPLETED` only after the final output exists. If completion cannot be authenticated, FACT removes the placed output rather than leave an apparently successful unaudited disclosure. Failed attempts remain historical state.

A completed export binds the source project chain anchor, actor, policy sequence, scope, view, representation, exact source file identities, output paths, source and output content-digest values, manifest digest and final container/tree digest. The portable `FACT-EXPORT.json` is therefore a representation of a recorded disclosure, not a second authority ledger.

The current representation is `native`. Directory and deterministic tar output are supported, and tar output may optionally be protected to recipient OpenPGP keys. Confidential note ciphertext is the default retained representation. Authorised plaintext note export is recorded as a derived output whose digest is distinct from its encrypted source `FILE-######`. Rendered, flattened and archival representations remain future work until their deterministic/provenance semantics are implemented.

## Confidential object-owner transfer

Immutable creator attribution and current confidential access authority are separate. A `TRANSFER-######` changes direct object-owner authority for the selected confidential objects; it does not collapse every other access basis into that transfer.

Only the project owner may propose a transfer, and the exact target object set is bound into the proposal. The nominated incoming active member must explicitly accept or reject it; the owner may cancel while pending. Acceptance must complete every required cryptographic transition before direct object-owner authority changes. Confidential notes implement this today by creating new immutable encrypted revision files. Generic encrypted file/artefact transfer is fail-closed until a generic encrypted-payload format exists.

An operator may separately hold role-derived or explicitly granted access to the same object. Those bases are recorded and revoked independently. A transfer therefore cannot be described as revoking all access unless no other authenticated basis survives.

## Verification scopes and reports

Verification has two different directions. `fact verify file <path>` starts outside FACT and establishes byte correspondence to every matching committed file identity. Structural verification starts from a FACT object (`artefact`, `acquisition`, `case`, `project`, or an immutable ID), verifies the selected object's descendant payloads, and verifies the authenticated catalogue/history that anchors the object to the project.

The catalogue rolling chain, signatures, reconstructed authority state and identifier/state invariants are always checked. For a narrow structural target, unrelated sibling payload bytes are not redundantly rehashed. `fact verify project` is exhaustive and rehashes every committed file. The result explicitly records how many payloads were hashed and states relevant scope limitations.

`fact verify export <path>` validates the portable descriptor/container, exact output membership and hashes, the matching `EXPORT-######` completion event, the recorded source history anchor and the source `FILE-######` records. An encrypted export envelope can be matched exactly to its recorded encrypted digest without claiming that its internal plaintext was inspected.

Text, HTML, JSON and PDF reports are renderings of the same structured verification result. `--detailed` exposes the supporting checks and metadata; it does not change what is verified. Reports are generated outputs and do not enter the project record unless a later explicit check-in operation admits them as new files.

## Confidential access authority

Confidential access is provenance-aware and multi-basis. Cryptographic possession is necessary but is not treated as sufficient authority. Protected decryption paths must resolve current authenticated access before decrypting. See `CONFIDENTIAL_ACCESS.md` for the current authority model, transfer semantics, security limitations and the deliberately deferred envelope-encryption/recovery architecture.
