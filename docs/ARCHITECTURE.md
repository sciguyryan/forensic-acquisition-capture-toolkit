# FACT architecture

FACT is structured so that source-specific capture logic remains separate from the evidential lifecycle around that capture. The distinction is deliberate: adding a collector must not require reimplementing project management, staging rules, artefact classification, hashing, sealing, signing, packaging or generic verification.

## Architectural rule

A collector acquires a source. FACT core preserves, records, seals and verifies the result.

The intended lifecycle is:

```text
project/case context
        |
        v
acquisition workspace + INCOMPLETE marker
        |
        v
collector capture
        |
        v
explicit artefact registry
        |
        v
provenance and records
        |
        v
evidence-set manifest
        |
        v
archive + hashes + signatures
        |
        v
mandatory self-verification
        |
        v
sealed acquisition
```

The `INCOMPLETE` marker is an evidential state marker, not temporary cosmetic state. It exists until capture reaches the sealing boundary and is recreated if mandatory self-verification fails.

## Source layout

The canonical Python package is now `fact`.

```text
src/fact/
├── core/
│   ├── acquisition.py
│   ├── catalogue.py
│   ├── packaging.py
│   ├── project.py
│   ├── records.py
│   ├── sealing.py
│   └── verification.py
├── services/
│   ├── archive.py
│   ├── commands.py
│   └── hashing.py
├── collectors/
│   ├── base.py
│   ├── registry.py
│   └── youtube/
│       └── collector.py
├── review/
├── acquire.py
├── cli.py
├── identity.py
├── keys.py
└── models.py
```

The historical `youtube_forensics` Python package remains only as a compatibility namespace. It contains no independent evidential implementation. This is important because maintaining two implementations of hashing, verification or sealing logic would create unacceptable drift risk.

## Acquisition context

Collectors receive an `AcquisitionContext`. It contains the acquisition ID, case ID, staging workspace, artefact registry and command service needed to perform capture.

Collectors must not allocate project or case identifiers. They must not create toolkit signing keys, seal archives or decide whether an acquisition has passed mandatory verification.

The context is also the boundary through which reusable services are supplied. This makes collector behaviour testable without invoking real external programs.

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
- writing acquired material beneath its staging workspace;
- registering every intentional collector artefact;
- returning source-specific metadata, evidence metadata, warnings and observations.

A collector is not responsible for:

- project or case creation;
- identifier allocation;
- evidence-key management;
- operator signing policy;
- generic manifests;
- archive sealing;
- mandatory verification;
- project packaging.

The current built-in registry contains the YouTube collector. The registry is explicit rather than plugin-driven for now. This provides a clean extension point without committing FACT to a third-party plugin security model prematurely.

## Artefact registry

Collector outputs are explicit first-class artefacts.

Each registered artefact has a staging-relative path and a role. Initial roles are:

- `primary`;
- `supporting`;
- `metadata`;
- `transcript`;
- `derived`;
- `annotation`;
- `redaction_request`;
- `preview`.

The important boundary is between acquired evidence and material produced later by review or derivation. A redacted image, annotation layer or preview must never silently replace or masquerade as the acquired original.

The registry rejects symbolic links and files outside the acquisition staging directory. This prevents a collector from registering an unrelated host file as acquisition evidence merely by referring to it.

`ARTEFACTS.json` serialises the registry for later verification and review tooling.

## Evidence-set identity

The collector-independent sealing layer creates `EVIDENCESET-SHA256.txt` from the explicitly registered collector artefacts.

This replaces the weaker architectural assumption that every regular file found beneath certain hard-coded directories is necessarily part of the acquired source payload. Future collectors can use whatever sensible directory layout their source requires while the evidential membership rule remains the same.

Generated FACT records, signing material and manifests are not part of this source-payload identity. They are covered by the later package manifests and archive signatures.

## Command service

Collectors receive a `CommandRunner` rather than invoking `subprocess` directly.

The existing functional command API remains available internally, but the runner gives collectors an injectable service boundary for:

- command execution;
- environment handling;
- transcript generation;
- return-code policy;
- required executable discovery;
- version probing.

Future security work, including argument redaction for sensitive command-line values, can therefore be implemented centrally.

## YouTube migration

YouTube remains the first collector and behavioural baseline.

The former monolithic acquisition function has been divided so that:

- YouTube URL parsing, `yt-dlp`, live-chat capture, supplemental HTTP capture and media inspection live under `collectors/youtube/`;
- workspace creation and artefact registration live under `core/acquisition.py`;
- archive sealing, source-payload manifests, hashing, signatures and mandatory self-verification live under `core/sealing.py`;
- external commands live under `services/commands.py`.

The legacy `fact acquire URL` form remains accepted during migration. The preferred collector-oriented spelling is:

```bash
fact acquire youtube URL --case-id CASE-ID --case-comment "Purpose"
```

The `youtube-forensics` console entry point remains a compatibility alias to `fact`.

## Review and derivation boundary

The `review/` package is intentionally present as an architectural destination but does not yet contain the screenshot review implementation.

FACT uses the following distinction:

> Acquisition creates evidence. Review describes evidence. Derivation creates representations of evidence.

This rule will govern screenshot annotations and requested redactions. The original screenshot will remain immutable. Annotation and proposed-redaction layers will be stored separately, and rendered derivatives will be explicitly identified as derivatives.

The same review model is intended to support later image evidence, PDF pages, extracted video frames and the closed-project HTML evidence browser.

## Next collectors

The architecture is designed for the following near-term collectors:

- screenshot capture;
- logical file capture;
- web-page capture.

Screenshot capture is now implemented through a reusable capability/backend boundary. `ScreenshotCollector` owns evidential semantics, `LinuxScreenshotCapability` owns Linux backend policy, and `XdgDesktopPortalBackend` owns the concrete D-Bus portal interaction. Detailed behaviour is documented in `SCREENSHOT_CAPTURE.md`.

## Compatibility and migration

Internal imports should use `fact`, not `youtube_forensics`.

Compatibility wrappers exist only to reduce unnecessary breakage while the project transitions from its original name. New modules, tests and documentation should use the canonical `fact` package.

Compatibility aliases must not grow new functionality. New evidential logic belongs only in the canonical FACT implementation.
