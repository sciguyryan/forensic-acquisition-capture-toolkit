# FACT development TODO

This document records accepted future work that has not yet been implemented. Items are architectural commitments or investigation targets rather than promises that a particular interface is final.

## Identity and key lifecycle

- Add auditable operator signing-key rotation without invalidating historical signatures or rewriting the key that represented an operator at an earlier catalogue sequence.
- Add explicit signing-key revocation and compromised or lost-key recovery with conservative, highly visible exceptional transactions rather than making recovery appear to be an ordinary key rotation.
- Design exceptional ownership recovery for situations in which the current owner cannot participate. Recovery must never masquerade as a consensual ownership transfer and must retain the reason, authority and recovery path in project history.
- Review contributor public-key import and explicit project-identity selection ergonomics while preserving the rule that local keyring state cannot redefine project-retained identity.
- Continue extending individually signed authority semantics to later structural lifecycle operations where attribution is evidentially meaningful.

## Notes

- Add first-class retained notes with project scope and optional case association, with a future-friendly optional acquisition association.
- Preserve note authorship, creation time, revisions, edit history, and reasons for meaningful changes. Do not silently overwrite note history.
- Add package-time note disclosure controls. Notes remain retained inside FACT but are excluded from external packages by default unless explicitly included.
- Support inclusion of all notes or selected notes and retain internal package history describing what each export included or withheld.

## Case lifecycle

- Add case audit as an integrity and completeness inspection operation.
- Add case verification as a structural and cryptographic validation operation.
- Add case sealing as an explicit lifecycle transition that binds the responsible owner and verified state.
- Add case packaging as a transport/export operation distinct from sealing.

## Screenshot review and presentation

- Continue the generic review subsystem with editable structured annotations and auditable revision history.
- Support common screenshot-style annotation shapes including arrows, rectangles, circles/ellipses, lines, highlights, markers, text, and freehand paths.
- Preserve the immutable original image. Annotation geometry remains in normalised coordinates and is rendered as separate scalable layers.
- Add proposed redactions as a separate layer with a mandatory reason for every redaction.
- Keep requested/proposed redactions distinct from destructively flattened redacted derivatives.
- Build a minimal self-contained HTML/SVG review application around the existing review-layer foundation.
- On project closure, generate a self-contained static HTML media browser for project evidence, derivatives, provenance, review layers, and other appropriate retained records.
