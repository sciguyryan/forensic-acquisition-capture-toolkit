# Image review layers and browser foundation

FACT preserves acquired visual evidence separately from review and presentation data.

The governing rule is:

> Acquisition creates evidence. Review describes evidence. Derivation creates representations of evidence.

The screenshot collector therefore continues to preserve the original capture bytes unchanged. Annotation and proposed-redaction data are separate structured layers that refer to the immutable original by committed content digest or stable file identity and original dimensions.

## Initial annotation vocabulary

The review model reserves simple primitives familiar from ordinary screenshot tools:

- rectangle;
- ellipse;
- arrow;
- line;
- freehand path;
- numbered or labelled marker;
- text;
- highlight.

This release establishes the data model and presentation plumbing. It does not yet expose a graphical editor for creating these objects.

## Scale-independent coordinates

Review geometry is stored using normalised coordinates from `0.0` to `1.0` relative to the original image dimensions. This avoids binding an annotation to whichever CSS size, monitor scale, or zoom level happened to be used during review.

The browser shell converts those normalised values back into the original image coordinate space and renders them in an SVG overlay whose view box matches the original pixel dimensions. The browser can therefore resize the underlying image while the overlay remains aligned.

Invalid points, boxes outside the image, and zero-size regions are rejected by the review model.

## Proposed redactions

A proposed redaction is not a mutation of the evidence image. It is a structured rectangular region with a stable identifier and a mandatory reason. A category may also be recorded.

FACT will later be able to use the same proposal to:

- display a redaction preview over the original;
- produce a human-readable requested-redactions report;
- generate a deliberately flattened redacted derivative when policy requires one.

The original screenshot remains available and independently verifiable in every case.

## Minimal browser shell

`fact.review.browser` now provides the static presentation shell that future screenshot review and project closure work can build upon.

The shell contains no third-party JavaScript or network dependency. It loads the immutable image as a normal local resource and renders annotations and proposed redactions in separate SVG layers. Each layer can be toggled independently.

A generated presentation copy of the structured review JSON is embedded in the HTML configuration so the shell continues to work when opened directly from `file://`, where browsers often restrict `fetch()` of sibling local files. The canonical review JSON remains a separate project artefact; the embedded copy is only generated presentation state.

The shell currently renders the basic box, ellipse, line, arrow, highlight, and proposed-redaction primitives needed to prove the layer architecture. Editor controls, notes panels, audit history for review changes, and derivative export belong to subsequent work.

## Closed-project browser

The eventual project-closure browser should reuse this same layer model rather than inventing a second screenshot presentation format. A closed project can then provide a static media index over screenshots, video, audio, files and other supported material while preserving raw originals beneath the presentation layer.

Preserved web content and other untrusted evidence must never be injected into the browser application's trusted DOM as executable markup. Evidence metadata should be rendered as data, and active web content should be isolated or presented through safe derived representations.
