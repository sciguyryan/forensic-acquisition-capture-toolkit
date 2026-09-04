# Screenshot capture

FACT v2.4 introduces the first screenshot acquisition capability. The initial implementation targets Arch Linux and other modern Linux desktop environments that provide the XDG Desktop Portal Screenshot interface.

Screenshot acquisition follows the same collector-independent lifecycle as YouTube acquisition. Capture produces an immutable original, registers it as primary evidence, writes capture metadata, and passes those artefacts to the normal FACT hashing, sealing, signing, and mandatory verification path.

## Evidential boundary

A screenshot collector captures pixels. It does not annotate, redact, resize, crop, colour-correct, or otherwise edit them.

The original file returned by the selected capture backend is copied byte-for-byte into the FACT acquisition staging area before non-essential image inspection occurs. FACT then reads only enough image structure to identify common formats and, where possible, record pixel dimensions. It does not open and re-save the image.

This preserves the project rule:

> Acquisition creates evidence. Review describes evidence. Derivation creates representations of evidence.

Future annotation and requested-redaction layers will therefore reference the immutable screenshot instead of modifying it.

## Arch Linux and Wayland

FACT's preferred Linux backend is XDG Desktop Portal.

On Wayland, applications generally do not have unrestricted access to enumerate and capture other applications' windows. FACT deliberately respects that security boundary rather than relying on compositor-specific bypasses.

Screenshot portal version 3 defines explicit capture targets for:

- screen;
- window;
- area; and
- active window.

For a normal FACT screenshot acquisition, the requested target defaults to `window`. The desktop/compositor presents its trusted selection interface and the operator chooses the window there. FACT records that the selection was portal-mediated but does not invent a window title or identity that the portal did not provide.

This means the current Wayland workflow is intentionally not a FACT-owned textual list of windows. A future X11 backend may be able to enumerate windows explicitly and present a FACT-owned list, but that interface must implement the same backend contract and must not weaken the Wayland design.

The relevant upstream interfaces are documented at:

- https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Screenshot.html
- https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Request.html
- https://wiki.archlinux.org/title/XDG_Desktop_Portal

## Dependencies

Screenshot capture has one optional Python dependency, `dbus-next`, used to communicate with the desktop portal over the session D-Bus.

Install FACT for screenshot development with:

```bash
python -m pip install -e '.[dev,screenshot]'
```

The Linux desktop must also have `xdg-desktop-portal` and a suitable portal backend configured for the active desktop environment. Arch Linux provides desktop-specific backends such as the KDE, GNOME, wlroots, GTK, COSMIC, and other implementations.

FACT does not select or replace the user's desktop portal backend. The desktop environment remains responsible for routing the request to the appropriate implementation.

## Command line

The basic window-capture command is:

```bash
fact acquire screenshot \
    --acquisition-comment "Capture the selected application window"
```

The default screenshot target is `window`.

Other portal target classes can be requested explicitly:

```bash
fact acquire screenshot \
    --screenshot-target screen \
    --acquisition-comment "Capture the complete display"
```

Current target values are:

```text
window
screen
area
active-window
```

The Linux backend can be selected explicitly with:

```bash
--screenshot-backend portal
```

`auto` is the default and currently resolves to the portal backend on Linux. This option is intentionally present now so additional Linux and non-Linux backends can be added without changing the collector's evidence model or command structure.

## Portal requirements and conservative failure

FACT requires Screenshot portal version 3 or later for explicit target selection. It also checks the portal's `AvailableTargets` bitmask before requesting the capture.

FACT fails rather than silently capturing a different class of source when:

- the portal interface is too old;
- the requested target is not advertised;
- the operator cancels selection;
- the portal returns an invalid or non-local result URI;
- the returned path is not a regular file;
- the backend attempts to return evidence outside FACT staging; or
- the portal interaction otherwise fails.

A failed or cancelled acquisition retains the normal `INCOMPLETE` staging state and initial case record.

## Acquisition contents

A successful screenshot collector run contributes at least:

```text
evidence/
  screenshot-original.png
metadata/
  screenshot-capture.json
```

The original extension can differ if the portal returns another recognised image format. Unrecognised bytes are still preserved rather than transformed, and FACT records that the media type was not identified.

`screenshot-capture.json` records information such as:

- capture type;
- requested target;
- capture backend;
- selection method;
- original filename;
- operating-system and machine information;
- portal interface version;
- portal target capabilities;
- desktop/session information exposed by the environment;
- image media type; and
- pixel dimensions when FACT can read them without decoding or rewriting the image.

The source record explicitly identifies the acquisition as a screenshot capture.

## Window identity limitation

The XDG Screenshot portal returns the screenshot image URI, but does not provide FACT with a portable, trustworthy window title or application identity as part of the Screenshot response.

FACT therefore records the source as an operator-selected window and records the selection mechanism. It does not infer the title from unrelated desktop APIs. This is a deliberate provenance decision: unavailable information is preferable to guessed information in an evidence record.

A future platform backend may provide stronger source descriptors when the operating system exposes them through a trustworthy capture API.

## Modularity

The screenshot implementation is split into three levels:

```text
ScreenshotCollector
    |
    v
LinuxScreenshotCapability
    |
    v
XdgDesktopPortalBackend
```

The collector owns FACT-specific evidence semantics. The capability owns platform policy. The backend owns the concrete desktop API.

Future additions can therefore include, for example:

```text
LinuxScreenshotCapability
  |- XdgDesktopPortalBackend
  `- X11WindowBackend

WindowsScreenshotCapability
  `- WindowsGraphicsCaptureBackend

MacOSScreenshotCapability
  `- ScreenCaptureKitBackend
```

without making the screenshot collector depend on one operating system.

## Review layers

FACT now has the foundation for annotation and proposed-redaction layers, while the graphical editor remains future work.

The review system loads the immutable original and maintains separate structured overlay layers. Shapes such as arrows, circles, rectangles, highlights, markers, and text will be stored as scalable/normalised geometry rather than burned into the source image. Proposed redactions will form a separate layer and each redaction will require a reason.

The same layer data is designed to drive:

- the interactive FACT review UI;
- the closed-project HTML media browser;
- human-readable annotation/redaction reports; and
- optional rendered derivatives.

No review operation will change the original acquired screenshot.
