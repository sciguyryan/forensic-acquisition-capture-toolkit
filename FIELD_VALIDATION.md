# FACT v2.4.0 field validation

This release introduces FACT's first screenshot collector and the first platform-specific acquisition capability. Field validation should concentrate on the real Arch Linux desktop portal, preservation of the original screenshot bytes, and unchanged YouTube behaviour.

## Fresh environment

From the extracted release directory on Arch Linux with fish:

```fish
python -m venv .venv
source .venv/bin/activate.fish
python -m pip install -e '.[dev,screenshot]'
```

Confirm the CLI and optional screenshot dependency are available:

```fish
fact --help
python -c 'import dbus_next; print("dbus-next available")'
```

Run the automated suite and local style checks:

```fish
python -m pytest
ruff check .
ruff format --check .
```

## Desktop portal prerequisites

Confirm a portal is available in the current graphical session:

```fish
systemctl --user status xdg-desktop-portal.service
```

The service may be socket/D-Bus activated and need not have been started manually before use. Your desktop must also have an appropriate XDG portal backend installed and configured.

For troubleshooting, record the output of:

```fish
echo $XDG_SESSION_TYPE
echo $XDG_CURRENT_DESKTOP
```

Do not alter portal configuration merely to make FACT pass unless the existing desktop portal setup is itself broken.

## Window screenshot acquisition

Create or select a disposable case, then run:

```fish
fact \
    --root /path/to/project \
    acquire screenshot \
    --case-id CASE-000001 \
    --case-comment "FACT v2.4 screenshot field validation"
```

Expected behaviour:

1. FACT logs that screenshot capture is starting with target `window`.
2. The desktop/compositor presents its normal screenshot/window-selection interface.
3. Select one ordinary application window.
4. FACT completes the acquisition, seals the evidence archive, and reports mandatory self-verification success.

On Wayland, the selector is expected to be desktop-owned rather than a FACT-owned list. This is deliberate.

## Inspect the retained staging tree

Locate the `.staging-...` directory retained for the successful acquisition.

Confirm it contains an original screenshot under:

```text
evidence/
```

and capture metadata at:

```text
metadata/screenshot-capture.json
```

Confirm `ARTEFACTS.json` identifies the screenshot as `primary` and `screenshot-capture.json` as `metadata`.

Confirm `CASE_RECORD.json` includes:

```text
collector: screenshot
capture_type: screenshot
screenshot_target: window
```

and identifies the selection mechanism/backend.

The screenshot should contain only the selected source returned by your desktop capture implementation. FACT must not draw any annotation, border, watermark, redaction, title, or other modification onto it.

## Exact-byte and metadata expectations

Do not edit the acquired screenshot during validation.

Confirm the file can be opened by an ordinary image viewer and that the recorded dimensions in `metadata/screenshot-capture.json`, when present, match the image.

The screenshot image is expected to be the exact byte sequence returned by the portal. FACT may inspect image structure but must not re-save or normalise the image.

## Cancellation test

Run another screenshot acquisition and cancel the desktop selector instead of choosing a source.

Expected behaviour:

- FACT reports that screenshot selection was cancelled;
- no successful evidence archive is reported;
- the staging directory remains present;
- `INCOMPLETE` remains present; and
- the initial case record remains available.

Cancellation must not be converted into a successful blank or fallback screenshot.

## Other portal target classes

If your desktop advertises them, optionally exercise:

```fish
--screenshot-target screen
--screenshot-target area
--screenshot-target active-window
```

FACT should request exactly the named target class and should fail rather than silently substitute another class when the portal does not support it.

## YouTube regression

Perform one representative YouTube acquisition using:

```fish
fact acquire youtube URL --case-id CASE-ID --case-comment "Regression check"
```

Confirm the existing hashing, toolkit signature, operator signature, and mandatory self-verification behaviour remains intact.

## Acceptance

The release is accepted when:

- a real Arch Linux window capture succeeds through the desktop portal;
- the selected screenshot is preserved as immutable primary evidence;
- screenshot metadata is present and coherent;
- cancellation leaves an `INCOMPLETE` acquisition rather than sealing evidence;
- the sealed archive verifies normally; and
- representative YouTube acquisition continues to work.

Please also note which desktop environment/compositor and whether the session is Wayland or X11. That result will guide the next backend work.
