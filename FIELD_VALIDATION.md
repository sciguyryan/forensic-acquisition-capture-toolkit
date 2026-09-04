# FACT v2.3.0 field validation

This release is primarily an architectural refactor. Field validation should therefore concentrate on proving that existing YouTube behaviour still works while the canonical Python implementation has moved to the generic FACT architecture.

## Fresh environment

From the extracted release directory on Arch Linux with fish:

```fish
python -m venv .venv
source .venv/bin/activate.fish
python -m pip install -e '.[dev]'
```

Confirm both console names resolve to the same FACT CLI:

```fish
fact --help
youtube-forensics --help
```

Run the automated suite:

```fish
python -m pytest
ruff check .
ruff format --check .
```

## Collector syntax

Confirm the preferred explicit collector form parses correctly:

```fish
fact acquire youtube --help
```

The current parser also preserves the v2.2 URL-only form for compatibility. During this release the actual acquisition options remain the same as the existing YouTube workflow.

## Representative YouTube acquisition

Perform one representative acquisition using the explicit collector form and the same operator profile/key material you would normally use.

Confirm that the resulting staging directory contains the familiar acquisition records plus the new:

```text
ARTEFACTS.json
```

Inspect `ARTEFACTS.json` and confirm the captured media is identified as `primary` and supporting collector output is listed separately.

Confirm `TOOLKIT.json` identifies FACT and records `youtube` as the collector.

Confirm the archive is hashed, signed by the FACT evidence key, signed by the operator, and passes mandatory self-verification as before.

## Failure state

If practical in a disposable test case, attempt an acquisition with a deliberately invalid or unavailable YouTube target.

Confirm the staging directory remains present and retains:

```text
INCOMPLETE
CASE_RECORD.json
CASE_RECORD.md
```

A failed capture must not be reported as sealed evidence.

## Regression expectation

The refactor is accepted when ordinary YouTube acquisition and verification remain operational, the new explicit collector syntax works, and no new code path depends on the historical `youtube_forensics` implementation namespace.
