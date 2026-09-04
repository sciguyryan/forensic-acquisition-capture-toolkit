# FACT v2.6.0 field validation

This release introduces the interactive shell foundation. Field validation should concentrate on context visibility, safe project and case switching, normal command dispatch, and unchanged screenshot/YouTube acquisition behaviour.

## Fresh environment

From the extracted release directory on Arch Linux with fish:

```fish
python -m venv .venv
source .venv/bin/activate.fish
python -m pip install -e '.[dev,screenshot]'
```

Run the automated and local style checks:

```fish
python -m pytest
ruff check .
ruff format --check .
```

Confirm the new command is present:

```fish
fact --help
fact shell
```

## Start inside an existing project

Change into your test project or one of its case directories and start:

```fish
fact shell
```

Expected behaviour:

1. FACT identifies the containing project automatically.
2. The prompt shows the project ID.
3. If the project already has a selected active case, the prompt also shows that case ID.
4. `context` prints the project ID, project path, and selected case.

A typical prompt should resemble:

```text
JAMES-KOASH-2026 / CASE-000001> 
```

## Start outside a project

From a directory that is not within a FACT project:

```fish
fact shell
```

The prompt should be:

```text
fact> 
```

Run:

```text
context
project select /mnt/storage/Forensic/projects/james-koash-2026
```

FACT should bind the explicit project and change the prompt. It must not guess a project merely because other FACT projects exist elsewhere on the system.

## Case selection

Inside the shell, try:

```text
case list
case select
case current
```

When more than one active case exists, the numbered selector should allow selection without retyping the case ID. The prompt should update immediately after selection.

Also test the direct form with a known disposable case:

```text
select case CASE-000001
```

If practical, retire the selected disposable case from a second terminal. The existing shell prompt should change to:

```text
PROJECT-ID / !invalid-case> 
```

FACT must not silently choose another active case. Select a valid case explicitly before continuing.

## Screenshot acquisition through the shell

With the correct project and case visible in the prompt, run:

```text
acquire screenshot --acquisition-comment "FACT v2.6 shell screenshot validation"
```

Expected behaviour is identical to the ordinary CLI screenshot workflow. On Wayland, the desktop/compositor should present its trusted capture selector. FACT must preserve the returned original screenshot bytes without annotations, redactions, resizing, or re-encoding.

After capture, verify that the acquisition receives the next catalogue-owned `ACQ-######` identifier and completes the normal sealing and self-verification path.

## Command and input behaviour

Confirm:

```text
help
context
catalogue verify
```

Then test the following interaction behaviour:

- press `Ctrl-C` at an empty shell prompt and confirm the shell remains active;
- enter a malformed quoted command and confirm FACT reports the parsing error without exiting;
- type `shell` and confirm nested shell creation is refused;
- type `exit` or `quit` and confirm the shell exits cleanly.

## Regression checks

Run one representative YouTube acquisition through the ordinary CLI or the shell and confirm its output remains consistent with the accepted v2.5 behaviour.

Create a normal project package and confirm sealed acquisition archives and their sidecars remain present while mutable `.staging-*` directories remain excluded.

The `.gitignore` in this release should match the accepted FACT baseline and the release tree should not contain `src/fact_forensic_toolkit.egg-info/` or other generated `*.egg-info/` directories.
