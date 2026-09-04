# Interactive FACT shell

FACT 2.6 introduces the first interactive shell foundation. The shell is an operator interface over the existing command handlers and core services. It is not a separate evidential implementation and must not duplicate acquisition, catalogue, cryptographic, verification, or packaging logic.

## Starting the shell

Run:

```bash
fact shell
```

When started inside a FACT project, including a case subdirectory, the shell discovers the containing project automatically. When started elsewhere, it remains deliberately unbound until the operator selects a project.

A bound prompt always exposes the current evidential context:

```text
JAMES-KOASH-2026> 
JAMES-KOASH-2026 / CASE-000017> 
```

The prompt is an operator safety feature. It makes the target project and case visible before a state-changing command is entered.

## Project context

Select an existing project by path:

```text
fact> project select /path/to/project
```

The equivalent shell-friendly alias is:

```text
fact> select project /path/to/project
```

Clear only the transient shell binding with:

```text
PROJECT-ID> project clear
```

This does not alter the project, catalogue, cases, or evidence.

Use `context` at any time to print the selected project path and selected case.

Project selection by a global project ID alone is intentionally not implemented yet because FACT does not currently maintain a trusted global project registry. The shell therefore requires a project path unless it was started inside a project. This avoids guessing between unrelated projects that happen to exist on the host.

## Case context

Existing case commands work inside the shell:

```text
PROJECT-ID> case list
PROJECT-ID> case select
PROJECT-ID> case select CASE-000017
PROJECT-ID / CASE-000017> case current
```

The alias form is also accepted:

```text
PROJECT-ID> select case
```

When the selected-case pointer becomes invalid, for example because the selected case was retired from another session, the prompt displays:

```text
PROJECT-ID / !invalid-case> 
```

FACT does not silently switch to another case. The operator must deliberately select a valid case.

## Acquisition and other commands

Commands that operate on the current project are translated to the same canonical CLI arguments used outside the shell. For example:

```text
PROJECT-ID / CASE-000017> acquire screenshot
```

is dispatched in-process as the equivalent of:

```bash
fact --root /path/to/project acquire screenshot
```

No child `fact` process is spawned and the shell has no alternate acquisition implementation.

The foundation also accepts existing project-scoped command families such as:

```text
catalogue verify
package
```

Evidence archive verification remains usable without a selected project because it operates on the archive supplied by the operator.

## Input behaviour

`help` prints the current shell command summary. `exit` and `quit` leave the shell. End-of-file also exits cleanly.

`Ctrl-C` cancels the current shell input and returns to a fresh prompt rather than terminating the shell. Malformed shell quoting is reported as an input error and does not end the session.

The shell uses POSIX-style quoting rules through Python's `shlex` parser. Paths or arguments containing spaces should therefore be quoted in the normal shell style.

## History and completion

The v2.6 foundation deliberately does not persist command history and does not add an interactive completion dependency. The implementation keeps those concerns outside the evidential command path so future history and completion support can be added without changing command semantics.

Any future persistent shell history must be treated as local operational data rather than evidence and must avoid retaining secrets or other sensitive arguments unnecessarily.

## Future command families

The shell is intended to host later project and case operations, including ownership, notes, audit, verification, sealing, packaging, screenshot review, and project closure. Those capabilities should be implemented in reusable core/application services first and then exposed through both the ordinary CLI and this shell.
