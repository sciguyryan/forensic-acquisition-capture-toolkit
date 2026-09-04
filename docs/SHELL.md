# Interactive FACT shell

FACT 2.7 completes the interactive shell foundation. The shell is an operator interface over the existing command handlers and core services. It is not a separate evidential implementation and must not duplicate acquisition, catalogue, cryptographic, verification, or packaging logic.

## Starting the shell

Run:

```bash
fact shell
```

To disable persistent local command history while retaining completion, run:

```bash
fact shell --no-history
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

After FACT has explicitly encountered a project by path, the shell records its project ID and path in a per-user local registry. The registry is operational convenience state, not evidence, and every entry is revalidated against the project's canonical `PROJECT.toml` before use. You can then select a uniquely registered project by ID:

```text
fact> project select JAMES-KOASH-2026
```

Use `projects` to show currently validated registry entries. If multiple valid paths claim the same project ID, FACT treats the ID as ambiguous and requires an explicit path rather than guessing.

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

`help` prints the current shell command summary. `help COMMAND ...` delegates to the canonical CLI parser for command-specific help. `exit` and `quit` leave the shell. End-of-file also exits cleanly.

`Ctrl-C` cancels the current shell input and returns to a fresh prompt rather than terminating the shell. Malformed shell quoting is reported as an input error and does not end the session.

The shell uses POSIX-style quoting rules through Python's `shlex` parser. Paths or arguments containing spaces should therefore be quoted in the normal shell style.

## History and completion

When the platform provides Python's optional `readline` module and the shell is attached through the normal interactive input path, FACT enables tab completion and a bounded local command history. These features are convenience state only and never enter the evidential catalogue or packages.

History is stored under the user's XDG state directory, or `~/.local/state/fact/` when `XDG_STATE_HOME` is not set. FACT writes the state directory owner-only and the history file mode `0600` where the platform permits it. Obvious sensitive command forms such as password, passphrase, token, private-key, cookie-file, public-key, requestor, acquisition-comment, case-comment, and key-export commands are not retained. Automated or injected input functions do not activate readline history. Operators can disable persistent history entirely with `fact shell --no-history`.

Completion includes the shell command surface, common subcommands and collector names, validated registered project IDs, and active case IDs in the selected project. It does not execute acquisitions or other evidential operations.

## Future command families

The shell is intended to host later project and case operations, including ownership, notes, audit, verification, sealing, packaging, screenshot review, and project closure. Those capabilities should be implemented in reusable core/application services first and then exposed through both the ordinary CLI and this shell.

## Authenticated operator context

FACT 2.8 adds a cryptographically authenticated operator context to the interactive shell. After selecting an authority-enabled project, run:

```text
PROJECT-ID> auth OPERATOR-ID
```

FACT resolves the selected project-retained operator identity, asks the local GnuPG environment to sign a fresh project-scoped challenge with that identity's exact retained fingerprint, and verifies the result against the retained public key. The shell then records that operator as authenticated for the selected project.

Use:

```text
PROJECT-ID> whoami
PROJECT-ID> logout
```

Changing or clearing the selected project clears the authenticated operator automatically. The shell requires an authenticated context before dispatching protected project mutations such as acquisition, contributor changes, ownership changes, record decisions, case creation or retirement, catalogue checkpointing, and project packaging.

Authentication does not replace transaction signatures. Authority-changing operations still sign the exact catalogue transaction separately before it enters the rolling chain. The session challenge proves possession of the project-retained key for the current interactive context; the transaction signature binds the operator to the specific project mutation.

Authority and responsibility commands available through the same canonical command dispatcher include:

```text
contributor list
contributor invite --operator-id OPERATOR-ID --public-key /path/to/operator-public-key.asc
contributor accept --operator-id OPERATOR-ID
contributor reject --operator-id OPERATOR-ID
owner current
owner transfer OPERATOR-ID --reason "Handover"
owner accept --operator-id OPERATOR-ID
owner reject --operator-id OPERATOR-ID --reason "Declined"
owner cancel --reason "Plans changed"
record list
record approve ACQ-000123
record reject ACQ-000123 --reason "Outside scope"
```

The project owner remains responsible for approving or rejecting pending contributor acquisitions. Rejected records remain in project history. Ownership changes are proposed by the current owner and require signed acceptance by the intended incoming owner before responsibility changes.
