# Project, case and acquisition context

FACT allocates evidential identifiers. Operators should not normally transcribe identifiers into every acquisition command.

## Identifier namespaces

Cases and acquisitions use separate monotonically increasing catalogue namespaces:

```text
CASE-000001
CASE-000002
...

ACQ-000001
ACQ-000002
...
```

Once issued, an identifier is permanently consumed. Retirement, failed acquisition, later removal of material, or an interrupted workflow must never make an identifier available for unrelated material.

Current-generation FACT projects initialise every supported identifier namespace when the catalogue is created. A missing required namespace is treated as an incompatible or damaged catalogue and FACT fails closed rather than rewriting it in place.

A failed project acquisition records the issued acquisition identifier as `failed`. Where a staging tree was created, the `INCOMPLETE` marker remains so the failed attempt is not confused with committed evidence.

Acquisition through the current FACT command-line workflow is project based and uses catalogue-owned identifiers. Source collectors do not allocate independent evidence identifiers outside that project authority.

## Case creation and selection

Creating a case allocates the next `CASE-######` identifier automatically. The command-line interface then makes the new active case the project-local selected case:

```bash
fact --root /evidence/project case create --title "Relevant messages"
```

The operator can inspect or change that selection:

```bash
fact --root /evidence/project case current
fact --root /evidence/project case select
```

`fact case select` displays active cases as a numbered list. The normal interactive workflow therefore asks the operator to choose a meaningful case rather than retype a case identifier. An explicit case identifier remains supported for automation and deliberate operator override.

## Acquisition case resolution

When an acquisition starts without `--case-id`, FACT resolves the case in this order:

1. an explicit `--case-id`, if supplied;
2. an active case inferred from the current directory when the command is run inside that case tree;
3. the project's persisted selected case;
4. the sole active case when exactly one exists;
5. an interactive numbered selector when multiple active cases exist and an interactive terminal is available.

If multiple active cases remain ambiguous in a non-interactive environment, FACT refuses the acquisition rather than guessing.

A selected case must still be active. A stale selection pointing to a retired case is rejected and must be replaced explicitly.

## Case metadata and acquisition comments

`CASE.toml` remains the human-readable case record. Its title and comment can supply default acquisition context, so routine commands do not require the operator to repeat them.

The preferred acquisition-specific options are:

```text
--acquisition-comment
--acquisition-comment-file
```

An explicitly supplied comment file must not be blank.

## Running commands from inside a project

FACT discovers the nearest containing project by walking upwards until it finds both `PROJECT.toml` and `.fact/catalogue.sqlite`. This makes commands usable from the project root or from inside a case directory without changing which catalogue owns the operation.

The transient `.fact/selected-case` pointer is operator workflow state. It does not alter the case record, does not allocate identifiers, and is not a substitute for catalogue verification.
