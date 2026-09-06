from __future__ import annotations

from pathlib import Path

import pytest

from fact.core.context import (
    active_case_contexts,
    choose_case_interactively,
    discover_project_root,
    get_selected_case,
    infer_case_from_path,
    read_case_context,
    resolve_case_context,
    set_selected_case,
)
from fact.core.project import _initialise_project as initialise_project
from fact.core.project import create_case, retire_case
from fact.errors import ToolkitError


def make_project(tmp_path: Path) -> tuple[Path, str, str]:
    root = tmp_path / "project"
    initialise_project(root, "P-1", "Project")
    first = create_case(root, "First case", "First comment")
    second = create_case(root, "Second case", "Second comment")
    return root, first, second


def test_discover_project_root_from_case_subdirectory(tmp_path: Path) -> None:
    root, first, _ = make_project(tmp_path)
    nested = root / "cases" / first / "acquisitions"
    assert discover_project_root(nested) == root
    with pytest.raises(ToolkitError, match="No FACT project"):
        discover_project_root(tmp_path / "elsewhere")


def test_case_context_reads_and_infers_from_path(tmp_path: Path) -> None:
    root, first, _ = make_project(tmp_path)
    context = read_case_context(root, first)
    assert context.title == "First case"
    nested = context.path / "acquisitions" / "anything"
    nested.mkdir(parents=True)
    inferred = infer_case_from_path(root, nested)
    assert inferred is not None
    assert inferred.case_id == first
    assert infer_case_from_path(root, root) is None


def test_selected_case_is_persisted_and_must_remain_active(tmp_path: Path) -> None:
    root, first, _ = make_project(tmp_path)
    selected = set_selected_case(root, first)
    assert selected.case_id == first
    assert get_selected_case(root).case_id == first
    retire_case(root, first, "done")
    with pytest.raises(ToolkitError, match="no longer usable"):
        get_selected_case(root)


def test_resolution_precedence_and_sole_case(tmp_path: Path) -> None:
    root, first, second = make_project(tmp_path)
    assert resolve_case_context(root, explicit_case_id=second).case_id == second

    # A current-directory case takes precedence over a persisted selection.
    set_selected_case(root, second)
    assert (
        resolve_case_context(
            root, current=root / "cases" / first, interactive=False
        ).case_id
        == first
    )

    # With no stored selection, the sole active case is safe to choose automatically.
    (root / ".fact" / "selected-case").unlink()
    retire_case(root, second, "done")
    assert resolve_case_context(root, current=root, interactive=False).case_id == first


def test_multiple_cases_require_selection_when_noninteractive(tmp_path: Path) -> None:
    root, _, _ = make_project(tmp_path)
    with pytest.raises(ToolkitError, match="Multiple active cases"):
        resolve_case_context(root, current=root, interactive=False)


def test_interactive_case_choice_uses_numbers_not_transcribed_ids(
    tmp_path: Path,
) -> None:
    root, first, second = make_project(tmp_path)
    chosen = choose_case_interactively(root, input_fn=lambda _: "2")
    assert chosen.case_id == second
    assert get_selected_case(root).case_id == second
    with pytest.raises(ToolkitError, match="must be a number"):
        choose_case_interactively(root, input_fn=lambda _: "CASE-000001")
    with pytest.raises(ToolkitError, match="outside"):
        choose_case_interactively(root, input_fn=lambda _: "99")
    assert [case.case_id for case in active_case_contexts(root)] == [first, second]


def test_case_context_rejects_unknown_or_retired_explicit_case(tmp_path: Path) -> None:
    root, first, _ = make_project(tmp_path)
    with pytest.raises(ToolkitError, match="Unknown FACT case"):
        resolve_case_context(root, explicit_case_id="CASE-999999")
    retire_case(root, first, "done")
    with pytest.raises(ToolkitError, match="not active"):
        resolve_case_context(root, explicit_case_id=first)


def test_discovery_rejects_project_from_different_schema(tmp_path: Path) -> None:
    """Do not reinterpret an active project created under another trust model."""
    initialise_project(tmp_path, "P-OLD", "Older project")
    project_file = tmp_path / "PROJECT.toml"
    project_text = project_file.read_text(encoding="utf-8")
    assert "schema_version = 11" in project_text
    assert 'fact_version = "2.19.0"' in project_text
    project_file.write_text(
        project_file.read_text(encoding="utf-8").replace(
            "schema_version = 11", "schema_version = 1"
        ),
        encoding="utf-8",
    )

    with pytest.raises(ToolkitError, match="different FACT project schema"):
        discover_project_root(tmp_path)


def test_discovery_rejects_interrupted_owner_bootstrap_marker(tmp_path: Path) -> None:
    """Never treat a marked, interrupted owner bootstrap as an active project."""
    initialise_project(tmp_path, "P-INT", "Interrupted")
    (tmp_path / ".fact-initialising").write_text("in progress\n", encoding="utf-8")
    with pytest.raises(ToolkitError, match="initialisation is incomplete"):
        discover_project_root(tmp_path)
