"""Extended tests for CLI command dispatch and helper behaviour."""

from argparse import Namespace
from pathlib import Path

import pytest

from fact import cli
from fact.core.project import _initialise_project as initialise_project
from fact.errors import ToolkitError
from fact.identity import OperatorIdentity

IDENTITY = OperatorIdentity(1, "jane", "Jane Doe", None, None, None, "A" * 40, "B" * 40)


def test_acquisition_comments_reads_file_and_rejects_empty(tmp_path: Path) -> None:
    """Read comments from UTF-8 files and reject blank content."""
    comment_file = tmp_path / "comment.txt"
    comment_file.write_text("  Purpose  \n", encoding="utf-8")
    assert (
        cli._acquisition_comments(
            Namespace(acquisition_comment=None, acquisition_comment_file=comment_file)
        )
        == "Purpose"
    )
    comment_file.write_text("  \n", encoding="utf-8")
    with pytest.raises(ToolkitError, match="must not be empty"):
        cli._acquisition_comments(
            Namespace(acquisition_comment=None, acquisition_comment_file=comment_file)
        )


def test_verify_keygen_and_export_helpers(tmp_path: Path, monkeypatch) -> None:
    """Verify the project and invoke key-management helpers."""
    calls = []
    monkeypatch.setattr(cli, "discover_project_root", lambda path: tmp_path)
    monkeypatch.setattr(
        cli,
        "verify_chain",
        lambda root: {"event_count": 7, "chain_head": "a" * 64},
    )
    monkeypatch.setattr(cli, "log", lambda *args: calls.append(args))
    assert cli._verify(Namespace(path=tmp_path)) == 0
    assert calls[-1][0] == "PASS"

    monkeypatch.setattr(cli, "ensure_key", lambda *args: "FPR")
    assert cli._keygen(Namespace(root=tmp_path)) == 0
    assert calls[-1][0] == "PASS"

    monkeypatch.setattr(cli, "security_warning", lambda lines: calls.append(lines))
    monkeypatch.setattr(
        cli, "export_keypair", lambda *args, **kwargs: calls.append((args, kwargs))
    )
    assert cli._export_keypair(Namespace(root=tmp_path, output=None, force=True)) == 0


def test_main_dispatches_and_translates_toolkit_errors(monkeypatch) -> None:
    """Dispatch known commands and translate toolkit failures to exit status one."""
    monkeypatch.setattr(cli, "_keygen", lambda args: 7)
    assert cli.main(["keygen"]) == 7
    monkeypatch.setattr(
        cli, "_keygen", lambda args: (_ for _ in ()).throw(ToolkitError("boom"))
    )
    messages = []
    monkeypatch.setattr(cli, "log", lambda *args: messages.append(args))
    assert cli.main(["keygen"]) == 1
    assert messages[-1] == ("ERROR", "boom")


def test_acquire_helper_builds_case_from_project_identity(
    tmp_path: Path, monkeypatch
) -> None:
    """Build acquisition metadata from the project-retained operator identity."""
    case_context = type(
        "CaseContext",
        (),
        {
            "case_id": "CASE-000001",
            "comment": "Case default comment",
            "title": "Case title",
        },
    )()
    monkeypatch.setattr(cli, "discover_project_root", lambda root: tmp_path)
    monkeypatch.setattr(
        cli, "resolve_case_context", lambda *args, **kwargs: case_context
    )
    monkeypatch.setattr(
        cli, "_active_project_identity", lambda root, operator_id: IDENTITY
    )
    monkeypatch.setattr(cli.getpass, "getuser", lambda: "login-user")
    calls = []
    monkeypatch.setattr(
        cli, "run_collector_acquisition", lambda **kwargs: calls.append(kwargs)
    )
    args = Namespace(
        root=tmp_path,
        operator_id="jane",
        acquisition_comment="Purpose",
        acquisition_comment_file=None,
        case_id="CASE-000001",
        requestor="Requestor",
        matter_title="Matter",
        source="youtube",
        target="https://youtu.be/abc",
        cookies=None,
        subtitle_langs="en.*",
        no_live_chat=True,
        sleep_requests="1",
        sleep_subtitles="2",
        min_sleep="3",
        max_sleep="4",
        rate_limit="1M",
        screenshot_target="window",
        screenshot_backend="auto",
    )

    assert cli._acquire(args) == 0
    case = calls[0]["case"]
    assert case.operator_username == "login-user"
    assert case.operator_identity["operator_id"] == "jane"
    assert calls[0]["request"].live_chat is False


def test_package_command_dispatches_project_packaging(
    tmp_path: Path, monkeypatch
) -> None:
    """Create a project package through the public command-line dispatcher."""
    project = tmp_path / "project"
    initialise_project(project, "P-1", "Project")
    monkeypatch.setattr(cli, "require_project_authority", lambda root: None)
    calls = []
    archive = tmp_path / "P-1.fact.tar.gz"
    monkeypatch.setattr(
        cli,
        "create_project_package",
        lambda *args, **kwargs: calls.append((args, kwargs)) or {"archive": archive},
    )
    monkeypatch.setattr(cli, "log", lambda *args: None)

    assert (
        cli.main(
            [
                "--root",
                str(project),
                "package",
                "--toolkit-root",
                str(tmp_path / "toolkit"),
                "--encrypt-to",
                "RECIPIENT",
            ]
        )
        == 0
    )
    assert calls[0][1]["encrypt_to"] == ["RECIPIENT"]


def test_authority_cli_dispatches_project_creation_and_membership(
    tmp_path: Path, monkeypatch
) -> None:
    """Create signed projects and invite contributors without external identity files."""
    project = tmp_path / "project"
    calls = []
    monkeypatch.setattr(cli, "interactive_identity", lambda **kwargs: IDENTITY)
    monkeypatch.setattr(cli, "export_public_key_text", lambda identity: "PUBLIC KEY")
    monkeypatch.setattr(
        cli,
        "initialise_owned_project",
        lambda *args, **kwargs: (
            calls.append(("project", args, kwargs)) or project / "PROJECT.toml"
        ),
    )
    monkeypatch.setattr(cli, "log", lambda *args: calls.append(("log", args)))
    assert (
        cli.main(
            [
                "project",
                "init",
                str(project),
                "--project-id",
                "P-1",
                "--title",
                "Project",
            ]
        )
        == 0
    )
    assert calls[0][0] == "project"

    monkeypatch.setattr(cli, "discover_project_root", lambda root: project)
    monkeypatch.setattr(cli, "require_project_authority", lambda root: None)
    monkeypatch.setattr(
        cli, "_active_project_identity", lambda root, operator_id: IDENTITY
    )
    contributor = OperatorIdentity(
        1, "bob", "Bob", None, None, None, "C" * 40, "D" * 40
    )
    monkeypatch.setattr(cli, "validate_identity", lambda data: contributor)
    monkeypatch.setattr(cli, "export_public_key_text", lambda identity: "PUBLIC BOB")
    monkeypatch.setattr(
        cli, "invite_contributor", lambda *args: calls.append(("invite", args))
    )
    assert (
        cli.main(
            [
                "--root",
                str(project),
                "--operator-id",
                "jane",
                "contributor",
                "invite",
                "bob",
                "--name",
                "Bob",
                "--key-fingerprint",
                "C" * 40,
                "--signing-fingerprint",
                "D" * 40,
            ]
        )
        == 0
    )
    assert any(item[0] == "invite" for item in calls)


def test_authority_cli_owner_record_and_listing_paths(
    tmp_path: Path, monkeypatch
) -> None:
    """Dispatch owner decisions, contributor state and record review commands."""
    project = tmp_path / "project"
    project.mkdir()
    calls = []
    monkeypatch.setattr(cli, "discover_project_root", lambda root: project)
    monkeypatch.setattr(cli, "require_project_authority", lambda root: None)
    monkeypatch.setattr(
        cli, "_active_project_identity", lambda root, operator_id: IDENTITY
    )

    monkeypatch.setattr(
        cli,
        "list_members",
        lambda root: [
            {
                "operator_id": "jane",
                "membership_role": "owner",
                "state": "active",
                "name": "Jane Doe",
            }
        ],
    )
    assert cli.main(["--root", str(project), "contributor", "list"]) == 0

    monkeypatch.setattr(
        cli, "accept_contributor", lambda *args: calls.append("accept-contributor")
    )
    monkeypatch.setattr(
        cli, "reject_contributor", lambda *args: calls.append("reject-contributor")
    )
    monkeypatch.setattr(
        cli, "remove_contributor", lambda *args: calls.append("remove-contributor")
    )
    assert (
        cli.main(
            ["--root", str(project), "--operator-id", "jane", "contributor", "accept"]
        )
        == 0
    )
    assert (
        cli.main(
            ["--root", str(project), "--operator-id", "jane", "contributor", "reject"]
        )
        == 0
    )
    assert (
        cli.main(
            [
                "--root",
                str(project),
                "--operator-id",
                "jane",
                "contributor",
                "remove",
                "bob",
                "--reason",
                "done",
            ]
        )
        == 0
    )

    monkeypatch.setattr(
        cli,
        "current_owner",
        lambda *args, **kwargs: {
            "owner_id": "jane",
            "name": "Jane Doe",
            "effective_from_sequence": 2,
        },
    )
    assert cli.main(["--root", str(project), "owner", "current"]) == 0
    monkeypatch.setattr(
        cli, "propose_ownership_transfer", lambda *args, **kwargs: "XFER-1"
    )
    monkeypatch.setattr(
        cli, "accept_ownership_transfer", lambda *args, **kwargs: "XFER-1"
    )
    monkeypatch.setattr(
        cli, "reject_ownership_transfer", lambda *args, **kwargs: "XFER-1"
    )
    monkeypatch.setattr(
        cli, "cancel_ownership_transfer", lambda *args, **kwargs: "XFER-1"
    )
    assert (
        cli.main(
            [
                "--root",
                str(project),
                "--operator-id",
                "jane",
                "owner",
                "transfer",
                "bob",
                "--reason",
                "handover",
            ]
        )
        == 0
    )

    assert (
        cli.main(["--root", str(project), "--operator-id", "jane", "owner", "accept"])
        == 0
    )
    assert (
        cli.main(
            [
                "--root",
                str(project),
                "--operator-id",
                "jane",
                "owner",
                "reject",
                "--reason",
                "declined",
            ]
        )
        == 0
    )
    assert (
        cli.main(
            [
                "--root",
                str(project),
                "--operator-id",
                "jane",
                "owner",
                "cancel",
                "--reason",
                "changed",
            ]
        )
        == 0
    )

    monkeypatch.setattr(
        cli,
        "list_records",
        lambda root: [
            {
                "object_id": "ACQ-000001",
                "status": "pending",
                "submitted_by": "bob",
                "scope_id": "CASE-000001",
            }
        ],
    )
    assert cli.main(["--root", str(project), "record", "list"]) == 0
    monkeypatch.setattr(
        cli, "decide_record", lambda *args: calls.append(("decision", args))
    )
    assert (
        cli.main(
            [
                "--root",
                str(project),
                "--operator-id",
                "jane",
                "record",
                "approve",
                "ACQ-000001",
            ]
        )
        == 0
    )
    assert (
        cli.main(
            [
                "--root",
                str(project),
                "--operator-id",
                "jane",
                "record",
                "reject",
                "ACQ-000002",
                "--reason",
                "irrelevant",
            ]
        )
        == 0
    )


def test_active_project_identity_requires_explicit_operator(
    tmp_path: Path, monkeypatch
) -> None:
    """Fail closed when an ordinary CLI mutation has no operator context."""
    with pytest.raises(ToolkitError, match="requires --operator-id"):
        cli._active_project_identity(tmp_path, None)
    monkeypatch.setattr(
        cli, "registered_operator_identity", lambda root, operator_id: IDENTITY
    )
    assert cli._active_project_identity(tmp_path, "jane") == IDENTITY


def test_screenshot_acquire_uses_project_identity(tmp_path: Path, monkeypatch) -> None:
    """Dispatch screenshot capture from retained project identity."""
    context = type(
        "CaseContext",
        (),
        {"case_id": "CASE-000001", "comment": "", "title": "Screenshot"},
    )()
    monkeypatch.setattr(cli, "discover_project_root", lambda root: tmp_path)
    monkeypatch.setattr(cli, "resolve_case_context", lambda *args, **kwargs: context)
    monkeypatch.setattr(
        cli, "_active_project_identity", lambda root, operator_id: IDENTITY
    )
    calls = []
    monkeypatch.setattr(
        cli, "run_collector_acquisition", lambda **kwargs: calls.append(kwargs)
    )
    args = Namespace(
        root=tmp_path,
        operator_id="jane",
        source="screenshot",
        target=None,
        case_id="CASE-000001",
        acquisition_comment=None,
        acquisition_comment_file=None,
        requestor=None,
        matter_title=None,
        screenshot_target="window",
        screenshot_backend="portal",
    )
    assert cli._acquire(args) == 0
    assert calls[0]["request"].backend == "portal"
    assert calls[0]["initial_source"]["collector"] == "screenshot"


def test_case_and_authority_read_paths_dispatch(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """Exercise current project read paths without a migration path."""
    project = tmp_path / "project"
    monkeypatch.setattr(cli, "discover_project_root", lambda root: project)
    monkeypatch.setattr(
        cli,
        "list_identifiers",
        lambda root: [{"identifier": "CASE-000001", "state": "active"}],
    )
    assert cli.main(["--root", str(project), "case", "list"]) == 0
    assert "CASE-000001" in capsys.readouterr().out

    selected = type("Selected", (), {"case_id": "CASE-000001", "title": "Matter"})()
    monkeypatch.setattr(cli, "get_selected_case", lambda root: selected)
    assert cli.main(["--root", str(project), "case", "current"]) == 0
    assert "Matter" in capsys.readouterr().out

    monkeypatch.setattr(cli, "authority_enabled", lambda root: True)
    monkeypatch.setattr(
        cli,
        "current_owner",
        lambda root: {
            "owner_id": "jane",
            "name": "Jane Doe",
            "effective_from_sequence": 1,
        },
    )
    assert cli.main(["--root", str(project), "authority", "status"]) == 0
    assert "Owner: jane" in capsys.readouterr().out


def test_catalogue_verify_paths_and_checkpoint_requirement(
    tmp_path: Path, monkeypatch
) -> None:
    """Exercise ordinary and checkpoint catalogue verification dispatch."""
    project = tmp_path / "project"
    monkeypatch.setattr(cli, "discover_project_root", lambda root: project)
    monkeypatch.setattr(cli, "verify_chain", lambda root: {"event_count": 7})
    monkeypatch.setattr(cli, "log", lambda *args: None)
    assert cli.main(["--root", str(project), "catalogue", "verify"]) == 0
    assert (
        cli.main(["--root", str(project), "catalogue", "verify", "--checkpoint"]) == 1
    )

    public_key = tmp_path / "key.asc"
    monkeypatch.setattr(cli, "verify_checkpoint", lambda root, key: {"event_count": 7})
    assert (
        cli.main(
            [
                "--root",
                str(project),
                "catalogue",
                "verify",
                "--checkpoint",
                "--public-key",
                str(public_key),
            ]
        )
        == 0
    )


def test_note_cli_dispatches_create_read_revise_list_and_disclosure(
    tmp_path: Path, monkeypatch
) -> None:
    """Exercise the operator-facing note command family without real cryptography."""
    project = tmp_path / "project"
    project.mkdir()
    calls = []
    monkeypatch.setattr(cli, "discover_project_root", lambda root: project)
    monkeypatch.setattr(cli, "require_project_authority", lambda root: None)
    monkeypatch.setattr(
        cli, "_active_project_identity", lambda root, operator_id: IDENTITY
    )
    monkeypatch.setattr(cli, "log", lambda *args: calls.append(("log", args)))
    monkeypatch.setattr(
        cli,
        "create_note",
        lambda *args, **kwargs: calls.append(("create", args, kwargs)) or "NOTE-000001",
    )
    monkeypatch.setattr(
        cli,
        "list_notes",
        lambda root: [
            {
                "note_id": "NOTE-000001",
                "visibility": "project",
                "author_id": "jane",
                "case_id": None,
                "latest_revision": 2,
                "package_disclosure": "withheld",
            }
        ],
    )
    monkeypatch.setattr(
        cli,
        "read_note",
        lambda *args, **kwargs: {
            "note_id": "NOTE-000001",
            "revision": 2,
            "visibility": "project",
            "title": "Title",
            "body": "Body",
        },
    )
    monkeypatch.setattr(
        cli, "revise_note", lambda *args, **kwargs: calls.append(("revise", args)) or 3
    )
    monkeypatch.setattr(
        cli, "set_note_disclosure", lambda *args: calls.append(("disclose", args))
    )

    base = ["--root", str(project), "--operator-id", "jane", "note"]
    assert (
        cli.main([*base, "create", "--title", "T", "--body", "B", "--confidential"])
        == 0
    )
    assert cli.main([*base, "list"]) == 0
    assert cli.main([*base, "read", "NOTE-000001", "--revision", "2"]) == 0
    assert (
        cli.main(
            [
                *base,
                "revise",
                "NOTE-000001",
                "--title",
                "T2",
                "--body",
                "B2",
                "--reason",
                "clarify",
            ]
        )
        == 0
    )
    assert cli.main([*base, "disclose", "NOTE-000001", "include"]) == 0
    assert any(item[0] == "create" for item in calls)
    assert any(item[0] == "revise" for item in calls)
    assert any(item[0] == "disclose" for item in calls)


def test_note_body_requires_exactly_one_source(tmp_path: Path) -> None:
    """Reject ambiguous or absent note-body sources."""
    body = tmp_path / "body.txt"
    body.write_text("From file", encoding="utf-8")
    assert cli._note_body(Namespace(body=None, body_file=body)) == "From file"
    assert cli._note_body(Namespace(body="Inline", body_file=None)) == "Inline"
    with pytest.raises(ToolkitError, match="either --body or --body-file"):
        cli._note_body(Namespace(body="Inline", body_file=body))
    with pytest.raises(ToolkitError, match="requires --body"):
        cli._note_body(Namespace(body=None, body_file=None))
