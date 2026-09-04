"""Extended tests for CLI command dispatch and helper behaviour."""

from argparse import Namespace
from pathlib import Path

import pytest

from fact import cli
from fact.core.project import create_case, initialise_project
from fact.errors import ToolkitError
from fact.identity import OperatorIdentity
from fact.models import VerificationSummary

IDENTITY = OperatorIdentity(1, "jane", "Jane Doe", None, None, None, "A" * 40, "B" * 40)


def test_case_comments_reads_file_and_rejects_empty(tmp_path: Path) -> None:
    """Read comments from UTF-8 files and reject blank content."""
    comment_file = tmp_path / "comment.txt"
    comment_file.write_text("  Purpose  \n", encoding="utf-8")
    assert (
        cli._case_comments(Namespace(case_comment=None, case_comment_file=comment_file))
        == "Purpose"
    )
    comment_file.write_text("  \n", encoding="utf-8")
    with pytest.raises(ToolkitError, match="must not be empty"):
        cli._case_comments(Namespace(case_comment=None, case_comment_file=comment_file))


def test_initialise_reports_selected_identity(tmp_path: Path, monkeypatch) -> None:
    """Initialise an identity and present a successful summary."""
    path = tmp_path / "operators" / "jane.json"
    monkeypatch.setattr(
        cli, "interactive_identity", lambda *args, **kwargs: (IDENTITY, path)
    )
    calls = []
    monkeypatch.setattr(cli, "summary", lambda *args: calls.append(args))
    args = Namespace(root=tmp_path, force=False, test_key=False)

    assert cli._initialise(args) == 0
    assert calls[0][0] == "TOOLKIT INITIALIZED"


def test_verify_keygen_and_export_helpers(tmp_path: Path, monkeypatch) -> None:
    """Return verification status and invoke key-management helpers."""
    passed = VerificationSummary(tmp_path / "case.7z")
    failed = VerificationSummary(tmp_path / "bad.7z")
    failed.add("stage", "FAIL")
    monkeypatch.setattr(cli, "verify_archive", lambda *args: passed)
    assert (
        cli._verify(Namespace(archive=passed.archive, public_key=None, report=None))
        == 0
    )
    monkeypatch.setattr(cli, "verify_archive", lambda *args: failed)
    assert (
        cli._verify(Namespace(archive=failed.archive, public_key=None, report=None))
        == 1
    )

    calls = []
    monkeypatch.setattr(cli, "ensure_key", lambda *args: "FPR")
    monkeypatch.setattr(cli, "log", lambda *args: calls.append(args))
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


def test_acquire_helper_builds_case_and_forwards_options(
    tmp_path: Path, monkeypatch
) -> None:
    """Build case metadata from the selected identity and forward CLI options."""
    initialise_project(tmp_path, "P-1", "Project")
    case_id = create_case(tmp_path, "Case title", "Case default comment")
    profile = tmp_path / "jane.json"
    profile.write_text("profile", encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "resolve_identity",
        lambda root, override: (IDENTITY, profile, "active_profile"),
    )
    monkeypatch.setattr(cli.getpass, "getuser", lambda: "login-user")
    calls = []
    monkeypatch.setattr(cli, "acquire", lambda **kwargs: calls.append(kwargs))
    args = Namespace(
        root=tmp_path,
        identity_file=None,
        case_comment="Purpose",
        case_comment_file=None,
        case_id=case_id,
        requestor="Requestor",
        matter_title="Matter",
        url="https://youtu.be/abc",
        cookies=None,
        subtitle_langs="en.*",
        no_live_chat=True,
        sleep_requests="1",
        sleep_subtitles="2",
        min_sleep="3",
        max_sleep="4",
        rate_limit="1M",
    )

    assert cli._acquire(args) == 0
    case = calls[0]["case"]
    assert case.operator_username == "login-user"
    assert case.operator_source == "active_profile"
    assert calls[0]["live_chat"] is False


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


def test_authority_cli_dispatches_project_bootstrap_and_membership(
    tmp_path: Path, monkeypatch
) -> None:
    """Expose signed authority operations through the canonical CLI dispatcher."""
    project = tmp_path / "project"
    profile = tmp_path / "owner.json"
    profile.write_text("{}", encoding="utf-8")
    calls = []
    monkeypatch.setattr(
        cli,
        "resolve_identity",
        lambda *args, **kwargs: (IDENTITY, profile, "active_profile"),
    )
    monkeypatch.setattr(cli, "export_public_key_text", lambda identity: "PUBLIC KEY")
    monkeypatch.setattr(
        cli,
        "initialise_owned_project",
        lambda *args: calls.append(("project", args)) or project / "PROJECT.toml",
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

    project.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(cli, "discover_project_root", lambda root: project)
    monkeypatch.setattr(cli, "require_project_authority", lambda root: None)
    monkeypatch.setattr(cli, "_active_project_identity", lambda root: (IDENTITY, profile, "active"))
    contributor = OperatorIdentity(1, "bob", "Bob", None, None, None, "C" * 40, "D" * 40)
    monkeypatch.setattr(cli, "load_identity_file", lambda path: contributor)
    monkeypatch.setattr(cli, "invite_contributor", lambda *args: calls.append(("invite", args)))
    assert (
        cli.main(
            [
                "--root",
                str(project),
                "contributor",
                "invite",
                "--identity-file",
                str(tmp_path / "bob.json"),
            ]
        )
        == 0
    )
    assert any(item[0] == "invite" for item in calls)


def test_authority_cli_owner_record_and_listing_paths(tmp_path: Path, monkeypatch) -> None:
    """Dispatch owner decisions, contributor state and record review commands."""
    project = tmp_path / "project"
    project.mkdir()
    profile = tmp_path / "owner.json"
    calls = []
    monkeypatch.setattr(cli, "discover_project_root", lambda root: project)
    monkeypatch.setattr(cli, "require_project_authority", lambda root: None)
    monkeypatch.setattr(cli, "_active_project_identity", lambda root: (IDENTITY, profile, "active"))
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

    monkeypatch.setattr(cli, "accept_contributor", lambda *args: calls.append("accept-contributor"))
    monkeypatch.setattr(cli, "reject_contributor", lambda *args: calls.append("reject-contributor"))
    monkeypatch.setattr(cli, "remove_contributor", lambda *args: calls.append("remove-contributor"))
    assert cli.main(["--root", str(project), "contributor", "accept"]) == 0
    assert cli.main(["--root", str(project), "contributor", "reject"]) == 0
    assert (
        cli.main(
            [
                "--root",
                str(project),
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
    monkeypatch.setattr(cli, "propose_ownership_transfer", lambda *args, **kwargs: "XFER-1")
    monkeypatch.setattr(cli, "accept_ownership_transfer", lambda *args, **kwargs: "XFER-1")
    monkeypatch.setattr(cli, "reject_ownership_transfer", lambda *args, **kwargs: "XFER-1")
    monkeypatch.setattr(cli, "cancel_ownership_transfer", lambda *args, **kwargs: "XFER-1")
    assert (
        cli.main(
            [
                "--root",
                str(project),
                "owner",
                "transfer",
                "bob",
                "--reason",
                "handover",
            ]
        )
        == 0
    )
    assert cli.main(["--root", str(project), "owner", "accept"]) == 0
    assert (
        cli.main(
            ["--root", str(project), "owner", "reject", "--reason", "declined"]
        )
        == 0
    )
    assert (
        cli.main(
            ["--root", str(project), "owner", "cancel", "--reason", "changed"]
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
    monkeypatch.setattr(cli, "decide_record", lambda *args: calls.append(("decision", args)))
    assert (
        cli.main(["--root", str(project), "record", "approve", "ACQ-000001"])
        == 0
    )
    assert (
        cli.main(
            [
                "--root",
                str(project),
                "record",
                "reject",
                "ACQ-000002",
                "--reason",
                "irrelevant",
            ]
        )
        == 0
    )
