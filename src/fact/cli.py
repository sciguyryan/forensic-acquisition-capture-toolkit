"""Provide the command-line interface for FACT.

The CLI dispatches project, catalogue, packaging and source-specific acquisition
commands while keeping evidential lifecycle policy in reusable core modules.
"""

from __future__ import annotations

import argparse
import getpass
from collections.abc import Sequence
from pathlib import Path

from .capabilities.screenshot import CaptureTarget
from .collectors.registry import default_registry
from .collectors.screenshot.collector import ScreenshotRequest
from .collectors.youtube.collector import YouTubeRequest, video_id
from .console import log, security_warning
from .core.authority import (
    accept_contributor,
    accept_ownership_transfer,
    authority_enabled,
    cancel_ownership_transfer,
    current_owner,
    decide_record,
    invite_contributor,
    list_members,
    list_records,
    propose_ownership_transfer,
    registered_operator_identity,
    reject_contributor,
    reject_ownership_transfer,
    remove_contributor,
    require_project_authority,
)
from .core.catalogue import (
    list_identifiers,
    verify_chain,
    verify_checkpoint,
    write_checkpoint,
)
from .core.context import (
    choose_case_interactively,
    clear_selected_case,
    discover_project_root,
    get_selected_case,
    resolve_case_context,
    selected_case_path,
    set_selected_case,
)
from .core.notes import (
    create_note,
    list_notes,
    read_note,
    revise_note,
    set_note_disclosure,
)
from .core.orchestration import run_collector_acquisition
from .core.packaging import create_project_package
from .core.project import (
    create_owned_case,
    initialise_owned_project,
    retire_case,
)
from .core.verification import verify_archive
from .errors import ToolkitError
from .identity import export_public_key_text, interactive_identity, validate_identity
from .keys import ensure_key, export_keypair
from .models import CaseInfo


def parser() -> argparse.ArgumentParser:
    """Build and return the toolkit's command-line argument parser."""

    argument_parser = argparse.ArgumentParser(
        prog="fact",
        description="Forensic Acquisition & Capture Toolkit",
    )
    argument_parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
    )
    argument_parser.add_argument(
        "--operator-id",
        help="Project operator identity used for signed operations",
    )

    subcommands = argument_parser.add_subparsers(
        dest="command",
        required=True,
    )

    acquire_parser = subcommands.add_parser("acquire")
    acquire_parser.add_argument(
        "source",
        help="Collector name, for example 'youtube' or 'screenshot'",
    )
    acquire_parser.add_argument(
        "target",
        nargs="?",
        help=(
            "Collector target; required for YouTube and omitted for "
            "interactive screenshots"
        ),
    )
    acquire_parser.add_argument(
        "--case-id",
        help="Explicit case override; normally FACT resolves case context automatically",
    )

    comment_group = acquire_parser.add_mutually_exclusive_group(required=False)
    comment_group.add_argument("--acquisition-comment")
    comment_group.add_argument("--acquisition-comment-file", type=Path)

    acquire_parser.add_argument("--matter-title")
    acquire_parser.add_argument("--requestor")
    acquire_parser.add_argument("--cookies", type=Path)
    acquire_parser.add_argument("--subtitle-langs", default="en.*,orig.*")
    acquire_parser.add_argument("--no-live-chat", action="store_true")
    acquire_parser.add_argument("--sleep-requests", default="3")
    acquire_parser.add_argument("--sleep-subtitles", default="8")
    acquire_parser.add_argument("--min-sleep", default="5")
    acquire_parser.add_argument("--max-sleep", default="12")
    acquire_parser.add_argument("--rate-limit", default="5M")
    acquire_parser.add_argument(
        "--screenshot-target",
        choices=[item.value for item in CaptureTarget],
        default=CaptureTarget.WINDOW.value,
        help="Screenshot source class; defaults to an operator-selected window",
    )
    acquire_parser.add_argument(
        "--screenshot-backend",
        choices=["auto", "portal"],
        default="auto",
        help="Linux screenshot backend; auto currently selects XDG Desktop Portal",
    )

    verify_parser = subcommands.add_parser("verify")
    verify_parser.add_argument("archive", type=Path)
    verify_parser.add_argument("--public-key", type=Path)
    verify_parser.add_argument("--report", type=Path)

    subcommands.add_parser("keygen")

    export_parser = subcommands.add_parser("export-keypair")
    export_parser.add_argument("--output", type=Path)
    export_parser.add_argument("--force", action="store_true")

    project_parser = subcommands.add_parser("project")
    project_commands = project_parser.add_subparsers(
        dest="project_command",
        required=True,
    )
    project_init = project_commands.add_parser("init")
    project_init.add_argument("path", type=Path, nargs="?", default=Path.cwd())
    project_init.add_argument("--project-id", required=True)
    project_init.add_argument("--title", required=True)
    project_init.add_argument("--test-key", action="store_true")

    case_parser = subcommands.add_parser("case")
    case_commands = case_parser.add_subparsers(dest="case_command", required=True)
    case_create = case_commands.add_parser("create")
    case_create.add_argument("--title", default="")
    case_create.add_argument("--comment", default="")
    case_retire = case_commands.add_parser("retire")
    case_retire.add_argument("case_id")
    case_retire.add_argument("--reason")
    case_commands.add_parser("list")
    case_select = case_commands.add_parser("select")
    case_select.add_argument("case_id", nargs="?")
    case_commands.add_parser("current")

    authority_parser = subcommands.add_parser("authority")
    authority_commands = authority_parser.add_subparsers(
        dest="authority_command", required=True
    )
    authority_commands.add_parser("status")

    contributor_parser = subcommands.add_parser("contributor")
    contributor_commands = contributor_parser.add_subparsers(
        dest="contributor_command", required=True
    )
    contributor_invite = contributor_commands.add_parser("invite")
    contributor_invite.add_argument("invitee_id")
    contributor_invite.add_argument("--name", required=True)
    contributor_invite.add_argument("--key-fingerprint", required=True)
    contributor_invite.add_argument("--signing-fingerprint", required=True)
    contributor_invite.add_argument("--public-contact")
    contributor_invite.add_argument("--organisation")
    contributor_invite.add_argument("--role")
    contributor_commands.add_parser("accept")
    contributor_commands.add_parser("reject")
    contributor_remove = contributor_commands.add_parser("remove")
    contributor_remove.add_argument("contributor_id")
    contributor_remove.add_argument("--reason", required=True)
    contributor_commands.add_parser("list")

    owner_parser = subcommands.add_parser("owner")
    owner_commands = owner_parser.add_subparsers(dest="owner_command", required=True)
    owner_current = owner_commands.add_parser("current")
    owner_current.add_argument("--case-id")
    owner_transfer = owner_commands.add_parser("transfer")
    owner_transfer.add_argument("new_owner_id")
    owner_transfer.add_argument("--reason", required=True)
    owner_transfer.add_argument("--case-id")
    owner_accept = owner_commands.add_parser("accept")
    owner_accept.add_argument("--case-id")
    owner_reject = owner_commands.add_parser("reject")
    owner_reject.add_argument("--reason", required=True)
    owner_reject.add_argument("--case-id")
    owner_cancel = owner_commands.add_parser("cancel")
    owner_cancel.add_argument("--reason", required=True)
    owner_cancel.add_argument("--case-id")

    record_parser = subcommands.add_parser("record")
    record_commands = record_parser.add_subparsers(dest="record_command", required=True)
    record_commands.add_parser("list")
    record_approve = record_commands.add_parser("approve")
    record_approve.add_argument("acquisition_id")
    record_reject = record_commands.add_parser("reject")
    record_reject.add_argument("acquisition_id")
    record_reject.add_argument("--reason", required=True)

    note_parser = subcommands.add_parser("note")
    note_commands = note_parser.add_subparsers(dest="note_command", required=True)
    note_create = note_commands.add_parser("create")
    note_create.add_argument("--title", default="")
    note_create.add_argument("--body")
    note_create.add_argument("--body-file", type=Path)
    note_create.add_argument("--case-id")
    note_create.add_argument("--confidential", action="store_true")
    note_commands.add_parser("list")
    note_read = note_commands.add_parser("read")
    note_read.add_argument("note_id")
    note_read.add_argument("--revision", type=int)
    note_revise = note_commands.add_parser("revise")
    note_revise.add_argument("note_id")
    note_revise.add_argument("--title", default="")
    note_revise.add_argument("--body")
    note_revise.add_argument("--body-file", type=Path)
    note_revise.add_argument("--reason", required=True)
    note_disclose = note_commands.add_parser("disclose")
    note_disclose.add_argument("note_id")
    note_disclose.add_argument("policy", choices=["include", "withhold"])

    catalogue_parser = subcommands.add_parser("catalogue")
    catalogue_commands = catalogue_parser.add_subparsers(
        dest="catalogue_command",
        required=True,
    )
    catalogue_verify = catalogue_commands.add_parser("verify")
    catalogue_verify.add_argument("--checkpoint", action="store_true")
    catalogue_verify.add_argument("--public-key", type=Path)
    catalogue_checkpoint = catalogue_commands.add_parser("checkpoint")
    catalogue_checkpoint.add_argument("--toolkit-root", type=Path)

    help_parser = subcommands.add_parser("help")
    help_parser.add_argument("topic", nargs="*")

    shell_parser = subcommands.add_parser("shell")
    shell_parser.add_argument(
        "--no-history",
        action="store_true",
        help="Disable persistent local shell history while retaining completion",
    )

    package_parser = subcommands.add_parser("package")
    package_parser.add_argument("--toolkit-root", type=Path)
    package_parser.add_argument("--output", type=Path)
    package_parser.add_argument("--encrypt-to", action="append", default=[])
    package_parser.add_argument("--force", action="store_true")

    return argument_parser


def _acquisition_comments(args: argparse.Namespace, default: str = "") -> str:
    """Return an acquisition comment without forcing repetitive CLI boilerplate.

    If no acquisition-specific note is supplied, FACT carries forward the human-readable comment
    from ``CASE.toml`` rather than requiring the operator to retype it.
    """

    if args.acquisition_comment is not None:
        return args.acquisition_comment.strip()
    if args.acquisition_comment_file is not None:
        comments = args.acquisition_comment_file.read_text(encoding="utf-8").strip()
        if not comments:
            raise ToolkitError("Acquisition comments file must not be empty")
        return comments
    return default.strip()


def _active_project_identity(project_root: Path, operator_id: str | None) -> object:
    """Resolve the explicit project-retained operator used for this command."""
    if not operator_id:
        raise ToolkitError(
            "This operation requires --operator-id, or an authenticated FACT shell session"
        )
    return registered_operator_identity(project_root, operator_id)


def _scope(args: argparse.Namespace) -> tuple[str, str | None]:
    case_id = getattr(args, "case_id", None)
    return ("case", case_id) if case_id else ("project", None)


def _acquire(args: argparse.Namespace) -> int:
    """Resolve the collector syntax and run a forensic acquisition."""

    target_arg = getattr(args, "target", None)
    source_arg = getattr(args, "source", getattr(args, "url", None))
    registry = default_registry()

    if str(source_arg) not in registry.names():
        raise ToolkitError(f"Unknown FACT collector: {source_arg}")
    source_name = str(source_arg)
    target = target_arg

    try:
        collector = registry.get(source_name)
    except KeyError as exc:
        raise ToolkitError(str(exc)) from exc

    project_root = discover_project_root(args.root)
    current = Path.cwd().resolve()
    if current != project_root and project_root not in current.parents:
        current = args.root
    case_context = resolve_case_context(
        project_root,
        explicit_case_id=args.case_id,
        current=current,
    )
    comments = _acquisition_comments(args, case_context.comment)
    identity = _active_project_identity(project_root, args.operator_id)

    case = CaseInfo(
        case_context.case_id,
        comments,
        identity.public_dict(),
        getpass.getuser(),
        args.requestor,
        args.matter_title or case_context.title or None,
    )

    if source_name == "youtube":
        if not target:
            raise ToolkitError("The YouTube collector requires a URL target")
        run_collector_acquisition(
            root=project_root,
            case=case,
            collector=collector,
            request=YouTubeRequest(
                url=str(target),
                cookies=args.cookies,
                subtitle_langs=args.subtitle_langs,
                live_chat=not args.no_live_chat,
                sleep_requests=args.sleep_requests,
                sleep_subtitles=args.sleep_subtitles,
                min_sleep=args.min_sleep,
                max_sleep=args.max_sleep,
                rate_limit=args.rate_limit,
            ),
            initial_source={
                "submitted_url": str(target),
                "collector": "youtube",
                "video_id": video_id(str(target)),
            },
            initial_evidence={
                "live_chat_status": "Pending" if not args.no_live_chat else "Skipped"
            },
        )
        return 0

    if source_name == "screenshot":
        if target is not None:
            raise ToolkitError(
                "The screenshot collector uses interactive source selection; "
                "do not supply a positional target"
            )
        screenshot_target = CaptureTarget(args.screenshot_target)
        run_collector_acquisition(
            root=project_root,
            case=case,
            collector=collector,
            request=ScreenshotRequest(
                target=screenshot_target,
                backend=args.screenshot_backend,
            ),
            initial_source={
                "collector": "screenshot",
                "capture_type": "screenshot",
                "target": f"operator-selected {screenshot_target.value}",
            },
        )
        return 0

    raise ToolkitError(
        f"Collector is registered but has no CLI request adapter: {source_name}"
    )


def _verify(args: argparse.Namespace) -> int:
    """Verify an evidence archive and return a shell-compatible status."""

    verification = verify_archive(
        args.archive,
        args.public_key,
        args.report,
    )
    return 0 if verification.passed else 1


def _keygen(args: argparse.Namespace) -> int:
    """Ensure that the dedicated evidence-signing key exists."""

    pgp_dir = args.root / "pgp"
    fingerprint = ensure_key(
        pgp_dir / "keyring",
        pgp_dir / "evidence-public-key.asc",
        pgp_dir / "evidence-key-fingerprint.txt",
    )
    log("PASS", f"Evidence key ready: {fingerprint}")
    return 0


def _export_keypair(args: argparse.Namespace) -> int:
    """Export the evidence keypair after presenting a security warning."""

    security_warning(["This exports plaintext private key material."])
    export_keypair(
        args.root / "pgp" / "keyring",
        args.output or args.root / "keys",
        force=args.force,
    )
    return 0


def _command_help(topic: Sequence[str]) -> int:
    """Print top-level or command-specific help through the canonical parser."""

    argument_parser = parser()
    if not topic:
        argument_parser.print_help()
        return 0
    try:
        argument_parser.parse_args([*topic, "--help"])
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def _note_body(args: argparse.Namespace) -> str:
    """Read note text from one explicit CLI source."""
    if args.body is not None and args.body_file is not None:
        raise ToolkitError("Use either --body or --body-file, not both")
    if args.body_file is not None:
        return args.body_file.read_text(encoding="utf-8")
    if args.body is not None:
        return args.body
    raise ToolkitError("Note content requires --body or --body-file")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested command and return a process exit status."""

    args = parser().parse_args(argv)

    try:
        if args.command == "acquire":
            project_root = discover_project_root(args.root)
            require_project_authority(project_root)
            return _acquire(args)
        if args.command == "verify":
            return _verify(args)
        if args.command == "keygen":
            return _keygen(args)
        if args.command == "export-keypair":
            return _export_keypair(args)
        if args.command == "project" and args.project_command == "init":
            identity = interactive_identity(test_key=args.test_key)
            public_key = export_public_key_text(identity)
            path = initialise_owned_project(
                args.path, args.project_id, args.title, identity, public_key
            )
            log("PASS", f"FACT project created: {path.parent}")
            log("PASS", f"Initial owner recorded and signed: {identity.operator_id}")
            return 0
        if args.command == "case":
            project_root = discover_project_root(args.root)
            if args.case_command == "create":
                require_project_authority(project_root)
                identity = _active_project_identity(project_root, args.operator_id)
                identifier = create_owned_case(
                    project_root, identity, args.title, args.comment
                )
                selected = set_selected_case(project_root, identifier)
                log("PASS", f"Case created and selected: {selected.case_id}")
                return 0
            if args.case_command == "retire":
                require_project_authority(project_root)
                selection_path = selected_case_path(project_root)
                selected_id = (
                    selection_path.read_text(encoding="utf-8").strip()
                    if selection_path.is_file()
                    else None
                )
                retire_case(project_root, args.case_id, args.reason)
                if selected_id == args.case_id:
                    clear_selected_case(project_root)
                log("PASS", f"Case retired: {args.case_id}")
                return 0
            if args.case_command == "list":
                for item in list_identifiers(project_root):
                    print(f"{item['identifier']}\t{item['state']}")
                return 0
            if args.case_command == "select":
                if args.case_id:
                    selected = set_selected_case(project_root, args.case_id)
                else:
                    selected = choose_case_interactively(project_root)
                log(
                    "PASS",
                    f"Selected case: {selected.case_id} - "
                    f"{selected.title or 'Untitled case'}",
                )
                return 0
            if args.case_command == "current":
                selected = get_selected_case(project_root)
                if selected is None:
                    raise ToolkitError("No FACT case is currently selected")
                print(f"{selected.case_id}\t{selected.title}")
                return 0
        if args.command == "authority":
            project_root = discover_project_root(args.root)
            if args.authority_command == "status":
                if not authority_enabled(project_root):
                    raise ToolkitError(
                        "Current-generation FACT project is missing its signed authority genesis"
                    )
                owner = current_owner(project_root)
                print(
                    f"Authority: active\nOwner: {owner['owner_id']} - {owner['name']}\n"
                    f"Effective sequence: {owner['effective_from_sequence']}"
                )
                return 0
        if args.command == "contributor":
            project_root = discover_project_root(args.root)
            require_project_authority(project_root)
            if args.contributor_command == "list":
                for item in list_members(project_root):
                    print(
                        f"{item['operator_id']}\t{item['membership_role']}\t"
                        f"{item['state']}\t{item['name']}"
                    )
                return 0
            actor = _active_project_identity(project_root, args.operator_id)
            if args.contributor_command == "invite":
                contributor = validate_identity(
                    {
                        "operator_id": args.invitee_id,
                        "name": args.name,
                        "public_contact": args.public_contact,
                        "organisation": args.organisation,
                        "role": args.role,
                        "operator_key_fingerprint": args.key_fingerprint,
                        "operator_signing_subkey_fingerprint": args.signing_fingerprint,
                    }
                )
                public_key = export_public_key_text(contributor)
                invite_contributor(project_root, actor, contributor, public_key)
                log(
                    "PASS",
                    f"Contributor invitation recorded: {contributor.operator_id}",
                )
                return 0
            if args.contributor_command == "accept":
                accept_contributor(project_root, actor)
                log("PASS", f"Contributor invitation accepted: {actor.operator_id}")
                return 0
            if args.contributor_command == "reject":
                reject_contributor(project_root, actor)
                log("PASS", f"Contributor invitation rejected: {actor.operator_id}")
                return 0
            if args.contributor_command == "remove":
                remove_contributor(
                    project_root, actor, args.contributor_id, args.reason
                )
                log("PASS", f"Contributor removed: {args.contributor_id}")
                return 0
        if args.command == "owner":
            project_root = discover_project_root(args.root)
            require_project_authority(project_root)
            scope_type, scope_id = _scope(args)
            if args.owner_command == "current":
                owner = current_owner(
                    project_root, scope_type=scope_type, scope_id=scope_id
                )
                print(
                    f"{owner['owner_id']}\t{owner['name']}\t"
                    f"sequence={owner['effective_from_sequence']}"
                )
                return 0
            actor = _active_project_identity(project_root, args.operator_id)
            if args.owner_command == "transfer":
                transfer_id = propose_ownership_transfer(
                    project_root,
                    actor,
                    args.new_owner_id,
                    args.reason,
                    scope_type=scope_type,
                    scope_id=scope_id,
                )
                log("PASS", f"Ownership transfer proposed: {transfer_id}")
                return 0
            if args.owner_command == "accept":
                transfer_id = accept_ownership_transfer(
                    project_root, actor, scope_type=scope_type, scope_id=scope_id
                )
                log("PASS", f"Ownership transfer accepted: {transfer_id}")
                return 0
            if args.owner_command == "reject":
                transfer_id = reject_ownership_transfer(
                    project_root,
                    actor,
                    args.reason,
                    scope_type=scope_type,
                    scope_id=scope_id,
                )
                log("PASS", f"Ownership transfer rejected: {transfer_id}")
                return 0
            if args.owner_command == "cancel":
                transfer_id = cancel_ownership_transfer(
                    project_root,
                    actor,
                    args.reason,
                    scope_type=scope_type,
                    scope_id=scope_id,
                )
                log("PASS", f"Ownership transfer cancelled: {transfer_id}")
                return 0
        if args.command == "record":
            project_root = discover_project_root(args.root)
            require_project_authority(project_root)
            if args.record_command == "list":
                for item in list_records(project_root):
                    print(
                        f"{item['object_id']}\t{item['status']}\t"
                        f"submitted-by={item['submitted_by']}\tcase={item['scope_id']}"
                    )
                return 0
            actor = _active_project_identity(project_root, args.operator_id)
            if args.record_command == "approve":
                decide_record(project_root, actor, args.acquisition_id, "approved")
                log("PASS", f"Record approved: {args.acquisition_id}")
                return 0
            if args.record_command == "reject":
                decide_record(
                    project_root,
                    actor,
                    args.acquisition_id,
                    "rejected",
                    args.reason,
                )
                log("PASS", f"Record rejected: {args.acquisition_id}")
                return 0
        if args.command == "note":
            project_root = discover_project_root(args.root)
            require_project_authority(project_root)
            if args.note_command == "list":
                for item in list_notes(project_root):
                    print(
                        f"{item['note_id']}\t{item['visibility']}\t"
                        f"author={item['author_id']}\tcase={item['case_id'] or '-'}\t"
                        f"revision={item['latest_revision']}\tdisclosure={item['package_disclosure']}"
                    )
                return 0
            actor = _active_project_identity(project_root, args.operator_id)
            if args.note_command == "create":
                note_id = create_note(
                    project_root,
                    actor,
                    args.title,
                    _note_body(args),
                    visibility="confidential" if args.confidential else "project",
                    case_id=args.case_id,
                )
                log("PASS", f"Note retained: {note_id}")
                return 0
            if args.note_command == "read":
                item = read_note(
                    project_root, actor, args.note_id, revision=args.revision
                )
                print(
                    f"{item['note_id']} revision {item['revision']} [{item['visibility']}]"
                )
                if item["title"]:
                    print(item["title"])
                print(item["body"])
                return 0
            if args.note_command == "revise":
                revision = revise_note(
                    project_root,
                    actor,
                    args.note_id,
                    args.title,
                    _note_body(args),
                    args.reason,
                )
                log("PASS", f"Note revised: {args.note_id} revision {revision}")
                return 0
            if args.note_command == "disclose":
                set_note_disclosure(
                    project_root, actor, args.note_id, args.policy == "include"
                )
                log("PASS", f"Note disclosure changed: {args.note_id} -> {args.policy}")
                return 0
        if args.command == "catalogue":
            project_root = discover_project_root(args.root)
            if args.catalogue_command == "checkpoint":
                require_project_authority(project_root)
                path = write_checkpoint(project_root, args.toolkit_root or project_root)
                log("PASS", f"Catalogue checkpoint signed: {path}")
                return 0
            if args.catalogue_command == "verify":
                if args.checkpoint:
                    if args.public_key is None:
                        raise ToolkitError("--public-key is required with --checkpoint")
                    result = verify_checkpoint(project_root, args.public_key)
                else:
                    result = verify_chain(project_root)
                log("PASS", f"Catalogue valid: {result['event_count']} events")
                return 0
        if args.command == "help":
            return _command_help(args.topic)
        if args.command == "shell":
            from .shell import run_shell

            return run_shell(
                start=args.root,
                dispatch=main,
                history_enabled=not args.no_history,
            )
        if args.command == "package":
            project_root = discover_project_root(args.root)
            require_project_authority(project_root)
            outputs = create_project_package(
                project_root,
                args.toolkit_root or Path.cwd(),
                args.output,
                encrypt_to=args.encrypt_to,
                force=args.force,
            )
            log("PASS", f"FACT project package created: {outputs['archive']}")
            if "encrypted" in outputs:
                log("PASS", f"Encrypted package created: {outputs['encrypted']}")
            return 0
    except ToolkitError as exc:
        log("ERROR", str(exc))
        return 1

    return 2
