"""Provide the command-line interface for FACT.

The CLI dispatches project, catalogue, packaging and source-specific acquisition
commands while keeping evidential lifecycle policy in reusable core modules.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
from collections.abc import Sequence
from pathlib import Path

from .acquire import acquire
from .capabilities.screenshot import CaptureTarget
from .collectors.screenshot.collector import ScreenshotRequest
from .console import log, security_warning, summary
from .collectors.registry import default_registry
from .errors import ToolkitError
from .identity import interactive_identity, resolve_identity
from .keys import ensure_key, export_keypair
from .models import CaseInfo
from .core.orchestration import run_collector_acquisition
from .core.packaging import create_project_package
from .core.catalogue import list_identifiers, verify_chain, verify_checkpoint, write_checkpoint
from .core.project import create_case, initialise_project, retire_case
from .core.verification import verify_archive


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

    subcommands = argument_parser.add_subparsers(
        dest="command",
        required=True,
    )

    acquire_parser = subcommands.add_parser("acquire")
    acquire_parser.add_argument(
        "source",
        help=(
            "Collector name (for example 'youtube' or 'screenshot') or, for "
            "v2.2 compatibility, a YouTube URL"
        ),
    )
    acquire_parser.add_argument(
        "target",
        nargs="?",
        help="Collector target; required for YouTube and omitted for interactive screenshots",
    )
    acquire_parser.add_argument("--case-id", required=True)

    comment_group = acquire_parser.add_mutually_exclusive_group(required=True)
    comment_group.add_argument("--case-comment")
    comment_group.add_argument("--case-comment-file", type=Path)

    acquire_parser.add_argument("--matter-title")
    acquire_parser.add_argument("--requestor")
    acquire_parser.add_argument("--identity-file", type=Path)
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

    init_parser = subcommands.add_parser("init")
    init_parser.add_argument("--force", action="store_true")
    init_parser.add_argument("--test-key", action="store_true")

    export_parser = subcommands.add_parser("export-keypair")
    export_parser.add_argument("--output", type=Path)
    export_parser.add_argument("--force", action="store_true")

    project_parser = subcommands.add_parser("project")
    project_commands = project_parser.add_subparsers(dest="project_command", required=True)
    project_init = project_commands.add_parser("init")
    project_init.add_argument("path", type=Path, nargs="?", default=Path.cwd())
    project_init.add_argument("--project-id", required=True)
    project_init.add_argument("--title", required=True)

    case_parser = subcommands.add_parser("case")
    case_commands = case_parser.add_subparsers(dest="case_command", required=True)
    case_create = case_commands.add_parser("create")
    case_create.add_argument("--title", default="")
    case_create.add_argument("--comment", default="")
    case_retire = case_commands.add_parser("retire")
    case_retire.add_argument("case_id")
    case_retire.add_argument("--reason")
    case_commands.add_parser("list")

    catalogue_parser = subcommands.add_parser("catalogue")
    catalogue_commands = catalogue_parser.add_subparsers(dest="catalogue_command", required=True)
    catalogue_verify = catalogue_commands.add_parser("verify")
    catalogue_verify.add_argument("--checkpoint", action="store_true")
    catalogue_verify.add_argument("--public-key", type=Path)
    catalogue_checkpoint = catalogue_commands.add_parser("checkpoint")
    catalogue_checkpoint.add_argument("--toolkit-root", type=Path)

    package_parser = subcommands.add_parser("package")
    package_parser.add_argument("--toolkit-root", type=Path)
    package_parser.add_argument("--output", type=Path)
    package_parser.add_argument("--encrypt-to", action="append", default=[])
    package_parser.add_argument("--force", action="store_true")

    return argument_parser


def _case_comments(args: argparse.Namespace) -> str:
    """Return validated case comments from text or a supplied file."""

    if args.case_comment is not None:
        comments = args.case_comment
    else:
        comments = args.case_comment_file.read_text(encoding="utf-8").strip()

    if not comments:
        raise ToolkitError("Case comments must not be empty")

    return comments


def _initialise(args: argparse.Namespace) -> int:
    """Initialise and activate an operator profile."""

    identity, path = interactive_identity(
        args.root,
        force=args.force,
        test_key=args.test_key,
    )
    summary(
        "TOOLKIT INITIALIZED",
        [
            ("Operator profile", str(path), "PASS"),
            ("Operator", identity.name, "PASS"),
            (
                "Signing key",
                identity.operator_signing_subkey_fingerprint,
                "PASS",
            ),
        ],
        True,
    )
    return 0


def _acquire(args: argparse.Namespace) -> int:
    """Resolve the collector syntax and run a forensic acquisition."""

    target_arg = getattr(args, "target", None)
    source_arg = getattr(args, "source", getattr(args, "url", None))
    registry = default_registry()

    # Explicit collector names take priority.  A single unrecognised positional
    # value retains the v2.2 ``fact acquire URL`` YouTube compatibility form.
    # This avoids treating ``fact acquire screenshot`` as a YouTube URL merely
    # because screenshots intentionally have no textual target argument.
    if str(source_arg) in registry.names():
        source_name = str(source_arg)
        target = target_arg
    elif target_arg is None:
        source_name = "youtube"
        target = source_arg
    else:
        raise ToolkitError(f"Unknown FACT collector: {source_arg}")

    try:
        collector = registry.get(source_name)
    except KeyError as exc:
        raise ToolkitError(str(exc)) from exc

    comments = _case_comments(args)
    identity, path, source = resolve_identity(
        args.root,
        args.identity_file,
    )
    profile_hash = hashlib.sha256(path.read_bytes()).hexdigest()

    case = CaseInfo(
        args.case_id,
        comments,
        identity.public_dict(),
        source,
        profile_hash,
        getpass.getuser(),
        args.requestor,
        args.matter_title,
    )

    if source_name == "youtube":
        if not target:
            raise ToolkitError("The YouTube collector requires a URL target")
        acquire(
            root=args.root,
            url=str(target),
            case=case,
            cookies=args.cookies,
            subtitle_langs=args.subtitle_langs,
            live_chat=not args.no_live_chat,
            sleep_requests=args.sleep_requests,
            sleep_subtitles=args.sleep_subtitles,
            min_sleep=args.min_sleep,
            max_sleep=args.max_sleep,
            rate_limit=args.rate_limit,
            collector=collector,
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
            root=args.root,
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

    raise ToolkitError(f"Collector is registered but has no CLI request adapter: {source_name}")


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


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested command and return a process exit status."""

    args = parser().parse_args(argv)

    try:
        if args.command == "init":
            return _initialise(args)
        if args.command == "acquire":
            return _acquire(args)
        if args.command == "verify":
            return _verify(args)
        if args.command == "keygen":
            return _keygen(args)
        if args.command == "export-keypair":
            return _export_keypair(args)
        if args.command == "project":
            if args.project_command == "init":
                path = initialise_project(args.path, args.project_id, args.title)
                log("PASS", f"FACT project created: {path.parent}")
                return 0
        if args.command == "case":
            if args.case_command == "create":
                identifier = create_case(args.root, args.title, args.comment)
                log("PASS", f"Case created: {identifier}")
                return 0
            if args.case_command == "retire":
                retire_case(args.root, args.case_id, args.reason)
                log("PASS", f"Case retired: {args.case_id}")
                return 0
            if args.case_command == "list":
                for item in list_identifiers(args.root):
                    print(f"{item['identifier']}\t{item['state']}")
                return 0
        if args.command == "catalogue":
            if args.catalogue_command == "checkpoint":
                path = write_checkpoint(args.root, args.toolkit_root or args.root)
                log("PASS", f"Catalogue checkpoint signed: {path}")
                return 0
            if args.catalogue_command == "verify":
                if args.checkpoint:
                    if args.public_key is None:
                        raise ToolkitError("--public-key is required with --checkpoint")
                    result = verify_checkpoint(args.root, args.public_key)
                else:
                    result = verify_chain(args.root)
                log("PASS", f"Catalogue valid: {result['event_count']} events")
                return 0
        if args.command == "package":
            outputs = create_project_package(
                args.root,
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
