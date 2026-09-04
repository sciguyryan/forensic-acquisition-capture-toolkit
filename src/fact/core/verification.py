"""Verify the authenticity, integrity, and safe structure of evidence archives.

Verification covers external checksums and signatures, archive path safety,
operator signatures, internal manifests, required records, and extraction
safety.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from ..console import log, summary
from ..models import VerificationSummary
from ..services.archive import extract, unsafe_members
from ..services.commands import require, run
from ..services.hashing import digest, verify_manifest


def _record(result: VerificationSummary, name: str, ok: bool, detail: str = "") -> None:
    """Record and log a verification stage."""
    state = "PASS" if ok else "FAIL"
    result.add(name, state, detail)
    log(state, f"{name}{': ' + detail if detail else ''}")


def verify_archive(
    archive: Path, public_key: Path | None = None, report: Path | None = None
) -> VerificationSummary:
    """Verify an evidence archive and its associated sidecar files."""
    archive = archive.resolve()
    result = VerificationSummary(archive=archive)
    side_sha256 = Path(str(archive) + ".sha256")
    side_sha512 = Path(str(archive) + ".sha512")
    side_sig = Path(str(archive) + ".asc")
    operator_sig = Path(str(archive) + ".operator.asc")
    if public_key is None:
        public_key = archive.parent.parent / "pgp" / "evidence-public-key.asc"
    for path, label in (
        (archive, "Archive readable"),
        (public_key, "Public key readable"),
    ):
        _record(result, label, path.is_file(), str(path))
    if not result.passed:
        return _finish(result, report)

    require("gpg")
    with tempfile.TemporaryDirectory(prefix="fact-evidence-verify-") as td:
        temp = Path(td)
        home = temp / "gnupg"
        home.mkdir(mode=0o700)
        imported = run(
            ["gpg", "--homedir", str(home), "--batch", "--import", str(public_key)],
            check=False,
        )
        _record(result, "Public key import", imported.returncode == 0)
        sig = run(
            [
                "gpg",
                "--homedir",
                str(home),
                "--batch",
                "--verify",
                str(side_sig),
                str(archive),
            ],
            check=False,
        )
        _record(
            result,
            "Detached GPG signature",
            sig.returncode == 0,
            (sig.stderr.strip().splitlines()[-1] if sig.stderr.strip() else ""),
        )

        for algorithm, side, label in (
            ("sha256", side_sha256, "External SHA-256"),
            ("sha512", side_sha512, "External SHA-512"),
        ):
            ok = False
            detail = "sidecar missing"
            if side.is_file():
                expected = side.read_text(encoding="utf-8").split()[0]
                actual = digest(archive, algorithm)
                ok = expected == actual
                detail = actual
            _record(result, label, ok, detail)

        unsafe = unsafe_members(archive)
        _record(result, "Archive path safety", not unsafe, ", ".join(unsafe[:3]))
        if unsafe:
            return _finish(result, report)
        extracted = temp / "extracted"
        try:
            extract(archive, extracted)
            _record(result, "Archive extraction", True)
        except Exception as exc:
            _record(result, "Archive extraction", False, str(exc))
            return _finish(result, report)

        symlinks = [
            p.relative_to(extracted).as_posix()
            for p in extracted.rglob("*")
            if p.is_symlink()
        ]
        _record(result, "Symlink safety", not symlinks, ", ".join(symlinks[:3]))

        operator_public = extracted / "operator-public-key.asc"
        operator_identity = extracted / "operator-identity.json"
        if (
            operator_public.is_file()
            and operator_identity.is_file()
            and operator_sig.is_file()
        ):
            imported_operator = run(
                [
                    "gpg",
                    "--homedir",
                    str(home),
                    "--batch",
                    "--import",
                    str(operator_public),
                ],
                check=False,
            )
            _record(
                result, "Operator public key import", imported_operator.returncode == 0
            )
            operator_check = run(
                [
                    "gpg",
                    "--homedir",
                    str(home),
                    "--batch",
                    "--status-fd",
                    "1",
                    "--verify",
                    str(operator_sig),
                    str(archive),
                ],
                check=False,
            )
            _record(
                result,
                "Operator detached signature",
                operator_check.returncode == 0,
                (
                    operator_check.stderr.strip().splitlines()[-1]
                    if operator_check.stderr.strip()
                    else ""
                ),
            )
            try:
                import json

                identity_data = json.loads(
                    operator_identity.read_text(encoding="utf-8")
                )
                expected = str(
                    identity_data.get("operator_signing_subkey_fingerprint", "")
                ).upper()
                actual = ""
                for line in operator_check.stdout.splitlines():
                    if line.startswith("[GNUPG:] VALIDSIG "):
                        actual = line.split()[2].upper()
                        break
                _record(
                    result,
                    "Operator signing fingerprint",
                    bool(expected and actual == expected),
                    actual or "unavailable",
                )
            except Exception as exc:
                _record(result, "Operator identity record", False, str(exc))
        else:
            _record(
                result,
                "Operator signature files",
                False,
                "operator-public-key.asc, operator-identity.json, or .operator.asc missing",
            )

        for filename, algorithm, label in (
            ("SHA256SUMS.txt", "sha256", "Internal SHA-256 manifest"),
            ("SHA512SUMS.txt", "sha512", "Internal SHA-512 manifest"),
        ):
            manifest = extracted / filename
            if not manifest.is_file():
                _record(result, label, False, f"missing {filename}")
            else:
                failures = verify_manifest(extracted, manifest, algorithm)
                _record(result, label, not failures, "; ".join(failures[:5]))

        required = [
            "acquisition.txt",
            "FILELIST.txt",
            "VERIFICATION.txt",
            "evidence-public-key.asc",
            "CASE_RECORD.json",
            "CASE_RECORD.md",
            "TOOLKIT.json",
            "operator-identity.json",
            "operator-public-key.asc",
        ]
        for filename in required:
            _record(result, f"Document: {filename}", (extracted / filename).is_file())
    return _finish(result, report)


def _finish(result: VerificationSummary, report: Path | None) -> VerificationSummary:
    """Write and display the final verification result."""
    lines = [
        "FACT evidence verification report",
        f"Archive: {result.archive}",
        "",
    ]
    lines.extend(
        f"[{s.status}] {s.name}{': ' + s.detail if s.detail else ''}"
        for s in result.stages
    )
    lines += ["", f"Overall result: {'PASS' if result.passed else 'FAIL'}"]
    if report:
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    summary(
        "EVIDENCE VERIFICATION PASSED"
        if result.passed
        else "EVIDENCE VERIFICATION FAILED",
        [(s.name, s.detail or s.status, s.status) for s in result.stages],
        result.passed,
    )
    return result
