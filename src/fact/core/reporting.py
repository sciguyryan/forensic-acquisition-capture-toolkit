"""Render one structured FACT verification result into multiple report formats.

All report formats are views over the same verification-result model. Reports
are generated representations and do not become evidential files unless an
operator explicitly checks them back into FACT later.
"""

from __future__ import annotations

import html
import json
import textwrap
from pathlib import Path

from ..errors import ToolkitError

REPORT_FORMATS = {"text", "html", "json", "pdf"}


def _text(result: dict[str, object], detailed: bool) -> str:
    lines = [
        "FACT Verification Report",
        "========================",
        f"Status: {str(result.get('status', '')).upper()}",
        f"Type: {result.get('verification_kind')}",
        f"Target: {result.get('target')}",
        "",
        str(result.get("summary", "")),
    ]
    scope = result.get("scope")
    if isinstance(scope, dict):
        chain = scope.get("project_chain")
        if isinstance(chain, dict):
            lines.extend(
                [
                    "",
                    "Project anchor",
                    "--------------",
                    f"Project: {chain.get('project_id')}",
                    f"Events: {chain.get('event_count')}",
                    f"Chain head: {chain.get('chain_head')}",
                    f"State digest: {chain.get('state_digest')}",
                    f"Rehashed payloads: {chain.get('hashed_file_count')}",
                ]
            )
    matches = result.get("matches")
    if isinstance(matches, list) and matches:
        lines.extend(["", "Matches", "-------"])
        for match in matches:
            if isinstance(match, dict):
                identity = match.get("file_id") or match.get("export_id") or "match"
                lines.append(str(identity))
                if detailed:
                    for key, value in match.items():
                        if key in {"file_id", "export_id"}:
                            continue
                        lines.append(f"  {key}: {value}")
    checks = result.get("checks")
    if isinstance(checks, list) and checks:
        lines.extend(["", "Checks", "------"])
        lines.extend(f"- {item}" for item in checks)
    for title, key in (("Warnings", "warnings"), ("Limitations", "limitations")):
        values = result.get(key)
        if isinstance(values, list) and values:
            lines.extend(["", title, "-" * len(title)])
            lines.extend(f"- {item}" for item in values)
    if detailed:
        lines.extend(
            [
                "",
                "Detailed structured result",
                "--------------------------",
                json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False),
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _html(result: dict[str, object], detailed: bool) -> str:
    status = html.escape(str(result.get("status", "unknown")))
    summary = html.escape(str(result.get("summary", "")))
    checks = result.get("checks") if isinstance(result.get("checks"), list) else []
    warnings = (
        result.get("warnings") if isinstance(result.get("warnings"), list) else []
    )
    limitations = (
        result.get("limitations") if isinstance(result.get("limitations"), list) else []
    )
    details = ""
    if detailed:
        details = (
            "<details open><summary>Structured verification detail</summary><pre>"
            + html.escape(
                json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False)
            )
            + "</pre></details>"
        )
    return f"""<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FACT Verification Report</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 72rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }}
header, section, details {{ border: 1px solid #bbb; border-radius: .5rem; padding: 1rem; margin: 1rem 0; }}
.status {{ font-weight: 700; text-transform: uppercase; }}
code, pre {{ font-family: ui-monospace, monospace; overflow-wrap: anywhere; white-space: pre-wrap; }}
table {{ border-collapse: collapse; width: 100%; }} th, td {{ border: 1px solid #ccc; padding: .4rem; text-align: left; vertical-align: top; }}
</style>
</head>
<body>
<header>
<h1>FACT Verification Report</h1>
<p class="status">{status}</p>
<p><strong>Type:</strong> {html.escape(str(result.get("verification_kind")))}</p>
<p><strong>Target:</strong> <code>{html.escape(str(result.get("target")))}</code></p>
<p>{summary}</p>
</header>
<section><h2>Checks performed</h2><ul>{"".join(f"<li>{html.escape(str(item))}</li>" for item in checks)}</ul></section>
<section><h2>Warnings</h2><ul>{"".join(f"<li>{html.escape(str(item))}</li>" for item in warnings) or "<li>None</li>"}</ul></section>
<section><h2>Scope and limitations</h2><ul>{"".join(f"<li>{html.escape(str(item))}</li>" for item in limitations) or "<li>No additional limitations recorded.</li>"}</ul></section>
{details}
</body>
</html>
"""


def _pdf_bytes(text: str) -> bytes:
    """Produce a dependency-free, text-oriented PDF using standard Helvetica."""

    wrapped: list[str] = []
    for source_line in text.splitlines():
        wrapped.extend(textwrap.wrap(source_line, width=95) or [""])
    pages = [wrapped[index : index + 52] for index in range(0, len(wrapped), 52)] or [
        []
    ]
    objects: list[bytes] = []

    def add(payload: bytes) -> int:
        objects.append(payload)
        return len(objects)

    font_id = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids: list[int] = []
    content_ids: list[int] = []
    # Reserve page objects after creating content streams; parent is patched once
    # the pages tree object number is known.
    for page in pages:
        commands = ["BT", "/F1 10 Tf", "50 790 Td", "12 TL"]
        for line in page:
            safe = line.encode("latin-1", "replace").decode("latin-1")
            safe = safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            commands.append(f"({safe}) Tj")
            commands.append("T*")
        commands.append("ET")
        stream = "\n".join(commands).encode("latin-1")
        content_ids.append(
            add(
                b"<< /Length "
                + str(len(stream)).encode()
                + b" >>\nstream\n"
                + stream
                + b"\nendstream"
            )
        )
        page_ids.append(0)
    pages_id = len(objects) + len(pages) + 1
    for index, content_id in enumerate(content_ids):
        page_ids[index] = add(
            (
                f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 595 842] "
                f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>"
            ).encode("ascii")
        )
    actual_pages_id = add(
        (
            f"<< /Type /Pages /Count {len(page_ids)} /Kids ["
            + " ".join(f"{page_id} 0 R" for page_id in page_ids)
            + "] >>"
        ).encode("ascii")
    )
    if actual_pages_id != pages_id:
        raise ToolkitError("Internal PDF object numbering failure")
    catalog_id = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii"))

    output = bytearray(b"%PDF-1.4\n%FACT\n")
    offsets = [0]
    for number, payload in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode("ascii"))
        output.extend(payload)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(output)


def render_report(
    result: dict[str, object], *, format_name: str, detailed: bool = False
) -> bytes:
    """Render a verification result to one supported report byte format."""

    if format_name not in REPORT_FORMATS:
        raise ToolkitError(f"Unsupported verification report format: {format_name}")
    if format_name == "json":
        return (
            json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
    text = _text(result, detailed)
    if format_name == "text":
        return text.encode("utf-8")
    if format_name == "html":
        return _html(result, detailed).encode("utf-8")
    return _pdf_bytes(text)


def write_report(
    result: dict[str, object],
    *,
    format_name: str,
    output: Path,
    detailed: bool = False,
) -> Path:
    """Write one report without admitting it into the FACT file catalogue."""

    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = render_report(result, format_name=format_name, detailed=detailed)
    output.write_bytes(payload)
    return output
