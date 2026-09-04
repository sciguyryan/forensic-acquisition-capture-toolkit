"""Render timestamped console messages, summaries, and security warnings.

Colour is used only when standard output is attached to a terminal and the
``NO_COLOR`` environment variable has not been set.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime


def _color_enabled() -> bool:
    """Return whether ANSI colour output should be enabled."""
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def paint(text: str, code: str) -> str:
    """Wrap text in an ANSI colour sequence when colour output is enabled."""
    return f"\033[{code}m{text}\033[0m" if _color_enabled() else text


def log(level: str, message: str) -> None:
    """Write a timestamped toolkit log message to standard output."""
    colors = {"INFO": "36", "PASS": "32", "WARN": "33", "FAIL": "31", "ERROR": "31"}
    now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    print(f"[{now}] [{paint(level, colors.get(level, '0'))}] {message}", flush=True)


def summary(title: str, rows: list[tuple[str, str, str]], passed: bool) -> None:
    """Render a formatted verification or operation summary."""
    width = 76
    status = "PASS" if passed else "FAIL"
    symbol = "✓" if passed else "✗"
    color = "32" if passed else "31"
    print("\n" + "=" * width)
    print(f"  {paint(symbol, color)}  {paint(title, color)}")
    print("=" * width)
    label_width = max(28, *(len(label) for label, _, _ in rows)) if rows else 28
    for label, value, state in rows:
        sym = {"PASS": "✓", "FAIL": "✗", "WARN": "!", "INFO": "•", "SKIP": "-"}.get(
            state, "•"
        )
        col = {
            "PASS": "32",
            "FAIL": "31",
            "WARN": "33",
            "INFO": "36",
            "SKIP": "33",
        }.get(state, "0")
        print(f"  {paint(sym, col)} {label:<{label_width}} {value}")
    print("-" * width)
    print(f"  {paint(symbol, color)} {'Overall result':<{label_width}} {status}")
    print("-" * width)


def security_warning(lines: list[str]) -> None:
    """Render a prominent multi-line security warning."""
    width = max(76, *(len(line) + 6 for line in lines)) if lines else 76
    border = "!" * width
    print("\n" + paint(border, "1;31"))
    print(paint("  ⚠  SECURITY WARNING", "1;31"))
    for line in lines:
        print(paint(f"  {line}", "1;33"))
    print(paint(border, "1;31") + "\n")
