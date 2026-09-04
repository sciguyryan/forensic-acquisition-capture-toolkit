"""Tests for terminal summary formatting."""

from fact.console import summary


def test_summary_aligns_values_after_longest_label(capsys) -> None:
    """Align summary values using the width of the longest label."""
    rows = [
        ("Archive readable", "/tmp/archive.7z", "PASS"),
        ("Document: evidence-public-key.asc", "PASS", "PASS"),
        ("Document: TOOLKIT.json", "PASS", "PASS"),
    ]

    summary("EVIDENCE VERIFICATION PASSED", rows, True)
    lines = capsys.readouterr().out.splitlines()
    detail_lines = [
        next(line for line in lines if label in line) for label, _, _ in rows
    ]
    values = [value for _, value, _ in rows]
    value_columns = [
        line.index(value) for line, value in zip(detail_lines, values, strict=True)
    ]

    assert len(set(value_columns)) == 1
