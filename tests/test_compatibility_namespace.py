"""Tests for the historical Python package compatibility namespace."""


def test_historical_package_resolves_to_canonical_modules() -> None:
    """Compatibility imports must not maintain a second implementation."""

    import fact.acquire as canonical
    import youtube_forensics.acquire as historical

    assert historical is canonical
