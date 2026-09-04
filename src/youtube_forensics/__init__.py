"""Compatibility package for the pre-FACT ``youtube_forensics`` import name.

New code should import :mod:`fact`.  This namespace is intentionally thin so
there is only one implementation of evidential logic to maintain.
"""

from fact import __version__

__all__ = ["__version__"]
