"""Expose configuration-path helpers for the toolkit.

The canonical implementation remains in :mod:`identity`; this module provides
a stable import location for callers that treat configuration as a separate
concern.
"""

from .identity import config_path

__all__ = ["config_path"]
