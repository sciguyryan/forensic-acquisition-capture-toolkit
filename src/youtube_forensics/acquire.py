"""Compatibility import path for :mod:`fact.acquire`."""

import sys

from fact import acquire as _implementation

sys.modules[__name__] = _implementation
