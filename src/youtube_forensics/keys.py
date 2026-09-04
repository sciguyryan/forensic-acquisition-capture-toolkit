"""Compatibility import path for :mod:`fact.keys`."""

import sys

from fact import keys as _implementation

sys.modules[__name__] = _implementation
