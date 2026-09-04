"""Compatibility import path for :mod:`fact.identity`."""

import sys

from fact import identity as _implementation

sys.modules[__name__] = _implementation
