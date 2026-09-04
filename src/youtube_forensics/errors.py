"""Compatibility import path for :mod:`fact.errors`."""

import sys
from fact import errors as _implementation

sys.modules[__name__] = _implementation
