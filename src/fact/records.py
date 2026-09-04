"""Compatibility import path for :mod:`fact.core.records`."""

import sys
from fact.core import records as _implementation

sys.modules[__name__] = _implementation
