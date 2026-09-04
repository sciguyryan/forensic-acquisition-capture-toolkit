"""Compatibility import path for :mod:`fact.console`."""

import sys
from fact import console as _implementation

sys.modules[__name__] = _implementation
