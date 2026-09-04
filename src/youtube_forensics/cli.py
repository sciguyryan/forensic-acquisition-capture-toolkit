"""Compatibility import path for :mod:`fact.cli`."""

import sys
from fact import cli as _implementation

sys.modules[__name__] = _implementation
