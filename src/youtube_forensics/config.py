"""Compatibility import path for :mod:`fact.config`."""

import sys
from fact import config as _implementation

sys.modules[__name__] = _implementation
