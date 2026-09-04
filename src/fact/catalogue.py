"""Compatibility import path for :mod:`fact.core.catalogue`."""

import sys

from fact.core import catalogue as _implementation

sys.modules[__name__] = _implementation
