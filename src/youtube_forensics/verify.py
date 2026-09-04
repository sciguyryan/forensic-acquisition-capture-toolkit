"""Compatibility import path for :mod:`fact.core.verification`."""

import sys

from fact.core import verification as _implementation

sys.modules[__name__] = _implementation
