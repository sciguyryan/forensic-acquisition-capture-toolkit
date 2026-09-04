"""Compatibility import path for :mod:`fact.core.packaging`."""

import sys

from fact.core import packaging as _implementation

sys.modules[__name__] = _implementation
