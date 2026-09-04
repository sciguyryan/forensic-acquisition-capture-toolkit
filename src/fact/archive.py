"""Compatibility import path for :mod:`fact.services.archive`."""

import sys
from fact.services import archive as _implementation

sys.modules[__name__] = _implementation
