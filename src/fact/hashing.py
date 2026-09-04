"""Compatibility import path for :mod:`fact.services.hashing`."""

import sys
from fact.services import hashing as _implementation

sys.modules[__name__] = _implementation
