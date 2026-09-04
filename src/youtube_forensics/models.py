"""Compatibility import path for :mod:`fact.models`."""

import sys
from fact import models as _implementation

sys.modules[__name__] = _implementation
