"""Compatibility import path for :mod:`fact.core.project`."""

import sys
from fact.core import project as _implementation

sys.modules[__name__] = _implementation
