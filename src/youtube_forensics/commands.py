"""Compatibility import path for :mod:`fact.services.commands`."""

import sys

from fact.services import commands as _implementation

sys.modules[__name__] = _implementation
