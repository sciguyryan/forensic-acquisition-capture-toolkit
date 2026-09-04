"""Interactive operator shell for FACT.

The shell is intentionally a presentation and dispatch layer. Evidential work
continues to run through the same CLI/application handlers and reusable core
services used by non-interactive commands.
"""

from .repl import run_shell
from .session import ShellSession

__all__ = ["ShellSession", "run_shell"]
