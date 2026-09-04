"""Optional local history and completion support for FACT's operator shell."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from contextlib import suppress

from .registry import history_path


_HISTORY_LIMIT = 500
_SENSITIVE_MARKERS = (
    "--password",
    "--passphrase",
    "--secret",
    "--token",
    "--private-key",
    "--cookies",
    "--identity-file",
    "--requestor",
    "--acquisition-comment",
    "--case-comment",
    "export-keypair",
)


def should_retain_history(line: str) -> bool:
    """Return whether an input line is safe enough for local history storage."""

    lowered = line.casefold()
    return bool(line.strip()) and not any(
        marker in lowered for marker in _SENSITIVE_MARKERS
    )


class ReadlineFeatures:
    """Manage optional readline state without making it a FACT dependency."""

    def __init__(
        self,
        candidates: Callable[[str], Iterable[str]],
        *,
        enabled: bool = True,
        history_enabled: bool = True,
    ) -> None:
        self._candidates = candidates
        self._enabled = enabled
        self._history_enabled = history_enabled
        self._readline = None
        self._before_count = 0

    def __enter__(self) -> "ReadlineFeatures":
        if not self._enabled:
            return self
        try:
            import readline
        except ImportError:
            return self
        self._readline = readline
        if self._history_enabled:
            path = history_path()
            if path.is_file():
                with suppress(OSError):
                    readline.read_history_file(path)
            readline.set_history_length(_HISTORY_LIMIT)
        readline.set_completer_delims(" \t\n")
        readline.set_completer(self._complete)
        with suppress(RuntimeError):
            readline.parse_and_bind("tab: complete")
        return self

    def before_input(self) -> None:
        """Record history length before builtin input potentially adds a line."""

        if self._readline is not None and self._history_enabled:
            self._before_count = self._readline.get_current_history_length()

    def after_input(self, line: str) -> None:
        """Remove a newly-added sensitive line from readline history."""

        if (
            self._readline is None
            or not self._history_enabled
            or should_retain_history(line)
        ):
            return
        while self._readline.get_current_history_length() > self._before_count:
            self._readline.remove_history_item(self._before_count)

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self._readline is None or not self._history_enabled:
            return
        path = history_path()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with suppress(OSError):
            path.parent.chmod(0o700)
            self._readline.write_history_file(path)
            path.chmod(0o600)

    def _complete(self, text: str, state: int) -> str | None:
        matches = sorted(set(self._candidates(text)))
        return matches[state] if state < len(matches) else None
