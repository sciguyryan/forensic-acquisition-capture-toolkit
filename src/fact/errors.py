"""Define expected operational and verification exceptions."""


class ToolkitError(RuntimeError):
    """Expected operational failure."""


class VerificationError(ToolkitError):
    """Evidence verification failed."""
