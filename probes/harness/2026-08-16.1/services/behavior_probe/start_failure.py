"""Classify initialize_failed rows from server_stderr_head only (no package names)."""

from __future__ import annotations

import re

from services.behavior_probe.constants import (
    STDERR_CAPTURE_CAPTURED,
    START_FAILED_DEPENDENCY_INCOMPATIBLE,
    START_FAILED_ENTRYPOINT_NOT_MCP,
    START_FAILED_OTHER,
    START_FAILED_STDERR_UNAVAILABLE,
)

# Import / dependency failure signals (case-insensitive substring).
_DEPENDENCY_MARKERS = (
    "traceback",
    "modulenotfounderror",
    "importerror",
    "no module named",
    "needs the mcp sdk",
)

# CLI usage / help — process started but did not speak MCP.
_ENTRYPOINT_MARKERS = (
    "usage:",
    "show this help",
    "positional arguments:",
)

_HELP_WORD = re.compile(r"\bhelp\b", re.IGNORECASE)


def classify_start_failure(
    stderr: str | None,
    *,
    stderr_capture: str | None = None,
) -> str:
    """Return one START_FAILED_* value from captured stderr only.

    Empty pipes and unread pipes are not ``start_failed_other``.
    ``start_failed_other`` is only for captured text that matches no known type.
    Package names are never consulted.
    """
    if stderr_capture is not None and stderr_capture != STDERR_CAPTURE_CAPTURED:
        return START_FAILED_STDERR_UNAVAILABLE

    text = stderr or ""
    if not text:
        return START_FAILED_STDERR_UNAVAILABLE

    lower = text.lower()

    if any(marker in lower for marker in _DEPENDENCY_MARKERS):
        return START_FAILED_DEPENDENCY_INCOMPATIBLE

    if any(marker in lower for marker in _ENTRYPOINT_MARKERS):
        return START_FAILED_ENTRYPOINT_NOT_MCP

    if _HELP_WORD.search(text):
        return START_FAILED_ENTRYPOINT_NOT_MCP

    return START_FAILED_OTHER
