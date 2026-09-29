"""Behavior probe — observe declared-offline MCP servers under network=none."""

from __future__ import annotations

from typing import Any

__all__ = ["run_behavior_probe"]


def __getattr__(name: str) -> Any:
    # Lazy: avoid pulling orchestrator/build/run on submodule imports (tests).
    if name == "run_behavior_probe":
        from services.behavior_probe.orchestrator import run_behavior_probe

        return run_behavior_probe
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
