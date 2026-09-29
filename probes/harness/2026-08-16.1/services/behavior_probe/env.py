"""Host environment gates for behavior probe (podman PATH · cgroup controllers)."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from services.behavior_probe.constants import CPUS, MEMORY_LIMIT, PIDS_LIMIT

CGROUP_CPU_NOT_DELEGATED = "cgroup cpu controller not delegated"
PODMAN_PATH_HINT = (
    "podman / conmon not on PATH (pass PATH when launching from systemd)"
)


class PodmanMissingError(RuntimeError):
    """podman or conmon not resolvable via shutil.which — stop before any probe rows."""


class CgroupControllerMissingError(RuntimeError):
    """Required cgroup controllers (memory / pids) not delegated — refuse to run."""


def require_podman_tools(
    *,
    which: Any | None = None,
) -> dict[str, str]:
    """Resolve podman and conmon on PATH. Raises PodmanMissingError if either missing."""
    which_fn = which if which is not None else shutil.which
    podman = which_fn("podman")
    conmon = which_fn("conmon")
    missing: list[str] = []
    if not podman:
        missing.append("podman")
    if not conmon:
        missing.append("conmon")
    if missing:
        raise PodmanMissingError(
            f"{PODMAN_PATH_HINT}: missing={','.join(missing)}"
        )
    return {"podman": str(podman), "conmon": str(conmon)}


def _own_cgroup_path() -> Path | None:
    """Return the cgroup v2 directory for this process, or None if unreadable."""
    try:
        text = Path("/proc/self/cgroup").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        # cgroup v2: "0::/user.slice/..."
        if line.startswith("0::"):
            rel = line[3:].strip() or "/"
            return Path("/sys/fs/cgroup") / rel.lstrip("/")
    return None


def read_cgroup_controllers(
    *,
    controllers_text: str | None = None,
    cgroup_dir: Path | None = None,
) -> set[str]:
    """Return the set of controllers listed in cgroup.controllers.

    When ``controllers_text`` is provided (tests), parse that string instead of
    reading the filesystem.
    """
    if controllers_text is not None:
        return {tok for tok in controllers_text.split() if tok}

    base = cgroup_dir if cgroup_dir is not None else _own_cgroup_path()
    if base is None:
        raise CgroupControllerMissingError(
            "cannot resolve own cgroup path (cgroup v2 required)"
        )
    ctrl_file = base / "cgroup.controllers"
    try:
        raw = ctrl_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise CgroupControllerMissingError(
            f"cannot read {ctrl_file}: {exc}"
        ) from exc
    return {tok for tok in raw.split() if tok}


@dataclass(frozen=True)
class ResourceLimits:
    memory: str
    pids: int
    cpus: str | None
    cpus_not_applied_reason: str | None

    def as_record(self) -> dict[str, Any]:
        return {
            "memory": self.memory,
            "pids": self.pids,
            "cpus": self.cpus,
            "cpus_not_applied_reason": self.cpus_not_applied_reason,
        }


def resolve_resource_limits(
    *,
    controllers: set[str] | None = None,
    controllers_text: str | None = None,
) -> ResourceLimits:
    """Apply --cpus only when cpu is delegated; require memory and pids."""
    ctrl = controllers
    if ctrl is None:
        ctrl = read_cgroup_controllers(controllers_text=controllers_text)

    if "memory" not in ctrl:
        raise CgroupControllerMissingError(
            "cgroup memory controller not available; refusing to run without --memory"
        )
    if "pids" not in ctrl:
        raise CgroupControllerMissingError(
            "cgroup pids controller not available; refusing to run without --pids-limit"
        )

    if "cpu" in ctrl:
        return ResourceLimits(
            memory=MEMORY_LIMIT,
            pids=int(PIDS_LIMIT),
            cpus=CPUS,
            cpus_not_applied_reason=None,
        )
    return ResourceLimits(
        memory=MEMORY_LIMIT,
        pids=int(PIDS_LIMIT),
        cpus=None,
        cpus_not_applied_reason=CGROUP_CPU_NOT_DELEGATED,
    )


def build_podman_run_base_args(limits: ResourceLimits) -> list[str]:
    """podman run flags up to (but not including) image ref. No -v / --env."""
    args = [
        "podman",
        "run",
        "-i",
        "--network=none",
        "--memory",
        limits.memory,
        "--pids-limit",
        str(limits.pids),
    ]
    if limits.cpus is not None:
        args.extend(["--cpus", limits.cpus])
    return args
