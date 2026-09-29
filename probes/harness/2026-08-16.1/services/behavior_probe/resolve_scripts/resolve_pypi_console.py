#!/usr/bin/env python3
"""Build-stage: resolve console_scripts → /app/mcp-launch (no pip/uvx at runtime).

Usage: python resolve_pypi_console.py <distribution-name>
Prints REASON:no_console_script on failure (exit 1).
"""
from __future__ import annotations

import json
import pathlib
import sys
from importlib.metadata import PackageNotFoundError, distribution, version

MCP_LAUNCH = "/app/mcp-launch"
VERSIONS_PATH = "/app/aos-bp-installed-versions.json"


def main() -> int:
    if len(sys.argv) < 2:
        print("REASON:no_console_script", file=sys.stderr)
        return 1
    ident = sys.argv[1]
    try:
        dist = distribution(ident)
    except PackageNotFoundError:
        print("REASON:no_console_script", file=sys.stderr)
        return 1

    scripts: dict[str, str] = {}
    try:
        eps = dist.entry_points
    except Exception:  # noqa: BLE001 — metadata variance across versions
        eps = []
    for ep in eps:
        group = getattr(ep, "group", None) or ""
        if group == "console_scripts":
            scripts[ep.name] = ep.value

    if not scripts:
        # entry_points.txt fallback
        for f in dist.files or []:
            parts = pathlib.PurePath(str(f)).parts
            if (
                len(parts) >= 2
                and parts[0].endswith(".dist-info")
                and parts[1] == "entry_points.txt"
            ):
                text = dist.read_text("entry_points.txt")
                if not text:
                    continue
                section = None
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("[") and line.endswith("]"):
                        section = line[1:-1]
                        continue
                    if section == "console_scripts" and "=" in line:
                        name, _, rest = line.partition("=")
                        scripts[name.strip()] = rest.strip()

    if not scripts:
        print("REASON:no_console_script", file=sys.stderr)
        return 1

    names = list(scripts.keys())
    chosen: str | None = None
    if len(names) == 1:
        chosen = names[0]
    else:
        bare = ident.split("/")[-1]
        for cand in (bare, bare.replace("-", "_"), bare.replace("_", "-")):
            if cand in scripts:
                chosen = cand
                break
    if not chosen:
        print("REASON:no_console_script", file=sys.stderr)
        return 1

    target = None
    for c in (pathlib.Path("/usr/local/bin") / chosen, pathlib.Path("/usr/bin") / chosen):
        if c.is_file():
            target = c
            break
    if target is None:
        print("REASON:no_console_script", file=sys.stderr)
        return 1

    launch = pathlib.Path(MCP_LAUNCH)
    launch.write_text("#!/bin/sh\nexec " + json.dumps(str(target)) + ' "$@"\n', encoding="utf-8")
    launch.chmod(0o755)
    _record_installed_versions(ident)
    return 0


def _record_installed_versions(ident: str) -> None:
    """Write target package + mcp versions; never fails the resolve step."""
    out: dict[str, str] = {}
    for name in (ident, "mcp"):
        try:
            out[name] = version(name)
        except PackageNotFoundError:
            continue
        except Exception:  # noqa: BLE001 — metadata variance must not fail build
            continue
    try:
        pathlib.Path(VERSIONS_PATH).write_text(
            json.dumps(out, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
    except OSError:
        pass


if __name__ == "__main__":
    raise SystemExit(main())
