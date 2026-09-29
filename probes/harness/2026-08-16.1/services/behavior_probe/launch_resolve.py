"""Resolve runtime launch argv without package managers (npx/npm/pip/uv/uvx)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Must never appear in server CMD / runtime argv (build-stage install RUNs are separate).
RUNTIME_FORBIDDEN_LAUNCHERS = frozenset({"npx", "npm", "pip", "uv", "uvx"})


@dataclass(frozen=True)
class LaunchResolve:
    """Host-side resolution of bin / console_scripts metadata."""

    ok: bool
    relative_path: str | None = None
    script_name: str | None = None
    reason: str | None = None


def bare_package_name(identifier: str) -> str:
    """Strip npm scope: ``@scope/name`` → ``name``; otherwise identity."""
    if "/" in identifier:
        return identifier.rsplit("/", 1)[-1]
    return identifier


def resolve_npm_bin(identifier: str, bin_field: Any) -> LaunchResolve:
    """Select package.json ``bin`` entry.

    - string → that path
    - object → key matching bare package name, else the sole key
    - missing / empty → ``no_bin``
    - multiple keys without a name match → ``ambiguous_bin``
    """
    if bin_field is None or bin_field == "" or bin_field == {}:
        return LaunchResolve(False, reason="no_bin")
    if isinstance(bin_field, str):
        return LaunchResolve(True, relative_path=bin_field)
    if isinstance(bin_field, dict):
        bare = bare_package_name(identifier)
        if bare in bin_field:
            return LaunchResolve(True, relative_path=str(bin_field[bare]), script_name=bare)
        if len(bin_field) == 1:
            key, val = next(iter(bin_field.items()))
            return LaunchResolve(True, relative_path=str(val), script_name=str(key))
        if len(bin_field) == 0:
            return LaunchResolve(False, reason="no_bin")
        return LaunchResolve(False, reason="ambiguous_bin")
    return LaunchResolve(False, reason="no_bin")


def resolve_pypi_console_script(
    package_name: str,
    console_scripts: dict[str, str] | list[str] | None,
) -> LaunchResolve:
    """Select a console_scripts entry; no ``python -m`` guessing.

    - exactly one → that script name
    - none → ``no_console_script``
    - multiple → name match (bare / dash-underscore), else ``no_console_script``
      (unresolvable; do not guess)
    """
    if not console_scripts:
        return LaunchResolve(False, reason="no_console_script")

    if isinstance(console_scripts, list):
        names = [str(x) for x in console_scripts]
        mapping = {n: n for n in names}
    else:
        mapping = {str(k): str(v) for k, v in console_scripts.items()}
        names = list(mapping.keys())

    if len(names) == 0:
        return LaunchResolve(False, reason="no_console_script")
    if len(names) == 1:
        return LaunchResolve(True, script_name=names[0])

    bare = bare_package_name(package_name)
    candidates = [bare, bare.replace("-", "_"), bare.replace("_", "-")]
    for cand in candidates:
        if cand in mapping:
            return LaunchResolve(True, script_name=cand)
    return LaunchResolve(False, reason="no_console_script")


def assert_no_runtime_package_managers(argv: list[str]) -> None:
    for tok in argv:
        base = tok.rsplit("/", 1)[-1]
        if base in RUNTIME_FORBIDDEN_LAUNCHERS or tok in RUNTIME_FORBIDDEN_LAUNCHERS:
            raise ValueError(f"runtime argv must not launch package manager: {tok!r}")


def cmd_line_has_package_manager(dockerfile_text: str) -> bool:
    """True if any CMD line token is a forbidden launcher."""
    for line in dockerfile_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("CMD"):
            continue
        lower = stripped.lower()
        for bad in RUNTIME_FORBIDDEN_LAUNCHERS:
            # Token-ish: appear as JSON string element or bare word after CMD.
            if f'"{bad}"' in stripped or f"'{bad}'" in stripped:
                return True
            # Avoid matching substrings inside longer paths; check word boundaries lightly.
            if f" {bad} " in f" {lower} " or lower.endswith(f" {bad}"):
                return True
    return False
