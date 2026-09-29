"""Podman image build for a single MCP package (network allowed only here)."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from services.behavior_probe.constants import (
    BUILD_TIMEOUT_SEC,
    NODE_BASE_TAG,
    PYTHON_BASE_TAG,
)
from services.behavior_probe.launch_resolve import assert_no_runtime_package_managers
from services.behavior_probe.targets import ProbeTarget

# Resolve base tags to digests on first successful pull; pin thereafter in-process.
_BASE_TAGS = {
    "npm": NODE_BASE_TAG,
    "pypi": PYTHON_BASE_TAG,
}
_resolved_base: dict[str, str] = {}

# Fixed in-image launch path — resolved at build (RUN), never via npx/pip/uvx at run.
MCP_LAUNCH_PATH = "/app/mcp-launch"
DNS_RECORDER_PATH = "/usr/local/lib/aos-bp/dns_recorder.py"
ENTRYPOINT_PATH = "/usr/local/lib/aos-bp/aos_bp_entrypoint.sh"

_RESOLVE_FAIL_MARKERS = ("ambiguous_bin", "no_bin", "no_console_script")

_RESOLVE_SCRIPTS_DIR = Path(__file__).resolve().parent / "resolve_scripts"

# Shared RUN layer: strace + python3 (dns recorder) + bake recorder/entrypoint into image.
_APT_STRACE_PYTHON = (
    "RUN apt-get update \\\n"
    " && apt-get install -y --no-install-recommends strace ca-certificates python3 \\\n"
    " && rm -rf /var/lib/apt/lists/* \\\n"
    " && mkdir -p /usr/local/lib/aos-bp\n"
    "COPY dns_recorder.py aos_bp_entrypoint.sh /usr/local/lib/aos-bp/\n"
    "RUN chmod 755 /usr/local/lib/aos-bp/aos_bp_entrypoint.sh "
    "/usr/local/lib/aos-bp/dns_recorder.py\n"
)

_STRACE_ENTRYPOINT = (
    f'ENTRYPOINT ["{ENTRYPOINT_PATH}"]\n'
)


@dataclass
class BuildResult:
    ok: bool
    image_ref: str | None
    image_digest: str | None
    build_log: str
    reason: str | None = None
    server_argv: list[str] | None = None
    installed_versions: dict[str, str] | None = None
    artifact_sha256: dict[str, str] | None = None


INSTALLED_VERSIONS_PATH = "/app/aos-bp-installed-versions.json"
ARTIFACT_SHA256_PATH = "/app/aos-bp-artifact-sha256.json"
ARTIFACT_STAGING_DIR = "/tmp/aos-bp-artifacts"


def _run(cmd: list[str], *, timeout: float, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def resolve_base_image(registry_type: str) -> str:
    if registry_type in _resolved_base:
        return _resolved_base[registry_type]
    tag = _BASE_TAGS[registry_type]
    pull = _run(["podman", "pull", tag], timeout=BUILD_TIMEOUT_SEC)
    if pull.returncode != 0:
        raise RuntimeError(f"podman pull failed for {tag}: {pull.stderr}")
    inspect = _run(
        ["podman", "image", "inspect", tag, "--format", "{{.Digest}}"],
        timeout=60,
    )
    digest = (inspect.stdout or "").strip()
    if not digest.startswith("sha256:"):
        inspect2 = _run(
            ["podman", "image", "inspect", tag, "--format", "{{.Id}}"],
            timeout=60,
        )
        digest = (inspect2.stdout or "").strip()
    if digest.startswith("sha256:"):
        name = re.sub(r":[^:/]+$", "", tag)
        pinned = f"{name}@{digest}"
    else:
        pinned = tag
    _resolved_base[registry_type] = pinned
    return pinned


def _image_name(target: ProbeTarget) -> str:
    raw = f"{target.registry_type}-{target.identifier}-{target.version}"
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", raw).lower().strip("-")[:80]
    digest = hashlib.sha256(raw.encode()).hexdigest()[:12]
    return f"localhost/aos-behavior-probe/{slug}:{digest}"


def _expand_package_args(pkg: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key in ("runtimeArguments", "packageArguments"):
        for item in pkg.get(key) or []:
            if not isinstance(item, dict):
                continue
            itype = item.get("type")
            if itype == "positional":
                val = item.get("value")
                if val is not None:
                    out.append(str(val))
            elif itype == "named":
                name = item.get("name")
                val = item.get("value")
                if name:
                    out.append(str(name))
                    if val is not None and val != "":
                        out.append(str(val))
    return out


def _server_argv(extra: list[str]) -> list[str]:
    argv = [MCP_LAUNCH_PATH, *extra]
    assert_no_runtime_package_managers(argv)
    return argv


def build_dockerfile(target: ProbeTarget, base: str) -> tuple[str, list[str]]:
    """Return Dockerfile text and server argv.

    Build may use npm/pip (install only). Runtime CMD never launches package managers;
    ``runtimeHint`` is ignored for argv selection.

    Expects build context to contain ``resolve_npm_bin.js`` / ``resolve_pypi_console.py``.
    """
    extra = _expand_package_args(target.package)
    argv = _server_argv(extra)

    if target.registry_type == "npm":
        ident = target.identifier
        ver = target.version
        spec = f"{ident}@{ver}"
        # Download tarball first, then install from the local file (hash at build, no later fetch).
        install = (
            f"mkdir -p {ARTIFACT_STAGING_DIR} "
            f"&& npm pack {spec} --pack-destination {ARTIFACT_STAGING_DIR} "
            f"&& npm install --ignore-scripts -g {ARTIFACT_STAGING_DIR}/*.tgz"
        )
        # Shell-escape identifier for RUN argv (JSON string is safe inside double quotes via sh).
        ident_sh = json.dumps(ident)
        df = f"""FROM {base}
USER root
{_APT_STRACE_PYTHON}RUN {install}
WORKDIR /app
COPY resolve_npm_bin.js /tmp/resolve_npm_bin.js
COPY hash_artifacts.py /tmp/hash_artifacts.py
RUN node /tmp/resolve_npm_bin.js {ident_sh}
RUN python3 /tmp/hash_artifacts.py {ARTIFACT_STAGING_DIR} {ARTIFACT_SHA256_PATH}
# ENTRYPOINT: resolv→127.0.0.1 + DNS recorder (outside strace) + strace server.
{_STRACE_ENTRYPOINT}CMD {json.dumps(argv)}
"""
        return df, argv

    if target.registry_type == "pypi":
        ident = target.identifier
        ver = target.version
        install = (
            f"mkdir -p {ARTIFACT_STAGING_DIR} "
            f"&& pip download --no-cache-dir --only-binary=:all: "
            f"--dest {ARTIFACT_STAGING_DIR} {ident}=={ver} "
            f"&& pip install --no-cache-dir --no-index "
            f"--find-links {ARTIFACT_STAGING_DIR} --only-binary=:all: {ident}=={ver}"
        )
        ident_sh = json.dumps(ident)
        df = f"""FROM {base}
USER root
{_APT_STRACE_PYTHON}RUN {install}
WORKDIR /app
COPY resolve_pypi_console.py /tmp/resolve_pypi_console.py
COPY hash_artifacts.py /tmp/hash_artifacts.py
RUN python /tmp/resolve_pypi_console.py {ident_sh}
RUN python3 /tmp/hash_artifacts.py {ARTIFACT_STAGING_DIR} {ARTIFACT_SHA256_PATH}
{_STRACE_ENTRYPOINT}CMD {json.dumps(argv)}
"""
        return df, argv

    raise ValueError(f"unsupported registry type for build: {target.registry_type}")


def build_dockerfile_from_local(
    *,
    registry_type: str,
    identifier: str,
    fixture_dir_name: str,
    base: str,
    extra_args: list[str] | None = None,
) -> tuple[str, list[str]]:
    """Dockerfile for in-repo calibration fixtures (COPY + local install)."""
    extra = list(extra_args or [])
    argv = _server_argv(extra)
    ident_sh = json.dumps(identifier)

    if registry_type == "npm":
        df = f"""FROM {base}
USER root
{_APT_STRACE_PYTHON}COPY {fixture_dir_name} /src/calibrate_pkg
        RUN npm install --ignore-scripts -g /src/calibrate_pkg
WORKDIR /app
COPY resolve_npm_bin.js /tmp/resolve_npm_bin.js
COPY hash_artifacts.py /tmp/hash_artifacts.py
RUN node /tmp/resolve_npm_bin.js {ident_sh}
RUN python3 /tmp/hash_artifacts.py {ARTIFACT_STAGING_DIR} {ARTIFACT_SHA256_PATH}
{_STRACE_ENTRYPOINT}CMD {json.dumps(argv)}
"""
        return df, argv

    if registry_type == "pypi":
        df = f"""FROM {base}
USER root
{_APT_STRACE_PYTHON}COPY {fixture_dir_name} /src/calibrate_pkg
        RUN pip install --no-cache-dir /src/calibrate_pkg
WORKDIR /app
COPY resolve_pypi_console.py /tmp/resolve_pypi_console.py
COPY hash_artifacts.py /tmp/hash_artifacts.py
RUN python /tmp/resolve_pypi_console.py {ident_sh}
RUN python3 /tmp/hash_artifacts.py {ARTIFACT_STAGING_DIR} {ARTIFACT_SHA256_PATH}
{_STRACE_ENTRYPOINT}CMD {json.dumps(argv)}
"""
        return df, argv

    raise ValueError(f"unsupported registry type for local build: {registry_type}")


def _stage_instrument_scripts(context_dir: Path) -> None:
    """Copy DNS recorder + entrypoint (always; no mounts/env at run)."""
    dest_dir = context_dir  # COPY paths are relative to build context root
    shutil.copy2(_RESOLVE_SCRIPTS_DIR / "dns_recorder.py", dest_dir / "dns_recorder.py")
    shutil.copy2(
        _RESOLVE_SCRIPTS_DIR / "aos_bp_entrypoint.sh",
        dest_dir / "aos_bp_entrypoint.sh",
    )


def _stage_resolve_scripts(context_dir: Path, registry_type: str) -> None:
    _stage_instrument_scripts(context_dir)
    shutil.copy2(_RESOLVE_SCRIPTS_DIR / "hash_artifacts.py", context_dir / "hash_artifacts.py")
    if registry_type == "npm":
        shutil.copy2(_RESOLVE_SCRIPTS_DIR / "resolve_npm_bin.js", context_dir / "resolve_npm_bin.js")
    elif registry_type == "pypi":
        shutil.copy2(
            _RESOLVE_SCRIPTS_DIR / "resolve_pypi_console.py",
            context_dir / "resolve_pypi_console.py",
        )


def _read_image_json_dict(image_ref: str, path: str) -> dict[str, str]:
    """Best-effort read of a build-stage JSON object; never raises to caller."""
    try:
        proc = _run(
            [
                "podman",
                "run",
                "--rm",
                "--network=none",
                "--entrypoint",
                "cat",
                image_ref,
                path,
            ],
            timeout=60,
        )
    except Exception:  # noqa: BLE001 — measurement must proceed with {}
        return {}
    if proc.returncode != 0:
        return {}
    raw = (proc.stdout or "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, str] = {}
    for key, val in data.items():
        if isinstance(key, str) and isinstance(val, str):
            out[key] = val
    return out


def _read_installed_versions(image_ref: str) -> dict[str, str]:
    """Best-effort read of build-stage version dump; never raises to caller."""
    return _read_image_json_dict(image_ref, INSTALLED_VERSIONS_PATH)


def _read_artifact_sha256(image_ref: str) -> dict[str, str]:
    """Best-effort read of hashed install artifacts; never raises to caller."""
    return _read_image_json_dict(image_ref, ARTIFACT_SHA256_PATH)


def _reason_from_build_log(log: str, registry_type: str) -> str:
    for marker in _RESOLVE_FAIL_MARKERS:
        if f"REASON:{marker}" in log:
            return marker
    for marker in _RESOLVE_FAIL_MARKERS:
        if marker in log:
            return marker
    reason = "build_failed"
    if registry_type == "pypi" and (
        "only-binary" in log.lower()
        or "no matching distribution" in log.lower()
        or "from sources" in log.lower()
    ):
        reason = "pypi_sdist_only_or_no_binary"
    if registry_type == "npm" and (
        "missing script" in log.lower() or "cannot find module" in log.lower()
    ):
        reason = "npm_requires_scripts"
    return reason


def build_image(target: ProbeTarget) -> BuildResult:
    try:
        base = resolve_base_image(target.registry_type)
    except Exception as exc:  # noqa: BLE001 — surface as not_measured
        return BuildResult(False, None, None, str(exc), reason=f"base_pull_failed:{exc}")

    image = _image_name(target)
    try:
        df_text, argv = build_dockerfile(target, base)
    except ValueError as exc:
        return BuildResult(False, None, None, str(exc), reason=str(exc))

    with tempfile.TemporaryDirectory(prefix="aos-bp-build-") as tmp:
        tmp_path = Path(tmp)
        df_path = tmp_path / "Dockerfile"
        df_path.write_text(df_text, encoding="utf-8")
        _stage_resolve_scripts(tmp_path, target.registry_type)
        proc = _run(
            ["podman", "build", "-t", image, "-f", str(df_path), str(tmp_path)],
            timeout=BUILD_TIMEOUT_SEC,
        )
        log = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if proc.returncode != 0:
            return BuildResult(
                False, None, None, log, reason=_reason_from_build_log(log, target.registry_type)
            )

    inspect = _run(
        ["podman", "image", "inspect", image, "--format", "{{.Digest}}"],
        timeout=60,
    )
    digest = (inspect.stdout or "").strip() or None
    if target.registry_type == "npm" and "--ignore-scripts" not in df_text:
        return BuildResult(False, None, None, log, reason="missing_ignore_scripts")
    if target.registry_type == "pypi" and "--only-binary=:all:" not in df_text:
        return BuildResult(False, None, None, log, reason="missing_only_binary")

    versions = _read_installed_versions(image)
    artifacts = _read_artifact_sha256(image)
    return BuildResult(
        True,
        image,
        digest,
        log,
        server_argv=argv,
        installed_versions=versions,
        artifact_sha256=artifacts,
    )


def build_local_image(
    *,
    registry_type: str,
    identifier: str,
    fixture_dir: Path,
    image_tag: str,
) -> BuildResult:
    """Build from an in-repo fixture directory (calibration)."""
    try:
        base = resolve_base_image(registry_type)
    except Exception as exc:  # noqa: BLE001
        return BuildResult(False, None, None, str(exc), reason=f"base_pull_failed:{exc}")

    fixture_name = fixture_dir.name
    df_text, argv = build_dockerfile_from_local(
        registry_type=registry_type,
        identifier=identifier,
        fixture_dir_name=fixture_name,
        base=base,
    )
    with tempfile.TemporaryDirectory(prefix="aos-bp-cal-build-") as tmp:
        tmp_path = Path(tmp)
        dest = tmp_path / fixture_name
        shutil.copytree(fixture_dir, dest, dirs_exist_ok=True)
        df_path = tmp_path / "Dockerfile"
        df_path.write_text(df_text, encoding="utf-8")
        _stage_resolve_scripts(tmp_path, registry_type)
        proc = _run(
            ["podman", "build", "-t", image_tag, "-f", str(df_path), str(tmp_path)],
            timeout=BUILD_TIMEOUT_SEC,
        )
        log = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if proc.returncode != 0:
            return BuildResult(
                False, None, None, log, reason=_reason_from_build_log(log, registry_type)
            )

    inspect = _run(
        ["podman", "image", "inspect", image_tag, "--format", "{{.Digest}}"],
        timeout=60,
    )
    digest = (inspect.stdout or "").strip() or None
    versions = _read_installed_versions(image_tag)
    artifacts = _read_artifact_sha256(image_tag)
    return BuildResult(
        True,
        image_tag,
        digest,
        log,
        server_argv=argv,
        installed_versions=versions,
        artifact_sha256=artifacts,
    )


def dockerfile_contains_required_flags(df_text: str, registry_type: str) -> bool:
    if registry_type == "npm":
        return "--ignore-scripts" in df_text
    if registry_type == "pypi":
        return "--only-binary=:all:" in df_text
    return False
