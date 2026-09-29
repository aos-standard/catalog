"""Fixed digests, timeouts, and verdict vocabulary for behavior probe phase 1."""

from __future__ import annotations

# Verdict vocabulary only. Do not add verified/compliant/safe.
VERDICT_CLAIM_CONTRADICTED = "claim_contradicted"
VERDICT_NOT_CONTRADICTED = "not_contradicted_within_coverage"
VERDICT_NOT_MEASURED = "not_measured"

VERDICTS = frozenset(
    {
        VERDICT_CLAIM_CONTRADICTED,
        VERDICT_NOT_CONTRADICTED,
        VERDICT_NOT_MEASURED,
    }
)

FORBIDDEN_OUTPUT_WORDS = frozenset({"verified", "compliant", "safe"})
# Matching is word-boundary only, and only on authored fields — see report.py
# THIRD_PARTY_ROW_KEYS (claim / tools[].description / server_stderr_head / …).

# Sub-reasons under not_measured_reason=initialize_failed (stderr-only taxonomy).
START_FAILED_DEPENDENCY_INCOMPATIBLE = "start_failed_dependency_incompatible"
START_FAILED_ENTRYPOINT_NOT_MCP = "start_failed_entrypoint_not_mcp"
START_FAILED_OTHER = "start_failed_other"
START_FAILED_STDERR_UNAVAILABLE = "start_failed_stderr_unavailable"

START_FAILED_REASONS = frozenset(
    {
        START_FAILED_DEPENDENCY_INCOMPATIBLE,
        START_FAILED_ENTRYPOINT_NOT_MCP,
        START_FAILED_OTHER,
        START_FAILED_STDERR_UNAVAILABLE,
    }
)

# stderr_capture — did we actually read the process pipe?
STDERR_CAPTURE_CAPTURED = "captured"
STDERR_CAPTURE_EMPTY = "empty"
STDERR_CAPTURE_UNAVAILABLE = "unavailable"
STDERR_CAPTURE_VALUES = frozenset(
    {
        STDERR_CAPTURE_CAPTURED,
        STDERR_CAPTURE_EMPTY,
        STDERR_CAPTURE_UNAVAILABLE,
    }
)
STDERR_DRAIN_AFTER_EXIT_SEC = 5.0

METHOD_VERSION = "2026-08-16.1"
EXPECTED_OFFLINE_TOTAL = 27
EXPECTED_BY_REGISTRY: dict[str, int] = {
    "npm": 14,
    "pypi": 9,
    "mcpb": 2,
    "nuget": 1,
    "cargo": 1,
}
MEASURED_REGISTRY_TYPES = frozenset({"npm", "pypi"})
EXCLUDED_REGISTRY_TYPES = frozenset({"mcpb", "nuget", "cargo"})

# Base image tags; build.resolve_base_image() pins to digest after first pull.
NODE_BASE_TAG = "docker.io/library/node:20-bookworm-slim"
PYTHON_BASE_TAG = "docker.io/library/python:3.12-slim-bookworm"

BUILD_TIMEOUT_SEC = 300
RUN_TIMEOUT_SEC = 120
TOOL_CALL_TIMEOUT_SEC = 20
MEMORY_LIMIT = "2g"
CPUS = "2"
PIDS_LIMIT = "256"

STRACE_FILTER = "network,execve,openat,unlink,rename"

# Positive-control DNS name (entrypoint selftest). Exclude from dns_query counts/judge only.
DNS_SELFTEST_QNAME = "aos-bp-selftest.invalid"
DNS_RECORDER_NOT_RECORDING = "dns_recorder_not_recording"

JSONRPC_INVALID_PARAMS = -32602
