"""Verdict assignment — published vocabulary only.

Phase-1 rule: claim_contradicted only when unprompted_network
(startup / tools_list) has >=1 attempt. Tool-invoked network is recorded
for humans and does not change the verdict.
"""

from __future__ import annotations

from typing import Any

from services.behavior_probe.constants import (
    VERDICT_CLAIM_CONTRADICTED,
    VERDICT_NOT_CONTRADICTED,
    VERDICT_NOT_MEASURED,
)
from services.behavior_probe.strace_parse import ParseResult, partition_network_evidence


def judge(
    *,
    measured: bool,
    not_measured_reason: str | None,
    parsed: ParseResult | None,
    tools: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not measured:
        return {
            "verdict": VERDICT_NOT_MEASURED,
            "not_measured_reason": not_measured_reason or "not_measured",
            "network_attempt_count": 0,
            "tool_invoked_network_present": False,
        }
    if parsed is None:
        return {
            "verdict": VERDICT_NOT_MEASURED,
            "not_measured_reason": not_measured_reason or "no_strace",
            "network_attempt_count": 0,
            "tool_invoked_network_present": False,
        }
    partitioned = partition_network_evidence(parsed, tools)
    count = int(partitioned["unprompted_count"])
    present = bool(partitioned["tool_invoked_network_present"])
    if count >= 1:
        return {
            "verdict": VERDICT_CLAIM_CONTRADICTED,
            "not_measured_reason": None,
            "network_attempt_count": count,
            "tool_invoked_network_present": present,
            "unprompted_network": partitioned["unprompted_network"],
            "tool_invoked_network": partitioned["tool_invoked_network"],
        }
    return {
        "verdict": VERDICT_NOT_CONTRADICTED,
        "not_measured_reason": None,
        "network_attempt_count": 0,
        "tool_invoked_network_present": present,
        "unprompted_network": partitioned["unprompted_network"],
        "tool_invoked_network": partitioned["tool_invoked_network"],
    }
