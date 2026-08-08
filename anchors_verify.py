#!/usr/bin/env python3
"""Verify ANCHORS.jsonl + digest sidecar from public URLs (stdlib only).

Each JSONL line hash includes the trailing newline byte(s) as stored on disk.
Signature verification is not implemented (signature_suite parameter only).
Truncation detection (vectors 1 and 2) holds only while witness platform
history has not been rewritten (e.g. force-push on the witness repository).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from typing import Any

WITNESS_EVENT_NAME = "witness_ref_introduced"
SIGNATURE_SUITE_EVENT_NAME = "signature_suite_introduced"
DEFAULT_SIGNATURE_SUITE_NONE = "none"

VERIFY_ERROR = "verify_error"


class VerifyError(Exception):
    """Verification failed — fail closed."""


def _fail(message: str) -> None:
    raise VerifyError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_line(line: str) -> str:
    return sha256_bytes(line.encode("utf-8"))


def fetch_url(url: str, *, timeout: float = 60.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "aos-anchors-verify/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        _fail(f"HTTP {exc.code} fetching {url}")
    except urllib.error.URLError as exc:
        _fail(f"network error fetching {url}: {exc.reason}")
    raise AssertionError("unreachable")


def bytes_to_lines(content: bytes) -> list[str]:
    text = content.decode("utf-8")
    lines: list[str] = []
    for raw in text.splitlines(keepends=True):
        if raw.endswith("\n"):
            lines.append(raw)
        elif raw.strip():
            lines.append(raw + "\n")
    if text and not text.endswith("\n") and not lines:
        lines.append(text + "\n")
    return lines


def parse_row(line: str) -> dict[str, Any]:
    stripped = line.strip()
    if not stripped:
        _fail("empty anchor line")
    try:
        row = json.loads(stripped)
    except json.JSONDecodeError as exc:
        _fail(f"invalid JSONL line: {exc}")
    if not isinstance(row, dict):
        _fail("anchor line must be a JSON object")
    return row


def is_witness_introduction_event(row: dict[str, Any]) -> bool:
    return row.get("event") == WITNESS_EVENT_NAME


def is_signature_suite_introduction_event(row: dict[str, Any]) -> bool:
    return row.get("event") == SIGNATURE_SUITE_EVENT_NAME


def is_versioned_boundary_event(row: dict[str, Any]) -> bool:
    return is_witness_introduction_event(row) or is_signature_suite_introduction_event(row)


def is_anchor_record(row: dict[str, Any]) -> bool:
    return isinstance(row.get("asset_id"), str) and "event" not in row


def load_active_witness(lines: list[str]) -> dict[str, Any] | None:
    witness: dict[str, Any] | None = None
    for line in lines:
        row = parse_row(line)
        if not is_witness_introduction_event(row):
            continue
        if witness is not None:
            _fail("multiple witness_ref_introduced events")
        candidate = row.get("witness")
        if not isinstance(candidate, dict):
            _fail("witness_ref_introduced event missing witness object")
        rule_version = row.get("rule_version")
        if not isinstance(rule_version, str) or not rule_version:
            _fail("witness_ref_introduced event missing rule_version")
        witness = candidate
    return witness


def witness_record_matches_active(record_witness: Any, active_witness: dict[str, Any]) -> bool:
    if not isinstance(record_witness, dict):
        return False
    for key in ("kind", "repo", "commit"):
        if record_witness.get(key) != active_witness.get(key):
            return False
    return True


def verify_witness_boundary(lines: list[str]) -> None:
    boundary_index: int | None = None
    active_witness: dict[str, Any] | None = None
    for index, line in enumerate(lines):
        row = parse_row(line)
        if is_witness_introduction_event(row):
            if boundary_index is not None:
                _fail("multiple witness_ref_introduced events")
            boundary_index = index
            active_witness = load_active_witness(lines)
            continue
        if is_signature_suite_introduction_event(row):
            continue
        if "event" in row:
            _fail(f"unknown event at line {index + 1}")
        if not is_anchor_record(row):
            _fail(f"unrecognized record at line {index + 1}")

        has_witness = "witness" in row
        if boundary_index is None:
            if has_witness:
                _fail(f"witness before introduction at line {index + 1}")
            continue
        if index < boundary_index:
            if has_witness:
                _fail(f"witness before introduction at line {index + 1}")
        elif index > boundary_index:
            if not has_witness:
                _fail(f"missing witness after introduction at line {index + 1}")
            if active_witness is None or not witness_record_matches_active(
                row.get("witness"), active_witness
            ):
                _fail(f"witness mismatch at line {index + 1}")


def load_active_signature_suite(lines: list[str]) -> str | None:
    suite: str | None = None
    for line in lines:
        row = parse_row(line)
        if not is_signature_suite_introduction_event(row):
            continue
        if suite is not None:
            _fail("multiple signature_suite_introduced events")
        rule_version = row.get("rule_version")
        if not isinstance(rule_version, str) or not rule_version:
            _fail("signature_suite_introduced event missing rule_version")
        candidate = row.get("signature_suite")
        if not isinstance(candidate, str) or not candidate:
            _fail("signature_suite_introduced event missing signature_suite")
        suite = candidate
    return suite


def verify_signature_suite_boundary(lines: list[str]) -> None:
    boundary_index: int | None = None
    active_suite: str | None = None
    for index, line in enumerate(lines):
        row = parse_row(line)
        if is_versioned_boundary_event(row):
            if is_signature_suite_introduction_event(row):
                if boundary_index is not None:
                    _fail("multiple signature_suite_introduced events")
                boundary_index = index
                active_suite = load_active_signature_suite(lines)
            continue
        if "event" in row:
            _fail(f"unknown event at line {index + 1}")
        if not is_anchor_record(row):
            _fail(f"unrecognized record at line {index + 1}")

        has_suite = "signature_suite" in row
        if boundary_index is None:
            if has_suite:
                _fail(f"signature_suite before introduction at line {index + 1}")
            continue
        if index < boundary_index:
            if has_suite:
                _fail(f"signature_suite before introduction at line {index + 1}")
        elif index > boundary_index:
            if not has_suite:
                _fail(f"missing signature_suite after introduction at line {index + 1}")
            if active_suite is None or row.get("signature_suite") != active_suite:
                _fail(f"signature_suite mismatch at line {index + 1}")


def verify_anchor_boundaries(lines: list[str]) -> None:
    verify_witness_boundary(lines)
    verify_signature_suite_boundary(lines)


def load_line_digests(content: bytes) -> list[str]:
    try:
        data = json.loads(content.decode("utf-8"))
    except json.JSONDecodeError as exc:
        _fail(f"invalid digest sidecar JSON: {exc}")
    if not isinstance(data, dict):
        _fail("digest sidecar must be a JSON object")
    digests = data.get("line_sha256")
    if not isinstance(digests, list):
        _fail("digest sidecar missing line_sha256 list")
    return [str(item) for item in digests]


def verify_lines_against_digests(lines: list[str], digests: list[str]) -> None:
    """Vector 1: records-only truncation while sidecar retains prior digests."""
    if len(digests) > len(lines):
        _fail(
            "truncation vector 1: fewer anchor lines than digest sidecar "
            "(append-only violation)"
        )
    for index, expected in enumerate(digests):
        actual = sha256_line(lines[index])
        if actual != expected:
            _fail(f"digest mismatch at line {index + 1}")


def repo_from_raw_github_url(url: str) -> str | None:
    prefix = "https://raw.githubusercontent.com/"
    if not url.startswith(prefix):
        return None
    rest = url[len(prefix) :]
    parts = rest.split("/", 2)
    if len(parts) < 2:
        return None
    return f"{parts[0]}/{parts[1]}"


def raw_github_url(repo: str, ref: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{ref}/{path}"


def fetch_repo_lines(repo: str, ref: str, path: str) -> list[str]:
    url = raw_github_url(repo, ref, path)
    return bytes_to_lines(fetch_url(url))


def verify_truncation_against_witness(
    presented_lines: list[str],
    *,
    witness_lines: list[str] | None,
    main_lines: list[str] | None,
) -> None:
    """Vector 2: both records and sidecar truncated but internally consistent.

    Detected by comparing line counts to witness platform snapshots.
    Broken if witness history is rewritten (e.g. force-push).
    """
    presented_count = len(presented_lines)
    if witness_lines is not None and len(witness_lines) > presented_count:
        _fail(
            "truncation vector 2: presented stream shorter than witness commit "
            f"({presented_count} vs {len(witness_lines)} lines); "
            "detection assumes witness platform history has not been rewritten"
        )
    if main_lines is not None and len(main_lines) > presented_count:
        _fail(
            "truncation vector 2: presented stream shorter than main branch "
            f"({presented_count} vs {len(main_lines)} lines); "
            "detection assumes witness platform history has not been rewritten"
        )


def verify_from_bytes(
    anchors_content: bytes,
    digests_content: bytes,
    *,
    witness_lines: list[str] | None = None,
    main_lines: list[str] | None = None,
    check_witness_platform: bool = True,
    anchors_url: str | None = None,
) -> dict[str, Any]:
    lines = bytes_to_lines(anchors_content)
    digests = load_line_digests(digests_content)
    verify_lines_against_digests(lines, digests)
    verify_anchor_boundaries(lines)

    witness = load_active_witness(lines)
    if check_witness_platform:
        repo: str | None = None
        commit: str | None = None
        if witness is not None:
            repo_val = witness.get("repo")
            commit_val = witness.get("commit")
            if isinstance(repo_val, str) and isinstance(commit_val, str):
                repo, commit = repo_val, commit_val
            else:
                _fail("active witness missing repo or commit")
        elif anchors_url:
            repo = repo_from_raw_github_url(anchors_url)

        if repo or witness_lines is not None or main_lines is not None:
            if witness_lines is None and repo and commit:
                witness_lines = fetch_repo_lines(repo, commit, "ANCHORS.jsonl")
            if main_lines is None and repo:
                main_lines = fetch_repo_lines(repo, "main", "ANCHORS.jsonl")
            verify_truncation_against_witness(
                lines,
                witness_lines=witness_lines,
                main_lines=main_lines,
            )

    return {
        "lines": len(lines),
        "digests": len(digests),
        "witness_repo": witness.get("repo") if witness else None,
        "witness_commit": witness.get("commit") if witness else None,
    }


def verify_urls(anchors_url: str, digests_url: str) -> dict[str, Any]:
    anchors_content = fetch_url(anchors_url)
    digests_content = fetch_url(digests_url)
    return verify_from_bytes(
        anchors_content,
        digests_content,
        check_witness_platform=True,
        anchors_url=anchors_url,
    )


def run_self_test() -> int:
    """Adversarial vectors must fail closed; valid minimal stream must pass."""
    cases_failed = 0

    def expect_fail(label: str, fn) -> None:
        nonlocal cases_failed
        try:
            fn()
        except VerifyError:
            print(f"PASS self-test: {label} (fail closed)", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL self-test: {label} unexpected {exc!r}", file=sys.stderr)
            cases_failed += 1
        else:
            print(f"FAIL self-test: {label} did not fail closed", file=sys.stderr)
            cases_failed += 1

    line_a = '{"date":"2099-W01","asset_id":"demo-a","sha256":"aa","size_bytes":1,"note":""}\n'
    line_b = '{"date":"2099-W01","asset_id":"demo-b","sha256":"bb","size_bytes":1,"note":""}\n'
    witness_event = (
        '{"event":"witness_ref_introduced","rule_version":"witness-ref-v1",'
        '"witness":{"kind":"public_vcs","repo":"example/catalog",'
        '"commit":"abc123"},"introduced_at":"2099-01-01"}\n'
    )
    suite_event = (
        '{"event":"signature_suite_introduced","rule_version":"signature-suite-v1",'
        '"signature_suite":"none","introduced_at":"2099-01-02"}\n'
    )
    line_c = (
        '{"date":"2099-W02","asset_id":"demo-c","sha256":"cc","size_bytes":1,"note":"",'
        '"witness":{"kind":"public_vcs","repo":"example/catalog","commit":"abc123"},'
        '"signature_suite":"none"}\n'
    )

    full_lines = [line_a, line_b, witness_event, suite_event, line_c]
    full_digests = [sha256_line(line) for line in full_lines]

    expect_fail(
        "vector 1 records-only truncation",
        lambda: verify_lines_against_digests(full_lines[:2], full_digests),
    )

    truncated = full_lines[:4]
    truncated_digests = [sha256_line(line) for line in truncated]
    long_witness = full_lines + [line_c]

    expect_fail(
        "vector 2 both truncated vs witness reference",
        lambda: verify_truncation_against_witness(
            truncated,
            witness_lines=long_witness,
            main_lines=long_witness,
        ),
    )

    try:
        verify_from_bytes(
            "".join(truncated).encode("utf-8"),
            json.dumps({"version": "1.0.0", "line_sha256": truncated_digests}).encode(
                "utf-8"
            ),
            witness_lines=long_witness,
            main_lines=long_witness,
            check_witness_platform=True,
        )
    except VerifyError:
        print("PASS self-test: vector 2 end-to-end (fail closed)", file=sys.stderr)
    else:
        print("FAIL self-test: vector 2 end-to-end did not fail closed", file=sys.stderr)
        cases_failed += 1

    try:
        result = verify_from_bytes(
            "".join(full_lines).encode("utf-8"),
            json.dumps({"version": "1.0.0", "line_sha256": full_digests}).encode(
                "utf-8"
            ),
            witness_lines=full_lines,
            main_lines=full_lines,
            check_witness_platform=True,
        )
    except VerifyError as exc:
        print(f"FAIL self-test: valid stream rejected ({exc})", file=sys.stderr)
        cases_failed += 1
    else:
        print(
            f"PASS self-test: valid stream accepted ({result['lines']} lines)",
            file=sys.stderr,
        )

    return 1 if cases_failed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify ANCHORS.jsonl and digest sidecar from public URLs. "
            "Stdlib only. Does not verify signatures. "
            "Truncation detection depends on witness platform history integrity."
        ),
    )
    parser.add_argument(
        "--anchors-url",
        help="HTTPS URL to ANCHORS.jsonl (e.g. raw.githubusercontent.com/.../ANCHORS.jsonl)",
    )
    parser.add_argument(
        "--digests-url",
        help="HTTPS URL to ANCHORS.jsonl.digests.json",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in adversarial vectors (no network)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    if not args.anchors_url or not args.digests_url:
        parser.error("--anchors-url and --digests-url are required unless --self-test")

    try:
        result = verify_urls(args.anchors_url, args.digests_url)
    except VerifyError as exc:
        print(f"VERIFY FAILED: {exc}", file=sys.stderr)
        return 1

    print(
        "VERIFY OK: "
        f"lines={result['lines']} digests={result['digests']} "
        f"witness_repo={result['witness_repo']} witness_commit={result['witness_commit']}"
    )
    print(
        "Note: truncation checks assume witness platform history has not been rewritten.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
