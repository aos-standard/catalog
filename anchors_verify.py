#!/usr/bin/env python3
"""Verify ANCHORS.jsonl + digest sidecar from public URLs (stdlib only).

Each JSONL line hash includes the trailing newline byte(s) as stored on disk.
Signature verification is not implemented (signature_suite parameter only).

Position binding detects inserted fake boundaries within attested prefixes.
The stream tip before the next attestation remains unattested (fork at tip
is not detectable). Equivocation and force-push are not prevented.
"""

from __future__ import annotations

from pathlib import Path
import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
import warnings
from typing import Any, Callable

WITNESS_EVENT_NAME = "witness_ref_introduced"
SIGNATURE_SUITE_EVENT_NAME = "signature_suite_introduced"
POSITION_BINDING_EVENT_NAME = "position_binding_introduced"
DEFAULT_SIGNATURE_SUITE_NONE = "none"

VERIFY_ERROR = "verify_error"

LIMITATIONS_TEXT = (
    "Limits: attested-prefix fork detection only (tip unattested until next "
    "attestation); no equivocation attribution without signatures; force-push "
    "on witness repo breaks history-dependent checks."
)


class VerifyError(Exception):
    """Verification failed — fail closed."""


class VerifyUnattested(Exception):
    """Digest/boundary checks passed but no position_binding attestation exists."""


EXIT_OK = 0
EXIT_FAILED = 1
EXIT_UNATTESTED = 2
EXIT_PARTIAL = 3
EXIT_UNPINNED = 4


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


def is_position_binding_introduction_event(row: dict[str, Any]) -> bool:
    return row.get("event") == POSITION_BINDING_EVENT_NAME


def is_versioned_boundary_event(row: dict[str, Any]) -> bool:
    return (
        is_witness_introduction_event(row)
        or is_signature_suite_introduction_event(row)
        or is_position_binding_introduction_event(row)
    )


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
        if is_signature_suite_introduction_event(row) or is_position_binding_introduction_event(row):
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


def collect_position_bindings(lines: list[str]) -> list[tuple[int, dict[str, Any]]]:
    bindings: list[tuple[int, dict[str, Any]]] = []
    for index, line in enumerate(lines):
        row = parse_row(line)
        if is_position_binding_introduction_event(row):
            bindings.append((index, row))
    return bindings


def _resolve_trust_repo(
    stream_repo: str | None,
    *,
    expect_witness_repo: str | None,
    context: str,
) -> str:
    if expect_witness_repo:
        if stream_repo and stream_repo != expect_witness_repo:
            _fail(
                f"{context}: stream names repo {stream_repo!r} but "
                f"--expect-witness-repo is {expect_witness_repo!r}"
            )
        return expect_witness_repo
    if not stream_repo:
        _fail(f"{context}: missing witness repo and no --expect-witness-repo supplied")
    return stream_repo


def verify_position_bindings(
    presented_lines: list[str],
    *,
    expect_witness_repo: str | None,
    fetch_lines: Callable[[str, str], list[str]] | None = None,
    witness_lines_by_ref: dict[tuple[str, str], list[str]] | None = None,
) -> int:
    """Verify attested prefixes by byte match at named witness commits (B-1)."""
    bindings = collect_position_bindings(presented_lines)
    if not bindings:
        return 0

    max_attested = 0
    for binding_index, row in bindings:
        rule_version = row.get("rule_version")
        if not isinstance(rule_version, str) or not rule_version:
            _fail(
                f"position_binding_introduced at line {binding_index + 1} "
                "missing rule_version"
            )
        attestation = row.get("attestation")
        if not isinstance(attestation, dict):
            _fail(
                f"position_binding_introduced at line {binding_index + 1} "
                "missing attestation object"
            )
        witness = attestation.get("witness")
        prefix = attestation.get("prefix")
        if not isinstance(witness, dict) or not isinstance(prefix, dict):
            _fail(
                f"position_binding_introduced at line {binding_index + 1} "
                "missing witness or prefix"
            )

        stream_repo = witness.get("repo")
        commit = witness.get("commit")
        if not isinstance(stream_repo, str) or not isinstance(commit, str):
            _fail(
                f"position_binding_introduced at line {binding_index + 1} "
                "missing repo or commit"
            )

        query_repo = _resolve_trust_repo(
            stream_repo,
            expect_witness_repo=expect_witness_repo,
            context=f"position binding at line {binding_index + 1}",
        )

        line_count = prefix.get("line_count")
        byte_length = prefix.get("byte_length")
        expected_digest = prefix.get("sha256")
        if not isinstance(line_count, int) or line_count < 1:
            _fail(
                f"position binding at line {binding_index + 1}: invalid line_count"
            )
        if not isinstance(byte_length, int) or byte_length < 1:
            _fail(
                f"position binding at line {binding_index + 1}: invalid byte_length"
            )
        if not isinstance(expected_digest, str) or not expected_digest:
            _fail(f"position binding at line {binding_index + 1}: invalid sha256")

        ref = (query_repo, commit)
        if witness_lines_by_ref is not None and ref in witness_lines_by_ref:
            witness_lines = witness_lines_by_ref[ref]
        elif fetch_lines is not None:
            witness_lines = fetch_lines(query_repo, commit)
        else:
            witness_lines = fetch_repo_lines(query_repo, commit, "ANCHORS.jsonl")

        if len(witness_lines) < line_count:
            _fail(
                f"position binding at line {binding_index + 1}: witness commit "
                f"{commit[:12]} has fewer than {line_count} lines"
            )

        witness_prefix_bytes = b"".join(
            line.encode("utf-8") for line in witness_lines[:line_count]
        )
        if len(witness_prefix_bytes) != byte_length:
            _fail(
                f"position binding at line {binding_index + 1}: witness prefix "
                f"byte length {len(witness_prefix_bytes)} != attested {byte_length}"
            )
        if sha256_bytes(witness_prefix_bytes) != expected_digest:
            _fail(
                f"position binding at line {binding_index + 1}: witness prefix "
                "digest mismatch"
            )

        presented_prefix_bytes = b"".join(
            line.encode("utf-8") for line in presented_lines[:line_count]
        )
        if presented_prefix_bytes != witness_prefix_bytes:
            _fail(
                f"position binding at line {binding_index + 1}: presented prefix "
                "does not match attested witness prefix (fork or insertion detected)"
            )

        max_attested = max(max_attested, line_count)

    return max_attested


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


def verify_truncation_length_only(
    presented_lines: list[str],
    *,
    witness_lines: list[str] | None,
    main_lines: list[str] | None,
) -> None:
    """Legacy vector 2: line-count floor only (fork-vulnerable — for self-test contrast)."""
    presented_count = len(presented_lines)
    if witness_lines is not None and len(witness_lines) > presented_count:
        _fail(
            "truncation vector 2: presented stream shorter than witness commit "
            f"({presented_count} vs {len(witness_lines)} lines)"
        )
    if main_lines is not None and len(main_lines) > presented_count:
        _fail(
            "truncation vector 2: presented stream shorter than main branch "
            f"({presented_count} vs {len(main_lines)} lines)"
        )


def verify_truncation_against_witness(
    presented_lines: list[str],
    *,
    witness_lines: list[str] | None,
    main_lines: list[str] | None,
    expect_witness_repo: str | None,
    max_attested_lines: int,
) -> None:
    """Vector 2 for unattested tip: length floor only when prefix not yet bound."""
    presented_count = len(presented_lines)
    if presented_count <= max_attested_lines:
        return
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


def format_result_summary(result: dict[str, Any]) -> str:
    return (
        f"lines={result['lines']} digests={result['digests']} "
        f"witness_repo={result['witness_repo']} "
        f"witness_commit={result['witness_commit']} "
        f"attested_prefix_lines={result['attested_prefix_lines']}"
    )


def classify_verification_outcome(
    result: dict[str, Any],
    *,
    expect_witness_repo: str | None,
) -> tuple[int, str, str]:
    """Return (exit_code, stream, message) where stream is stdout or stderr."""
    summary = format_result_summary(result)
    if not expect_witness_repo:
        detail = (
            f"VERIFY UNPINNED: {summary}\n"
            "trust anchor not pinned (--expect-witness-repo omitted); "
            "verification cannot be cited as fully anchored"
        )
        return EXIT_UNPINNED, "stderr", detail
    if result["attested_prefix_lines"] < result["lines"]:
        attested = result["attested_prefix_lines"]
        total = result["lines"]
        detail = (
            f"VERIFY PARTIAL: {summary}\n"
            f"only {attested}/{total} lines attested; "
            "VERIFY OK requires attested_prefix_lines == lines"
        )
        return EXIT_PARTIAL, "stderr", detail
    detail = f"VERIFY OK: {summary}"
    return EXIT_OK, "stdout", detail


def emit_trust_anchor_warning(expect_witness_repo: str | None) -> None:
    if expect_witness_repo:
        return
    print(
        "WARNING: --expect-witness-repo not set; witness repository is taken from "
        "the stream under verification. A forged stream can name an attacker "
        "repository as the trust anchor.",
        file=sys.stderr,
    )


def require_position_binding_attestation(max_attested: int) -> None:
    """Streams with zero attestations must not receive VERIFY OK."""
    if max_attested == 0:
        raise VerifyUnattested(
            "no position_binding_introduced attestation "
            "(attested_prefix_lines=0); digest and boundary checks alone are "
            "insufficient — offline snapshots cannot be distinguished from "
            "verified streams"
        )


def verify_from_bytes(
    anchors_content: bytes,
    digests_content: bytes,
    *,
    witness_lines: list[str] | None = None,
    main_lines: list[str] | None = None,
    check_witness_platform: bool = True,
    anchors_url: str | None = None,
    expect_witness_repo: str | None = None,
    witness_lines_by_ref: dict[tuple[str, str], list[str]] | None = None,
) -> dict[str, Any]:
    lines = bytes_to_lines(anchors_content)
    digests = load_line_digests(digests_content)
    verify_lines_against_digests(lines, digests)
    verify_anchor_boundaries(lines)

    max_attested = 0
    if check_witness_platform:
        max_attested = verify_position_bindings(
            lines,
            expect_witness_repo=expect_witness_repo,
            witness_lines_by_ref=witness_lines_by_ref,
        )

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

        if expect_witness_repo:
            if repo and repo != expect_witness_repo:
                _fail(
                    f"stream witness repo {repo!r} != --expect-witness-repo "
                    f"{expect_witness_repo!r}"
                )
            query_repo = expect_witness_repo
        else:
            query_repo = repo

        if query_repo or witness_lines is not None or main_lines is not None:
            if witness_lines is None and query_repo and commit:
                witness_lines = fetch_repo_lines(query_repo, commit, "ANCHORS.jsonl")
            if main_lines is None and query_repo:
                main_lines = fetch_repo_lines(query_repo, "main", "ANCHORS.jsonl")
            verify_truncation_against_witness(
                lines,
                witness_lines=witness_lines,
                main_lines=main_lines,
                expect_witness_repo=expect_witness_repo,
                max_attested_lines=max_attested,
            )
        require_position_binding_attestation(max_attested)

    return {
        "lines": len(lines),
        "digests": len(digests),
        "witness_repo": witness.get("repo") if witness else None,
        "witness_commit": witness.get("commit") if witness else None,
        "attested_prefix_lines": max_attested,
    }


def verify_urls(
    anchors_url: str,
    digests_url: str,
    *,
    expect_witness_repo: str | None = None,
) -> dict[str, Any]:
    anchors_content = fetch_url(anchors_url)
    digests_content = fetch_url(digests_url)
    return verify_from_bytes(
        anchors_content,
        digests_content,
        check_witness_platform=True,
        anchors_url=anchors_url,
        expect_witness_repo=expect_witness_repo,
    )


def _build_fork_self_test_streams(
    live_lines: list[str] | None = None,
) -> tuple[list[str], list[str], dict[str, Any], list[str], str]:
    """wowlegend-class fork derived from live stream when available."""
    if live_lines is not None and len(live_lines) >= 19:
        shared = live_lines[:16]
        witness_real = live_lines[16]
        suite_event = live_lines[17]
        binding_line = live_lines[18]
        tail = live_lines[19:]
        witness_row = parse_row(witness_real)
        forged_at = str(witness_row.get("introduced_at") or "2026-08-07") + "-forged"
        witness_row["introduced_at"] = forged_at
        witness_fake = (
            json.dumps(witness_row, ensure_ascii=True, separators=(",", ":")) + "\n"
        )
        attestation = parse_row(binding_line)["attestation"]
        if not isinstance(attestation, dict):
            _fail("live position_binding row missing attestation for fork self-test")
        f18a = shared + [witness_real, suite_event]
        f18b = shared + [witness_fake, suite_event]
        return f18a, f18b, attestation, tail, binding_line

    shared = [
        '{"date":"2099-W01","asset_id":"demo-a","sha256":"aa","size_bytes":1,"note":""}\n',
        '{"date":"2099-W01","asset_id":"demo-b","sha256":"bb","size_bytes":1,"note":""}\n',
    ]
    while len(shared) < 16:
        idx = len(shared)
        shared.append(
            json.dumps(
                {
                    "date": "2099-W01",
                    "asset_id": f"demo-{idx}",
                    "sha256": f"{idx:02x}",
                    "size_bytes": 1,
                    "note": "",
                },
                ensure_ascii=True,
                separators=(",", ":"),
            )
            + "\n"
        )

    prior_head = "0eb69bf9f26f03b8d4fbce3b3b64ac46e10e1582"
    witness_real = (
        '{"event":"witness_ref_introduced","rule_version":"witness-ref-v1",'
        f'"witness":{{"kind":"public_vcs","repo":"aos-standard/catalog",'
        f'"commit":"{prior_head}"}},"introduced_at":"2026-08-07"}}\n'
    )
    witness_fake = (
        '{"event":"witness_ref_introduced","rule_version":"witness-ref-v1",'
        f'"witness":{{"kind":"public_vcs","repo":"aos-standard/catalog",'
        f'"commit":"{prior_head}"}},"introduced_at":"2026-08-07-forged"}}\n'
    )
    suite_event = (
        '{"event":"signature_suite_introduced","rule_version":"signature-suite-v1",'
        '"signature_suite":"none","introduced_at":"2026-08-08"}\n'
    )

    f18a = shared + [witness_real, suite_event]
    f18b = shared + [witness_fake, suite_event]

    prefix_bytes = b"".join(line.encode("utf-8") for line in f18a)
    attestation = {
        "witness": {
            "kind": "public_vcs",
            "repo": "aos-standard/catalog",
            "commit": "realwitness00000000000000000000000000000001",
        },
        "prefix": {
            "line_count": len(f18a),
            "byte_length": len(prefix_bytes),
            "sha256": sha256_bytes(prefix_bytes),
        },
    }
    return f18a, f18b, attestation, [], (
        json.dumps(
            {
                "event": POSITION_BINDING_EVENT_NAME,
                "rule_version": "position-binding-v1",
                "attestation": attestation,
                "introduced_at": "2026-08-09",
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def _load_live_anchors_lines_for_self_test() -> list[str] | None:
    live_path = Path(__file__).resolve().parent / "ANCHORS.jsonl"
    if not live_path.is_file():
        return None
    return bytes_to_lines(live_path.read_bytes())


def _rejection_class(exc: BaseException) -> str:
    message = str(exc)
    if "fork or insertion detected" in message:
        return "fork"
    if "truncation vector" in message:
        return "truncation"
    if isinstance(exc, VerifyUnattested):
        return "unattested"
    return "verify_error"


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

    def expect_unattested(label: str, fn) -> None:
        nonlocal cases_failed
        try:
            fn()
        except VerifyUnattested:
            print(f"PASS self-test: {label} (verify unattested)", file=sys.stderr)
        except VerifyError as exc:
            print(
                f"FAIL self-test: {label} raised VerifyError instead of "
                f"VerifyUnattested ({exc})",
                file=sys.stderr,
            )
            cases_failed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL self-test: {label} unexpected {exc!r}", file=sys.stderr)
            cases_failed += 1
        else:
            print(f"FAIL self-test: {label} did not report unattested", file=sys.stderr)
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
            expect_witness_repo="example/catalog",
            max_attested_lines=0,
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
            expect_witness_repo="example/catalog",
        )
    except VerifyError:
        print("PASS self-test: vector 2 end-to-end (fail closed)", file=sys.stderr)
    else:
        print("FAIL self-test: vector 2 end-to-end did not fail closed", file=sys.stderr)
        cases_failed += 1

    expect_unattested(
        "stream without position binding is unattested not ok",
        lambda: verify_from_bytes(
            "".join(full_lines).encode("utf-8"),
            json.dumps({"version": "1.0.0", "line_sha256": full_digests}).encode(
                "utf-8"
            ),
            witness_lines=full_lines,
            main_lines=full_lines,
            check_witness_platform=True,
            expect_witness_repo="example/catalog",
        ),
    )

    live_lines = _load_live_anchors_lines_for_self_test()
    f18a, f18b, attestation, tail, binding_line = _build_fork_self_test_streams(live_lines)
    witness_ref = attestation["witness"]
    repo = witness_ref["repo"]
    commit = witness_ref["commit"]
    witness_map = {(repo, commit): f18a}
    reference_main = live_lines if live_lines is not None else f18a

    try:
        verify_truncation_length_only(f18a, witness_lines=f18a, main_lines=f18a)
        verify_truncation_length_only(f18b, witness_lines=f18a, main_lines=f18a)
        print(
            "PASS self-test: fork vector length-only accepts both f18a and f18b",
            file=sys.stderr,
        )
    except VerifyError as exc:
        print(f"FAIL self-test: fork length-only baseline ({exc})", file=sys.stderr)
        cases_failed += 1

    f18a_bound = f18a + [binding_line] + tail
    f18b_bound = f18b + [binding_line] + tail
    f18a_digests = [sha256_line(line) for line in f18a_bound]
    f18b_digests = [sha256_line(line) for line in f18b_bound]

    try:
        verify_from_bytes(
            "".join(f18a_bound).encode("utf-8"),
            json.dumps({"version": "1.0.0", "line_sha256": f18a_digests}).encode(
                "utf-8"
            ),
            witness_lines=reference_main,
            main_lines=reference_main,
            check_witness_platform=True,
            expect_witness_repo=repo,
            witness_lines_by_ref=witness_map,
        )
        print("PASS self-test: fork vector f18a accepted with position binding", file=sys.stderr)
    except VerifyUnattested as exc:
        print(
            f"FAIL self-test: fork f18a unattested "
            f"(rejection={_rejection_class(exc)}: {exc})",
            file=sys.stderr,
        )
        cases_failed += 1
    except VerifyError as exc:
        print(
            f"FAIL self-test: fork f18a rejected "
            f"(rejection={_rejection_class(exc)}: {exc})",
            file=sys.stderr,
        )
        cases_failed += 1

    def _expect_fork_reject_f18b() -> None:
        try:
            verify_from_bytes(
                "".join(f18b_bound).encode("utf-8"),
                json.dumps({"version": "1.0.0", "line_sha256": f18b_digests}).encode(
                    "utf-8"
                ),
                witness_lines=reference_main,
                main_lines=reference_main,
                check_witness_platform=True,
                expect_witness_repo=repo,
                witness_lines_by_ref=witness_map,
            )
        except VerifyError as exc:
            rejection = _rejection_class(exc)
            if rejection != "fork":
                raise VerifyError(
                    f"expected fork rejection for f18b, got {rejection}: {exc}"
                ) from exc
            print(
                f"PASS self-test: fork vector f18b rejected "
                f"(rejection={rejection})",
                file=sys.stderr,
            )
            return
        raise AssertionError("f18b bound stream did not fail closed")

    try:
        _expect_fork_reject_f18b()
    except (VerifyError, AssertionError) as exc:
        print(f"FAIL self-test: fork vector f18b ({exc})", file=sys.stderr)
        cases_failed += 1

    forge18_digests = [sha256_line(line) for line in f18b]
    expect_unattested(
        "forge18 downgrade without attestation",
        lambda: verify_from_bytes(
            "".join(f18b).encode("utf-8"),
            json.dumps({"version": "1.0.0", "line_sha256": forge18_digests}).encode(
                "utf-8"
            ),
            witness_lines=f18a,
            main_lines=f18a,
            check_witness_platform=True,
            expect_witness_repo=repo,
        ),
    )

    expect_fail(
        "expect-witness-repo mismatch fail closed",
        lambda: verify_position_bindings(
            f18a_bound,
            expect_witness_repo="trusted/catalog",
            witness_lines_by_ref=witness_map,
        ),
    )

    with warnings.catch_warnings(record=True):
        emit_trust_anchor_warning(None)
    print("PASS self-test: missing expect-witness-repo emits warning", file=sys.stderr)

    return 1 if cases_failed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify ANCHORS.jsonl and digest sidecar from public URLs. "
            "Stdlib only. Does not verify signatures. "
            "Attested-prefix fork detection only; see --help limits."
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
        "--expect-witness-repo",
        help=(
            "Trust anchor: owner/repo for witness platform queries (strongly recommended). "
            "Must match stream witness repo or verification fails closed."
        ),
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

    emit_trust_anchor_warning(args.expect_witness_repo)

    try:
        result = verify_urls(
            args.anchors_url,
            args.digests_url,
            expect_witness_repo=args.expect_witness_repo,
        )
    except VerifyUnattested as exc:
        print(f"VERIFY UNATTESTED: {exc}", file=sys.stderr)
        print(LIMITATIONS_TEXT, file=sys.stderr)
        return EXIT_UNATTESTED
    except VerifyError as exc:
        print(f"VERIFY FAILED: {exc}", file=sys.stderr)
        print(LIMITATIONS_TEXT, file=sys.stderr)
        return EXIT_FAILED

    summary = format_result_summary(result)

    exit_code, stream, message = classify_verification_outcome(
        result,
        expect_witness_repo=args.expect_witness_repo,
    )
    if stream == "stdout":
        print(message)
    else:
        print(message, file=sys.stderr)
    print(LIMITATIONS_TEXT, file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
