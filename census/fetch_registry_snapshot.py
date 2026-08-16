#!/usr/bin/env python3
"""Fetch the official MCP registry snapshot (cursor-paged JSON array).

Output is a single JSON file whose top-level value is a list of server records
(one row per published version). Downstream tooling deduplicates by server name.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0/servers?limit=100"


def fetch_all(*, timeout: float = 30.0, progress_every: int = 20) -> list[dict]:
    out: list[dict] = []
    cursor: str | None = None
    pages = 0
    while True:
        url = REGISTRY_URL + (f"&cursor={cursor}" if cursor else "")
        last_error: Exception | None = None
        payload: dict | None = None
        for attempt in range(3):
            try:
                with urllib.request.urlopen(url, timeout=timeout) as response:
                    payload = json.load(response)
                break
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt == 2:
                    raise
        if payload is None:
            raise RuntimeError(f"fetch failed: {last_error}")
        out.extend(payload.get("servers", []))
        pages += 1
        if progress_every and pages % progress_every == 0:
            print(f"pages={pages} records={len(out)}", file=sys.stderr, flush=True)
        cursor = (payload.get("metadata") or {}).get("nextCursor")
        if not cursor:
            break
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch MCP registry snapshot to JSON.")
    parser.add_argument(
        "-o",
        "--output",
        default="registry_full.json",
        help="Output path (default: registry_full.json)",
    )
    args = parser.parse_args()
    records = fetch_all()
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(records, handle, ensure_ascii=False)
    print(f"DONE records={len(records)} -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
