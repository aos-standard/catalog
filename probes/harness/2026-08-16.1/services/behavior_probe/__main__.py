"""Entry: ``python -m services.behavior_probe --only <name-or-identifier>``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m services.behavior_probe",
        description=(
            "Observe registry servers that claim local-only / no-network behavior."
        ),
    )
    parser.add_argument(
        "--only",
        help="Limit to one server name or package identifier.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Upper bound on measured (npm/pypi) servers.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Parallel workers (default 1).",
    )
    parser.add_argument(
        "--run-tag",
        dest="run_tag",
        help="Suffix for BEHAVIOR_PROBE_<YYYYMMDD>_<TAG> report names.",
    )
    parser.add_argument(
        "--census-dir",
        type=Path,
        dest="census_dir",
        help="Directory that contains registry_capability_census.py and the snapshot.",
    )
    parser.add_argument(
        "--snapshot",
        type=Path,
        dest="snapshot",
        help="registry_YYYY-MM-DD.jsonl.gz path (default: <census-dir>/registry_2026-08-16.jsonl.gz).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        dest="out_dir",
        default=None,
        help="Directory that receives docs/reports/ (default: current working directory).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    from services.behavior_probe.calibrate import InstrumentContaminatedError
    from services.behavior_probe.env import CgroupControllerMissingError, PodmanMissingError
    from services.behavior_probe.orchestrator import run_behavior_probe
    from services.behavior_probe.report import ForbiddenOutputError
    from services.behavior_probe.targets import CountMismatchError

    out_dir = (args.out_dir or Path.cwd()).resolve()
    try:
        summary = run_behavior_probe(
            out_dir,
            limit=args.limit,
            only=args.only,
            concurrency=args.concurrency if args.concurrency else 1,
            snapshot_path=args.snapshot,
            census_dir=args.census_dir,
            run_tag=args.run_tag,
        )
    except InstrumentContaminatedError as exc:
        print(f"behavior-probe (stop): {exc}", file=sys.stderr)
        if getattr(exc, "report", None) is not None:
            print(
                json.dumps(exc.report.as_dict(), ensure_ascii=False, indent=2),
                file=sys.stderr,
            )
        return 5
    except PodmanMissingError as exc:
        print(f"behavior-probe (stop): {exc}", file=sys.stderr)
        return 3
    except CgroupControllerMissingError as exc:
        print(f"behavior-probe (stop): {exc}", file=sys.stderr)
        return 4
    except CountMismatchError as exc:
        print(f"behavior-probe count mismatch (stop): {exc}", file=sys.stderr)
        return 2
    except ForbiddenOutputError as exc:
        print(f"behavior-probe: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"behavior-probe: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
