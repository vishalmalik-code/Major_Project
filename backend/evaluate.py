#!/usr/bin/env python3
"""LLM Extraction Firewall -- Evaluation Runner.

Runs the full battery: all 5 attack strategies x {fast, slow} and all 5
normal-user personas x {fast, slow} -- 20 sessions -- entirely through the
real POST /api/chat endpoint (same path as attacker.py, normal_user.py, and
a real browser). Computes detection-rate / false-positive-rate metrics and
writes a comparison report.

This script does NOT modify firewall weights, thresholds, or any detection
logic -- it only measures how the firewall currently performs.

Usage:

    python evaluate.py
    python evaluate.py --attacker-count 10 --normal-count 10 --seed 2024
    python evaluate.py --fast-delay 0.3 --slow-min-delay 3 --slow-max-delay 6
"""

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from evaluation.report import build_report
from evaluation.runner import run_one_session, save_result
from evaluation.sessions import build_battery


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--seed", type=int, default=2024,
                   help="Base seed; every session's seed is derived from "
                        "this + its label, so the whole battery is "
                        "reproducible from one number (default: 2024).")
    p.add_argument("--attacker-count", type=int, default=10,
                   help="Queries per attack session (default: 10).")
    p.add_argument("--normal-count", type=int, default=10,
                   help="Queries per normal-user session (default: 10).")
    p.add_argument("--target", type=str, default="http://localhost:8000")
    p.add_argument("--fast-delay", type=float, default=0.3)
    p.add_argument("--slow-min-delay", type=float, default=3.0,
                   help="Reduced from the CLI's real-world default (5s) to "
                        "keep total evaluation wall-clock time reasonable "
                        "-- still clearly slower than FAST, still tests the "
                        "same 'burst_rate contributes ~0' condition.")
    p.add_argument("--slow-max-delay", type=float, default=6.0)
    p.add_argument("--out-dir", type=str, default="evaluation_results")
    p.add_argument("--only", choices=["attacker", "normal_user"], default=None,
                   help="Run only one session type (for partial/faster runs).")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    run_tag = uuid.uuid4().hex[:6]   # short: embedded in every client_id (64-char API limit)
    run_id = f"eval-{datetime.now(timezone.utc):%Y%m%dT%H%M%S}-{run_tag}"
    out_dir = Path(args.out_dir) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    results_jsonl = out_dir / "results.jsonl"

    battery = build_battery(args.seed, args.attacker_count, args.normal_count, run_tag)
    if args.only:
        battery = [s for s in battery if s.session_type == args.only]

    print(f"Run ID: {run_id}")
    print(f"Sessions to run: {len(battery)}")
    print(f"Output: {out_dir}\n")

    log_dir_attacker = f"attacker_logs/{run_id}"
    log_dir_user = f"normal_user_logs/{run_id}"

    results = []
    for i, spec in enumerate(battery, start=1):
        print(f"\n[{i}/{len(battery)}] ", end="")
        log_dir = log_dir_attacker if spec.session_type == "attacker" else log_dir_user
        result = run_one_session(
            spec, run_id=run_id, target=args.target, log_dir=log_dir,
            fast_delay=args.fast_delay, slow_min=args.slow_min_delay,
            slow_max=args.slow_max_delay, verbose=True,
        )
        save_result(result, str(results_jsonl))
        results.append(_result_to_dict(result))

    finished_at = datetime.now(timezone.utc).isoformat()
    meta = {"run_id": run_id, "base_seed": args.seed, "target": args.target,
           "finished_at": finished_at, "attacker_count": args.attacker_count,
           "normal_count": args.normal_count}
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2))

    report_md = build_report(results, meta)
    report_path = out_dir / "report.md"
    report_path.write_text(report_md)

    print("\n\n" + "=" * 70)
    print(report_md)
    print("=" * 70)
    print(f"\nFull results: {results_jsonl}")
    print(f"Report:       {report_path}")

    return 0


def _result_to_dict(result) -> dict:
    from dataclasses import asdict
    return asdict(result)


if __name__ == "__main__":
    sys.exit(main())
