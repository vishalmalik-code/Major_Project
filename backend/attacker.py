#!/usr/bin/env python3
"""LLM Extraction Firewall -- Attacker Simulator CLI.

A standalone tool that behaves like an external attacker: it knows a
client_id, a target API base URL, an attack strategy, and its own generated
queries -- nothing else. Every query goes over real HTTP to POST /api/chat,
the exact same endpoint a normal user's browser calls. There is no shortcut
to the LLM and no access to the firewall's internal risk state, thresholds,
or query window.

    Attacker  --HTTP POST /api/chat-->  Firewall  -->  LLM      (correct)
    Attacker  ------------------------------------->  LLM      (never happens)

Examples:

    python attacker.py --list-strategies

    python attacker.py --strategy repetition --mode fast
    python attacker.py --strategy repetition --mode slow
    python attacker.py --strategy minimal_modification --mode fast
    python attacker.py --strategy value_sweep --mode slow --count 15
    python attacker.py --strategy output_constraint --mode fast --delay 0.5
    python attacker.py --strategy boundary --mode slow --min-delay 3 --max-delay 8

    python attacker.py --strategy value_sweep --mode fast --base-topic jwt
    python attacker.py --strategy repetition --mode fast --client-id my-test-1
"""

import argparse
import sys

from app.attacker.registry import CLI_ALIASES as CLI_STRATEGY_ALIASES
from app.attacker.registry import STRATEGIES, get as get_strategy
from attacker_cli.client_id import next_client_id
from attacker_cli.pacing import FastPacer, SlowPacer
from attacker_cli.runner import run_attack

# CLI-facing strategy names (matching the prompt's examples), mapped to the
# internal registry ids used by app.attacker. Shared with the attacker-console
# web UI's SSE endpoint via app.attacker.registry.CLI_ALIASES, so the mapping
# exists in exactly one place.


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Attacker simulator for the LLM Extraction Firewall. "
                    "Sends generated queries to POST /api/chat over real "
                    "HTTP, exactly like a normal client.",
    )
    parser.add_argument("--list-strategies", action="store_true",
                        help="List the five attack strategies and exit.")
    parser.add_argument("--strategy", choices=sorted(CLI_STRATEGY_ALIASES),
                        help="Which attack pattern to run.")
    parser.add_argument("--mode", choices=["fast", "slow"],
                        help="Pacing mode. The query sequence is identical "
                             "in both modes -- only timing changes.")
    parser.add_argument("--count", type=int, default=20,
                        help="Number of queries to send (default: 20).")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducible query generation.")
    parser.add_argument("--base-topic", type=str, default=None,
                        help="Optional keyword (e.g. 'jwt', 'xss') to steer "
                             "which template the strategy builds around.")
    parser.add_argument("--client-id", type=str, default=None,
                        help="Client id to use. Auto-generated as "
                             "attacker-<strategy>-<mode>-NNN if omitted.")
    parser.add_argument("--target", type=str, default="http://localhost:8000",
                        help="Base URL of the firewall API "
                             "(default: http://localhost:8000).")

    # Fast mode pacing
    parser.add_argument("--delay", type=float, default=0.3,
                        help="FAST mode: base delay in seconds between "
                             "queries, suggested range 0.1-1.0 (default: 0.3).")

    # Slow mode pacing
    parser.add_argument("--min-delay", type=float, default=5.0,
                        help="SLOW mode: minimum delay in seconds "
                             "(default: 5.0).")
    parser.add_argument("--max-delay", type=float, default=15.0,
                        help="SLOW mode: maximum delay in seconds "
                             "(default: 15.0).")

    parser.add_argument("--on-block", choices=["continue", "stop"], default="continue",
                        help="What to do after the firewall returns BLOCK: "
                             "'continue' keeps sending the remaining planned "
                             "queries (still BLOCKed, still logged), 'stop' "
                             "ends the run immediately. Default: continue.")
    parser.add_argument("--log-dir", type=str, default="attacker_logs",
                        help="Directory to write the run's log file into "
                             "(default: attacker_logs/).")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress per-query console output.")

    return parser


def print_strategies() -> None:
    print("Available attack strategies:\n")
    for cli_name, internal_id in CLI_STRATEGY_ALIASES.items():
        strat = STRATEGIES[internal_id]
        print(f"  {cli_name}")
        print(f"    name:        {strat.name}")
        print(f"    description: {strat.description}")
        print(f"    targets:     {', '.join(strat.targets)}")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_strategies:
        print_strategies()
        return 0

    if not args.strategy or not args.mode:
        parser.error("--strategy and --mode are required "
                     "(or use --list-strategies)")

    internal_id = CLI_STRATEGY_ALIASES[args.strategy]
    strategy = get_strategy(internal_id)

    client_id = args.client_id or next_client_id(args.strategy, args.mode)

    queries = strategy.generate(args.count, seed=args.seed, topic=args.base_topic)

    if args.mode == "fast":
        pacer = FastPacer(delay=args.delay)
    else:
        pacer = SlowPacer(min_delay=args.min_delay, max_delay=args.max_delay)

    print(f"Strategy:   {strategy.name} ({args.strategy})")
    print(f"Mode:       {args.mode}")
    print(f"Client ID:  {client_id}")
    print(f"Target:     {args.target}")
    print(f"Count:      {len(queries)}")
    print(f"On block:   {args.on_block}")
    print()

    outcome = run_attack(
        strategy_id=internal_id, strategy_name=strategy.name, queries=queries,
        mode=args.mode, pacer=pacer, client_id=client_id, target=args.target,
        log_dir=args.log_dir, on_block=args.on_block, verbose=not args.quiet,
    )

    print()
    print(f"Done. Sent {outcome.total_sent}/{len(queries)} queries"
         f"{' (stopped early)' if outcome.stopped_early else ''}.")
    print(f"Log:     {outcome.log_path}")
    print(f"Summary: {outcome.summary_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
