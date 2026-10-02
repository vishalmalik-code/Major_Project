#!/usr/bin/env python3
"""LLM Extraction Firewall -- Normal User Simulator CLI.

Behaves like a legitimate user across five realistic personas (casual_user,
student, developer, researcher, incident_responder). Every query goes over
real HTTP to POST /api/chat, exactly like the attacker CLI and a real
browser -- there is no internal shortcut here either.

Examples:

    python normal_user.py --list-personas

    python normal_user.py --persona student --mode slow
    python normal_user.py --persona developer --mode fast --base-topic auth
    python normal_user.py --persona incident_responder --mode fast --count 6
"""

import argparse
import sys

from attacker_cli.pacing import FastPacer, SlowPacer
from normal_user_cli.registry import PERSONAS, get as get_persona
from normal_user_cli.runner import run_session


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Normal-user simulator for the LLM Extraction Firewall. "
                    "Sends persona-driven queries to POST /api/chat over "
                    "real HTTP, exactly like a real user.",
    )
    parser.add_argument("--list-personas", action="store_true")
    parser.add_argument("--persona", choices=sorted(PERSONAS))
    parser.add_argument("--mode", choices=["fast", "slow"])
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--base-topic", type=str, default=None)
    parser.add_argument("--client-id", type=str, default=None)
    parser.add_argument("--target", type=str, default="http://localhost:8000")
    parser.add_argument("--delay", type=float, default=0.3,
                        help="FAST mode base delay (default 0.3).")
    parser.add_argument("--min-delay", type=float, default=5.0)
    parser.add_argument("--max-delay", type=float, default=15.0)
    parser.add_argument("--log-dir", type=str, default="normal_user_logs")
    parser.add_argument("--quiet", action="store_true")
    return parser


def print_personas() -> None:
    print("Available normal-user personas:\n")
    for pid, persona in PERSONAS.items():
        print(f"  {pid}")
        print(f"    name:        {persona.name}")
        print(f"    description: {persona.description}")
        print(f"    traits:      {', '.join(persona.traits)}")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_personas:
        print_personas()
        return 0

    if not args.persona or not args.mode:
        parser.error("--persona and --mode are required (or use --list-personas)")

    persona = get_persona(args.persona)
    client_id = args.client_id or f"user-{args.persona}-{args.mode}-{_short_id()}"
    queries = persona.generate(args.count, seed=args.seed, topic=args.base_topic)
    pacer = (FastPacer(delay=args.delay) if args.mode == "fast"
            else SlowPacer(min_delay=args.min_delay, max_delay=args.max_delay))

    print(f"Persona:    {persona.name} ({args.persona})")
    print(f"Mode:       {args.mode}")
    print(f"Client ID:  {client_id}")
    print(f"Target:     {args.target}")
    print(f"Count:      {len(queries)}")
    print()

    outcome = run_session(
        persona_id=args.persona, queries=queries, mode=args.mode, pacer=pacer,
        client_id=client_id, target=args.target, log_dir=args.log_dir,
        verbose=not args.quiet,
    )

    print()
    print(f"Done. Sent {outcome.total_sent}/{len(queries)} queries.")
    print(f"Log:     {outcome.log_path}")
    print(f"Summary: {outcome.summary_path}")
    return 0


def _short_id() -> str:
    import uuid
    return uuid.uuid4().hex[:6]


if __name__ == "__main__":
    sys.exit(main())
