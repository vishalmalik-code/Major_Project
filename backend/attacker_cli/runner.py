"""Ties query generation, pacing, the HTTP client, and logging together.

    generate queries (reused, firewall-agnostic templates from app.attacker)
        -> for each query:
             sleep(pacer.delay())
             FirewallClient.send(client_id, query)   # the ONLY path to the LLM
             log the result
             apply the on-block policy
"""

import sys
import time
from dataclasses import dataclass

from attacker_cli.attack_logger import AttackLogger
from attacker_cli.http_client import ChatResult, FirewallClient
from attacker_cli.pacing import Pacer

MAX_CONSECUTIVE_ERRORS = 3


@dataclass
class RunOutcome:
    client_id: str
    total_sent: int
    stopped_early: bool
    log_path: str
    summary_path: str


def run_attack(*, strategy_id: str, strategy_name: str, queries: list[str],
               mode: str, pacer: Pacer, client_id: str, target: str,
               log_dir: str, on_block: str = "continue",
               verbose: bool = True) -> RunOutcome:
    client = FirewallClient(base_url=target)
    logger = AttackLogger(log_dir=log_dir, client_id=client_id,
                          strategy=strategy_id, mode=mode, target=target)

    consecutive_errors = 0
    stopped_early = False

    try:
        for i, query in enumerate(queries, start=1):
            if i > 1:
                time.sleep(pacer.delay())

            result: ChatResult = client.send(client_id, query)
            logger.log_query(i, query, result)

            if verbose:
                _print_step(i, len(queries), query, result)

            if not result.ok:
                consecutive_errors += 1
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    print(f"\n!! {consecutive_errors} consecutive request "
                         f"errors -- aborting run. Is the server at "
                         f"{target} up?", file=sys.stderr)
                    stopped_early = True
                    break
                continue
            consecutive_errors = 0

            if result.decision == "BLOCK" and on_block == "stop":
                if verbose:
                    print(f"\n>> BLOCKed at query {i}; stopping "
                         f"(--on-block stop).")
                stopped_early = True
                break
    finally:
        logger.finish(stopped_early=stopped_early)
        client.close()

    return RunOutcome(
        client_id=client_id, total_sent=logger.summary.total_sent,
        stopped_early=stopped_early, log_path=str(logger.jsonl_path),
        summary_path=str(logger.summary_path),
    )


def _print_step(i: int, total: int, query: str, result: ChatResult) -> None:
    if not result.ok:
        print(f"  [{i:>3}/{total}] ERROR  {result.error}")
        return
    risk = f"{result.risk_score:6.1f}" if result.risk_score is not None else "   n/a"
    got = "llm" if result.got_llm_response else "-  "
    q_preview = query if len(query) <= 60 else query[:57] + "..."
    print(f"  [{i:>3}/{total}] {result.decision:8s} risk={risk} "
         f"[{got}]  {q_preview}")
