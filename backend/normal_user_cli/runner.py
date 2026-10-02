"""Drives one normal-user session through the SAME public /api/chat path the
attacker CLI and a real browser use -- reuses attacker_cli's HTTP client and
pacer (both are generic: they know nothing about strategies or personas,
just "send this string, wait this long").
"""

import time
from dataclasses import dataclass

from attacker_cli.http_client import ChatResult, FirewallClient
from attacker_cli.pacing import Pacer
from normal_user_cli.user_logger import UserSessionLogger

MAX_CONSECUTIVE_ERRORS = 3


@dataclass
class RunOutcome:
    client_id: str
    total_sent: int
    log_path: str
    summary_path: str


def run_session(*, persona_id: str, queries: list[str], mode: str, pacer: Pacer,
                client_id: str, target: str, log_dir: str,
                verbose: bool = True) -> RunOutcome:
    client = FirewallClient(base_url=target)
    logger = UserSessionLogger(log_dir=log_dir, client_id=client_id,
                               persona=persona_id, mode=mode, target=target)

    consecutive_errors = 0
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
                    break
                continue
            consecutive_errors = 0
    finally:
        logger.finish()
        client.close()

    return RunOutcome(
        client_id=client_id, total_sent=logger.summary.total_sent,
        log_path=str(logger.jsonl_path), summary_path=str(logger.summary_path),
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
