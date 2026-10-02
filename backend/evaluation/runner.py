"""Executes one SessionSpec against the real /api/chat endpoint and returns a
SessionResult carrying full reproducibility metadata plus computed metrics.

Reuses attacker_cli.http_client.FirewallClient (the same real-HTTP-only
client the attacker CLI uses) so attacker and normal-user evaluation traffic
travels through the exact same code path as either standalone tool -- the
evaluation runner does not talk to the LLM, the DB, or the firewall engine
directly for the query traffic itself.
"""

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from attacker_cli.http_client import FirewallClient
from attacker_cli.pacing import FastPacer, Pacer, SlowPacer
from evaluation.metrics import SessionMetrics, compute_metrics
from evaluation.sessions import SessionSpec

MAX_CONSECUTIVE_ERRORS = 3


@dataclass
class SessionResult:
    run_id: str
    session_type: str
    label: str
    mode: str
    client_id: str
    seed: int
    started_at: str
    finished_at: str
    query_count: int
    log_path: str
    metrics: dict = field(default_factory=dict)


def _pacer_for(mode: str, *, fast_delay: float, slow_min: float, slow_max: float) -> Pacer:
    return FastPacer(delay=fast_delay) if mode == "fast" else SlowPacer(
        min_delay=slow_min, max_delay=slow_max)


def run_one_session(spec: SessionSpec, *, run_id: str, target: str, log_dir: str,
                    fast_delay: float, slow_min: float, slow_max: float,
                    verbose: bool = True) -> SessionResult:
    pacer = _pacer_for(spec.mode, fast_delay=fast_delay, slow_min=slow_min, slow_max=slow_max)
    client = FirewallClient(base_url=target)

    log_path = Path(log_dir) / f"{spec.client_id}.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    started_at = _now_iso()

    if verbose:
        print(f"\n=== {spec.session_type}:{spec.label} [{spec.mode}] "
             f"client={spec.client_id} ===")

    consecutive_errors = 0
    try:
        with open(log_path, "w") as fh:
            for i, query in enumerate(spec.queries, start=1):
                if i > 1:
                    time.sleep(pacer.delay())

                result = client.send(spec.client_id, query)
                row = {
                    "timestamp": _now_iso(), "client_id": spec.client_id,
                    "session_type": spec.session_type, "label": spec.label,
                    "mode": spec.mode, "query_number": i, "query": query,
                    "decision": result.decision if result.ok else "ERROR",
                    "risk_score": result.risk_score, "risk_band": result.risk_band,
                    "response_status": result.http_status,
                    "got_llm_response": result.got_llm_response,
                    "notice": result.notice, "error": result.error,
                }
                rows.append(row)
                fh.write(json.dumps(row) + "\n")
                fh.flush()

                if verbose:
                    risk = f"{result.risk_score:6.1f}" if result.risk_score is not None else "   n/a"
                    dec = row["decision"]
                    print(f"  [{i:>2}/{len(spec.queries)}] {dec:8s} risk={risk}")

                if not result.ok:
                    consecutive_errors += 1
                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                        break
                    continue
                consecutive_errors = 0
    finally:
        client.close()

    finished_at = _now_iso()
    metrics: SessionMetrics = compute_metrics(rows)

    return SessionResult(
        run_id=run_id, session_type=spec.session_type, label=spec.label,
        mode=spec.mode, client_id=spec.client_id, seed=spec.seed,
        started_at=started_at, finished_at=finished_at,
        query_count=len(rows), log_path=str(log_path),
        metrics=metrics.as_dict(),
    )


def save_result(result: SessionResult, results_jsonl_path: str) -> None:
    with open(results_jsonl_path, "a") as fh:
        fh.write(json.dumps(asdict(result)) + "\n")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
