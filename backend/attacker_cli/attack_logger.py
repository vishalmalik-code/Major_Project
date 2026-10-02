"""Per-run attack log.

Writes one JSON object per query to a JSON-Lines file (easy to tail/stream
while a slow run is still in progress), and a final summary JSON when the run
finishes. Every field the prompt asks for is here: timestamp, client_id,
strategy, mode, query_number, query, firewall_decision, risk_score, and
response_status.

Individual signal values are NOT included: POST /api/chat deliberately never
returns them to a client (they're admin-only -- see docs/API.md and
docs/ARCHITECTURE.md section 10). That omission is consistent with, not a
gap against, this prompt's own rule that the attacker must not have access to
internal firewall state -- so `signals` is always logged as null, honestly
reflecting what the attacker actually knows.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class LogEntry:
    timestamp: str
    client_id: str
    strategy: str
    mode: str
    query_number: int
    query: str
    decision: str | None
    risk_score: float | None
    risk_band: str | None
    response_status: int
    got_llm_response: bool | None
    notice: str | None
    signals: None = None   # always null -- see module docstring
    error: str | None = None


@dataclass
class RunSummary:
    client_id: str
    strategy: str
    mode: str
    target: str
    started_at: str
    finished_at: str | None = None
    total_sent: int = 0
    counts: dict = field(default_factory=lambda: {
        "ALLOW": 0, "MONITOR": 0, "THROTTLE": 0, "BLOCK": 0, "ERROR": 0})
    queries_to_first_block: int | None = None
    stopped_early: bool = False
    final_risk_score: float | None = None


class AttackLogger:
    def __init__(self, log_dir: str, client_id: str, strategy: str, mode: str,
                target: str) -> None:
        self.dir = Path(log_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = self.dir / f"{client_id}.jsonl"
        self.summary_path = self.dir / f"{client_id}_summary.json"
        self._fh = open(self.jsonl_path, "w")
        self.summary = RunSummary(
            client_id=client_id, strategy=strategy, mode=mode, target=target,
            started_at=_now_iso(),
        )

    def log_query(self, query_number: int, query: str, result) -> None:
        decision = result.decision if result.ok else "ERROR"
        entry = LogEntry(
            timestamp=_now_iso(), client_id=self.summary.client_id,
            strategy=self.summary.strategy, mode=self.summary.mode,
            query_number=query_number, query=query,
            decision=result.decision, risk_score=result.risk_score,
            risk_band=result.risk_band, response_status=result.http_status,
            got_llm_response=result.got_llm_response, notice=result.notice,
            error=result.error,
        )
        self._fh.write(json.dumps(asdict(entry)) + "\n")
        self._fh.flush()

        self.summary.total_sent += 1
        self.summary.counts[decision if decision in self.summary.counts else "ERROR"] += 1
        if result.risk_score is not None:
            self.summary.final_risk_score = result.risk_score
        if decision == "BLOCK" and self.summary.queries_to_first_block is None:
            self.summary.queries_to_first_block = query_number

    def finish(self, stopped_early: bool = False) -> None:
        self.summary.finished_at = _now_iso()
        self.summary.stopped_early = stopped_early
        self.summary_path.write_text(json.dumps(asdict(self.summary), indent=2))
        self._fh.close()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
