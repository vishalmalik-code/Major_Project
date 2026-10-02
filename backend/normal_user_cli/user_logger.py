"""Per-run normal-user session log. Same shape as attacker_cli's logger
(timestamp, client_id, persona, mode, query_number, query, decision,
risk_score, response_status), written to normal_user_logs/ instead of
attacker_logs/ so the two simulators' output never mixes.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class LogEntry:
    timestamp: str
    client_id: str
    persona: str
    mode: str
    query_number: int
    query: str
    decision: str | None
    risk_score: float | None
    risk_band: str | None
    response_status: int
    got_llm_response: bool | None
    notice: str | None
    error: str | None = None


@dataclass
class RunSummary:
    client_id: str
    persona: str
    mode: str
    target: str
    started_at: str
    finished_at: str | None = None
    total_sent: int = 0
    counts: dict = field(default_factory=lambda: {
        "ALLOW": 0, "MONITOR": 0, "THROTTLE": 0, "BLOCK": 0, "ERROR": 0})
    final_risk_score: float | None = None
    peak_risk_score: float | None = None


class UserSessionLogger:
    def __init__(self, log_dir: str, client_id: str, persona: str, mode: str,
                target: str) -> None:
        self.dir = Path(log_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = self.dir / f"{client_id}.jsonl"
        self.summary_path = self.dir / f"{client_id}_summary.json"
        self._fh = open(self.jsonl_path, "w")
        self.summary = RunSummary(
            client_id=client_id, persona=persona, mode=mode, target=target,
            started_at=_now_iso(),
        )

    def log_query(self, query_number: int, query: str, result) -> None:
        decision = result.decision if result.ok else "ERROR"
        entry = LogEntry(
            timestamp=_now_iso(), client_id=self.summary.client_id,
            persona=self.summary.persona, mode=self.summary.mode,
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
            self.summary.peak_risk_score = max(
                self.summary.peak_risk_score or 0.0, result.risk_score)

    def finish(self) -> None:
        self.summary.finished_at = _now_iso()
        self.summary_path.write_text(json.dumps(asdict(self.summary), indent=2))
        self._fh.close()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
