"""Drives strategy x pacer x count against the SAME ChatService.handle() path
a browser request uses.

The runner deliberately calls the identical code path as /api/chat -- it never
imports FirewallEngine directly and never marks its requests as simulated.
If it did, the evaluation would be meaningless: the firewall must not be able
to cheat by knowing where a request came from.

Records an attack_runs row whose headline column is `queries_to_first_block`:
the same strategy in FAST and SLOW mode should both eventually block, with SLOW
needing more queries and far more wall-clock time. That gap is the result the
project exists to show.
"""

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.attacker.pacing import pacer_for
from app.attacker.registry import get as get_strategy
from app.core.constants import Action, AttackMode
from app.db.repository import AttackRunRepository, ClientRepository
from app.db.session import SessionLocal


@dataclass
class RunStep:
    seq: int
    query: str
    action: str
    risk: float
    top_signal: dict | None = None


@dataclass
class RunResult:
    run_id: str
    strategy: str
    mode: str
    total: int
    client_id: str
    sent: int = 0
    counts: dict[str, int] = field(default_factory=lambda: {
        "ALLOW": 0, "MONITOR": 0, "THROTTLE": 0, "BLOCK": 0})
    queries_to_first_block: int | None = None
    timeline: list[RunStep] = field(default_factory=list)
    status: str = "running"


class AttackRunner:
    def __init__(self, chat_service) -> None:
        self.chat_service = chat_service
        self._runs: dict[str, RunResult] = {}

    def get(self, run_id: str) -> RunResult | None:
        return self._runs.get(run_id)

    async def start(self, strategy_id: str, mode: AttackMode, count: int,
                    client_id: str, seed: int | None = None) -> RunResult:
        strategy = get_strategy(strategy_id)
        queries = strategy.generate(count, seed=seed)
        run_id = f"run-{uuid.uuid4().hex[:10]}"

        result = RunResult(run_id=run_id, strategy=strategy_id, mode=mode.value,
                           total=count, client_id=client_id)
        self._runs[run_id] = result

        db = SessionLocal()
        try:
            # The clients row is normally created lazily on first /api/chat
            # call, but attack_runs.client_id is a foreign key to it -- create
            # it here first so the run row can reference it immediately.
            ClientRepository(db).get_or_create(client_id, kind="attacker")
            AttackRunRepository(db).create(
                run_id=run_id, strategy=strategy_id, mode=mode.value,
                client_id=client_id, requested_count=count, seed=seed,
            )
            db.commit()
        finally:
            db.close()

        asyncio.create_task(self._run(result, queries, mode, client_id, seed))
        return result

    async def _run(self, result: RunResult, queries: list[str], mode: AttackMode,
                   client_id: str, seed: int | None) -> None:
        pacer = pacer_for(mode, seed=seed)

        for query in queries:
            db = SessionLocal()
            try:
                decision, _response, _latency = await self.chat_service.handle(
                    db, client_id, query, attack_run_id=result.run_id)
            finally:
                db.close()

            result.sent += 1
            result.counts[decision.action.value] += 1
            top_signal = None
            if decision.dominant_signal:
                top = next((s for s in decision.signals
                           if s.name == decision.dominant_signal), None)
                if top:
                    top_signal = {"name": top.name, "score": round(top.score, 3)}

            result.timeline.append(RunStep(
                seq=decision.seq, query=query, action=decision.action.value,
                risk=round(decision.risk_after, 1), top_signal=top_signal,
            ))

            if decision.action == Action.BLOCK and result.queries_to_first_block is None:
                result.queries_to_first_block = result.sent

            await asyncio.sleep(pacer.delay())

        result.status = "finished"

        db = SessionLocal()
        try:
            AttackRunRepository(db).update_progress(
                result.run_id, sent_count=result.sent,
                allowed_count=result.counts["ALLOW"],
                monitored_count=result.counts["MONITOR"],
                throttled_count=result.counts["THROTTLE"],
                blocked_count=result.counts["BLOCK"],
                queries_to_first_block=result.queries_to_first_block,
                status="finished", finished_at=datetime.now(timezone.utc),
            )
            db.commit()
        finally:
            db.close()
