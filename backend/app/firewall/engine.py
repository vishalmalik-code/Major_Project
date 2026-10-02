"""The firewall's decision core. Five of the six architecture steps live here:

    1. load the client's query window (last 20, ordered by seq)
    2. preprocess + embed the incoming query
    3. run all eight signals over the window
    4. fuse -> weighted score -> query-based risk delta -> new risk
    5. map risk to ALLOW / MONITOR / THROTTLE / BLOCK

`inspect()` is deliberately pure: no DB, no HTTP, no sleeping. It reads the
in-memory QueryWindow (already warm -- warming it from Postgres on a cache
miss is the caller's job, in app/services/chat_service.py) and returns a
Decision. This keeps the engine unit-testable without a database or a running
Ollama, and is exactly what tests/test_attack_detection.py and
tests/test_benign_user.py exercise directly.

Step 6 (persist + push into the window) is split across the caller
(DB writes) and `commit()` (the window push) -- see chat_service.py for how
they're sequenced. Every request passes through here, including the attack
simulator's: the simulator gets NO privileged path.
"""

from dataclasses import dataclass, field

from app.core.constants import Action, RiskBand
from app.firewall.actions import action_for, band_for, queries_to_clear, throttle_delay_for
from app.firewall.normalize import extract_constraint_tokens, extract_numbers, normalize
from app.firewall.risk import combine, dominant, update
from app.firewall.signals import Signal, SignalResult, default_signals
from app.firewall.signals.base import QueryContext
from app.firewall.window import QueryWindow, WindowEntry


@dataclass
class Decision:
    client_id: str
    seq: int
    action: Action
    risk_band: RiskBand
    risk_before: float
    risk_after: float
    risk_delta: float
    weighted_score: float
    text: str
    normalized: str
    embedding: object
    numbers: list[float]
    constraint_tokens: list[str]
    arrived_at_epoch: float
    throttle_delay_seconds: float = 0.0
    retry_after_queries: int = 0
    signals: list[SignalResult] = field(default_factory=list)
    dominant_signal: str | None = None
    reason: str = ""


class FirewallEngine:
    def __init__(self, window: QueryWindow, signals: list[Signal] | None = None) -> None:
        self.window = window
        self.signals = signals or default_signals()

    def inspect(self, client_id: str, seq: int, query: str, embedding,
               risk_before: float, arrived_at_epoch: float) -> Decision:
        """Steps 1-5. Pure decision: no LLM call, no HTTP, no delay applied.

        `seq`, `embedding`, and `risk_before` are supplied by the caller
        because assigning a seq and reading current risk both require the
        client row (a DB concern) -- inspect() itself never touches the DB.

        The caller is responsible for acting on the Decision: sleeping on
        THROTTLE, refusing on BLOCK, calling Ollama otherwise.
        """
        window = self.window.get(client_id)
        tight_window = self.window.get_tight(client_id)

        norm = normalize(query)
        numbers = extract_numbers(query)
        constraints = extract_constraint_tokens(query)

        ctx = QueryContext(
            client_id=client_id, seq=seq, text=query, normalized=norm,
            embedding=embedding, numbers=numbers, constraint_tokens=constraints,
            arrived_at_epoch=arrived_at_epoch, window=window, tight_window=tight_window,
        )

        results = [sig.evaluate(ctx) for sig in self.signals]
        weighted = combine(results)
        risk_update = update(risk_before=risk_before, weighted=weighted, results=results)
        risk_after = risk_update.risk_after
        band = band_for(risk_after)
        action = action_for(risk_after)
        d = dominant(results)

        return Decision(
            client_id=client_id, seq=seq, action=action, risk_band=band,
            risk_before=risk_before, risk_after=risk_after,
            risk_delta=risk_update.delta, weighted_score=weighted,
            text=query, normalized=norm, embedding=embedding, numbers=numbers,
            constraint_tokens=constraints, arrived_at_epoch=arrived_at_epoch,
            throttle_delay_seconds=throttle_delay_for(risk_after),
            retry_after_queries=queries_to_clear(risk_after),
            signals=results, dominant_signal=d.name if d else None,
            reason=risk_update.reason,
        )

    def commit(self, decision: Decision) -> None:
        """Push the inspected query into the in-memory window.

        This is the ONLY method that mutates the window from the request path.
        BLOCKED queries are committed too: a blocked attempt is evidence and
        still enters the window (DB persistence of `response=None` happens in
        the caller before this is invoked).
        """
        entry = WindowEntry(
            seq=decision.seq, text=decision.text, normalized=decision.normalized,
            embedding=decision.embedding, numbers=decision.numbers,
            constraint_tokens=decision.constraint_tokens,
            created_at_epoch=decision.arrived_at_epoch,
        )
        self.window.push(decision.client_id, entry)
