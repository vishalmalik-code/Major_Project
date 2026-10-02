"""Orchestration for the /api/chat path: the one piece that is neither pure
detection (FirewallEngine) nor pure HTTP (the route).

Sequence per request:
    1. Warm the client's in-memory window from Postgres if this process hasn't
       seen the client yet (`ORDER BY seq DESC LIMIT window_size` -- by seq).
    2. Reserve the next `seq` and read current risk (both live on the same
       `clients` row, updated in one transaction).
    3. engine.inspect() -> a pure Decision.
    4. Act on the decision:
         BLOCK    -> never call the LLM service.
         THROTTLE -> sleep(throttle_delay_seconds), then call the LLM service.
         MONITOR  -> call the LLM service, raise a security event.
         ALLOW    -> call the LLM service.
    5. Persist: clients.risk_score/band (the ONLY writer), the query row +
       its 8 signal_scores, any security_event.
    6. engine.commit() -> push the query into the in-memory window.

Steps 5 and 6 both run even on BLOCK: a blocked attempt is evidence and still
enters the window.
"""

import asyncio
import time

from app.core.constants import Action, EventType, Severity
from app.db.repository import ClientRepository, EventRepository, QueryRepository
from app.embeddings.encoder import Encoder
from app.firewall.engine import Decision, FirewallEngine
from app.services.llm import LLMService

_SEVERITY_FOR_ACTION = {
    Action.MONITOR: Severity.MEDIUM,
    Action.THROTTLE: Severity.HIGH,
    Action.BLOCK: Severity.CRITICAL,
}
_EVENT_FOR_ACTION = {
    Action.MONITOR: EventType.MONITORED,
    Action.THROTTLE: EventType.THROTTLED,
    Action.BLOCK: EventType.BLOCKED,
}

_warmed_clients: set[str] = set()


class ChatService:
    def __init__(self, engine: FirewallEngine, encoder: Encoder,
                llm: LLMService, bus=None, admin_bus=None) -> None:
        self.engine = engine
        self.encoder = encoder
        self.llm = llm
        # ConversationEventBus | None -- optional so tests/CLI tools that
        # build a ChatService directly (no live /chat tab to notify) don't
        # need one. See app/services/conversation_events.py.
        self.bus = bus
        # BroadcastBus | None -- the /admin live-monitoring feed. Same
        # optionality reasoning as `bus` above.
        self.admin_bus = admin_bus

    async def handle(self, db, client_id: str, query: str,
                     attack_run_id: str | None = None,
                     conversation_id: int | None = None,
                     source: str = "user",
                     ) -> tuple[Decision, str | None, int]:
        client_repo = ClientRepository(db)
        query_repo = QueryRepository(db)
        event_repo = EventRepository(db)

        client = client_repo.get_or_create(
            client_id, kind="attacker" if attack_run_id else "user")

        if client_id not in _warmed_clients:
            history = query_repo.load_window(client_id, self.engine.window.size)
            self.engine.window.rebuild_from_db(client_id, history)
            _warmed_clients.add(client_id)

        seq = client_repo.next_seq(client_id)
        risk_before = client.risk_score
        # Wall-clock epoch, NOT time.monotonic(): entries rebuilt from
        # Postgres carry `created_at.timestamp()` (also wall-clock), and
        # burst_rate compares timestamps across both sources. Mixing an
        # arbitrary monotonic origin into that comparison would corrupt the
        # signal after any process restart.
        arrived_at = time.time()
        embedding = self.encoder.encode(query)

        decision = self.engine.inspect(
            client_id=client_id, seq=seq, query=query, embedding=embedding,
            risk_before=risk_before, arrived_at_epoch=arrived_at,
        )

        t_start = time.monotonic()
        response_text: str | None = None
        if decision.action != Action.BLOCK:
            if decision.action == Action.THROTTLE and decision.throttle_delay_seconds > 0:
                await asyncio.sleep(decision.throttle_delay_seconds)
            response_text = await self.llm.generate(query)
        latency_ms = int((time.monotonic() - t_start) * 1000)

        client_repo.update_risk(client_id, decision.risk_after, decision.risk_band)

        query_row = query_repo.record(
            client_id=client_id, seq=seq, text=query, normalized=decision.normalized,
            embedding=embedding, numbers=decision.numbers,
            constraint_tokens=decision.constraint_tokens, action=decision.action,
            weighted_score=decision.weighted_score, risk_before=decision.risk_before,
            risk_after=decision.risk_after, response=response_text,
            latency_ms=latency_ms, attack_run_id=attack_run_id,
            signal_results=decision.signals, conversation_id=conversation_id,
            source=source,
        )

        security_event = None
        if decision.action in _EVENT_FOR_ACTION:
            message = self._event_message(decision)
            event_row = event_repo.record(
                client_id=client_id, query_id=query_row.id,
                severity=_SEVERITY_FOR_ACTION[decision.action].value,
                event_type=_EVENT_FOR_ACTION[decision.action].value,
                message=message,
                details={"weighted_score": decision.weighted_score,
                        "dominant_signal": decision.dominant_signal},
            )
            security_event = {
                "id": event_row.id,
                "severity": _SEVERITY_FOR_ACTION[decision.action].value,
                "event_type": _EVENT_FOR_ACTION[decision.action].value,
                "message": message,
            }

        db.commit()
        self.engine.commit(decision)

        # Tell any open /chat tab watching this conversation. Client-safe
        # payload only (mirrors ConversationMessage/the attacker console's
        # SSE shape): no action/risk_score/risk_band/notice. `source` is not
        # a firewall internal -- it's who sent the message, which the normal
        # chat UI is explicitly allowed to render as a subtle label.
        if self.bus is not None and conversation_id is not None:
            self.bus.publish(conversation_id, "message", {
                "seq": query_row.seq, "query": query, "response": response_text,
                "source": source, "created_at": query_row.created_at.isoformat(),
            })

        # Tell every open /admin tab. Unlike the chat-safe event above, this
        # one is exactly what /admin is authorized to see: decision, risk,
        # dominant signal, and the security event (if any) -- the same data
        # GET /api/admin/queries and /api/admin/events already expose,
        # delivered live instead of on the next poll. Published for EVERY
        # query (not just conversation-tagged ones), since /admin watches
        # the whole system, including CLI tools and the background
        # /api/attack/run runner, which share this same ChatService instance.
        if self.admin_bus is not None:
            self.admin_bus.publish("query", {
                "id": query_row.id, "client_id": client_id, "seq": seq,
                "text": query, "action": decision.action.value,
                "risk_before": round(decision.risk_before, 1),
                "risk_after": round(decision.risk_after, 1),
                "risk_band": decision.risk_band.value,
                "weighted_score": round(decision.weighted_score, 3),
                "dominant_signal": decision.dominant_signal,
                "created_at": query_row.created_at.isoformat(),
                "conversation_id": conversation_id, "source": source,
                "security_event": security_event,
            })

        return decision, response_text, latency_ms

    @staticmethod
    def _event_message(decision: Decision) -> str:
        dom = decision.dominant_signal or "no single dominant signal"
        return (
            f"Client {decision.client_id} moved to {decision.risk_band.value} "
            f"(risk {decision.risk_after:.1f}) at query seq {decision.seq}; "
            f"dominant signal: {dom}."
        )
