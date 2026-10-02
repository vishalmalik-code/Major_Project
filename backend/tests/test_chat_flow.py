"""Full-stack integration tests for POST /api/chat's underlying orchestration
(ChatService.handle), against the real Postgres database with a FakeLLMService
spy standing in for Ollama.

Covers checklist items 2, 3, 4, 11, 12, 13, 14 from the prompt:
  2.  Client A and Client B have independent histories.
  3.  A client can store 20 queries.
  4.  The 21st query removes the oldest query.
  11. BLOCK means the LLM is not called.
  12. ALLOW means the LLM is called.
  13. MONITOR means the LLM is called and the event is logged.
  14. THROTTLE does not bypass the firewall.

The firewall must decide BEFORE the LLM is ever touched: every assertion here
is expressed in terms of `fake_llm.call_count`, which only increases when
ChatService actually invokes generate() -- there is no other path to the LLM.
"""

from sqlalchemy import select

from app.core.constants import Action
from app.db.models import Query as QueryModel
from app.db.models import SecurityEvent


async def _send(service, db, client_id, query, n=1):
    """Send the same query `n` times sequentially, returning the last decision."""
    decision = None
    for _ in range(n):
        decision, response, _latency = await service.handle(db, client_id, query)
    return decision, response


# --- items 12: ALLOW calls the LLM -------------------------------------------

async def test_allow_calls_the_llm(build_chat_service, fake_llm, db_session,
                                   new_client_id, cleanup_client):
    cleanup_client.append(new_client_id)
    service = build_chat_service()

    decision, response = await _send(service, db_session, new_client_id,
                                     "What is SQL injection?")

    assert decision.action == Action.ALLOW
    assert fake_llm.call_count == 1
    assert response == fake_llm.response


# --- item 11: BLOCK does NOT call the LLM ------------------------------------

async def test_block_does_not_call_the_llm(build_chat_service, fake_llm, db_session,
                                           new_client_id, cleanup_client):
    cleanup_client.append(new_client_id)
    service = build_chat_service()
    query = "What is a SQL injection attack and how does it work?"

    decision = None
    for _ in range(10):
        decision, response, _latency = await service.handle(db_session, new_client_id, query)
        if decision.action == Action.BLOCK:
            break

    assert decision.action == Action.BLOCK, "expected repeated identical queries to reach BLOCK"
    calls_before_block = fake_llm.call_count
    response_at_block = response
    assert response_at_block is None, "BLOCK must not return LLM output"

    # Send once more while still CRITICAL -- must still not call the LLM.
    decision2, response2, _ = await service.handle(db_session, new_client_id, query)
    assert decision2.action == Action.BLOCK
    assert response2 is None
    assert fake_llm.call_count == calls_before_block, (
        "a second BLOCKed query must not increase LLM call count"
    )


# --- item 13: MONITOR calls the LLM AND logs a security event ----------------

async def test_monitor_calls_llm_and_logs_event(build_chat_service, fake_llm, db_session,
                                                new_client_id, cleanup_client):
    cleanup_client.append(new_client_id)
    service = build_chat_service()
    query = "What is a SQL injection attack and how does it work?"

    decision = None
    for _ in range(10):
        decision, response, _latency = await service.handle(db_session, new_client_id, query)
        if decision.action == Action.MONITOR:
            break

    assert decision.action == Action.MONITOR, "expected repeated queries to reach MONITOR"
    assert response == fake_llm.response, "MONITOR must still call the LLM"

    events = db_session.execute(
        select(SecurityEvent).where(SecurityEvent.client_id == new_client_id,
                                    SecurityEvent.event_type == "MONITORED")
    ).scalars().all()
    assert len(events) >= 1, "MONITOR must record a security event"
    assert events[-1].severity == "MEDIUM"


# --- item 14: THROTTLE still calls the LLM (does not bypass the firewall) ----

async def test_throttle_still_calls_llm_after_delay(build_chat_service, fake_llm, db_session,
                                                     new_client_id, cleanup_client, monkeypatch):
    cleanup_client.append(new_client_id)
    # Keep the test fast: the THROTTLE delay itself isn't what's under test,
    # only that it doesn't skip calling the LLM.
    from app.core.config import settings
    monkeypatch.setattr(settings, "throttle_delay_seconds", 0.01)

    service = build_chat_service()
    query = "What is a SQL injection attack and how does it work?"

    decision = None
    for _ in range(10):
        decision, response, _latency = await service.handle(db_session, new_client_id, query)
        if decision.action == Action.THROTTLE:
            break

    assert decision.action == Action.THROTTLE, "expected repeated queries to reach THROTTLE"
    assert response == fake_llm.response, "THROTTLE must still reach the LLM, just delayed"

    row = db_session.execute(
        select(QueryModel).where(QueryModel.client_id == new_client_id)
        .order_by(QueryModel.seq.desc()).limit(1)
    ).scalar_one()
    assert row.action == "THROTTLE"
    assert row.response is not None


# --- item 2: Client A and Client B have independent histories ----------------

async def test_clients_are_fully_independent(build_chat_service, fake_llm, db_session,
                                             cleanup_client):
    import uuid
    client_a = f"test-a-{uuid.uuid4().hex[:8]}"
    client_b = f"test-b-{uuid.uuid4().hex[:8]}"
    cleanup_client.extend([client_a, client_b])
    service = build_chat_service()

    # Drive client A deep into suspicious territory with repeated queries.
    suspicious = "What is a SQL injection attack and how does it work?"
    for _ in range(6):
        decision_a, _, _ = await service.handle(db_session, client_a, suspicious)

    # Client B has never been seen; a single, unrelated query must be LOW/ALLOW.
    decision_b, response_b, _ = await service.handle(
        db_session, client_b, "What is the capital of France in a security context?")

    assert decision_a.risk_after > 20.0, "client A should have accumulated risk"
    assert decision_b.risk_before == 0.0, "client B's risk must start at 0 regardless of A"
    assert decision_b.risk_after < 20.0, "client B must not inherit client A's risk"
    assert decision_b.action == Action.ALLOW

    window_b = service.engine.window.get(client_b)
    assert len(window_b) == 1
    assert window_b[0].seq == 1, "client B's window must not contain client A's queries"

    window_a = service.engine.window.get(client_a)
    assert all(e.text == suspicious for e in window_a)


# --- items 3 & 4: 20-query window storage and 21st-query eviction ------------

async def test_client_stores_up_to_20_queries_and_evicts_the_21st(
        build_chat_service, fake_llm, db_session, new_client_id, cleanup_client):
    cleanup_client.append(new_client_id)
    service = build_chat_service()

    # Vary the text slightly each time so we're testing window mechanics, not
    # accidentally triggering an early BLOCK that would still exercise the
    # window (BLOCK still enters the window) but could confuse the read below.
    for i in range(1, 21):
        await service.handle(db_session, new_client_id, f"Security question number {i}?")

    window = service.engine.window.get(new_client_id)
    assert len(window) == 20
    assert [e.seq for e in window] == list(range(1, 21))

    await service.handle(db_session, new_client_id, "Security question number 21?")

    window = service.engine.window.get(new_client_id)
    assert len(window) == 20, "window must stay capped at 20 after the 21st query"
    assert [e.seq for e in window] == list(range(2, 22)), (
        "query 1 must be evicted and queries 2..21 must remain"
    )
    assert 1 not in [e.seq for e in window]


# --- items 5 & 6: waiting affects neither the window nor risk, full-stack ----

async def test_waiting_between_queries_changes_nothing_end_to_end(
        build_chat_service, fake_llm, db_session, cleanup_client, monkeypatch):
    """Runs the identical suspicious query sequence twice through the real
    ChatService pipeline -- once with no gap between queries, once with
    synthetic gaps of 10s, 10min, and 1hr injected via a monkeypatched clock.

    burst_rate's weight is zeroed for this test: it is the one signal the
    spec explicitly allows to use timestamps (for detecting rapid bursts,
    section 5D), so identical text sent at different paces legitimately gets
    a different burst_rate score -- that is intended, not decay. What must be
    proven here is narrower and is the actual requirement (section 7): with
    that single time-aware signal held constant, elapsed time between queries
    must have NO effect on the outcome. With it zeroed, the two trajectories
    must be byte-for-byte identical.
    """
    import uuid
    import app.services.chat_service as chat_service_module
    from app.core.config import settings

    monkeypatch.setattr(settings, "weight_burst_rate", 0.0)

    client_nowait = f"test-nowait-{uuid.uuid4().hex[:8]}"
    client_wait = f"test-wait-{uuid.uuid4().hex[:8]}"
    cleanup_client.extend([client_nowait, client_wait])

    query = "What is a SQL injection attack and how does it work?"
    gaps = [0, 10, 600, 3600, 10]  # seconds of "elapsed time" before each query

    service = build_chat_service()
    trajectory_nowait = []
    for _ in gaps:
        decision, _, _ = await service.handle(db_session, client_nowait, query)
        trajectory_nowait.append(round(decision.risk_after, 6))

    real_time = chat_service_module.time.time
    clock = {"t": real_time()}

    def fake_time():
        return clock["t"]

    monkeypatch.setattr(chat_service_module.time, "time", fake_time)

    trajectory_wait = []
    for gap in gaps:
        clock["t"] += gap  # simulate the client waiting `gap` seconds
        decision, _, _ = await service.handle(db_session, client_wait, query)
        trajectory_wait.append(round(decision.risk_after, 6))

    assert trajectory_wait == trajectory_nowait, (
        f"waiting changed the risk trajectory: {trajectory_wait} != {trajectory_nowait}"
    )

    window_nowait = service.engine.window.get(client_nowait)
    window_wait = service.engine.window.get(client_wait)
    assert [e.normalized for e in window_wait] == [e.normalized for e in window_nowait]
    assert [e.seq for e in window_wait] == [e.seq for e in window_nowait]
