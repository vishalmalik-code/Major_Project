"""Prompt 6 final integration verification: dedicated tests matching the
prompt's exact scenarios (sections 3-8), each run against the REAL firewall
pipeline (FirewallEngine + real signals + real risk model) through
ChatService.handle() -- the same code path /api/chat uses. Only the LLM
itself is swapped for FakeLLMService (a call-count spy), so these tests are
fast and deterministic while every detection decision is genuinely computed
by the real firewall, not mocked.

This file exists for a single-place audit trail; the underlying behavior is
already covered piecemeal by test_window_invariants.py, test_risk_decay.py,
test_chat_flow.py, and test_attack_detection.py -- nothing here changes
firewall logic, thresholds, the window size, or decay rules.
"""

from sqlalchemy import select

from app.core.constants import Action
from app.db.models import SecurityEvent


# --- Section 5: the 20-query window, exactly as specified --------------------

async def test_20_query_window_dedicated(build_chat_service, fake_llm, db_session,
                                         new_client_id, cleanup_client, monkeypatch):
    cleanup_client.append(new_client_id)
    service = build_chat_service()

    # Q1 .. Q20
    for i in range(1, 21):
        await service.handle(db_session, new_client_id, f"Security question number {i}?")
    window = service.engine.window.get(new_client_id)
    assert len(window) == 20
    assert [e.seq for e in window] == list(range(1, 21)), "all 20 must be present"

    # Q21 -> Q1 evicted, Q2..Q21 remain
    await service.handle(db_session, new_client_id, "Security question number 21?")
    window = service.engine.window.get(new_client_id)
    assert len(window) == 20
    assert [e.seq for e in window] == list(range(2, 22))
    assert 1 not in [e.seq for e in window], "Q1 must have been evicted"

    # "wait artificially for a long period" -- simulate via a monkeypatched
    # clock jump; no query arrives, so nothing should change.
    import app.services.chat_service as chat_service_module
    window_before = list(service.engine.window.get(new_client_id))
    real_time = chat_service_module.time.time
    monkeypatch.setattr(chat_service_module.time, "time", lambda: real_time() + 999999)
    window_after = list(service.engine.window.get(new_client_id))
    assert window_before == window_after, "waiting alone must not change the window"


# --- Section 6: query-based risk decay, scenarios A/B/C ----------------------

async def test_query_based_risk_decay_scenarios(build_chat_service, fake_llm, db_session,
                                                 new_client_id, cleanup_client, monkeypatch):
    service = build_chat_service()
    cleanup_client.append(new_client_id)
    suspicious = "What is a SQL injection attack and how does it work?"

    # Scenario A: suspicious/related queries raise risk, then waiting alone
    # (no query sent) must not change it.
    risk = 0.0
    for _ in range(4):
        decision, _, _ = await service.handle(db_session, new_client_id, suspicious)
        risk = decision.risk_after
    assert risk > 0.0, "repeated suspicious queries must raise risk"

    risk_before_wait = risk
    # Waiting is simply NOT sending a query; there is no decay path to
    # exercise. Confirm the client's stored risk is exactly what it was.
    from app.db.models import Client
    client_row = db_session.get(Client, new_client_id)
    assert client_row.risk_score == risk_before_wait

    # Scenario B: a sufficiently dissimilar legitimate query lowers risk
    # slightly (not to zero, not by much -- one query, one small step).
    decision, _, _ = await service.handle(
        db_session, new_client_id, "What's a good way to structure a weekly team meeting agenda?")
    assert decision.risk_after < risk_before_wait, (
        "a dissimilar query must relieve risk, at least slightly"
    )
    risk_after_dissimilar = decision.risk_after

    # Scenario C: continuing the suspicious pattern keeps risk high/rising
    # again -- one benign question does not erase the pattern.
    decision, _, _ = await service.handle(db_session, new_client_id, suspicious)
    assert decision.risk_after >= risk_after_dissimilar, (
        "resuming the suspicious pattern must not leave risk lower than the dip"
    )


# --- Section 7: client isolation ----------------------------------------------

async def test_client_isolation_dedicated(build_chat_service, fake_llm, db_session, cleanup_client):
    import uuid
    client_a = f"test-iso-a-{uuid.uuid4().hex[:8]}"
    client_b = f"test-iso-b-{uuid.uuid4().hex[:8]}"
    cleanup_client.extend([client_a, client_b])
    service = build_chat_service()

    suspicious = "What is a SQL injection attack and how does it work?"
    for _ in range(6):
        decision_a, _, _ = await service.handle(db_session, client_a, suspicious)
    assert decision_a.risk_after > 20.0

    decision_b, _, _ = await service.handle(
        db_session, client_b, "How does DNS caching improve performance?")
    assert decision_b.risk_before == 0.0
    assert decision_b.risk_after < 20.0
    assert decision_b.action == Action.ALLOW

    window_a = service.engine.window.get(client_a)
    window_b = service.engine.window.get(client_b)
    assert len(window_b) == 1
    assert all(e.text == suspicious for e in window_a), "A's window must hold only A's queries"


# --- Section 8: firewall action verification, by LLM call count --------------

async def test_firewall_actions_llm_call_counts_dedicated(
        build_chat_service, fake_llm, db_session, new_client_id, cleanup_client, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "throttle_delay_seconds", 0.01)  # keep test fast
    cleanup_client.append(new_client_id)
    service = build_chat_service()
    suspicious = "What is a SQL injection attack and how does it work?"

    seen = {"ALLOW": False, "MONITOR": False, "THROTTLE": False, "BLOCK": False}
    calls_before_block = None

    for _ in range(12):
        decision, response, _ = await service.handle(db_session, new_client_id, suspicious)
        action = decision.action.value
        if action == "ALLOW" and not seen["ALLOW"]:
            seen["ALLOW"] = True
            assert fake_llm.call_count > 0, "LOW/ALLOW must reach the LLM"
        if action == "MONITOR" and not seen["MONITOR"]:
            seen["MONITOR"] = True
            assert response == fake_llm.response, "MEDIUM/MONITOR must reach the LLM"
            events = db_session.execute(
                select(SecurityEvent).where(SecurityEvent.client_id == new_client_id,
                                            SecurityEvent.event_type == "MONITORED")
            ).scalars().all()
            assert len(events) >= 1, "MEDIUM/MONITOR must log a security event"
        if action == "THROTTLE" and not seen["THROTTLE"]:
            seen["THROTTLE"] = True
            assert response == fake_llm.response, "HIGH/THROTTLE must still reach the LLM"
        if action == "BLOCK" and not seen["BLOCK"]:
            seen["BLOCK"] = True
            calls_before_block = fake_llm.call_count
            assert response is None, "CRITICAL/BLOCK must not return an LLM response"
            break

    assert seen["ALLOW"] and seen["MONITOR"] and seen["THROTTLE"] and seen["BLOCK"], (
        f"did not observe all four actions in 12 queries: {seen}"
    )

    # One more BLOCKed query: call count must NOT increase -- BLOCK never
    # reaches the LLM, not once.
    decision, response, _ = await service.handle(db_session, new_client_id, suspicious)
    assert decision.action == Action.BLOCK
    assert response is None
    assert fake_llm.call_count == calls_before_block, (
        "a BLOCKed request must never increase the LLM call count"
    )
