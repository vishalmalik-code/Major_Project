"""Tests for "CONNECT ATTACKER TO THE ACTIVE LLM CHAT IN REAL TIME": the
attacker console continuing a real user's already-open /chat conversation,
live, over the conversation's SSE stream.

Covers the PROMPT's testing checklist (section 26):
  1.  Active conversation can be targeted.
  2.  Attacker query enters the SAME conversation.
  3.  Attacker query continues the conversation's message sequence.
  4.  If the user already sent 3 queries, the attacker starts at seq 4.
  5.  Attacker uses the same firewall/security context (client_id) as the
      target session.
  6.  Attacker query is persisted.
  7.  LLM response is persisted.
  8.  A blocked query has no fake assistant response.
  9.  The open /chat SSE stream receives the new attacker query live.
  10. ...and the model response, live.
  11. No duplicate messages (one `message` event per persisted query).
  12. User A cannot be targeted by an attack meant for/reached via User B.
  13. Attacker (the console's own routes) cannot reach admin APIs.

Runs against the real local backend at http://localhost:8000 with the real
firewall, DB, and Ollama -- skipped if unreachable, same convention as
test_conversations_api.py and test_attacker_console.py.
"""

import json
import threading
import time
import uuid

import httpx
import pytest
from sqlalchemy import text

BACKEND_URL = "http://localhost:8000"
ADMIN_TOKEN = "change-me-local-only"


def _server_reachable() -> bool:
    try:
        r = httpx.get(f"{BACKEND_URL}/api/health", timeout=3.0)
        return r.status_code == 200
    except httpx.HTTPError:
        return False


requires_server = pytest.mark.skipif(
    not _server_reachable(),
    reason="backend server not reachable at http://localhost:8000",
)


def _fresh_username(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _register(username: str) -> dict:
    r = httpx.post(f"{BACKEND_URL}/api/auth/register",
                   json={"username": username, "password": "correct-horse-battery"})
    assert r.status_code == 200, r.text
    return r.json()


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _send(headers: dict, conv_id: int, query: str) -> dict:
    r = httpx.post(f"{BACKEND_URL}/api/conversations/{conv_id}/messages",
                   headers=headers, json={"query": query}, timeout=90.0)
    assert r.status_code == 200, r.text
    return r.json()


class _SseCollector:
    """Live-appends (event, data) tuples from an SSE endpoint on a background
    thread, so a test can start an attack and observe events arriving in
    real time rather than only after the whole connection closes."""

    def __init__(self, url: str, headers: dict | None = None) -> None:
        self.url = url
        self.headers = headers or {}
        self.events: list[tuple[str | None, str]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "_SseCollector":
        self._thread.start()
        return self

    def _run(self) -> None:
        try:
            with httpx.Client(timeout=60.0) as client:
                with client.stream("GET", self.url, headers=self.headers) as resp:
                    event_name = None
                    for line in resp.iter_lines():
                        if self._stop.is_set():
                            return
                        if line.startswith("event: "):
                            event_name = line[len("event: "):]
                        elif line.startswith("data: "):
                            self.events.append((event_name, line[len("data: "):]))
        except httpx.HTTPError:
            return

    def messages(self) -> list[dict]:
        return [json.loads(d) for name, d in self.events if name == "message"]

    def wait_for_messages(self, count: int, timeout: float = 60.0) -> list[dict]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            msgs = self.messages()
            if len(msgs) >= count:
                return msgs
            time.sleep(0.25)
        return self.messages()

    def stop(self) -> None:
        self._stop.set()


def _run_attack_and_collect(strategy: str, count: int, seed: int = 1,
                            client_id: str | None = None) -> tuple[dict, list[dict]]:
    """Runs an attacker-console SSE stream to completion, returning the
    parsed `meta` event and every `query` event."""
    params = f"strategy={strategy}&mode=fast&count={count}&seed={seed}"
    if client_id:
        params += f"&client_id={client_id}"
    meta = None
    queries = []
    with httpx.Client(timeout=180.0) as client:
        with client.stream("GET", f"{BACKEND_URL}/api/attacker-console/stream?{params}") as resp:
            event_name = None
            for line in resp.iter_lines():
                if line.startswith("event: "):
                    event_name = line[len("event: "):]
                elif line.startswith("data: "):
                    data = json.loads(line[len("data: "):])
                    if event_name == "meta":
                        meta = data
                    elif event_name == "query":
                        queries.append(data)
                    elif event_name == "done":
                        break
    return meta, queries


# --- items 1, 5, 14: target becomes available, only exposes a boolean -------

@requires_server
def test_active_conversation_becomes_target(cleanup_user):
    username = _fresh_username("tgt-avail")
    cleanup_user.append(username)
    reg = _register(username)
    headers = _auth(reg["token"])

    conv = httpx.post(f"{BACKEND_URL}/api/conversations", headers=headers).json()

    status = httpx.get(f"{BACKEND_URL}/api/attacker-console/target").json()
    assert status == {"available": True}, (
        "the target status endpoint must expose availability only -- no "
        "client_id/conversation_id/username (PROMPT section 14/25)"
    )
    _ = conv  # conversation created is what made the target available


# --- items 2, 3, 4, 5, 6, 7: same conversation, continuing seq, same client_id --

@requires_server
def test_attacker_continues_same_conversation_from_next_seq(cleanup_user):
    username = _fresh_username("tgt-continue")
    cleanup_user.append(username)
    reg = _register(username)
    headers = _auth(reg["token"])

    conv = httpx.post(f"{BACKEND_URL}/api/conversations", headers=headers).json()
    conv_id = conv["id"]
    for q in ["What is SQL injection?", "How does parameterized SQL prevent it?",
              "Give a simple example."]:
        _send(headers, conv_id, q)

    meta, queries = _run_attack_and_collect("repetition", count=2, seed=1)
    assert meta["targeted"] is True
    assert len(queries) == 2
    assert queries[0]["response"], "an ALLOWed attacker query must carry a real LLM response"

    detail = httpx.get(f"{BACKEND_URL}/api/conversations/{conv_id}", headers=headers).json()
    assert len(detail["messages"]) == 5, "3 user + 2 attacker turns in ONE conversation"
    seqs = [m["seq"] for m in detail["messages"]]
    assert seqs == [1, 2, 3, 4, 5], "attacker must continue the SAME per-client seq counter"
    assert [m["source"] for m in detail["messages"]] == \
        ["user", "user", "user", "attacker", "attacker"]

    # item 5: same client_id/firewall context -- confirmed via the admin
    # window, which is keyed by client_id and must show all 5 queries.
    admin = httpx.get(f"{BACKEND_URL}/api/admin/clients/{meta['client_id']}",
                      headers={"X-Admin-Token": ADMIN_TOKEN}).json()
    assert len(admin["window"]) == 5


# --- item 8: blocked attacker query has no fake response, live or persisted -

@requires_server
def test_blocked_attacker_query_has_no_fake_response(cleanup_user):
    username = _fresh_username("tgt-block")
    cleanup_user.append(username)
    reg = _register(username)
    headers = _auth(reg["token"])

    conv = httpx.post(f"{BACKEND_URL}/api/conversations", headers=headers).json()
    conv_id = conv["id"]
    _send(headers, conv_id, "What is SQL injection?")

    # 15 fast, identical repeats reliably drives repetition risk into BLOCK
    # (see test_attacker_console.py's equivalent, unblocked-view assertion).
    meta, queries = _run_attack_and_collect("repetition", count=15, seed=1)
    blocked = [q for q in queries if q["response"] is None]
    assert blocked, "expected at least one BLOCK among 15 fast identical repeats"
    for q in blocked:
        assert set(q.keys()) == {"query_number", "query", "response"}, (
            "no decision/risk/notice may leak into the attacker-facing stream"
        )

    detail = httpx.get(f"{BACKEND_URL}/api/conversations/{conv_id}", headers=headers).json()
    persisted_blocked = [m for m in detail["messages"]
                         if m["source"] == "attacker" and m["response"] is None]
    assert persisted_blocked, "the block must be persisted, with response left null (not faked)"


# --- items 9, 10, 11: live SSE delivery to the open /chat tab ---------------

@requires_server
def test_chat_stream_receives_attacker_messages_live_without_duplicates(cleanup_user):
    username = _fresh_username("tgt-live")
    cleanup_user.append(username)
    reg = _register(username)
    headers = _auth(reg["token"])

    conv = httpx.post(f"{BACKEND_URL}/api/conversations", headers=headers).json()
    conv_id = conv["id"]
    _send(headers, conv_id, "What is SQL injection?")

    collector = _SseCollector(
        f"{BACKEND_URL}/api/conversations/{conv_id}/stream?token={reg['token']}"
    ).start()
    time.sleep(1.0)  # let the SSE connection establish before the attack starts

    meta, queries = _run_attack_and_collect("minimal_modification", count=3, seed=2)
    assert meta["targeted"] is True

    live = collector.wait_for_messages(3, timeout=60.0)
    collector.stop()

    assert len(live) == 3, f"expected 3 live 'message' events, got {len(live)}"
    seqs = [m["seq"] for m in live]
    assert seqs == sorted(seqs) and len(set(seqs)) == 3, (
        "no duplicate/out-of-order live messages"
    )
    assert all(m["source"] == "attacker" for m in live)
    assert all(m["response"] for m in live), "live events must carry the real LLM response"
    for m in live:
        assert set(m.keys()) == {"seq", "query", "response", "source", "created_at"}


# --- item 12: cross-user isolation -------------------------------------------

@requires_server
def test_user_a_target_not_reachable_by_user_b(cleanup_user, db_session):
    user_a = _fresh_username("tgt-iso-a")
    user_b = _fresh_username("tgt-iso-b")
    cleanup_user.extend([user_a, user_b])
    reg_a = _register(user_a)
    reg_b = _register(user_b)

    conv_a = httpx.post(f"{BACKEND_URL}/api/conversations", headers=_auth(reg_a["token"])).json()
    _send(_auth(reg_a["token"]), conv_a["id"], "hello")  # A is now the active target

    r = httpx.get(f"{BACKEND_URL}/api/conversations/{conv_a['id']}/stream"
                 f"?token={reg_b['token']}")
    assert r.status_code == 404, "User B must not be able to open User A's conversation stream"

    a_client_id = db_session.execute(
        text("SELECT client_id FROM users WHERE username = :u"), {"u": user_a}
    ).scalar_one()

    # B becomes the active target, moving target_registry away from A.
    httpx.post(f"{BACKEND_URL}/api/conversations", headers=_auth(reg_b["token"]))

    # A forged /api/chat call carrying A's REAL client_id but A's real
    # conversation_id must NOT be honored once the registry points at B --
    # the (client_id, conversation_id) pair no longer matches.
    forged = httpx.post(f"{BACKEND_URL}/api/chat", json={
        "client_id": a_client_id, "query": "forged", "conversation_id": conv_a["id"],
    })
    assert forged.status_code == 200  # /api/chat itself still succeeds (unauth by design)...
    detail = httpx.get(f"{BACKEND_URL}/api/conversations/{conv_a['id']}",
                       headers=_auth(reg_a["token"])).json()
    assert not any(m["query"] == "forged" for m in detail["messages"]), (
        "a conversation_id that isn't the CURRENTLY registered target must never be honored, "
        "even paired with a real client_id"
    )


# --- item 13: attacker console cannot reach admin ----------------------------

@requires_server
def test_attacker_console_routes_carry_no_admin_access():
    """The attacker console's own surface (/api/attacker-console/*) has no
    dependency on require_admin and returns no admin-gated data; a caller
    with only that surface available still can't reach /api/admin/*."""
    r = httpx.get(f"{BACKEND_URL}/api/admin/stats")
    assert r.status_code == 401
    status = httpx.get(f"{BACKEND_URL}/api/attacker-console/target")
    assert status.status_code == 200
    assert set(status.json().keys()) == {"available"}


# --- regression: explicit client_id (CLI-style) still bypasses targeting ----

@requires_server
def test_explicit_client_id_bypasses_auto_targeting(cleanup_user):
    """Existing test_attacker_console.py behavior must be unaffected: passing
    an explicit client_id always wins over auto-targeting, even while a real
    target is active."""
    username = _fresh_username("tgt-bypass")
    cleanup_user.append(username)
    reg = _register(username)
    headers = _auth(reg["token"])
    conv = httpx.post(f"{BACKEND_URL}/api/conversations", headers=headers).json()
    _send(headers, conv["id"], "hello")

    standalone_id = f"test-standalone-{uuid.uuid4().hex[:8]}"
    meta, queries = _run_attack_and_collect("repetition", count=1, seed=1,
                                            client_id=standalone_id)
    assert meta["client_id"] == standalone_id
    assert meta["targeted"] is False

    httpx.post(f"{BACKEND_URL}/api/admin/clients/{standalone_id}/reset",
              headers={"X-Admin-Token": ADMIN_TOKEN})
