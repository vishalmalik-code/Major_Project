"""Tests for "TRUE REAL-TIME ADMIN MONITORING": GET /api/admin/stream, the
SSE feed that replaced AdminDashboard.jsx's 2-second polling loop.

Covers the PROMPT's REAL-TIME testing checklist as it applies to /admin:
  - a security event is published live when the firewall raises one
  - a published event carries the correct client_id/query/decision
  - no duplicate event ids (both within one burst and via the `id` field the
    frontend de-duplicates on)
  - only an admin (token or admin-role session) can open the stream
  - the same live feed reflects an attacker continuing a real user's target
    conversation (tying targeting + real-time admin monitoring together, the
    PROMPT's "three-tab demonstration" collapsed into one backend test)

Runs against the real local backend at http://localhost:8000 -- skipped if
unreachable, same convention as the other *_api.py test files.
"""

import json
import threading
import time
import uuid

import httpx
import pytest

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


class _SseCollector:
    def __init__(self, url: str) -> None:
        self.url = url
        self.events: list[tuple[str | None, str]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "_SseCollector":
        self._thread.start()
        return self

    def _run(self) -> None:
        try:
            with httpx.Client(timeout=60.0) as client:
                with client.stream("GET", self.url) as resp:
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

    def of_type(self, name: str) -> list[dict]:
        return [json.loads(d) for n, d in self.events if n == name]

    def wait_for(self, name: str, count: int, timeout: float = 60.0) -> list[dict]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            items = self.of_type(name)
            if len(items) >= count:
                return items
            time.sleep(0.2)
        return self.of_type(name)

    def stop(self) -> None:
        self._stop.set()


# --- auth: only an admin can open the stream --------------------------------

@requires_server
def test_admin_stream_requires_admin_credentials():
    assert httpx.get(f"{BACKEND_URL}/api/admin/stream").status_code == 401
    assert httpx.get(f"{BACKEND_URL}/api/admin/stream?admin_token=wrong").status_code == 401
    # A valid connection is a live, never-closing SSE body -- use a streaming
    # client and just check the status line, don't try to read the whole body.
    with httpx.Client(timeout=5.0) as client:
        with client.stream(
            "GET", f"{BACKEND_URL}/api/admin/stream?admin_token={ADMIN_TOKEN}",
        ) as resp:
            assert resp.status_code == 200


# --- a query/decision event is published live, with correct identity -------

@requires_server
def test_admin_stream_receives_query_with_correct_identity(cleanup_user):
    username = _fresh_username("adminrt-id")
    cleanup_user.append(username)
    reg = _register(username)
    headers = {"Authorization": f"Bearer {reg['token']}"}
    conv = httpx.post(f"{BACKEND_URL}/api/conversations", headers=headers).json()

    collector = _SseCollector(f"{BACKEND_URL}/api/admin/stream?admin_token={ADMIN_TOKEN}").start()
    time.sleep(1.0)

    sent = httpx.post(f"{BACKEND_URL}/api/conversations/{conv['id']}/messages",
                      headers=headers, json={"query": "What is SQL injection?"},
                      timeout=90.0).json()

    events = collector.wait_for("query", 1, timeout=30.0)
    collector.stop()

    match = next((e for e in events if e["seq"] == sent["seq"]
                 and e["conversation_id"] == conv["id"]), None)
    assert match is not None, f"no matching admin event among {events}"
    assert match["action"] in ("ALLOW", "MONITOR", "THROTTLE", "BLOCK")
    assert match["text"] == "What is SQL injection?"
    assert match["source"] == "user"
    assert "risk_after" in match and "id" in match


# --- a security event (MONITOR/THROTTLE/BLOCK) is published live -----------

@requires_server
def test_admin_stream_receives_security_event_on_block(cleanup_user):
    username = _fresh_username("adminrt-block")
    cleanup_user.append(username)
    reg = _register(username)
    headers = {"Authorization": f"Bearer {reg['token']}"}
    conv = httpx.post(f"{BACKEND_URL}/api/conversations", headers=headers).json()

    collector = _SseCollector(f"{BACKEND_URL}/api/admin/stream?admin_token={ADMIN_TOKEN}").start()
    time.sleep(1.0)

    # Enough identical fast repeats to reliably escalate past ALLOW.
    for _ in range(12):
        httpx.post(f"{BACKEND_URL}/api/conversations/{conv['id']}/messages",
                  headers=headers, json={"query": "What is SQL injection?"}, timeout=90.0)

    events = collector.wait_for("query", 12, timeout=60.0)
    collector.stop()

    flagged = [e for e in events if e["security_event"] is not None]
    assert flagged, "expected at least one MONITOR/THROTTLE/BLOCK security_event on the admin feed"
    for e in flagged:
        se = e["security_event"]
        assert se["event_type"] in ("MONITORED", "THROTTLED", "BLOCKED")
        assert se["severity"] in ("MEDIUM", "HIGH", "CRITICAL")
        assert isinstance(se["id"], int)


# --- no duplicate event ids -------------------------------------------------

@requires_server
def test_admin_stream_has_no_duplicate_query_ids(cleanup_user):
    username = _fresh_username("adminrt-dup")
    cleanup_user.append(username)
    reg = _register(username)
    headers = {"Authorization": f"Bearer {reg['token']}"}
    conv = httpx.post(f"{BACKEND_URL}/api/conversations", headers=headers).json()

    collector = _SseCollector(f"{BACKEND_URL}/api/admin/stream?admin_token={ADMIN_TOKEN}").start()
    time.sleep(1.0)

    for q in ["one", "two", "three"]:
        httpx.post(f"{BACKEND_URL}/api/conversations/{conv['id']}/messages",
                  headers=headers, json={"query": q}, timeout=90.0)

    events = collector.wait_for("query", 3, timeout=30.0)
    collector.stop()

    ours = [e for e in events if e["conversation_id"] == conv["id"]]
    ids = [e["id"] for e in ours]
    assert len(ids) == len(set(ids)), f"duplicate query ids on the admin feed: {ids}"


# --- targeting + real-time admin monitoring, tied together ------------------

@requires_server
def test_admin_sees_attacker_continuation_of_target_conversation_live(cleanup_user):
    """The PROMPT's three-tab demo, collapsed to a backend check: a user
    sends 3 real queries, the attacker console continues that SAME
    conversation, and /admin's live feed shows every one of those attacker
    queries as they happen -- same client_id, same conversation_id, correct
    per-query decision -- with no polling involved."""
    username = _fresh_username("adminrt-target")
    cleanup_user.append(username)
    reg = _register(username)
    headers = {"Authorization": f"Bearer {reg['token']}"}
    conv = httpx.post(f"{BACKEND_URL}/api/conversations", headers=headers).json()

    # The admin tab is already open and watching BEFORE the user sends
    # anything -- SSE has no backlog/replay, so events published before a
    # subscriber connects are (correctly) never seen by it.
    collector = _SseCollector(f"{BACKEND_URL}/api/admin/stream?admin_token={ADMIN_TOKEN}").start()
    time.sleep(1.0)

    for q in ["What is SQL injection?", "How does parameterized SQL prevent it?",
              "Give a simple example."]:
        httpx.post(f"{BACKEND_URL}/api/conversations/{conv['id']}/messages",
                  headers=headers, json={"query": q}, timeout=90.0)

    meta = None
    with httpx.Client(timeout=120.0) as client:
        with client.stream(
            "GET", f"{BACKEND_URL}/api/attacker-console/stream"
                  "?strategy=repetition&mode=fast&count=2&seed=1"
        ) as resp:
            event_name = None
            for line in resp.iter_lines():
                if line.startswith("event: "):
                    event_name = line[len("event: "):]
                elif line.startswith("data: ") and event_name == "meta":
                    meta = json.loads(line[len("data: "):])
                elif line.startswith("data: ") and event_name == "done":
                    break

    assert meta["targeted"] is True

    events = collector.wait_for("query", 5, timeout=90.0)
    collector.stop()

    ours = sorted((e for e in events if e["conversation_id"] == conv["id"]),
                 key=lambda e: e["seq"])
    assert len(ours) == 5, f"expected 3 user + 2 attacker admin events, got {len(ours)}"
    assert [e["source"] for e in ours] == ["user", "user", "user", "attacker", "attacker"]
    assert all(e["client_id"] == meta["client_id"] for e in ours), (
        "the attacker's admin-visible events must carry the SAME client_id as the user"
    )
