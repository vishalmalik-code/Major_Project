"""Tests for the /attacker web UI's backend surface: the SSE streaming route
at GET /api/attacker-console/stream.

Covers this feature's testing checklist:
  4. Attacker queries go through /api/chat.
  5. Attacker never calls Ollama directly.
  11. Live query stream updates correctly (meta -> query* -> done shape).
  13. BLOCK actually stops future LLM requests (already covered generally by
      test_chat_flow.py; here we confirm the console path exercises the same
      real firewall, not a shortcut).

Also covers the attacker/admin information separation added afterwards: the
SSE payload sent to the browser must never carry decision, risk_score,
risk_band, notice, or error -- only query_number, query, and response. A
blocked query must still be recorded internally (visible to /admin) even
though the attacker-facing stream shows nothing but a missing response.

Runs against the real local backend at http://localhost:8000 (same
convention as the other *_cli test files) -- skipped if unreachable.
"""

import ast
import uuid
from pathlib import Path

import httpx
import pytest

BACKEND_URL = "http://localhost:8000"
ROUTE_FILE = Path(__file__).parent.parent / "app" / "api" / "routes" / "attacker_console.py"


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


# --- item 5: never calls Ollama directly, never touches firewall internals --

def test_route_file_imports_no_firewall_or_ollama_internals():
    """Static check of the route module's own import list: it must only
    depend on the pure strategy registry and the HTTP-only attacker_cli
    client -- the same guarantee attacker.py's CLI gives, now for the web
    path. A regression here (e.g. someone importing ChatService or
    LLMService "for convenience") would silently reopen the bypass this
    feature was explicitly required not to have."""
    tree = ast.parse(ROUTE_FILE.read_text())
    imported_modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.add(alias.name)

    forbidden_prefixes = ("app.firewall", "app.db", "app.services", "app.llm")
    hits = [m for m in imported_modules if m.startswith(forbidden_prefixes)]
    assert not hits, f"attacker_console.py must not import: {hits}"
    assert "httpx" not in imported_modules, (
        "attacker_console.py must not make its own HTTP calls (e.g. to "
        "Ollama) -- it must only delegate to attacker_cli.http_client, "
        "which itself only ever POSTs to /api/chat"
    )


# --- items 4, 11: real streamed events, real /api/chat round trip ------------

@requires_server
def test_stream_emits_meta_then_query_then_done_with_real_data():
    client_id = f"test-console-{uuid.uuid4().hex[:8]}"
    events = list(_read_sse(
        f"{BACKEND_URL}/api/attacker-console/stream"
        f"?strategy=repetition&mode=fast&count=2&seed=1&client_id={client_id}"
    ))

    kinds = [e[0] for e in events]
    assert kinds[0] == "meta"
    assert kinds[-1] == "done"
    assert kinds.count("query") == 2

    import json
    meta = json.loads(events[0][1])
    assert meta["client_id"] == client_id
    assert meta["total"] == 2

    first_query = json.loads(events[1][1])
    assert first_query["query_number"] == 1
    assert set(first_query.keys()) == {"query_number", "query", "response"}
    assert first_query["response"], "a real LLM response must be present for ALLOW"

    done = json.loads(events[-1][1])
    assert done["status"] == "completed"

    httpx.post(f"{BACKEND_URL}/api/admin/clients/{client_id}/reset",
              headers={"X-Admin-Token": "change-me-local-only"})


@requires_server
def test_stream_hides_decision_on_block_but_admin_still_records_it():
    """The attacker-facing checklist's core requirement: a blocked query must
    arrive at the browser indistinguishable from any other missing response
    (no decision/risk/notice leaked), while /admin -- an entirely separate,
    token-gated surface -- still has the real block recorded."""
    client_id = f"test-console-{uuid.uuid4().hex[:8]}"
    events = list(_read_sse(
        f"{BACKEND_URL}/api/attacker-console/stream"
        f"?strategy=repetition&mode=fast&count=20&seed=1&client_id={client_id}"
    ))

    import json
    query_events = [json.loads(d) for name, d in events if name == "query"]
    forbidden = {"decision", "risk_score", "risk_band", "notice", "error"}
    for q in query_events:
        assert forbidden.isdisjoint(q.keys()), (
            f"attacker stream leaked internal keys: {forbidden & q.keys()}"
        )
        assert set(q.keys()) == {"query_number", "query", "response"}

    assert any(q["response"] is None for q in query_events), (
        "repeating the same query 20x fast should trigger at least one "
        "BLOCK internally -- if none were blocked this test can't prove "
        "the hide-on-block behavior actually happened"
    )

    admin = httpx.get(f"{BACKEND_URL}/api/admin/clients/{client_id}",
                      headers={"X-Admin-Token": "change-me-local-only"})
    assert admin.status_code == 200
    assert admin.json()["block_count"] >= 1, (
        "the firewall must still record the block internally for /admin "
        "even though the attacker-facing stream hid it"
    )

    httpx.post(f"{BACKEND_URL}/api/admin/clients/{client_id}/reset",
              headers={"X-Admin-Token": "change-me-local-only"})


@requires_server
def test_stream_client_id_matches_what_firewall_recorded():
    """The client_id the stream reports must be the exact one the firewall
    used to key its window/risk state -- proving this path really goes
    through the same client-isolated /api/chat mechanism, not a shortcut."""
    client_id = f"test-console-{uuid.uuid4().hex[:8]}"
    list(_read_sse(
        f"{BACKEND_URL}/api/attacker-console/stream"
        f"?strategy=repetition&mode=fast&count=1&seed=1&client_id={client_id}"
    ))

    admin = httpx.get(f"{BACKEND_URL}/api/admin/clients/{client_id}",
                      headers={"X-Admin-Token": "change-me-local-only"})
    assert admin.status_code == 200
    assert admin.json()["client_id"] == client_id
    assert len(admin.json()["window"]) == 1

    httpx.post(f"{BACKEND_URL}/api/admin/clients/{client_id}/reset",
              headers={"X-Admin-Token": "change-me-local-only"})


def _read_sse(url: str):
    """Minimal SSE reader: yields (event_name, data_str) tuples."""
    with httpx.Client(timeout=90.0) as client:
        with client.stream("GET", url) as resp:
            event_name = None
            for line in resp.iter_lines():
                if line.startswith("event: "):
                    event_name = line[len("event: "):]
                elif line.startswith("data: "):
                    yield event_name, line[len("data: "):]
