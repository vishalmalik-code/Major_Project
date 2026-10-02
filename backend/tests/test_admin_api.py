"""Admin API authorization and shape tests (Prompt 5, section 10-11, 13).

Covers the checklist:
  2. Normal user cannot access admin APIs (no token -> 401).
  3. Wrong token -> 401.
  4/5/6/7/8. Admin (correct token) can reach every admin endpoint and gets
     the expected shape.
  11. The chat response schema never leaks signals/internal detection data
      to a non-admin caller (regression against Prompt 2/5's "no internal
      firewall info to normal users" rule).

Runs against the real local backend at http://localhost:8000 (same
convention as test_llm_service.py and test_attacker_cli.py) -- skipped if
it isn't reachable.
"""

import httpx
import pytest

from app.core.config import settings

BACKEND_URL = "http://localhost:8000"
GOOD_TOKEN = settings.admin_token
BAD_TOKEN = "definitely-not-the-token"

ADMIN_GET_ENDPOINTS = [
    "/api/admin/stats",
    "/api/admin/clients",
    "/api/admin/events",
    "/api/admin/queries",
    "/api/admin/evaluation",
    "/api/admin/attack-runs",
    "/api/admin/config",
]


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


@requires_server
@pytest.mark.parametrize("path", ADMIN_GET_ENDPOINTS)
def test_admin_endpoint_requires_token(path):
    """A normal client with no X-Admin-Token must be refused."""
    r = httpx.get(f"{BACKEND_URL}{path}")
    assert r.status_code == 401


@requires_server
@pytest.mark.parametrize("path", ADMIN_GET_ENDPOINTS)
def test_admin_endpoint_rejects_wrong_token(path):
    r = httpx.get(f"{BACKEND_URL}{path}", headers={"X-Admin-Token": BAD_TOKEN})
    assert r.status_code == 401


@requires_server
@pytest.mark.parametrize("path", ADMIN_GET_ENDPOINTS)
def test_admin_endpoint_accepts_correct_token(path):
    r = httpx.get(f"{BACKEND_URL}{path}", headers={"X-Admin-Token": GOOD_TOKEN})
    assert r.status_code == 200


@requires_server
def test_admin_stats_shape():
    r = httpx.get(f"{BACKEND_URL}/api/admin/stats", headers={"X-Admin-Token": GOOD_TOKEN})
    body = r.json()
    for key in ("total_queries", "suspicious_queries", "throttled", "blocked",
               "unique_clients", "clients_at_risk", "by_action"):
        assert key in body


@requires_server
def test_admin_clients_have_highest_risk_field():
    r = httpx.get(f"{BACKEND_URL}/api/admin/clients", headers={"X-Admin-Token": GOOD_TOKEN})
    body = r.json()
    if body:
        assert "highest_risk" in body[0]
        assert body[0]["highest_risk"] >= 0.0


@requires_server
def test_admin_client_detail_has_window_size_and_counts():
    clients = httpx.get(f"{BACKEND_URL}/api/admin/clients",
                        headers={"X-Admin-Token": GOOD_TOKEN}).json()
    if not clients:
        pytest.skip("no clients recorded yet")
    client_id = clients[0]["client_id"]
    r = httpx.get(f"{BACKEND_URL}/api/admin/clients/{client_id}",
                  headers={"X-Admin-Token": GOOD_TOKEN})
    body = r.json()
    assert body["window_size"] == 20
    assert "throttle_count" in body
    assert "block_count" in body
    # the window must be in query order (ascending seq), not reverse-chron
    seqs = [q["seq"] for q in body["window"]]
    assert seqs == sorted(seqs)
    assert len(body["window"]) <= body["window_size"]


@requires_server
def test_admin_evaluation_never_fabricates_when_unavailable(monkeypatch, tmp_path):
    """If no evaluation has been run, the endpoint must say so honestly
    rather than inventing numbers. Simulated by pointing the route's search
    at an empty directory via monkeypatching Path resolution is awkward for
    a live-server test, so instead this just asserts the CONTRACT: whatever
    comes back, `available` implies non-empty `sessions` and vice versa."""
    r = httpx.get(f"{BACKEND_URL}/api/admin/evaluation",
                  headers={"X-Admin-Token": GOOD_TOKEN})
    body = r.json()
    if body["available"]:
        assert len(body["sessions"]) > 0
        assert body["run_id"] is not None
    else:
        assert body["sessions"] == []


@requires_server
def test_chat_response_never_includes_signals_or_internal_fields():
    """The normal-user-facing /api/chat response must never leak signal
    breakdowns, weights, or thresholds -- those are admin-only."""
    # A real Ollama generation regularly takes well past httpx's 5s default
    # timeout -- this isn't a hung server, just a normal LLM response time.
    r = httpx.post(f"{BACKEND_URL}/api/chat",
                   json={"client_id": "test-admin-api-leak-check",
                        "query": "What is authorization vs authentication?"},
                   timeout=90.0)
    body = r.json()
    forbidden_keys = {"signals", "signal_scores", "weights", "thresholds",
                      "evidence"}
    assert forbidden_keys.isdisjoint(body.keys()), (
        f"chat response leaked internal keys: {forbidden_keys & body.keys()}"
    )
    httpx.post(f"{BACKEND_URL}/api/admin/clients/test-admin-api-leak-check/reset",
              headers={"X-Admin-Token": GOOD_TOKEN})


@requires_server
def test_normal_client_cannot_reach_admin_reset_without_token():
    r = httpx.post(f"{BACKEND_URL}/api/admin/clients/some-client/reset")
    assert r.status_code == 401
