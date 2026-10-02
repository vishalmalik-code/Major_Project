"""Admin user-monitoring tests (Part 27's ADMIN checklist, extending
test_admin_api.py's coverage to the new /api/admin/users* surface).

Runs against the real local backend at http://localhost:8000 -- skipped if
it isn't reachable.
"""

import uuid

import httpx
import pytest

from app.core.config import settings

BACKEND_URL = "http://localhost:8000"
GOOD_TOKEN = settings.admin_token
BAD_TOKEN = "definitely-not-the-token"


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


@requires_server
def test_admin_users_requires_token():
    r = httpx.get(f"{BACKEND_URL}/api/admin/users")
    assert r.status_code == 401


@requires_server
def test_admin_users_rejects_wrong_token():
    r = httpx.get(f"{BACKEND_URL}/api/admin/users", headers={"X-Admin-Token": BAD_TOKEN})
    assert r.status_code == 401


@requires_server
def test_admin_sees_real_registered_user(cleanup_user):
    username = _fresh_username("adminview")
    cleanup_user.append(username)
    reg = _register(username)

    r = httpx.get(f"{BACKEND_URL}/api/admin/users", headers={"X-Admin-Token": GOOD_TOKEN})
    assert r.status_code == 200
    usernames = [u["username"] for u in r.json()]
    assert username in usernames

    row = next(u for u in r.json() if u["username"] == username)
    for key in ("id", "status", "client_id", "created_at", "last_active_at",
               "total_queries", "total_conversations", "current_risk",
               "highest_risk", "flagged_count", "throttled_count", "blocked_count"):
        assert key in row
    assert row["id"] == reg["user"]["id"]


@requires_server
def test_admin_stats_has_new_kpis():
    r = httpx.get(f"{BACKEND_URL}/api/admin/stats", headers={"X-Admin-Token": GOOD_TOKEN})
    body = r.json()
    for key in ("total_users", "active_users", "total_conversations",
               "flagged_users", "throttled_users", "blocked_users",
               "total_blocked_queries", "total_throttled_queries",
               "total_security_events"):
        assert key in body, f"missing KPI: {key}"
        assert isinstance(body[key], int)


@requires_server
def test_admin_can_click_user_and_see_only_prompts(cleanup_user):
    username = _fresh_username("adminprompt")
    cleanup_user.append(username)
    reg = _register(username)
    headers = {"Authorization": f"Bearer {reg['token']}"}

    conv = httpx.post(f"{BACKEND_URL}/api/conversations", headers=headers).json()
    httpx.post(f"{BACKEND_URL}/api/conversations/{conv['id']}/messages",
              headers=headers, json={"query": "Explain JWT expiration."}, timeout=90.0)

    admin_headers = {"X-Admin-Token": GOOD_TOKEN}
    users_list = httpx.get(f"{BACKEND_URL}/api/admin/users", headers=admin_headers).json()
    row = next(u for u in users_list if u["username"] == username)

    detail = httpx.get(f"{BACKEND_URL}/api/admin/users/{row['id']}",
                       headers=admin_headers)
    assert detail.status_code == 200
    body = detail.json()
    assert len(body["queries"]) == 1
    q = body["queries"][0]
    assert q["text"] == "Explain JWT expiration."
    assert "response" not in q, "admin user-observation view must never include model responses"
    for key in ("seq", "action", "risk_score", "created_at"):
        assert key in q


@requires_server
def test_admin_user_detail_404_for_unknown_id():
    r = httpx.get(f"{BACKEND_URL}/api/admin/users/999999999", headers={"X-Admin-Token": GOOD_TOKEN})
    assert r.status_code == 404


@requires_server
def test_user_cannot_reach_admin_users_endpoint(cleanup_user):
    username = _fresh_username("adminblock")
    cleanup_user.append(username)
    reg = _register(username)

    r = httpx.get(f"{BACKEND_URL}/api/admin/users",
                  headers={"Authorization": f"Bearer {reg['token']}"})
    assert r.status_code == 401
