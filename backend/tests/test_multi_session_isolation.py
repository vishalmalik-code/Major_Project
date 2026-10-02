"""Tests for "FIX MULTI-TAB AUTHENTICATION": independent, concurrently-valid
sessions for different accounts (and different roles), and that logging one
out never disturbs another.

The actual bug this addresses lived entirely in the FRONTEND (AuthContext.jsx
stored the session in `localStorage`, which is shared across every tab of the
same origin -- a second tab's login silently overwrote the first tab's token
on the next read). The fix there was to move to `sessionStorage` (tab-scoped)
-- see AuthContext.jsx's module docstring; that isn't something a backend
test can exercise. What backend tests CAN and must prove is the other half of
the fix's premise: that the existing sessions table already supports any
number of concurrently valid tokens, for any number of accounts/roles, with
no single-session-per-account constraint and no cross-session interference --
i.e. that once the frontend stops clobbering its own storage, nothing on the
server would have stopped multi-tab auth from working anyway.

Runs against the real local backend at http://localhost:8000 -- skipped if
unreachable, same convention as test_auth_api.py.
"""

import uuid

import httpx
import pytest

from app.core.config import settings

BACKEND_URL = "http://localhost:8000"
ADMIN_USERNAME = settings.admin_seed_username
ADMIN_PASSWORD = settings.admin_seed_password


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


def _login_admin() -> dict:
    r = httpx.post(f"{BACKEND_URL}/api/auth/login",
                   json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    return r.json()


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --- the exact "Tab 1 = user, Tab 3 = admin" scenario, backend half --------

@requires_server
def test_user_and_admin_sessions_coexist_and_stay_independent(cleanup_user):
    """Mirrors the CRITICAL AUTHENTICATION TEST from the PROMPT: a user logs
    in, sends a message, an admin logs in elsewhere, the user sends another
    message (must still work), the admin's own access must still work too --
    all interleaved, neither session ever touching the other's token."""
    username = _fresh_username("multisess-user")
    cleanup_user.append(username)
    user_reg = _register(username)
    user_headers = _auth(user_reg["token"])

    conv = httpx.post(f"{BACKEND_URL}/api/conversations", headers=user_headers).json()
    r1 = httpx.post(f"{BACKEND_URL}/api/conversations/{conv['id']}/messages",
                    headers=user_headers, json={"query": "hello"}, timeout=90.0)
    assert r1.status_code == 200

    # "Tab 3": admin logs in, on a completely separate token.
    admin = _login_admin()
    admin_headers = _auth(admin["token"])
    assert httpx.get(f"{BACKEND_URL}/api/admin/stats", headers=admin_headers).status_code == 200

    # "Return to Tab 1": the user's original token must still work, unaffected.
    me = httpx.get(f"{BACKEND_URL}/api/auth/me", headers=user_headers)
    assert me.status_code == 200
    assert me.json()["username"] == username
    assert me.json()["role"] == "user"

    r2 = httpx.post(f"{BACKEND_URL}/api/conversations/{conv['id']}/messages",
                    headers=user_headers, json={"query": "second message"}, timeout=90.0)
    assert r2.status_code == 200, "the user's session must still work after an admin logged in elsewhere"
    assert r2.json()["seq"] == 2

    # The admin session must also still be exactly what it was -- not
    # somehow demoted or altered by the user's continued activity.
    me_admin = httpx.get(f"{BACKEND_URL}/api/auth/me", headers=admin_headers)
    assert me_admin.status_code == 200
    assert me_admin.json()["role"] == "admin"


@requires_server
def test_logout_user_does_not_affect_admin_session(cleanup_user):
    username = _fresh_username("multisess-logout-u")
    cleanup_user.append(username)
    user_reg = _register(username)
    user_headers = _auth(user_reg["token"])
    admin = _login_admin()
    admin_headers = _auth(admin["token"])

    logout = httpx.post(f"{BACKEND_URL}/api/auth/logout", headers=user_headers)
    assert logout.status_code == 200

    assert httpx.get(f"{BACKEND_URL}/api/auth/me", headers=user_headers).status_code == 401
    still_ok = httpx.get(f"{BACKEND_URL}/api/admin/stats", headers=admin_headers)
    assert still_ok.status_code == 200, "logging out the user must not log out the admin"


@requires_server
def test_logout_admin_does_not_affect_user_session(cleanup_user):
    username = _fresh_username("multisess-logout-a")
    cleanup_user.append(username)
    user_reg = _register(username)
    user_headers = _auth(user_reg["token"])
    admin = _login_admin()
    admin_headers = _auth(admin["token"])

    logout = httpx.post(f"{BACKEND_URL}/api/auth/logout", headers=admin_headers)
    assert logout.status_code == 200

    assert httpx.get(f"{BACKEND_URL}/api/admin/stats", headers=admin_headers).status_code == 401
    still_ok = httpx.get(f"{BACKEND_URL}/api/auth/me", headers=user_headers)
    assert still_ok.status_code == 200, "logging out the admin must not log out the user"
    assert still_ok.json()["username"] == username


@requires_server
def test_two_concurrent_user_sessions_do_not_interfere(cleanup_user):
    """Not just user-vs-admin: two ordinary accounts logged in at once (e.g.
    two browser tabs, two different users) must both keep working."""
    user_a = _fresh_username("multisess-a")
    user_b = _fresh_username("multisess-b")
    cleanup_user.extend([user_a, user_b])
    reg_a = _register(user_a)
    reg_b = _register(user_b)

    me_a = httpx.get(f"{BACKEND_URL}/api/auth/me", headers=_auth(reg_a["token"]))
    me_b = httpx.get(f"{BACKEND_URL}/api/auth/me", headers=_auth(reg_b["token"]))
    assert me_a.status_code == 200 and me_a.json()["username"] == user_a
    assert me_b.status_code == 200 and me_b.json()["username"] == user_b

    httpx.post(f"{BACKEND_URL}/api/auth/logout", headers=_auth(reg_a["token"]))
    assert httpx.get(f"{BACKEND_URL}/api/auth/me",
                     headers=_auth(reg_a["token"])).status_code == 401
    still_b = httpx.get(f"{BACKEND_URL}/api/auth/me", headers=_auth(reg_b["token"]))
    assert still_b.status_code == 200 and still_b.json()["username"] == user_b


# --- the frontend can never grant itself authorization ----------------------

@requires_server
def test_user_role_claim_never_grants_admin_access(cleanup_user):
    """Belt-and-suspenders on top of test_auth_api.py's coverage: even a
    freshly minted, currently-valid user session -- coexisting with a valid
    admin session, as in the tests above -- gets no admin access no matter
    what. Authorization is re-derived from the DB role column server-side on
    every call, never from anything the frontend or a previous response
    claimed."""
    username = _fresh_username("multisess-noauth")
    cleanup_user.append(username)
    reg = _register(username)
    _login_admin()  # an admin session exists concurrently; must not matter

    r = httpx.get(f"{BACKEND_URL}/api/admin/clients", headers=_auth(reg["token"]))
    assert r.status_code == 401
    r2 = httpx.get(f"{BACKEND_URL}/api/admin/stream", headers=_auth(reg["token"]))
    assert r2.status_code == 401
