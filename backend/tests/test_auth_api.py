"""Authentication and account-layer tests (Part 27's AUTHENTICATION and
ADMIN checklists).

Runs against the real local backend at http://localhost:8000, same
convention as test_admin_api.py -- skipped if it isn't reachable.
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


def _register(username: str, password: str = "correct-horse-battery") -> dict:
    r = httpx.post(f"{BACKEND_URL}/api/auth/register",
                   json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


# --- valid user login ---------------------------------------------------

@requires_server
def test_register_then_login_as_user(cleanup_user):
    username = _fresh_username("auth-user")
    cleanup_user.append(username)
    reg = _register(username)
    assert reg["user"]["role"] == "user"
    assert "token" in reg

    r = httpx.post(f"{BACKEND_URL}/api/auth/login",
                   json={"username": username, "password": "correct-horse-battery"})
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["username"] == username
    assert body["user"]["role"] == "user"
    assert "password" not in body["user"]
    assert "password_hash" not in body["user"]


# --- valid admin login ----------------------------------------------------

@requires_server
def test_admin_login_returns_admin_role():
    r = httpx.post(f"{BACKEND_URL}/api/auth/login",
                   json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["role"] == "admin"
    assert body["user"]["username"] == ADMIN_USERNAME


# --- invalid password / invalid admin login -------------------------------

@requires_server
def test_login_wrong_password_rejected(cleanup_user):
    username = _fresh_username("auth-wrongpw")
    cleanup_user.append(username)
    _register(username)

    r = httpx.post(f"{BACKEND_URL}/api/auth/login",
                   json={"username": username, "password": "totally-wrong"})
    assert r.status_code == 401


@requires_server
def test_admin_login_wrong_password_rejected():
    r = httpx.post(f"{BACKEND_URL}/api/auth/login",
                   json={"username": ADMIN_USERNAME, "password": "not-the-real-password"})
    assert r.status_code == 401


@requires_server
def test_login_unknown_username_rejected():
    r = httpx.post(f"{BACKEND_URL}/api/auth/login",
                   json={"username": "no-such-user-ever", "password": "whatever123"})
    assert r.status_code == 401


# --- registration cannot mint an admin / cannot forge a role --------------

@requires_server
def test_register_ignores_client_supplied_role(cleanup_user):
    """A normal user must NEVER be able to choose 'admin' and become one --
    the request schema has no `role` field at all, so any such payload key
    is silently dropped, and every self-registered account is 'user'."""
    username = _fresh_username("auth-noadmin")
    cleanup_user.append(username)
    r = httpx.post(f"{BACKEND_URL}/api/auth/register",
                   json={"username": username, "password": "correct-horse-battery",
                        "role": "admin"})
    assert r.status_code == 200
    assert r.json()["user"]["role"] == "user"


@requires_server
def test_duplicate_username_rejected(cleanup_user):
    username = _fresh_username("auth-dup")
    cleanup_user.append(username)
    _register(username)
    r = httpx.post(f"{BACKEND_URL}/api/auth/register",
                   json={"username": username, "password": "another-password"})
    assert r.status_code == 409


# --- role enforcement: user cannot access admin surfaces ------------------

@requires_server
def test_user_session_cannot_access_admin_stats(cleanup_user):
    username = _fresh_username("auth-roleuser")
    cleanup_user.append(username)
    reg = _register(username)

    r = httpx.get(f"{BACKEND_URL}/api/admin/stats",
                  headers={"Authorization": f"Bearer {reg['token']}"})
    assert r.status_code == 401


@requires_server
def test_admin_session_reaches_admin_stats():
    login = httpx.post(f"{BACKEND_URL}/api/auth/login",
                       json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}).json()
    r = httpx.get(f"{BACKEND_URL}/api/admin/stats",
                  headers={"Authorization": f"Bearer {login['token']}"})
    assert r.status_code == 200
    assert "total_users" in r.json()


@requires_server
def test_no_token_at_all_rejected_from_conversations():
    r = httpx.get(f"{BACKEND_URL}/api/conversations")
    assert r.status_code == 401


@requires_server
def test_logout_invalidates_session(cleanup_user):
    username = _fresh_username("auth-logout")
    cleanup_user.append(username)
    reg = _register(username)
    headers = {"Authorization": f"Bearer {reg['token']}"}

    assert httpx.get(f"{BACKEND_URL}/api/auth/me", headers=headers).status_code == 200
    logout = httpx.post(f"{BACKEND_URL}/api/auth/logout", headers=headers)
    assert logout.status_code == 200
    assert httpx.get(f"{BACKEND_URL}/api/auth/me", headers=headers).status_code == 401
