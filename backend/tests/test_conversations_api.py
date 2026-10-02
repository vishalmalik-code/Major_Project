"""Chat history + user isolation tests (Part 27's CHAT HISTORY and USER
ISOLATION checklists, plus the "hello" regression from Part 8/9).

Runs against the real local backend at http://localhost:8000 with the real
firewall and Ollama -- skipped if the server isn't reachable. Every message
sent here goes through the actual protected path (ChatService.handle via
POST /api/conversations/{id}/messages), so this is also, incidentally, a
regression check that a brand-new account's very first message ("hello")
is never blocked by stale state -- there is no stale state to inherit,
because a fresh account gets a fresh client_id (see UserRepository.create).
"""

import uuid

import httpx
import pytest

BACKEND_URL = "http://localhost:8000"


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


# --- a brand-new account's first message is never pre-blocked ------------

@requires_server
def test_fresh_account_hello_is_never_blocked(cleanup_user):
    """The regression this restructuring specifically fixed: a genuinely new
    account must get a normal ALLOW response to "hello", never a leftover
    BLOCK from unrelated prior activity."""
    username = _fresh_username("hist-hello")
    cleanup_user.append(username)
    reg = _register(username)

    conv = httpx.post(f"{BACKEND_URL}/api/conversations", headers=_auth(reg["token"])).json()
    r = httpx.post(f"{BACKEND_URL}/api/conversations/{conv['id']}/messages",
                   headers=_auth(reg["token"]), json={"query": "hello"}, timeout=90.0)
    assert r.status_code == 200
    body = r.json()
    assert body["response"] is not None, (
        "a brand-new account's first-ever message must get a real response, not a block"
    )


# --- create / save / retrieve conversation --------------------------------

@requires_server
def test_create_send_and_retrieve_conversation(cleanup_user):
    username = _fresh_username("hist-crud")
    cleanup_user.append(username)
    reg = _register(username)
    headers = _auth(reg["token"])

    conv = httpx.post(f"{BACKEND_URL}/api/conversations", headers=headers).json()
    assert conv["title"] is None

    sent = httpx.post(f"{BACKEND_URL}/api/conversations/{conv['id']}/messages",
                      headers=headers, json={"query": "What is SQL injection?"},
                      timeout=90.0)
    assert sent.status_code == 200
    assert sent.json()["query"] == "What is SQL injection?"
    assert sent.json()["response"]

    detail = httpx.get(f"{BACKEND_URL}/api/conversations/{conv['id']}", headers=headers).json()
    assert detail["title"] == "What is SQL injection?"
    assert len(detail["messages"]) == 1
    assert detail["messages"][0]["query"] == "What is SQL injection?"
    assert detail["messages"][0]["response"]
    # the user-facing message shape must never carry security internals
    assert set(detail["messages"][0].keys()) == {
        "seq", "query", "response", "created_at", "source"}
    assert detail["messages"][0]["source"] == "user"


# --- new conversation starts with clean chat history, but shared security state

@requires_server
def test_new_conversation_has_no_messages_but_keeps_same_client_id(cleanup_user):
    username = _fresh_username("hist-newconv")
    cleanup_user.append(username)
    reg = _register(username)
    headers = _auth(reg["token"])

    conv1 = httpx.post(f"{BACKEND_URL}/api/conversations", headers=headers).json()
    httpx.post(f"{BACKEND_URL}/api/conversations/{conv1['id']}/messages",
              headers=headers, json={"query": "hello"}, timeout=90.0)

    conv2 = httpx.post(f"{BACKEND_URL}/api/conversations", headers=headers).json()
    assert conv2["id"] != conv1["id"]
    detail2 = httpx.get(f"{BACKEND_URL}/api/conversations/{conv2['id']}", headers=headers).json()
    assert detail2["messages"] == [], "a new conversation must start with empty chat history"

    r = httpx.post(f"{BACKEND_URL}/api/conversations/{conv2['id']}/messages",
                   headers=headers, json={"query": "what about xss?"}, timeout=90.0)
    assert r.status_code == 200
    # seq is per-client_id, not per-conversation: the 2nd message from this
    # account (even in a new conversation) must be seq 2, proving the
    # SAME underlying client_id/window was reused rather than reset.
    assert r.json()["seq"] == 2


# --- old conversation remains accessible (simulated logout/login) --------

@requires_server
def test_old_conversation_survives_a_new_login(cleanup_user):
    username = _fresh_username("hist-relogin")
    cleanup_user.append(username)
    reg = _register(username)
    headers = _auth(reg["token"])

    conv = httpx.post(f"{BACKEND_URL}/api/conversations", headers=headers).json()
    httpx.post(f"{BACKEND_URL}/api/conversations/{conv['id']}/messages",
              headers=headers, json={"query": "hello"}, timeout=90.0)

    relogin = httpx.post(f"{BACKEND_URL}/api/auth/login",
                         json={"username": username, "password": "correct-horse-battery"}).json()
    new_headers = _auth(relogin["token"])

    convs = httpx.get(f"{BACKEND_URL}/api/conversations", headers=new_headers).json()
    assert any(c["id"] == conv["id"] for c in convs)
    detail = httpx.get(f"{BACKEND_URL}/api/conversations/{conv['id']}", headers=new_headers).json()
    assert len(detail["messages"]) == 1


# --- USER ISOLATION --------------------------------------------------------

@requires_server
def test_user_a_cannot_read_user_b_conversation(cleanup_user):
    user_a = _fresh_username("iso-a")
    user_b = _fresh_username("iso-b")
    cleanup_user.extend([user_a, user_b])
    reg_a = _register(user_a)
    reg_b = _register(user_b)

    conv_a = httpx.post(f"{BACKEND_URL}/api/conversations", headers=_auth(reg_a["token"])).json()

    r = httpx.get(f"{BACKEND_URL}/api/conversations/{conv_a['id']}", headers=_auth(reg_b["token"]))
    assert r.status_code == 404, "User B must get no signal that User A's conversation exists"

    r2 = httpx.post(f"{BACKEND_URL}/api/conversations/{conv_a['id']}/messages",
                    headers=_auth(reg_b["token"]), json={"query": "hijack attempt"})
    assert r2.status_code == 404


@requires_server
def test_user_a_conversation_list_excludes_user_b(cleanup_user):
    user_a = _fresh_username("iso-lista")
    user_b = _fresh_username("iso-listb")
    cleanup_user.extend([user_a, user_b])
    reg_a = _register(user_a)
    reg_b = _register(user_b)

    httpx.post(f"{BACKEND_URL}/api/conversations", headers=_auth(reg_a["token"]))
    httpx.post(f"{BACKEND_URL}/api/conversations", headers=_auth(reg_a["token"]))

    convs_b = httpx.get(f"{BACKEND_URL}/api/conversations", headers=_auth(reg_b["token"])).json()
    assert convs_b == [], "a fresh account must never see another account's conversations"


@requires_server
def test_user_b_risk_state_unaffected_by_user_a_activity(cleanup_user):
    """User A sends repeated identical queries (driving risk up); User B,
    logging in fresh right after, must start with normal risk and an empty
    history -- proving per-account client_id isolation end-to-end over the
    real authenticated HTTP path, not just at the ChatService level (which
    test_chat_flow.py already covers)."""
    user_a = _fresh_username("iso-riska")
    user_b = _fresh_username("iso-riskb")
    cleanup_user.extend([user_a, user_b])
    reg_a = _register(user_a)
    reg_b = _register(user_b)

    conv_a = httpx.post(f"{BACKEND_URL}/api/conversations", headers=_auth(reg_a["token"])).json()
    suspicious = "What is a SQL injection attack and how does it work?"
    last = None
    for _ in range(6):
        last = httpx.post(f"{BACKEND_URL}/api/conversations/{conv_a['id']}/messages",
                          headers=_auth(reg_a["token"]), json={"query": suspicious},
                          timeout=90.0)
    assert last.status_code == 200

    conv_b = httpx.post(f"{BACKEND_URL}/api/conversations", headers=_auth(reg_b["token"])).json()
    r = httpx.post(f"{BACKEND_URL}/api/conversations/{conv_b['id']}/messages",
                   headers=_auth(reg_b["token"]),
                   json={"query": "What is the capital of France in a security context?"},
                   timeout=90.0)
    assert r.status_code == 200
    assert r.json()["seq"] == 1, "User B's first-ever query must be seq 1, not inheriting User A's count"
    assert r.json()["response"] is not None, "User B must not inherit User A's risk/block state"
