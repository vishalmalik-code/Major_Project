"""Shared fixtures for signal/risk integration tests."""

import uuid

import pytest
from sqlalchemy import text

from app.db.session import SessionLocal
from app.embeddings.encoder import Encoder
from app.firewall.engine import FirewallEngine
from app.firewall.normalize import extract_constraint_tokens, extract_numbers, normalize
from app.firewall.signals import default_signals
from app.firewall.signals.base import QueryContext
from app.firewall.window import QueryWindow, WindowEntry
from app.services import chat_service as chat_service_module
from app.services.chat_service import ChatService


@pytest.fixture(scope="session")
def encoder():
    enc = Encoder.instance()
    enc.load()
    return enc


@pytest.fixture
def make_entry(encoder):
    def _make(seq: int, text: str, t: float = 0.0) -> WindowEntry:
        return WindowEntry(
            seq=seq, text=text, normalized=normalize(text),
            embedding=encoder.encode(text),
            numbers=extract_numbers(text),
            constraint_tokens=extract_constraint_tokens(text),
            created_at_epoch=t,
        )
    return _make


@pytest.fixture
def make_context(encoder):
    def _make(text: str, window: list[WindowEntry], seq: int,
              arrived_at: float = 0.0) -> QueryContext:
        return QueryContext(
            client_id="test-client", seq=seq, text=text,
            normalized=normalize(text), embedding=encoder.encode(text),
            numbers=extract_numbers(text),
            constraint_tokens=extract_constraint_tokens(text),
            arrived_at_epoch=arrived_at, window=window,
            tight_window=window[-10:],
        )
    return _make


@pytest.fixture
def signals():
    return default_signals()


class FakeLLMService:
    """Spy double for LLMService: no real Ollama call, no real delay --
    lets chat_service-level tests assert "was the LLM called" and "how many
    times" without paying for real generation or real THROTTLE sleeps."""

    def __init__(self, response: str = "fake response") -> None:
        self.response = response
        self.calls: list[str] = []

    async def generate(self, prompt: str, max_tokens: int | None = None) -> str:
        self.calls.append(prompt)
        return self.response

    async def health(self) -> dict:
        return {"reachable": True, "model_available": True, "models": []}

    @property
    def call_count(self) -> int:
        return len(self.calls)


@pytest.fixture
def db_session():
    """A real session against the project's Postgres database. Not wrapped in
    a rollback: chat_service.handle() calls db.commit() internally, so tests
    use unique client_id values (see `new_client_id`) and clean up their own
    rows via `cleanup_client` instead of relying on transaction isolation."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def new_client_id():
    """A fresh, collision-free client_id per test."""
    return f"test-{uuid.uuid4().hex[:10]}"


@pytest.fixture
def cleanup_client(db_session):
    """Deletes a client's row (and, via ON DELETE CASCADE, its queries,
    signal_scores, and security_events) after the test. Yields a list the
    test appends client_ids to."""
    ids: list[str] = []
    yield ids
    for client_id in ids:
        db_session.execute(text("DELETE FROM clients WHERE client_id = :cid"),
                           {"cid": client_id})
        chat_service_module._warmed_clients.discard(client_id)
    db_session.commit()


@pytest.fixture
def cleanup_user(db_session):
    """Deletes a test account (and, via cascade, its sessions and
    conversations) plus its linked `clients` row (which cascades queries,
    signal_scores, and security_events) after the test. Yields a list the
    test appends usernames to -- the auth-layer counterpart to
    `cleanup_client`."""
    usernames: list[str] = []
    yield usernames
    for username in usernames:
        row = db_session.execute(
            text("SELECT client_id FROM users WHERE username = :u"), {"u": username}
        ).first()
        db_session.execute(text("DELETE FROM users WHERE username = :u"), {"u": username})
        if row is not None:
            db_session.execute(text("DELETE FROM clients WHERE client_id = :cid"), {"cid": row[0]})
            chat_service_module._warmed_clients.discard(row[0])
    db_session.commit()


@pytest.fixture
def fake_llm():
    return FakeLLMService()


@pytest.fixture
def build_chat_service(encoder, fake_llm):
    """Builds a ChatService with a fresh FirewallEngine/QueryWindow (so tests
    don't share window state with each other or with a running app process)
    and the FakeLLMService spy in place of real Ollama."""
    def _build(llm=None):
        window = QueryWindow(size=20, tight_size=10)
        engine = FirewallEngine(window)
        return ChatService(engine=engine, encoder=encoder, llm=llm or fake_llm)
    return _build


BENIGN_TRANSCRIPT = [
    "What is SQL injection?",
    "How do I prevent SQL injection in Python?",
    "Show me a prepared statement example.",
    "What about XSS?",
    "Is a CSP header enough to stop XSS?",
    "How does CSRF differ from XSS?",
]
