"""ORM models mirroring db/init.sql.

THE ORDERING RULE, restated because it is the project's core invariant:
`Query.seq` orders the window; `Query.created_at` never does. Every window
rebuild is `ORDER BY seq DESC LIMIT N`. `created_at` exists for the burst_rate
signal and the dashboard only.
"""

from datetime import datetime, timezone

from pgvector.sqlalchemy import Vector
from sqlalchemy import (ARRAY, JSON, CheckConstraint, DateTime, Float,
                        ForeignKey, Integer, String, Text, UniqueConstraint)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.core.config import settings


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Client(Base):
    __tablename__ = "clients"
    __table_args__ = (
        CheckConstraint("kind IN ('user','attacker')", name="ck_clients_kind"),
        CheckConstraint("risk_band IN ('LOW','MEDIUM','HIGH','CRITICAL')",
                        name="ck_clients_risk_band"),
        CheckConstraint("risk_score >= 0.0 AND risk_score <= 100.0",
                        name="ck_clients_risk_range"),
    )

    client_id: Mapped[str] = mapped_column(String, primary_key=True)
    kind: Mapped[str] = mapped_column(String, default="user")
    label: Mapped[str | None] = mapped_column(String, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_band: Mapped[str] = mapped_column(String, default="LOW")
    query_count: Mapped[int] = mapped_column(Integer, default=0)
    next_seq: Mapped[int] = mapped_column(Integer, default=1)
    blocked_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    queries: Mapped[list["Query"]] = relationship(back_populates="client")


class AttackRun(Base):
    __tablename__ = "attack_runs"
    __table_args__ = (
        CheckConstraint(
            "strategy IN ('exact_repetition','minimal_modification',"
            "'value_sweep','constraint_probing','boundary_probing')",
            name="ck_attack_runs_strategy",
        ),
        CheckConstraint("mode IN ('FAST','SLOW')", name="ck_attack_runs_mode"),
        CheckConstraint("status IN ('running','finished','aborted')",
                        name="ck_attack_runs_status"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    strategy: Mapped[str] = mapped_column(String)
    mode: Mapped[str] = mapped_column(String)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.client_id", ondelete="CASCADE"))
    requested_count: Mapped[int] = mapped_column(Integer)
    sent_count: Mapped[int] = mapped_column(Integer, default=0)
    allowed_count: Mapped[int] = mapped_column(Integer, default=0)
    monitored_count: Mapped[int] = mapped_column(Integer, default=0)
    throttled_count: Mapped[int] = mapped_column(Integer, default=0)
    blocked_count: Mapped[int] = mapped_column(Integer, default=0)
    queries_to_first_block: Mapped[int | None] = mapped_column(Integer, nullable=True)
    seed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String, default="running")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Query(Base):
    __tablename__ = "queries"
    __table_args__ = (
        UniqueConstraint("client_id", "seq", name="uq_queries_client_seq"),
        CheckConstraint("action IN ('ALLOW','MONITOR','THROTTLE','BLOCK')",
                        name="ck_queries_action"),
        CheckConstraint("source IN ('user','attacker')", name="ck_queries_source"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.client_id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(Integer)
    text: Mapped[str] = mapped_column(Text)
    normalized: Mapped[str] = mapped_column(Text)
    embedding = mapped_column(Vector(settings.embedding_dim), nullable=True)
    numbers: Mapped[list[float]] = mapped_column(ARRAY(Float), default=list)
    constraint_tokens: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    action: Mapped[str] = mapped_column(String)
    weighted_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_before: Mapped[float] = mapped_column(Float, default=0.0)
    risk_after: Mapped[float] = mapped_column(Float, default=0.0)
    risk_delta: Mapped[float] = mapped_column(Float, default=0.0)
    response: Mapped[str | None] = mapped_column(Text, nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attack_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("attack_runs.id", ondelete="SET NULL"), nullable=True)
    conversation_id: Mapped[int | None] = mapped_column(
        ForeignKey("conversations.id", ondelete="SET NULL"), nullable=True)
    source: Mapped[str] = mapped_column(String, default="user")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    client: Mapped["Client"] = relationship(back_populates="queries")
    signal_scores: Mapped[list["SignalScore"]] = relationship(back_populates="query")


class SignalScore(Base):
    __tablename__ = "signal_scores"
    __table_args__ = (
        UniqueConstraint("query_id", "signal_name", name="uq_signal_scores_query_signal"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    query_id: Mapped[int] = mapped_column(ForeignKey("queries.id", ondelete="CASCADE"))
    signal_name: Mapped[str] = mapped_column(String)
    score: Mapped[float] = mapped_column(Float)
    weight: Mapped[float] = mapped_column(Float)
    evidence: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    query: Mapped["Query"] = relationship(back_populates="signal_scores")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.client_id", ondelete="CASCADE"))
    query_id: Mapped[int | None] = mapped_column(
        ForeignKey("queries.id", ondelete="SET NULL"), nullable=True)
    severity: Mapped[str] = mapped_column(String)
    event_type: Mapped[str] = mapped_column(String)
    message: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class User(Base):
    """An authenticated account. `client_id` is this account's permanent
    firewall identity (one row in `clients`, created at registration and
    never reassigned) -- see the module docstring in db/init.sql for why
    that must stay separate from `conversations`."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('user','admin')", name="ck_users_role"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String, unique=True)
    password_hash: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String, default="user")
    client_id: Mapped[str] = mapped_column(
        ForeignKey("clients.client_id"), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_active_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    # Optional profile fields from the signup form -- display/contact info
    # only, never read by auth, the firewall, or role logic (see auth.py).
    first_name: Mapped[str | None] = mapped_column(String, nullable=True)
    last_name: Mapped[str | None] = mapped_column(String, nullable=True)
    email: Mapped[str | None] = mapped_column(String, nullable=True)


class UserSession(Base):
    """An opaque bearer token minted at login. Same shared-secret-in-a-header
    model as X-Admin-Token, just per-user and DB-backed instead of one static
    config value."""

    __tablename__ = "sessions"

    token: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Conversation(Base):
    """A chat-history grouping only. Never read by the firewall/window --
    those key exclusively on `queries.client_id` and `queries.seq`."""

    __tablename__ = "conversations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
