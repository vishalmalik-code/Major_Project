"""Persistence for the firewall path. Keeps SQL out of the engine and the
routes."""

import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.constants import Action, RiskBand
from app.db.models import (AttackRun, Client, Conversation, Query,
                           SecurityEvent, SignalScore, User, UserSession)
from app.firewall.window import WindowEntry


class ClientRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_or_create(self, client_id: str, kind: str = "user") -> Client:
        client = self.db.get(Client, client_id)
        if client is None:
            client = Client(client_id=client_id, kind=kind)
            self.db.add(client)
            self.db.flush()
        return client

    def next_seq(self, client_id: str) -> int:
        """Increment and return clients.next_seq in the same transaction as the
        risk update, so ordering and risk can never disagree."""
        client = self.get_or_create(client_id)
        seq = client.next_seq
        client.next_seq += 1
        client.query_count += 1
        client.last_seen_at = datetime.now(timezone.utc)
        return seq

    def update_risk(self, client_id: str, risk: float, band: RiskBand) -> None:
        """The ONLY writer of clients.risk_score in the entire system."""
        client = self.get_or_create(client_id)
        client.risk_score = risk
        client.risk_band = band.value
        if band == RiskBand.CRITICAL:
            client.blocked_count += 1


class QueryRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def load_window(self, client_id: str, size: int) -> list[WindowEntry]:
        """SELECT ... ORDER BY seq DESC LIMIT size, reversed.

        By `seq`. Never by `created_at`. Never with a time predicate.
        """
        stmt = (
            select(Query)
            .where(Query.client_id == client_id)
            .order_by(Query.seq.desc())
            .limit(size)
        )
        rows = list(self.db.execute(stmt).scalars())
        rows.reverse()  # oldest -> newest
        return [
            WindowEntry(
                seq=r.seq, text=r.text, normalized=r.normalized,
                embedding=r.embedding, numbers=list(r.numbers or []),
                constraint_tokens=list(r.constraint_tokens or []),
                created_at_epoch=r.created_at.timestamp(),
            )
            for r in rows
        ]

    def record(self, *, client_id: str, seq: int, text: str, normalized: str,
              embedding, numbers: list[float], constraint_tokens: list[str],
              action: Action, weighted_score: float, risk_before: float,
              risk_after: float, response: str | None, latency_ms: int | None,
              attack_run_id: str | None,
              signal_results: list, conversation_id: int | None = None,
              source: str = "user") -> Query:
        query = Query(
            client_id=client_id, seq=seq, text=text, normalized=normalized,
            embedding=embedding, numbers=numbers, constraint_tokens=constraint_tokens,
            action=action.value, weighted_score=weighted_score,
            risk_before=risk_before, risk_after=risk_after,
            risk_delta=risk_after - risk_before, response=response,
            latency_ms=latency_ms, attack_run_id=attack_run_id,
            conversation_id=conversation_id, source=source,
        )
        self.db.add(query)
        self.db.flush()

        for r in signal_results:
            self.db.add(SignalScore(
                query_id=query.id, signal_name=r.name, score=r.score,
                weight=r.weight, evidence=r.evidence, details=r.details,
            ))
        return query


class EventRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def record(self, *, client_id: str, query_id: int | None, severity: str,
              event_type: str, message: str, details: dict | None = None) -> SecurityEvent:
        event = SecurityEvent(
            client_id=client_id, query_id=query_id, severity=severity,
            event_type=event_type, message=message, details=details or {},
        )
        self.db.add(event)
        self.db.flush()
        return event


class AttackRunRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, *, run_id: str, strategy: str, mode: str, client_id: str,
              requested_count: int, seed: int | None) -> AttackRun:
        run = AttackRun(
            id=run_id, strategy=strategy, mode=mode, client_id=client_id,
            requested_count=requested_count, seed=seed,
        )
        self.db.add(run)
        self.db.flush()
        return run

    def get(self, run_id: str) -> AttackRun | None:
        return self.db.get(AttackRun, run_id)

    def update_progress(self, run_id: str, **fields) -> None:
        run = self.db.get(AttackRun, run_id)
        if run is None:
            return
        for k, v in fields.items():
            setattr(run, k, v)

    def list_recent(self, limit: int = 50) -> list[AttackRun]:
        stmt = select(AttackRun).order_by(AttackRun.started_at.desc()).limit(limit)
        return list(self.db.execute(stmt).scalars())


class StatsRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def overview(self) -> dict:
        from sqlalchemy import func

        total = self.db.execute(select(func.count(Query.id))).scalar() or 0
        by_action_rows = self.db.execute(
            select(Query.action, func.count(Query.id)).group_by(Query.action)
        ).all()
        by_action = {a: c for a, c in by_action_rows}
        suspicious = sum(c for a, c in by_action.items() if a != "ALLOW")
        unique_clients = self.db.execute(select(func.count(Client.client_id))).scalar() or 0
        clients_at_risk = self.db.execute(
            select(func.count(Client.client_id)).where(Client.risk_band != "LOW")
        ).scalar() or 0

        return {
            "total_queries": total,
            "suspicious_queries": suspicious,
            "throttled": by_action.get("THROTTLE", 0),
            "blocked": by_action.get("BLOCK", 0),
            "unique_clients": unique_clients,
            "clients_at_risk": clients_at_risk,
            "by_action": {a: by_action.get(a, 0) for a in
                         ("ALLOW", "MONITOR", "THROTTLE", "BLOCK")},
            **self.user_kpis(),
        }

    def user_kpis(self) -> dict:
        """Registered-account KPIs for the dashboard's top row (Part 12).
        Everything here is a real aggregate over users/conversations/queries/
        security_events -- no invented numbers. "Active" is the one
        UI-only judgment call: last_active_at within 24h, a display
        heuristic that never touches firewall risk/decay logic."""
        from sqlalchemy import func

        total_users = self.db.execute(
            select(func.count(User.id)).where(User.role == "user")
        ).scalar() or 0
        active_users = self.db.execute(
            select(func.count(User.id)).where(
                User.role == "user",
                User.last_active_at >= datetime.now(timezone.utc) - timedelta(hours=24),
            )
        ).scalar() or 0
        total_conversations = self.db.execute(
            select(func.count(Conversation.id))
        ).scalar() or 0
        total_security_events = self.db.execute(
            select(func.count(SecurityEvent.id))
        ).scalar() or 0
        total_blocked_queries = self.db.execute(
            select(func.count(Query.id)).where(Query.action == "BLOCK")
        ).scalar() or 0
        total_throttled_queries = self.db.execute(
            select(func.count(Query.id)).where(Query.action == "THROTTLE")
        ).scalar() or 0

        flagged_users = self.db.execute(
            select(func.count(func.distinct(User.id)))
            .select_from(User).join(Client, Client.client_id == User.client_id)
            .where(User.role == "user", Client.risk_band != "LOW")
        ).scalar() or 0
        throttled_users = self.db.execute(
            select(func.count(func.distinct(User.id)))
            .select_from(User)
            .join(Client, Client.client_id == User.client_id)
            .join(Query, Query.client_id == Client.client_id)
            .where(User.role == "user", Query.action == "THROTTLE")
        ).scalar() or 0
        blocked_users = self.db.execute(
            select(func.count(func.distinct(User.id)))
            .select_from(User)
            .join(Client, Client.client_id == User.client_id)
            .join(Query, Query.client_id == Client.client_id)
            .where(User.role == "user", Query.action == "BLOCK")
        ).scalar() or 0

        return {
            "total_users": total_users,
            "active_users": active_users,
            "total_conversations": total_conversations,
            "flagged_users": flagged_users,
            "throttled_users": throttled_users,
            "blocked_users": blocked_users,
            "total_blocked_queries": total_blocked_queries,
            "total_throttled_queries": total_throttled_queries,
            "total_security_events": total_security_events,
        }

    _STATUS_LABEL = {"LOW": "NORMAL", "MEDIUM": "MONITORED",
                     "HIGH": "THROTTLED", "CRITICAL": "BLOCKED"}

    def _user_row(self, user: User, client: Client | None) -> dict:
        from sqlalchemy import func

        total_queries = 0
        current_risk = 0.0
        highest_risk = 0.0
        status = "NORMAL"
        total_conversations = self.db.execute(
            select(func.count(Conversation.id)).where(Conversation.user_id == user.id)
        ).scalar() or 0
        flagged_count = throttled_count = blocked_count = 0

        if client is not None:
            total_queries = client.query_count
            current_risk = round(client.risk_score, 1)
            status = self._STATUS_LABEL.get(client.risk_band, "NORMAL")
            highest_risk = round(
                self.db.execute(
                    select(func.max(Query.risk_after)).where(Query.client_id == client.client_id)
                ).scalar() or 0.0, 1,
            )
            action_counts = self.db.execute(
                select(Query.action, func.count(Query.id))
                .where(Query.client_id == client.client_id)
                .group_by(Query.action)
            ).all()
            counts = {a: c for a, c in action_counts}
            flagged_count = sum(c for a, c in counts.items() if a != "ALLOW")
            throttled_count = counts.get("THROTTLE", 0)
            blocked_count = counts.get("BLOCK", 0)

        return {
            "id": user.id, "username": user.username, "status": status,
            "client_id": user.client_id, "created_at": user.created_at.isoformat(),
            "last_active_at": user.last_active_at.isoformat(),
            "total_queries": total_queries, "total_conversations": total_conversations,
            "current_risk": current_risk, "highest_risk": highest_risk,
            "flagged_count": flagged_count, "throttled_count": throttled_count,
            "blocked_count": blocked_count,
        }

    def users_table(self) -> list[dict]:
        """The admin User List (Part 13): one row per registered account,
        newest first."""
        users = self.db.execute(
            select(User).where(User.role == "user").order_by(User.created_at.desc())
        ).scalars().all()
        clients_by_id = {
            c.client_id: c for c in self.db.execute(
                select(Client).where(Client.client_id.in_([u.client_id for u in users]))
            ).scalars()
        } if users else {}
        return [self._user_row(u, clients_by_id.get(u.client_id)) for u in users]

    def user_detail(self, user_id: int) -> dict | None:
        """User detail drill-down (Part 14): profile + stats + PROMPTS ONLY
        (no `response` field anywhere in the query list -- Part 15)."""
        user = self.db.get(User, user_id)
        if user is None or user.role != "user":
            return None
        client = self.db.get(Client, user.client_id)
        row = self._user_row(user, client)

        rows = []
        if client is not None:
            rows = list(self.db.execute(
                select(Query).where(Query.client_id == client.client_id)
                .order_by(Query.seq)
            ).scalars())

        row["queries"] = [
            {"seq": q.seq, "text": q.text, "action": q.action,
            "risk_score": round(q.risk_after, 1), "created_at": q.created_at.isoformat()}
            for q in rows
        ]
        return row

    def clients(self) -> list[Client]:
        stmt = select(Client).order_by(Client.risk_score.desc())
        return list(self.db.execute(stmt).scalars())

    def peak_risk_by_client(self) -> dict[str, float]:
        """Highest risk_after ever recorded, per client -- for the admin
        client table's 'highest risk' column. Computed from the query log
        rather than stored on the client row, so it can never drift from
        what actually happened and needs no schema change."""
        from sqlalchemy import func

        rows = self.db.execute(
            select(Query.client_id, func.max(Query.risk_after)).group_by(Query.client_id)
        ).all()
        return {client_id: peak for client_id, peak in rows}

    def action_counts_for_client(self, client_id: str) -> dict[str, int]:
        """Lifetime THROTTLE/BLOCK counts for one client (not just the
        current 20-query window), for the client detail panel."""
        from sqlalchemy import func

        rows = self.db.execute(
            select(Query.action, func.count(Query.id))
            .where(Query.client_id == client_id)
            .group_by(Query.action)
        ).all()
        counts = {a: c for a, c in rows}
        return {"throttle_count": counts.get("THROTTLE", 0),
               "block_count": counts.get("BLOCK", 0)}

    def events(self, severity: str | None = None, limit: int = 50) -> list[SecurityEvent]:
        stmt = select(SecurityEvent).order_by(SecurityEvent.id.desc()).limit(limit)
        if severity:
            stmt = stmt.where(SecurityEvent.severity == severity)
        return list(self.db.execute(stmt).scalars())

    def queries(self, client_id: str | None = None, action: str | None = None,
               limit: int = 50, offset: int = 0) -> list[Query]:
        stmt = select(Query).order_by(Query.id.desc()).limit(limit).offset(offset)
        if client_id:
            stmt = stmt.where(Query.client_id == client_id)
        if action:
            stmt = stmt.where(Query.action == action)
        return list(self.db.execute(stmt).scalars())


class UserRepository:
    """Account storage. Every account gets exactly one `clients` row at
    registration time (kind='user', fresh risk_score=0.0) -- that row is the
    account's permanent security identity, never reassigned and never reset
    by chat-history actions like starting a new conversation."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_username(self, username: str) -> User | None:
        return self.db.execute(
            select(User).where(User.username == username)
        ).scalar_one_or_none()

    def get_by_id(self, user_id: int) -> User | None:
        return self.db.get(User, user_id)

    def create(self, *, username: str, password_hash: str, role: str = "user",
              first_name: str | None = None, last_name: str | None = None,
              email: str | None = None) -> User:
        # The client row must exist before the user row (FK), and its id
        # can't depend on user.id since users.client_id is NOT NULL from the
        # start -- so it's a random id, not "user-<id>", flushed first.
        client_id = f"user-{secrets.token_hex(6)}"
        self.db.add(Client(client_id=client_id, kind="user"))
        self.db.flush()

        user = User(username=username, password_hash=password_hash, role=role,
                    client_id=client_id, first_name=first_name,
                    last_name=last_name, email=email)
        self.db.add(user)
        self.db.flush()
        return user

    def touch_last_active(self, user_id: int) -> None:
        user = self.get_by_id(user_id)
        if user is not None:
            user.last_active_at = datetime.now(timezone.utc)

    def list_all(self) -> list[User]:
        return list(self.db.execute(
            select(User).where(User.role == "user").order_by(User.created_at)
        ).scalars())


class SessionRepository:
    """Bearer-token sessions. Tokens are opaque and unguessable
    (secrets.token_urlsafe); the only thing that makes a request "logged in"
    is a matching row in this table, looked up server-side on every call."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        self.db.add(UserSession(token=token, user_id=user_id))
        self.db.flush()
        return token

    def get_user(self, token: str) -> User | None:
        session = self.db.get(UserSession, token)
        if session is None:
            return None
        return self.db.get(User, session.user_id)

    def delete(self, token: str) -> None:
        session = self.db.get(UserSession, token)
        if session is not None:
            self.db.delete(session)


class ConversationRepository:
    """Chat-history grouping only -- never consulted by the firewall. See
    Conversation's docstring in db/models.py."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, user_id: int, title: str | None = None) -> Conversation:
        conv = Conversation(user_id=user_id, title=title)
        self.db.add(conv)
        self.db.flush()
        return conv

    def get(self, conversation_id: int) -> Conversation | None:
        return self.db.get(Conversation, conversation_id)

    def list_for_user(self, user_id: int) -> list[Conversation]:
        stmt = (
            select(Conversation).where(Conversation.user_id == user_id)
            .order_by(Conversation.updated_at.desc())
        )
        return list(self.db.execute(stmt).scalars())

    def touch(self, conversation_id: int, *, title_if_unset: str | None = None) -> None:
        conv = self.get(conversation_id)
        if conv is None:
            return
        conv.updated_at = datetime.now(timezone.utc)
        if title_if_unset and not conv.title:
            conv.title = title_if_unset

    def messages(self, conversation_id: int) -> list[Query]:
        stmt = (
            select(Query).where(Query.conversation_id == conversation_id)
            .order_by(Query.seq)
        )
        return list(self.db.execute(stmt).scalars())
