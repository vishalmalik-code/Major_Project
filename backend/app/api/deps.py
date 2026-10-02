"""Shared dependencies.

The admin gate is a shared secret in a header, OR a session token that
resolves (server-side, via the sessions/users tables) to an account with
role='admin'. Either is adequate for a local single-machine simulation and is
documented as such -- these are demonstration boundaries, not a production
auth system. What matters for the project is that the boundary EXISTS: normal
users have no route to the security dashboard, and the frontend's own claims
about who is logged in are never trusted -- every check here re-derives the
answer from the database.
"""

from fastapi import Depends, Header, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import User
from app.db.repository import SessionRepository
from app.db.session import SessionLocal
from app.services.chat_service import ChatService
from app.services.conversation_events import BroadcastBus, ConversationEventBus
from app.services.target_registry import TargetRegistry


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _unauthorized(message: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": {"code": "UNAUTHORIZED", "message": message}},
    )


def _user_from_bearer(authorization: str | None, db: Session) -> User | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        return None
    return SessionRepository(db).get_user(token)


def require_admin(x_admin_token: str | None = Header(default=None),
                  authorization: str | None = Header(default=None),
                  db: Session = Depends(get_db)) -> None:
    if x_admin_token == settings.admin_token:
        return
    user = _user_from_bearer(authorization, db)
    if user is not None and user.role == "admin":
        return
    raise _unauthorized("Valid X-Admin-Token, or an admin session, required.")


def get_current_user(authorization: str | None = Header(default=None),
                     db: Session = Depends(get_db)) -> User:
    """Gate for the authenticated user-facing routes (/api/conversations/*).
    Deliberately separate from require_admin: a normal user session must
    never satisfy the admin gate, and an admin token/session is not itself
    a user account (the seeded admin has no conversations of its own)."""
    user = _user_from_bearer(authorization, db)
    if user is None:
        raise _unauthorized("Valid session required. Log in via /api/auth/login.")
    return user


def get_current_user_sse(authorization: str | None = Header(default=None),
                         token: str | None = Query(default=None),
                         db: Session = Depends(get_db)) -> User:
    """Same gate as get_current_user, plus a `?token=` fallback -- ONLY for
    the SSE route (GET /api/conversations/{id}/stream). The browser's native
    EventSource cannot set an Authorization header, so that one endpoint
    needs a way to authenticate from the URL. Every other authenticated route
    keeps using the header-only get_current_user; this does not weaken that
    boundary anywhere else."""
    user = _user_from_bearer(authorization, db)
    if user is not None:
        return user
    if token:
        user = SessionRepository(db).get_user(token)
        if user is not None:
            return user
    raise _unauthorized("Valid session required. Log in via /api/auth/login.")


def require_admin_sse(x_admin_token: str | None = Header(default=None),
                      authorization: str | None = Header(default=None),
                      token: str | None = Query(default=None),
                      admin_token: str | None = Query(default=None),
                      db: Session = Depends(get_db)) -> None:
    """Same gate as require_admin, plus `?token=`/`?admin_token=` fallbacks --
    ONLY for the SSE route (GET /api/admin/stream), for the identical
    EventSource-cannot-set-headers reason as get_current_user_sse above.
    Still fully re-derives authorization server-side (a real session token
    resolved against the sessions/users tables, or the real shared secret);
    nothing here is weaker than require_admin, just reachable from a URL."""
    if x_admin_token == settings.admin_token or admin_token == settings.admin_token:
        return
    user = _user_from_bearer(authorization, db)
    if user is not None and user.role == "admin":
        return
    if token:
        user = SessionRepository(db).get_user(token)
        if user is not None and user.role == "admin":
            return
    raise _unauthorized("Valid X-Admin-Token, or an admin session, required.")


def get_chat_service(request: Request) -> ChatService:
    return request.app.state.chat_service


def get_target_registry(request: Request) -> TargetRegistry:
    return request.app.state.target_registry


def get_conversation_bus(request: Request) -> ConversationEventBus:
    return request.app.state.conversation_bus


def get_admin_bus(request: Request) -> BroadcastBus:
    return request.app.state.admin_bus
