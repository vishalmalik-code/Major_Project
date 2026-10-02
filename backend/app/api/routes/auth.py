"""Account creation and session management -- the ONE new layer this
restructuring adds in front of the existing, unchanged POST /api/chat.

    Browser --/api/auth/login--> this route --bcrypt.checkpw--> users table
                                                   |
                                              sessions row (Bearer token)

/api/chat itself is deliberately left untouched and still requires no login:
it is also the endpoint attacker.py, normal_user.py, evaluate.py, and the
attacker console all call directly, none of which are (or should be) forced
through a normal-user account. Authentication happens ONLY at this new layer
and at /api/conversations/*, which is where the real browser /chat page now
sends messages.

Every account gets exactly one permanent client_id (see
UserRepository.create), set once at registration and never reassigned. That
is what makes a brand-new account start with clean firewall state (risk 0,
empty window) regardless of what any other account has done, and what makes
"new conversation" a pure chat-history action with no effect on security
state -- see app/db/repository.py's ConversationRepository docstring.
"""

import bcrypt
from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.db.models import User
from app.db.repository import SessionRepository, UserRepository
from app.schemas.auth import (AuthResponse, LoginRequest, RegisterRequest,
                              UserPublic)

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _public(user: User) -> UserPublic:
    return UserPublic(id=user.id, username=user.username, role=user.role,
                      created_at=user.created_at.isoformat(),
                      first_name=user.first_name, last_name=user.last_name,
                      email=user.email)


@router.post("/register", response_model=AuthResponse)
async def register(request: RegisterRequest, db: Session = Depends(get_db)) -> AuthResponse:
    """Self-service signup for NORMAL USERS ONLY. `role` is never accepted
    from the client -- every account created here is hardcoded to 'user'.
    The one admin account is created exclusively by the seed script
    (scripts/seed_admin.py), never through this endpoint."""
    repo = UserRepository(db)
    if repo.get_by_username(request.username) is not None:
        raise HTTPException(status_code=409, detail={"error": {
            "code": "USERNAME_TAKEN", "message": "That username is already registered."}})

    password_hash = bcrypt.hashpw(request.password.encode(), bcrypt.gensalt()).decode()
    user = repo.create(username=request.username, password_hash=password_hash, role="user",
                       first_name=request.first_name, last_name=request.last_name,
                       email=request.email)
    token = SessionRepository(db).create(user.id)
    db.commit()

    return AuthResponse(token=token, user=_public(user))


@router.post("/login", response_model=AuthResponse)
async def login(request: LoginRequest, db: Session = Depends(get_db)) -> AuthResponse:
    """One login for both users and admins: the UI may present separate
    "User login" / "Admin login" tabs, but authorization is decided here,
    server-side, from the account's actual `role` column -- never from which
    tab the browser happened to submit."""
    repo = UserRepository(db)
    user = repo.get_by_username(request.username)
    if user is None or not bcrypt.checkpw(request.password.encode(),
                                          user.password_hash.encode()):
        raise HTTPException(status_code=401, detail={"error": {
            "code": "INVALID_CREDENTIALS", "message": "Incorrect username or password."}})

    repo.touch_last_active(user.id)
    token = SessionRepository(db).create(user.id)
    db.commit()

    return AuthResponse(token=token, user=_public(user))


@router.post("/logout")
async def logout(authorization: str | None = Header(default=None),
                 db: Session = Depends(get_db),
                 _user: User = Depends(get_current_user)) -> dict:
    """`_user` is only there to 401 an already-invalid/missing token; the
    actual deletion needs the raw token string, not the resolved account."""
    token = authorization.removeprefix("Bearer ").strip()
    SessionRepository(db).delete(token)
    db.commit()
    return {"status": "logged_out"}


@router.get("/me", response_model=UserPublic)
async def me(user: User = Depends(get_current_user)) -> UserPublic:
    return _public(user)
