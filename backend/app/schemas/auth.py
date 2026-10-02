"""Request/response models for the account layer (/api/auth/*,
/api/conversations/*).

What these deliberately never contain: password_hash, another user's data, or
any firewall/security internals (risk score, action, signals) -- those stay
admin-only, exactly like ChatResponse already keeps them out of the normal
/api/chat contract for signal-level detail. See app/schemas/chat.py.
"""

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=200)
    # Optional profile fields from the signup form. Additive on purpose --
    # every existing caller (tests, attacker/normal_user CLIs, evaluate.py)
    # posts only username/password and still validates exactly as before.
    first_name: str | None = Field(default=None, max_length=60)
    last_name: str | None = Field(default=None, max_length=60)
    email: str | None = Field(default=None, max_length=254)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=200)


class UserPublic(BaseModel):
    id: int
    username: str
    role: str
    created_at: str
    first_name: str | None = None
    last_name: str | None = None
    email: str | None = None


class AuthResponse(BaseModel):
    token: str
    user: UserPublic


class ConversationSummary(BaseModel):
    id: int
    title: str | None
    created_at: str
    updated_at: str


class ConversationMessage(BaseModel):
    """A normal user's own message pair. No action, risk_score, risk_band,
    or notice -- a plain chatbot transcript, per the "normal chatbot
    experience" requirement. A blocked/failed turn is indistinguishable from
    the outside: `response` is simply null, exactly like the attacker
    console's client-safe SSE payload does for the same reason."""

    seq: int
    query: str
    response: str | None
    created_at: str
    # 'user' or 'attacker' -- who this turn came from. Not a firewall
    # internal (no action/risk/etc leaks through this schema); the normal
    # chat UI is allowed to render this as a subtle label. See
    # app/core/constants.MessageSource.
    source: str = "user"


class ConversationDetail(BaseModel):
    id: int
    title: str | None
    messages: list[ConversationMessage]


class SendMessageRequest(BaseModel):
    query: str = Field(min_length=1, max_length=4000)


class SendMessageResponse(BaseModel):
    seq: int
    query: str
    response: str | None
