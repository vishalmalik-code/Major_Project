"""Request/response models for the protected path.

Note what ChatResponse does NOT contain: signal scores, evidence strings, or
thresholds. Normal users must not see security internals -- that breakdown is
admin-only, reachable through /api/admin/queries.
"""

from typing import Literal

from pydantic import BaseModel, Field

from app.core.constants import Action, RiskBand


class ChatRequest(BaseModel):
    client_id: str = Field(min_length=1, max_length=64)
    query: str = Field(min_length=1, max_length=4000)
    # Both optional, both self-reported by the caller -- the same trust
    # model client_id above already has (this route has never authenticated
    # its caller; see app/api/deps.py). conversation_id is NOT taken at face
    # value though: the route below only honors it when it matches the
    # (client_id, conversation_id) pair a real authenticated /chat session
    # most recently registered via app.services.target_registry -- so an
    # arbitrary caller cannot use this field to inject into someone else's
    # chat history. See PROMPT section 12/25 and target_registry.py.
    conversation_id: int | None = None
    source: Literal["user", "attacker"] = "user"


class ChatResponse(BaseModel):
    client_id: str
    seq: int
    action: Action
    risk_score: float
    risk_band: RiskBand
    response: str | None = None          # None when blocked
    notice: str | None = None            # user-facing, non-technical
    throttle_delay_seconds: float | None = None
    retry_after_queries: int | None = None   # queries, NOT seconds
    latency_ms: int | None = None
