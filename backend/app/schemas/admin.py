"""Admin dashboard API models. Everything here is behind X-Admin-Token."""

from pydantic import BaseModel

from app.core.constants import Action, RiskBand, Severity


class StatsResponse(BaseModel):
    total_queries: int
    suspicious_queries: int      # MONITOR and above
    throttled: int
    blocked: int
    unique_clients: int
    clients_at_risk: int
    by_action: dict[str, int]
    # --- account-layer KPIs (Part 12) -- all real DB aggregates, none invented ---
    total_users: int
    active_users: int            # last_active_at within 24h
    total_conversations: int
    flagged_users: int           # registered users whose client risk_band != LOW
    throttled_users: int         # registered users with >=1 THROTTLE query ever
    blocked_users: int           # registered users with >=1 BLOCK query ever
    total_blocked_queries: int
    total_throttled_queries: int
    total_security_events: int


class ClientSummary(BaseModel):
    client_id: str
    kind: str
    risk_score: float
    highest_risk: float
    risk_band: RiskBand
    query_count: int
    last_action: Action | None
    last_seen: str | None


class SignalDetail(BaseModel):
    name: str
    score: float
    weight: float
    evidence: str        # the explainability guarantee, rendered in the UI
    details: dict = {}


class QueryDetail(BaseModel):
    id: int
    client_id: str
    seq: int
    text: str
    action: Action
    weighted_score: float
    risk_before: float
    risk_after: float
    risk_delta: float
    signals: list[SignalDetail] = []
    created_at: str
    source: str = "user"   # 'user' or 'attacker' -- see Query.source


class ClientDetail(BaseModel):
    client_id: str
    risk_score: float
    risk_band: RiskBand
    window: list[QueryDetail]                 # the live last-20, in query order
    window_size: int                          # the configured window size (20)
    risk_trajectory: list[dict]               # [{seq, risk}] for the chart
    latest_signals: list[SignalDetail]
    throttle_count: int                       # lifetime, not just current window
    block_count: int                          # lifetime, not just current window


class SecurityEventItem(BaseModel):
    id: int
    client_id: str
    query_id: int | None
    severity: Severity
    event_type: str
    message: str
    risk_score: float | None    # the linked query's risk_after, when there is one
    created_at: str


class UserSummary(BaseModel):
    """One row of the admin User List (Part 13). `status` is derived
    straight from the account's existing client risk_band -- LOW/MEDIUM/
    HIGH/CRITICAL renamed to NORMAL/MONITORED/THROTTLED/BLOCKED, the same
    thresholds the firewall already uses, nothing new invented."""
    id: int
    username: str
    status: str
    client_id: str
    created_at: str
    last_active_at: str
    total_queries: int
    total_conversations: int
    current_risk: float
    highest_risk: float
    flagged_count: int     # queries with action != ALLOW
    throttled_count: int
    blocked_count: int


class UserQueryItem(BaseModel):
    """A prompt in the admin's user-observation view (Part 14/15).
    Deliberately has NO `response` field -- model responses stay private
    from the security dashboard even for the admin."""
    seq: int
    text: str
    action: Action
    risk_score: float
    created_at: str


class UserDetail(BaseModel):
    id: int
    username: str
    status: str
    client_id: str
    created_at: str
    last_active_at: str
    total_queries: int
    total_conversations: int
    current_risk: float
    highest_risk: float
    flagged_count: int
    throttled_count: int
    blocked_count: int
    queries: list[UserQueryItem]


class EvaluationResponse(BaseModel):
    """GET /api/admin/evaluation -- surfaces the most recent real evaluation
    run's results (backend/evaluate.py output). Never fabricated: if no
    evaluation has been run yet, `available` is False and `sessions` is
    empty."""
    available: bool
    run_id: str | None = None
    base_seed: int | None = None
    generated_at: str | None = None
    sessions: list[dict] = []
