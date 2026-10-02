"""Attack simulator API models."""

from pydantic import BaseModel, Field

from app.core.constants import Action, AttackMode, StrategyId


class StrategyInfo(BaseModel):
    id: str
    name: str
    description: str
    targets: list[str]


class PreviewRequest(BaseModel):
    strategy: StrategyId
    count: int = Field(ge=1, le=200)
    seed: int | None = None


class PreviewResponse(BaseModel):
    strategy: str
    queries: list[str]


class RunRequest(BaseModel):
    strategy: StrategyId
    mode: AttackMode
    count: int = Field(ge=1, le=200)
    client_id: str
    seed: int | None = None


class RunStep(BaseModel):
    seq: int
    query: str
    action: Action
    risk: float
    top_signal: dict | None = None


class RunResponse(BaseModel):
    run_id: str
    strategy: str
    mode: AttackMode
    status: str
    total: int
    sent: int = 0
    counts: dict[str, int] = {}
    queries_to_first_block: int | None = None
    timeline: list[RunStep] = []
