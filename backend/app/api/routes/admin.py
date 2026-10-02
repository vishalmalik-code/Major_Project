"""Security dashboard API. Every route is gated by require_admin -- normal
users must not have access to any of this."""

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_admin_bus, get_db, require_admin, require_admin_sse
from app.core.config import settings
from app.db.models import Query as QueryModel
from app.db.repository import AttackRunRepository, StatsRepository
from app.firewall.window import QueryWindow
from app.schemas.admin import (ClientDetail, ClientSummary, EvaluationResponse,
                               QueryDetail, SecurityEventItem, SignalDetail,
                               StatsResponse, UserDetail, UserSummary)
from app.services.conversation_events import BroadcastBus

router = APIRouter(prefix="/api/admin", tags=["admin"],
                   dependencies=[Depends(require_admin)])

# A SEPARATE router, deliberately NOT carrying the blanket require_admin
# dependency above: GET /stream below needs require_admin_sse instead (it
# accepts a `?token=`/`?admin_token=` query param too, since the browser's
# native EventSource cannot set the X-Admin-Token/Authorization headers
# require_admin checks). Still admin-only -- see require_admin_sse's
# docstring in app/api/deps.py for why this isn't a weaker boundary.
stream_router = APIRouter(prefix="/api/admin", tags=["admin"])


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


@stream_router.get("/stream")
async def admin_stream(req: Request, _: None = Depends(require_admin_sse),
                       bus: BroadcastBus = Depends(get_admin_bus),
                       ) -> StreamingResponse:
    """Live companion to /stats, /clients, /queries, /events: every firewall
    decision anywhere in the system (a real user's own message, the attacker
    console continuing a target conversation, the standalone attacker.py/
    normal_user.py CLIs, or the legacy /api/attack/run runner -- they all
    share the one ChatService instance that publishes here) arrives the
    moment it's decided, so /admin never needs a fixed-interval poll to stay
    current. See ChatService.handle()'s admin_bus.publish call for the exact
    payload (decision, risk, dominant signal, security event -- the same
    admin-authorized detail /api/admin/queries and /api/admin/events already
    expose)."""
    queue = bus.subscribe()

    async def event_source() -> AsyncIterator[str]:
        try:
            yield _sse("ready", {})
            while True:
                if await req.is_disconnected():
                    break
                try:
                    event, data = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield _sse(event, data)
                except asyncio.TimeoutError:
                    # NOT the builtin TimeoutError: asyncio.wait_for raises
                    # asyncio.TimeoutError, a distinct, unrelated class on
                    # Python <3.11 (they're only unified in 3.11+). Catching
                    # the wrong one here let this "expected, every-15s"
                    # timeout escape as an unhandled exception instead.
                    yield ": keep-alive\n\n"
        finally:
            bus.unsubscribe(queue)

    return StreamingResponse(
        event_source(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/stats", response_model=StatsResponse)
async def stats(db: Session = Depends(get_db)) -> StatsResponse:
    """Total, suspicious, throttled, blocked, clients at risk."""
    return StatsResponse(**StatsRepository(db).overview())


@router.get("/clients", response_model=list[ClientSummary])
async def clients(db: Session = Depends(get_db)) -> list[ClientSummary]:
    """Client risk table."""
    repo = StatsRepository(db)
    peak_by_client = repo.peak_risk_by_client()
    out = []
    for c in repo.clients():
        last_query = db.execute(
            select(QueryModel).where(QueryModel.client_id == c.client_id)
            .order_by(QueryModel.seq.desc()).limit(1)
        ).scalar_one_or_none()
        out.append(ClientSummary(
            client_id=c.client_id, kind=c.kind, risk_score=round(c.risk_score, 1),
            highest_risk=round(peak_by_client.get(c.client_id, c.risk_score), 1),
            risk_band=c.risk_band, query_count=c.query_count,
            last_action=last_query.action if last_query else None,
            last_seen=c.last_seen_at.isoformat() if c.last_seen_at else None,
        ))
    return out


@router.get("/clients/{client_id}", response_model=ClientDetail)
async def client_detail(client_id: str, req: Request,
                        db: Session = Depends(get_db)) -> ClientDetail:
    """Drill-down: the live last-20 window, the risk trajectory, and the eight
    signal scores with their evidence sentences. This is the demo centrepiece --
    every point of risk traces to a sentence a human can check."""
    from app.db.models import Client

    client = db.get(Client, client_id)
    if client is None:
        raise HTTPException(status_code=404, detail={"error": {
            "code": "CLIENT_NOT_FOUND", "message": f"No client {client_id}."}})

    rows = list(db.execute(
        select(QueryModel).where(QueryModel.client_id == client_id)
        .order_by(QueryModel.seq.desc()).limit(settings.query_window_size)
    ).scalars())
    rows.reverse()

    window_details = [_query_to_detail(q) for q in rows]
    trajectory = [{"seq": q.seq, "risk": round(q.risk_after, 1)} for q in rows]
    latest_signals = window_details[-1].signals if window_details else []
    action_counts = StatsRepository(db).action_counts_for_client(client_id)

    return ClientDetail(
        client_id=client.client_id, risk_score=round(client.risk_score, 1),
        risk_band=client.risk_band, window=window_details,
        window_size=settings.query_window_size,
        risk_trajectory=trajectory, latest_signals=latest_signals,
        throttle_count=action_counts["throttle_count"],
        block_count=action_counts["block_count"],
    )


@router.get("/queries", response_model=list[QueryDetail])
async def queries(client_id: str | None = None, action: str | None = None,
                  limit: int = 50, offset: int = 0,
                  db: Session = Depends(get_db)) -> list[QueryDetail]:
    """Paged query history with full signal breakdowns."""
    rows = StatsRepository(db).queries(client_id, action, limit, offset)
    return [_query_to_detail(q) for q in rows]


@router.get("/events", response_model=list[SecurityEventItem])
async def events(severity: str | None = None, limit: int = 50,
                 db: Session = Depends(get_db)) -> list[SecurityEventItem]:
    """Recent security events."""
    rows = StatsRepository(db).events(severity, limit)

    query_ids = [e.query_id for e in rows if e.query_id is not None]
    risk_by_query_id: dict[int, float] = {}
    if query_ids:
        linked = db.execute(
            select(QueryModel.id, QueryModel.risk_after)
            .where(QueryModel.id.in_(query_ids))
        ).all()
        risk_by_query_id = {qid: risk for qid, risk in linked}

    return [
        SecurityEventItem(
            id=e.id, client_id=e.client_id, query_id=e.query_id,
            severity=e.severity, event_type=e.event_type, message=e.message,
            risk_score=(round(risk_by_query_id[e.query_id], 1)
                       if e.query_id in risk_by_query_id else None),
            created_at=e.created_at.isoformat(),
        )
        for e in rows
    ]


@router.get("/users", response_model=list[UserSummary])
async def users(db: Session = Depends(get_db)) -> list[UserSummary]:
    """The registered-account table (Part 13) -- distinct from /clients,
    which also lists attacker sessions. One row per real login."""
    return [UserSummary(**row) for row in StatsRepository(db).users_table()]


@router.get("/users/{user_id}", response_model=UserDetail)
async def user_detail(user_id: int, db: Session = Depends(get_db)) -> UserDetail:
    """Drill-down for one account (Part 14): profile, stats, and the user's
    own prompts -- deliberately WITHOUT model responses (Part 15)."""
    row = StatsRepository(db).user_detail(user_id)
    if row is None:
        raise HTTPException(status_code=404, detail={"error": {
            "code": "USER_NOT_FOUND", "message": f"No user {user_id}."}})
    return UserDetail(**row)


@router.get("/attack-runs")
async def attack_runs(db: Session = Depends(get_db)) -> list[dict]:
    """Run summaries for the fast-vs-slow comparison table."""
    runs = AttackRunRepository(db).list_recent()
    return [
        {
            "id": r.id, "strategy": r.strategy, "mode": r.mode,
            "requested_count": r.requested_count, "sent_count": r.sent_count,
            "allowed_count": r.allowed_count, "monitored_count": r.monitored_count,
            "throttled_count": r.throttled_count, "blocked_count": r.blocked_count,
            "queries_to_first_block": r.queries_to_first_block,
            "status": r.status, "started_at": r.started_at.isoformat(),
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        }
        for r in runs
    ]


@router.get("/evaluation", response_model=EvaluationResponse)
async def evaluation() -> EvaluationResponse:
    """Surfaces the most recent real run of backend/evaluate.py (Prompt 4's
    evaluation battery: all 5 attack strategies x {fast,slow} and all 5
    normal-user personas x {fast,slow} against the real firewall).

    Reads straight from evaluation_results/<run_id>/{meta.json,results.jsonl}
    on disk -- evaluate.py is a standalone script, decoupled from the FastAPI
    app the same way attacker.py and normal_user.py are, so this is the only
    place that connects its output to the dashboard. Nothing here is
    computed or invented: if no run exists yet, `available` is False.
    """
    eval_root = Path(__file__).resolve().parents[3] / "evaluation_results"
    if not eval_root.is_dir():
        return EvaluationResponse(available=False)

    run_dirs = sorted(
        (d for d in eval_root.iterdir() if d.is_dir() and d.name.startswith("eval-")),
        key=lambda d: d.name,
    )
    if not run_dirs:
        return EvaluationResponse(available=False)

    latest = run_dirs[-1]
    results_path = latest / "results.jsonl"
    meta_path = latest / "meta.json"
    if not results_path.exists():
        return EvaluationResponse(available=False)

    sessions = []
    for line in results_path.read_text().splitlines():
        line = line.strip()
        if line:
            sessions.append(json.loads(line))

    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}

    return EvaluationResponse(
        available=True, run_id=meta.get("run_id", latest.name),
        base_seed=meta.get("base_seed"), generated_at=meta.get("finished_at"),
        sessions=sessions,
    )


@router.post("/clients/{client_id}/reset")
async def reset_client(client_id: str, req: Request,
                       db: Session = Depends(get_db)) -> dict:
    """Clear risk and window so a pattern can be re-run cleanly. Demo
    convenience -- the request path never calls this."""
    from app.core.constants import EventType, Severity
    from app.db.models import Client
    from app.db.repository import EventRepository

    client = db.get(Client, client_id)
    if client is None:
        raise HTTPException(status_code=404, detail={"error": {
            "code": "CLIENT_NOT_FOUND", "message": f"No client {client_id}."}})

    client.risk_score = 0.0
    client.risk_band = "LOW"
    EventRepository(db).record(
        client_id=client_id, query_id=None, severity=Severity.INFO.value,
        event_type=EventType.CLIENT_RESET.value,
        message=f"Client {client_id} risk and window reset by admin.",
    )
    db.commit()

    window: QueryWindow = req.app.state.window
    window.reset(client_id)
    from app.services import chat_service
    chat_service._warmed_clients.discard(client_id)

    return {"client_id": client_id, "status": "reset"}


@router.get("/config")
async def get_config() -> dict:
    """Current thresholds and signal weights."""
    return settings.model_dump()


@router.put("/config")
async def put_config(updates: dict) -> dict:
    """Live-tune thresholds/weights without a restart, to demonstrate the
    trade-off between false positives and queries-to-block."""
    unknown = [k for k in updates if not hasattr(settings, k)]
    if unknown:
        raise HTTPException(status_code=422, detail={"error": {
            "code": "VALIDATION_ERROR",
            "message": f"Unknown config keys: {unknown}"}})
    for k, v in updates.items():
        setattr(settings, k, v)
    return settings.model_dump()


def _query_to_detail(q: QueryModel) -> QueryDetail:
    return QueryDetail(
        id=q.id, client_id=q.client_id, seq=q.seq, text=q.text, action=q.action,
        weighted_score=round(q.weighted_score, 3), risk_before=round(q.risk_before, 1),
        risk_after=round(q.risk_after, 1), risk_delta=round(q.risk_delta, 1),
        signals=[
            SignalDetail(name=s.signal_name, score=round(s.score, 3),
                        weight=s.weight, evidence=s.evidence, details=s.details)
            for s in q.signal_scores
        ],
        created_at=q.created_at.isoformat(), source=q.source,
    )
