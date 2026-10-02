"""Attack simulator control surface.

`run` drives the strategy through the SAME ChatService path as /api/chat --
the simulator is an ordinary client with no special access to the firewall.
"""

from fastapi import APIRouter, HTTPException, Request

from app.attacker.registry import get as get_strategy, listing
from app.schemas.attack import (PreviewRequest, PreviewResponse, RunRequest,
                                RunResponse, RunStep, StrategyInfo)

router = APIRouter(prefix="/api/attack", tags=["attack"])


@router.get("/strategies", response_model=list[StrategyInfo])
async def strategies() -> list[StrategyInfo]:
    """The five patterns, with the signals each is designed to trip."""
    return listing()


@router.post("/preview", response_model=PreviewResponse)
async def preview(request: PreviewRequest) -> PreviewResponse:
    """Generate the queries WITHOUT sending them, so the console can show the
    pattern before it is fired."""
    strategy = get_strategy(request.strategy.value)
    queries = strategy.generate(request.count, seed=request.seed)
    return PreviewResponse(strategy=request.strategy.value, queries=queries)


@router.post("/run", response_model=RunResponse)
async def run(request: RunRequest, req: Request) -> RunResponse:
    """Start a run in the background and return a run_id immediately -- a SLOW
    run of 15 queries takes about 15 minutes at default pacing."""
    runner = req.app.state.attack_runner
    result = await runner.start(
        strategy_id=request.strategy.value, mode=request.mode,
        count=request.count, client_id=request.client_id, seed=request.seed,
    )
    return _to_response(result)


@router.get("/runs/{run_id}", response_model=RunResponse)
async def run_status(run_id: str, req: Request) -> RunResponse:
    """Progress and results, including queries_to_first_block."""
    runner = req.app.state.attack_runner
    result = runner.get(run_id)
    if result is None:
        raise HTTPException(status_code=404, detail={"error": {
            "code": "RUN_NOT_FOUND", "message": f"No attack run {run_id}."}})
    return _to_response(result)


def _to_response(result) -> RunResponse:
    return RunResponse(
        run_id=result.run_id, strategy=result.strategy, mode=result.mode,
        status=result.status, total=result.total, sent=result.sent,
        counts=result.counts, queries_to_first_block=result.queries_to_first_block,
        timeline=[RunStep(seq=s.seq, query=s.query, action=s.action, risk=s.risk,
                          top_signal=s.top_signal) for s in result.timeline],
    )
