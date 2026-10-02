"""Attacker Console (the /attacker web UI) streaming endpoint.

The ONE new backend surface this feature needed. Everything it does was
already built for the standalone attacker.py CLI -- this route is a thin
adapter that generates queries with the same reusable strategy generators
(app.attacker.registry), paces and sends them with the exact same HTTP-only
client the CLI uses (attacker_cli.http_client.FirewallClient -- a plain
POST /api/chat, nothing else), and streams each result to the browser over
Server-Sent Events as it arrives.

    Browser  --GET /api/attacker-console/stream-->  this route
                                                          |
                                                          | (per query)
                                                          v
                                            FirewallClient.send()
                                                          |
                                              HTTP POST /api/chat  <-- same
                                                          |          endpoint
                                                          v          a real
                                                     Firewall          user
                                                          |          hits
                                                          v
                                          Ollama (unless BLOCKed)

No firewall internals are imported here beyond what the CLI already touches
(app.attacker.registry is pure query templates; attacker_cli.http_client is a
plain HTTP client). This route does not call app.services.chat_service or
app.firewall.* directly, and never talks to Ollama itself.

The SSE payload sent to the browser is deliberately client-safe: FirewallClient
gets back the full /api/chat response (decision, risk_score, risk_band,
notice) because attacker.py's CLI wants that for its own console output, but
this route only forwards query_number, query, and response text -- exactly
what an external attacker/client would plausibly see. It never forwards
decision, risk_score, risk_band, notice, or error detail; a blocked or failed
query simply arrives with response: null, same as an unrelated failure would.
That distinction (attacker sees "no response"; /admin sees why) is the whole
point of this endpoint existing separately from attacker.py's CLI output.

SSE was chosen over WebSocket/polling because the data only flows one
direction (server -> browser) and the browser's native EventSource API needs
no library and no new infrastructure -- exactly the "simplest reliable
mechanism" the brief asked for. Stopping an attack is just the browser
closing the EventSource; the server notices via `request.is_disconnected()`
and stops sending further queries (no separate stop endpoint needed).
"""

import asyncio
import json
from collections.abc import AsyncIterator

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse

from app.attacker.registry import CLI_ALIASES, get as get_strategy
from attacker_cli.client_id import next_client_id
from attacker_cli.http_client import FirewallClient
from attacker_cli.pacing import FastPacer, SlowPacer

router = APIRouter(prefix="/api/attacker-console", tags=["attacker-console"])


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


@router.get("/target")
async def target_status(request: Request) -> dict:
    """Read-only "is there a live chat session to continue?" check for the
    console's TARGET indicator (PROMPT section 14). Deliberately returns
    nothing but a boolean -- no client_id, conversation_id, user_id, or
    username -- the attacker console never needs (and must never receive)
    enough information to pick a specific user or conversation itself; see
    target_registry.py's module docstring."""
    target = request.app.state.target_registry.get_active()
    return {"available": target is not None}


@router.get("/stream")
async def stream(
    request: Request,
    strategy: str = Query(..., description="repetition | minimal_modification | "
                          "value_sweep | output_constraint | boundary"),
    mode: str = Query(..., pattern="^(fast|slow)$"),
    count: int = Query(10, ge=1, le=200),
    topic: str | None = Query(None),
    client_id: str | None = Query(None),
    seed: int | None = Query(None),
) -> StreamingResponse:
    target_url = "http://localhost:8000"

    if strategy not in CLI_ALIASES:
        async def _bad_strategy() -> AsyncIterator[str]:
            yield _sse("error", {"message": f"unknown strategy '{strategy}'"})
        return StreamingResponse(_bad_strategy(), media_type="text/event-stream")

    internal_id = CLI_ALIASES[strategy]
    strat = get_strategy(internal_id)
    queries = strat.generate(count, seed=seed, topic=topic)
    pacer = FastPacer() if mode == "fast" else SlowPacer()

    # Targeting handshake: an explicit client_id (CLI-style / existing tests)
    # always wins and runs exactly as before -- a fresh, independent,
    # untargeted client. Only when the caller does NOT pin a client_id do we
    # look at the active target (PROMPT sections 1-3, 11): if a real user has
    # a live /chat conversation open, THIS run continues it, using that
    # user's own client_id/conversation_id -- same firewall/security state,
    # same conversation, "Q4" naturally follows "Q3" via the shared per-client
    # seq counter. Nothing here is client-suppliable: the browser cannot ask
    # for a specific target, only "auto" (no client_id) or "standalone"
    # (explicit client_id).
    conversation_id: int | None = None
    if client_id:
        cid = client_id
    else:
        active = request.app.state.target_registry.get_active()
        if active is not None:
            cid = active.client_id
            conversation_id = active.conversation_id
        else:
            cid = next_client_id(f"web-{strategy}", mode)

    async def event_source() -> AsyncIterator[str]:
        yield _sse("meta", {"client_id": cid, "strategy": strategy, "mode": mode,
                            "total": len(queries), "targeted": conversation_id is not None})

        client = FirewallClient(base_url=target_url)
        stopped = False
        try:
            for i, query in enumerate(queries, start=1):
                if await request.is_disconnected():
                    stopped = True
                    break
                if i > 1:
                    await asyncio.sleep(pacer.delay())
                if await request.is_disconnected():
                    stopped = True
                    break

                # FirewallClient.send is a synchronous httpx.Client call (it's
                # shared with the CLI, which has no need to be async); run it
                # in a worker thread so this coroutine doesn't block the event
                # loop -- and therefore every other request this server is
                # handling -- while it waits on a THROTTLE delay or Ollama.
                result = await asyncio.to_thread(
                    client.send, cid, query, conversation_id=conversation_id)

                # Client-safe payload only: no decision, risk_score, risk_band,
                # notice, or error detail reaches the browser. A blocked query
                # and a genuinely failed one both simply arrive with no
                # response text -- the attacker cannot tell them apart, and
                # cannot tell either apart from the firewall having acted.
                yield _sse("query", {
                    "query_number": i, "query": query,
                    "response": result.response if result.ok else None,
                })
        finally:
            client.close()

        yield _sse("done", {"status": "stopped" if stopped else "completed"})

    return StreamingResponse(
        event_source(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
