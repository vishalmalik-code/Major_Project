"""Authenticated chat history + the browser's send path.

    Browser --POST /api/conversations/{id}/messages--> this route
                                                             |
                                              ChatService.handle(client_id=user.client_id,
                                                                 conversation_id=id)
                                                             |
                                                        (unchanged path:)
                                                     Firewall -> LLM

This is the ONLY place a real logged-in user's browser reaches the firewall
-- it calls the exact same ChatService.handle() that /api/chat, the attacker
console, and every CLI tool already use (see app/services/chat_service.py);
nothing about detection, risk, or the query window is reimplemented here.

The one thing this route controls that /api/chat's own schema does not: which
`client_id` is used (always the caller's own permanent account identity,
never client-supplied) and which `conversation_id` a message is filed under
for chat-history purposes. Starting a new conversation only ever calls
POST /api/conversations, never touches clients.risk_score/window, and re-uses
the same client_id every time -- so a fresh conversation is a clean chat
transcript, not a firewall reset. See db/init.sql and repository.py's
Conversation docstrings for why those two ideas are kept apart.

The response shape (ConversationMessage/SendMessageResponse) mirrors the
attacker console's client-safe SSE payload: no action, risk_score, risk_band,
or notice -- a normal chatbot transcript, not a security console. A blocked
or failed turn is indistinguishable from any other missing response.
"""

import asyncio
import json
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import (get_chat_service, get_conversation_bus, get_current_user,
                          get_current_user_sse, get_db, get_target_registry)
from app.db.models import User
from app.db.repository import ConversationRepository, UserRepository
from app.schemas.auth import (ConversationDetail, ConversationMessage,
                              ConversationSummary, SendMessageRequest,
                              SendMessageResponse)
from app.services.chat_service import ChatService
from app.services.conversation_events import ConversationEventBus
from app.services.target_registry import TargetRegistry

router = APIRouter(prefix="/api/conversations", tags=["conversations"])


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _mark_active(targets: TargetRegistry, user: User, conversation_id: int) -> None:
    """The target-session handshake (PROMPT section 2): every time this
    user's own authenticated browser opens, creates, or sends in a
    conversation, that becomes the one conversation the attacker console can
    see as "connected" -- see target_registry.py for why this is safe."""
    targets.set_active(user_id=user.id, client_id=user.client_id,
                       conversation_id=conversation_id)


def _not_found() -> HTTPException:
    return HTTPException(status_code=404, detail={"error": {
        "code": "CONVERSATION_NOT_FOUND", "message": "No such conversation."}})


def _owned_conversation(conversation_id: int, user: User, db: Session):
    """Every lookup goes through here: a conversation that exists but belongs
    to someone else is reported as 404, identically to one that doesn't
    exist at all -- User A gets no signal, positive or negative, about
    whether conversation_id N belongs to User B."""
    conv = ConversationRepository(db).get(conversation_id)
    if conv is None or conv.user_id != user.id:
        raise _not_found()
    return conv


@router.post("", response_model=ConversationSummary)
async def create_conversation(user: User = Depends(get_current_user),
                              db: Session = Depends(get_db),
                              targets: TargetRegistry = Depends(get_target_registry),
                              ) -> ConversationSummary:
    conv = ConversationRepository(db).create(user_id=user.id)
    db.commit()
    _mark_active(targets, user, conv.id)
    return ConversationSummary(id=conv.id, title=conv.title,
                               created_at=conv.created_at.isoformat(),
                               updated_at=conv.updated_at.isoformat())


@router.get("", response_model=list[ConversationSummary])
async def list_conversations(user: User = Depends(get_current_user),
                             db: Session = Depends(get_db)) -> list[ConversationSummary]:
    convs = ConversationRepository(db).list_for_user(user.id)
    return [
        ConversationSummary(id=c.id, title=c.title, created_at=c.created_at.isoformat(),
                            updated_at=c.updated_at.isoformat())
        for c in convs
    ]


@router.get("/{conversation_id}", response_model=ConversationDetail)
async def get_conversation(conversation_id: int, user: User = Depends(get_current_user),
                           db: Session = Depends(get_db),
                           targets: TargetRegistry = Depends(get_target_registry),
                           ) -> ConversationDetail:
    conv = _owned_conversation(conversation_id, user, db)
    messages = ConversationRepository(db).messages(conversation_id)
    _mark_active(targets, user, conversation_id)
    return ConversationDetail(
        id=conv.id, title=conv.title,
        messages=[
            ConversationMessage(seq=m.seq, query=m.text, response=m.response,
                                created_at=m.created_at.isoformat(), source=m.source)
            for m in messages
        ],
    )


@router.post("/{conversation_id}/messages", response_model=SendMessageResponse)
async def send_message(conversation_id: int, request: SendMessageRequest,
                       user: User = Depends(get_current_user),
                       db: Session = Depends(get_db),
                       service: ChatService = Depends(get_chat_service),
                       targets: TargetRegistry = Depends(get_target_registry),
                       ) -> SendMessageResponse:
    _owned_conversation(conversation_id, user, db)
    _mark_active(targets, user, conversation_id)

    decision, response_text, _latency_ms = await service.handle(
        db, user.client_id, request.query, conversation_id=conversation_id)

    title = request.query[:48] + ("..." if len(request.query) > 48 else "")
    conv_repo = ConversationRepository(db)
    conv_repo.touch(conversation_id, title_if_unset=title)
    UserRepository(db).touch_last_active(user.id)
    db.commit()

    return SendMessageResponse(seq=decision.seq, query=request.query, response=response_text)


@router.get("/{conversation_id}/stream")
async def stream_conversation(conversation_id: int, req: Request,
                              user: User = Depends(get_current_user_sse),
                              db: Session = Depends(get_db),
                              bus: ConversationEventBus = Depends(get_conversation_bus),
                              ) -> StreamingResponse:
    """Real-time companion to GET /{conversation_id}: while this connection is
    open, any NEW message filed under this conversation -- from this user's
    own other tab, or from the attacker console continuing the same
    conversation (see attacker_console.py) -- arrives here the moment
    ChatService.handle() commits it, no polling and no page refresh.

    Same client-safe shape as GET /{conversation_id}'s messages (seq, query,
    response, source, created_at) -- no action/risk_score/risk_band/notice.
    The frontend de-duplicates by `seq`, so a message this same tab already
    rendered optimistically (its own send) is simply skipped when it also
    arrives here.
    """
    _owned_conversation(conversation_id, user, db)
    queue = bus.subscribe(conversation_id)

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
                    # Python <3.11 (unified with the builtin only in 3.11+).
                    yield ": keep-alive\n\n"  # SSE comment line -- no client-side event
        finally:
            bus.unsubscribe(conversation_id, queue)

    return StreamingResponse(
        event_source(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
