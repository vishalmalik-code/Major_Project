"""POST /api/chat -- THE PROTECTED PATH.

Every query in the system flows through here: normal users AND the attack
simulator. There is no bypass and no privileged caller. All orchestration
(window warming, persistence, acting on the decision) lives in
ChatService.handle(); this route is thin.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_chat_service, get_db, get_target_registry
from app.core.constants import Action
from app.schemas.chat import ChatRequest, ChatResponse
from app.services.chat_service import ChatService
from app.services.target_registry import TargetRegistry

router = APIRouter(prefix="/api", tags=["chat"])

_NOTICES = {
    Action.THROTTLE: "Response delayed due to unusual query patterns.",
    Action.BLOCK: "This request was blocked by usage policy.",
}


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, db: Session = Depends(get_db),
               service: ChatService = Depends(get_chat_service),
               targets: TargetRegistry = Depends(get_target_registry),
               ) -> ChatResponse:
    # A supplied conversation_id is only ever honored if it's the exact pair
    # a real authenticated /chat session most recently registered -- see
    # ChatRequest's docstring-comment and target_registry.py.
    conversation_id = request.conversation_id
    if conversation_id is not None and not targets.is_valid_pair(
            request.client_id, conversation_id):
        conversation_id = None

    decision, response_text, latency_ms = await service.handle(
        db, request.client_id, request.query,
        conversation_id=conversation_id, source=request.source)

    return ChatResponse(
        client_id=decision.client_id,
        seq=decision.seq,
        action=decision.action,
        risk_score=round(decision.risk_after, 1),
        risk_band=decision.risk_band,
        response=response_text,
        notice=_NOTICES.get(decision.action),
        throttle_delay_seconds=(decision.throttle_delay_seconds
                                if decision.action == Action.THROTTLE else None),
        retry_after_queries=(decision.retry_after_queries
                             if decision.action == Action.BLOCK else None),
        latency_ms=latency_ms,
    )
