"""FastAPI application.

    NORMAL USER / ATTACKER -> FIREWALL -> Llama 3.2 3B -> RESPONSE

The firewall is the product; the LLM is a black box behind it.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (admin, attack, attacker_console, auth, chat,
                            conversations, health)
from app.attacker.runner import AttackRunner
from app.core.config import settings
from app.embeddings.encoder import Encoder
from app.firewall.engine import FirewallEngine
from app.firewall.window import QueryWindow
from app.services.chat_service import ChatService
from app.services.conversation_events import BroadcastBus, ConversationEventBus
from app.services.llm import LLMService
from app.services.target_registry import TargetRegistry


@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup: load the MiniLM encoder once, wire the singletons every route
    # reads via app.state, and warm the query window lazily per-client.
    encoder = Encoder.instance()
    encoder.load()

    window = QueryWindow()
    engine = FirewallEngine(window)
    llm_service = LLMService()
    conversation_bus = ConversationEventBus()
    admin_bus = BroadcastBus()
    chat_service = ChatService(engine=engine, encoder=encoder, llm=llm_service,
                               bus=conversation_bus, admin_bus=admin_bus)

    app.state.encoder = encoder
    app.state.window = window
    app.state.engine = engine
    app.state.ollama = llm_service
    app.state.chat_service = chat_service
    app.state.attack_runner = AttackRunner(chat_service=chat_service)
    app.state.conversation_bus = conversation_bus
    app.state.admin_bus = admin_bus
    # The attacker<->live-chat target handshake (PROMPT "CONNECT ATTACKER TO
    # THE ACTIVE LLM CHAT IN REAL TIME"): populated only by authenticated
    # /api/conversations/* calls, read by the attacker console. See
    # app/services/target_registry.py.
    app.state.target_registry = TargetRegistry()

    yield
    # shutdown: nothing to release explicitly -- the encoder and pools are
    # process-lifetime objects.


app = FastAPI(
    title="LLM Model Extraction Detection Firewall",
    description="Query-analysis firewall protecting a local Llama 3.2 3B "
                "Instruct from model-extraction attacks.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(chat.router)
app.include_router(attack.router)
app.include_router(attacker_console.router)
app.include_router(admin.router)
app.include_router(admin.stream_router)
app.include_router(auth.router)
app.include_router(conversations.router)
