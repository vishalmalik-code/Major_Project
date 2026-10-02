"""GET /api/health -- service, Ollama, database, embeddings."""

from fastapi import APIRouter, Request
from sqlalchemy import text

from app.core.config import settings
from app.db.session import SessionLocal

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health")
async def health(request: Request) -> dict:
    ollama = request.app.state.ollama
    ollama_health = await ollama.health()

    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        db_status = "connected"
    except Exception as exc:  # pragma: no cover - environment-dependent
        db_status = f"unavailable: {exc}"

    encoder_loaded = request.app.state.encoder is not None

    return {
        "status": "ok" if ollama_health["reachable"] and db_status == "connected" else "degraded",
        "ollama": "reachable" if ollama_health["reachable"] else "unreachable",
        "model": settings.ollama_model,
        "model_available": ollama_health.get("model_available", False),
        "database": db_status,
        "embeddings": "loaded" if encoder_loaded else "not loaded",
    }
