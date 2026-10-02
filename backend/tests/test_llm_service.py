"""Item 1: LLM connection works.

Exercises app/services/llm.py against the real, locally running Ollama
instance -- no mocking. If Ollama isn't up or the model isn't pulled, this
test fails loudly rather than silently skipping, since a working LLM
connection is a hard prerequisite for the rest of the project.
"""

import pytest

from app.services.llm import LLMService


@pytest.mark.asyncio
async def test_ollama_is_reachable_and_model_is_available():
    service = LLMService()
    health = await service.health()
    assert health["reachable"] is True, (
        "Ollama is not reachable -- is it running? (ollama serve)"
    )
    assert health["model_available"] is True, (
        f"Model not pulled -- run: ollama pull {service.model}"
    )


@pytest.mark.asyncio
async def test_generate_returns_nonempty_text():
    service = LLMService()
    response = await service.generate("In one short sentence, what is a firewall?")
    assert isinstance(response, str)
    assert len(response.strip()) > 0
