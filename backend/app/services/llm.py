"""LLM service: the backend's only connection to Ollama.

Accepts a prompt, sends it to the locally running Llama 3.2 3B Instruct model
via Ollama's HTTP API, and returns the generated text. Deliberately dumb: this
service knows nothing about risk, clients, or the query window -- it is a
black box behind the firewall.

It is only ever called for ALLOW, MONITOR and THROTTLE decisions. A BLOCK
decision short-circuits in ChatService and never reaches this module -- the
query must never reach the LLM before the firewall has decided.

Ollama's URL and the model name are both configurable via .env
(OLLAMA_BASE_URL, OLLAMA_MODEL) -- see app/core/config.py.
"""

import httpx

from app.core.config import settings


class LLMService:
    def __init__(self) -> None:
        self.base_url = settings.ollama_base_url
        self.model = settings.ollama_model
        self.timeout = settings.ollama_timeout_seconds

    async def generate(self, prompt: str, max_tokens: int | None = None) -> str:
        """POST /api/generate. `max_tokens` lets THROTTLE optionally degrade
        response richness in addition to delaying it."""
        options = {}
        if max_tokens is not None:
            options["num_predict"] = max_tokens

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False,
                     "options": options},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "")

    async def health(self) -> dict:
        """GET /api/tags -- is Ollama up and is the model pulled?"""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                resp.raise_for_status()
                data = resp.json()
                models = [m["name"] for m in data.get("models", [])]
                return {"reachable": True, "model_available": self.model in models,
                       "models": models}
        except (httpx.HTTPError, httpx.TransportError) as exc:
            return {"reachable": False, "model_available": False, "error": str(exc)}
