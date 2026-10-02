"""The attacker's ONLY connection to the system: a plain HTTP client hitting
the same POST /api/chat endpoint a real user's browser calls.

This module deliberately imports nothing from `app.firewall`, `app.db`, or
`app.services` -- the attacker must not have (and cannot have, since this
process doesn't even import those packages) any access to internal firewall
state such as risk scores, signal weights, thresholds, or the query window.
All it knows is: a target URL, a client_id, and a query string.

    Attacker  --HTTP POST /api/chat-->  Firewall  -->  LLM

There is no other path to the LLM from this module.
"""

from dataclasses import dataclass

import httpx


@dataclass
class ChatResult:
    """What the firewall told us, and nothing more -- this mirrors exactly
    what a real client sees, since that's all this client is."""

    http_status: int
    ok: bool
    decision: str | None = None        # ALLOW / MONITOR / THROTTLE / BLOCK
    risk_score: float | None = None
    risk_band: str | None = None
    got_llm_response: bool | None = None
    response: str | None = None        # the actual LLM text, when present
    notice: str | None = None
    error: str | None = None


class FirewallClient:
    """Thin wrapper around one endpoint: POST {base_url}/api/chat."""

    def __init__(self, base_url: str, timeout: float = 90.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=timeout)

    def send(self, client_id: str, query: str, *,
             conversation_id: int | None = None, source: str = "attacker") -> ChatResult:
        body = {"client_id": client_id, "query": query, "source": source}
        if conversation_id is not None:
            body["conversation_id"] = conversation_id
        try:
            resp = self._client.post(f"{self.base_url}/api/chat", json=body)
        except httpx.HTTPError as exc:
            return ChatResult(http_status=0, ok=False, error=str(exc))

        if resp.status_code != 200:
            return ChatResult(http_status=resp.status_code, ok=False,
                              error=resp.text[:500])

        body = resp.json()
        return ChatResult(
            http_status=resp.status_code, ok=True,
            decision=body.get("action"), risk_score=body.get("risk_score"),
            risk_band=body.get("risk_band"),
            got_llm_response=body.get("response") is not None,
            response=body.get("response"),
            notice=body.get("notice"),
        )

    def close(self) -> None:
        self._client.close()
