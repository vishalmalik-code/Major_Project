# services/

Orchestration that is neither HTTP nor detection:

- `chat_service.py` — glue for the `/api/chat` path: engine.inspect → act on the
  decision (sleep / refuse / call Ollama) → engine.commit.
- `stats_service.py` — dashboard aggregations over `queries`, `security_events`,
  `attack_runs`.

Kept separate so `FirewallEngine` stays pure and unit-testable without a running
Ollama or database.
