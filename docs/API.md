# API Contract

Base URL: `http://localhost:8000`
All bodies are JSON. Admin routes require header `X-Admin-Token: <ADMIN_TOKEN>`.

---

## Public

### `GET /api/health`

```json
{ "status": "ok", "ollama": "reachable", "model": "llama3.2:3b-instruct-q4_K_M",
  "database": "connected", "embeddings": "loaded" }
```

---

### `POST /api/chat` — the protected path

Every query, from user or attacker, goes through here. There is no bypass.

**Request**
```json
{ "client_id": "user-a91f", "query": "How does TLS certificate pinning work?" }
```

**Response — allowed**
```json
{
  "client_id": "user-a91f",
  "seq": 7,
  "action": "ALLOW",
  "risk_score": 12.4,
  "risk_band": "LOW",
  "response": "Certificate pinning binds a host to ...",
  "notice": null,
  "latency_ms": 1840
}
```

**Response — throttled**
```json
{ "action": "THROTTLE", "risk_score": 61.2, "risk_band": "HIGH",
  "response": "...", "notice": "Response delayed due to unusual query patterns.",
  "throttle_delay_seconds": 5.0, "latency_ms": 6910 }
```

**Response — blocked** (HTTP 200 with `action: BLOCK`; the LLM is never called)
```json
{ "action": "BLOCK", "risk_score": 87.0, "risk_band": "CRITICAL",
  "response": null,
  "notice": "This request was blocked by usage policy.",
  "retry_after_queries": 2 }
```

`retry_after_queries` = how many sufficiently-dissimilar queries would bring risk
back under CRITICAL: `ceil((risk - RISK_THRESHOLD_CRITICAL) / DECAY_STEP)`.
Note it is measured in **queries, not seconds** — waiting changes nothing.

The client response **never** contains signal scores or evidence. Those are
admin-only; the same query inspected via `/api/admin/queries` carries the full
breakdown.

---

## Attack simulator

### `GET /api/attack/strategies`

```json
[ { "id": "exact_repetition",     "name": "Exact Query Repetition",
    "description": "Sends the identical query repeatedly.",
    "targets": ["exact_repetition", "text_similarity", "semantic_similarity"] },
  { "id": "minimal_modification",  "name": "Minimal Query Modification",  "...": "..." },
  { "id": "value_sweep",           "name": "Systematic Value Sweep",      "...": "..." },
  { "id": "constraint_probing",    "name": "Output-Constraint Probing",   "...": "..." },
  { "id": "boundary_probing",      "name": "Boundary / Edge-Case Probing","...": "..." } ]
```

### `POST /api/attack/preview`

Generate the queries **without sending them** — lets the UI show the pattern.

```json
{ "strategy": "value_sweep", "count": 8, "seed": 42 }
```
```json
{ "strategy": "value_sweep",
  "queries": ["Is TCP port 1 commonly used by malware?",
              "Is TCP port 2 commonly used by malware?", "..."] }
```

### `POST /api/attack/run`

```json
{ "strategy": "minimal_modification", "mode": "SLOW",
  "count": 15, "client_id": "attacker-3", "seed": 42 }
```
```json
{ "run_id": "run-7c21", "status": "running", "total": 15 }
```

### `GET /api/attack/runs/{run_id}`

```json
{
  "run_id": "run-7c21", "strategy": "minimal_modification", "mode": "SLOW",
  "status": "finished", "total": 15, "sent": 15,
  "counts": { "ALLOW": 4, "MONITOR": 3, "THROTTLE": 4, "BLOCK": 4 },
  "queries_to_first_block": 12,
  "timeline": [
    { "seq": 1, "query": "...", "action": "ALLOW",  "risk": 0.0,
      "top_signal": null },
    { "seq": 2, "query": "...", "action": "ALLOW",  "risk": 9.8,
      "top_signal": { "name": "semantic_similarity", "score": 0.71 } }
  ]
}
```

`queries_to_first_block` is the headline metric for the fast-vs-slow comparison.

---

## Admin

### `GET /api/admin/stats`
```json
{ "total_queries": 412, "suspicious_queries": 168, "throttled": 74,
  "blocked": 39, "unique_clients": 6, "clients_at_risk": 3,
  "by_action": { "ALLOW": 205, "MONITOR": 94, "THROTTLE": 74, "BLOCK": 39 } }
```

### `GET /api/admin/clients`
```json
[ { "client_id": "attacker-3", "kind": "attacker", "risk_score": 87.0,
    "risk_band": "CRITICAL", "query_count": 15, "last_action": "BLOCK",
    "last_seen": "2026-08-23T19:41:02Z" } ]
```

### `GET /api/admin/clients/{client_id}`
```json
{
  "client_id": "attacker-3", "risk_score": 87.0, "risk_band": "CRITICAL",
  "window": [ { "seq": 6, "text": "...", "action": "THROTTLE", "risk_after": 61.2 } ],
  "risk_trajectory": [ {"seq":1,"risk":0.0}, {"seq":2,"risk":9.8} ],
  "latest_signals": [
    { "name": "systematic_modification", "score": 0.91, "weight": 1.2,
      "evidence": "9 of last 10 queries share a fixed template with a single changed token in position 6." },
    { "name": "burst_rate", "score": 0.04, "weight": 0.5,
      "evidence": "Mean inter-arrival 74.2 s — no burst behaviour." }
  ]
}
```

The `evidence` strings are the explainability requirement: every point of risk
traces to a sentence a human can check.

### `GET /api/admin/queries?client_id=&action=&limit=&offset=`
Paged history; each row carries its full signal breakdown.

### `GET /api/admin/events?severity=&limit=`
```json
[ { "id": 88, "client_id": "attacker-3", "severity": "CRITICAL",
    "event_type": "BLOCKED",
    "message": "Client blocked after sustained systematic modification pattern.",
    "created_at": "2026-08-23T19:41:02Z" } ]
```

### `GET /api/admin/attack-runs`
Summary rows for the fast-vs-slow comparison table.

### `POST /api/admin/clients/{client_id}/reset`
Clears risk and window. Demo convenience so a pattern can be re-run cleanly.

### `GET` / `PUT` `/api/admin/config`
Read and live-tune thresholds and signal weights without a restart — used to
demonstrate sensitivity (e.g. how `SUSPICION_THRESHOLD` trades false positives
against queries-to-block).

---

## Error shape

```json
{ "error": { "code": "OLLAMA_UNAVAILABLE",
             "message": "Could not reach Ollama at http://localhost:11434." } }
```

| Code | HTTP |
|---|---|
| `VALIDATION_ERROR` | 422 |
| `UNAUTHORIZED` (bad/missing admin token) | 401 |
| `CLIENT_NOT_FOUND` | 404 |
| `OLLAMA_UNAVAILABLE` | 503 |
| `DATABASE_UNAVAILABLE` | 503 |

A firewall BLOCK is **not** an error — it is a successful inspection with a deny
outcome, returned as HTTP 200 with `action: "BLOCK"`.
