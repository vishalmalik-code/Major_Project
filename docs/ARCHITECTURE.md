# LLM Model Extraction Detection Firewall — Architecture

> **Status:** Design / skeleton phase. No detection logic, attack strategies, or
> LLM calls are implemented yet. This document is the contract that the
> implementation phase must satisfy.

---

## 1. Purpose

A local simulation showing how a **query-analysis firewall** can protect a locally
hosted LLM (**Llama 3.2 3B Instruct** on **Ollama**) from **model-extraction /
model-cloning** attacks.

Model extraction works by harvesting a large, *structured* set of
(prompt → response) pairs and training a clone on them. The harvest is what makes
it detectable: an extraction campaign does not look like a conversation, it looks
like a **dataset being enumerated**. The firewall's job is to notice enumeration.

The core claim the project demonstrates:

> Rate limiting alone cannot stop model extraction, because an attacker can simply
> slow down. **Query-text structure survives slowing down.**

### Non-goals (explicit scope fence)

Not in this project: QLoRA, fine-tuning, model training of any kind, multiple LLMs,
Kubernetes, microservices, ML pipelines, large datasets, cloud services, neural
detectors. Everything runs locally on one machine.

---

## 2. System Architecture

```
   ┌──────────────────┐        ┌──────────────────┐        ┌──────────────────┐
   │   NORMAL USER    │        │ ATTACK SIMULATOR │        │      ADMIN       │
   │  (React chat)    │        │ (React console)  │        │ (React dashboard)│
   └────────┬─────────┘        └────────┬─────────┘        └────────┬─────────┘
            │ POST /api/chat            │ POST /api/attack/run      │ GET /api/admin/*
            │                           │                           │
            ▼                           ▼                           │
   ╔════════════════════════════════════════════════════════╗       │
   ║                      FIREWALL                           ║       │
   ║  ┌──────────────────────────────────────────────────┐  ║       │
   ║  │ 1. Load client window (last 20 queries)          │  ║       │
   ║  │ 2. Embed incoming query (all-MiniLM-L6-v2)       │  ║       │
   ║  │ 3. Run 8 explainable signals over the window     │  ║       │
   ║  │ 4. Combine → delta → query-based risk update     │  ║       │
   ║  │ 5. Map risk → ALLOW / MONITOR / THROTTLE / BLOCK │  ║       │
   ║  │ 6. Persist query + signals + event               │  ║       │
   ║  └──────────────────────────────────────────────────┘  ║       │
   ╚════════════════════════════╤═══════════════════════════╝       │
                                │ (ALLOW / MONITOR / THROTTLE)      │
                                │  BLOCK short-circuits here        │
                                ▼                                   │
                     ┌─────────────────────┐                        │
                     │  Ollama · llama3.2  │                        │
                     │      :3b-instruct   │                        │
                     └──────────┬──────────┘                        │
                                │                                   │
                                ▼                                   │
                     ┌─────────────────────┐                        │
                     │      RESPONSE       │                        │
                     └─────────────────────┘                        │
                                                                    │
   ┌────────────────────────────────────────────────────────────────┘
   │
   ▼
┌──────────────────────────────────────────────────────────┐
│  PostgreSQL + pgvector                                    │
│  clients · queries(embedding vector(384)) · signals ·     │
│  security_events · attack_runs                            │
└──────────────────────────────────────────────────────────┘
```

**The firewall is the product.** The LLM is a black box behind it; the UIs are
instruments for driving and observing it.

---

## 3. Component Map

| Component | Location | Responsibility |
|---|---|---|
| API layer | `backend/app/api/routes/` | HTTP surface: chat, admin, attack, health |
| Firewall engine | `backend/app/firewall/engine.py` | Orchestrates the 6-step inspection pipeline |
| Query window | `backend/app/firewall/window.py` | Per-client rolling buffer of last N queries |
| Signals | `backend/app/firewall/signals/` | 8 independent, explainable detectors |
| Risk model | `backend/app/firewall/risk.py` | Signal fusion → risk delta → query-based update |
| Actions | `backend/app/firewall/actions.py` | Risk band → ALLOW/MONITOR/THROTTLE/BLOCK |
| Attack simulator | `backend/app/attacker/` | 5 generators + fast/slow pacing + runner |
| LLM client | `backend/app/llm/ollama_client.py` | Thin Ollama HTTP wrapper |
| Embeddings | `backend/app/embeddings/encoder.py` | all-MiniLM-L6-v2 → 384-dim vector |
| Persistence | `backend/app/db/` | SQLAlchemy models + session |
| Frontend | `frontend/src/pages/` | UserChat, AttackConsole, AdminDashboard |

---

## 4. Data Flow

### 4.1 Request path (single query)

```
1.  Client POSTs {client_id, query} to /api/chat
2.  FirewallEngine.inspect(client_id, query)
      a. window = QueryWindow.load(client_id)          # last 20, query-ordered
      b. embedding = Encoder.encode(query)             # 384-dim
      c. for each of 8 signals: score = signal.evaluate(query, embedding, window)
      d. delta = RiskModel.combine(signals)            # in [-DECAY_STEP, +MAX_GAIN]
      e. risk_new = clamp(risk_old + delta, 0, 100)    # query-based ONLY
      f. action = ActionPolicy.decide(risk_new)
3.  BLOCK      → return refusal, never touch the LLM
    THROTTLE   → apply penalty delay, then call LLM (or degrade response)
    MONITOR    → call LLM, flag the record
    ALLOW      → call LLM
4.  Ollama generate → response text
5.  Persist: queries row (+embedding), signal_scores row, security_events row
6.  QueryWindow.push(client_id, query)                 # evicts oldest if > 20
7.  Return {response, action, risk_score, signals[], reason} to client
    (the user-facing chat UI shows only response + a soft notice;
     full signal breakdown is admin-only)
```

### 4.2 Attack path

```
POST /api/attack/run {strategy, mode, count, client_id}
  → StrategyRegistry.get(strategy).generate(count) → [q1..qn]
  → Pacer(mode).delays(n)   # FAST: ~0s   SLOW: human-like random
  → for each query: sleep(delay); run the SAME /api/chat firewall path
  → stream/collect per-query {action, risk, top_signal}
  → persist attack_runs summary
```

The attack simulator has **no privileged path**. It is an ordinary client. This is
essential: the firewall must not be able to "cheat" by knowing a request came from
the simulator.

---

## 5. The Query Window

### 5.1 Definition

Per `client_id`, the firewall keeps a **rolling buffer of the last N queries**.

```
QUERY_WINDOW_SIZE = 20     # full analysis window (config)
TIGHT_WINDOW_SIZE = 10     # sub-window for burst/repetition (config)
```

> **Spec reconciliation.** The brief states "keep only the last 10 queries" in one
> place and "detection based on the last 20 queries" / "define the 20-query window"
> in others. Resolution: **store 20, and expose a tight last-10 slice.** Signals that
> need long-horizon evidence (value sweeps, boundary walks, constraint enumeration)
> read the 20-window; signals that need recency (exact repetition, burst) read the
> 10-window. Setting `QUERY_WINDOW_SIZE = TIGHT_WINDOW_SIZE = 10` in config reduces
> the system to the literal "last 10" behaviour with no code change.

### 5.2 It is query-based, never time-based

```
Q1 Q2 ... Q20 arrive      → window = [Q1 .. Q20]
Q21 arrives               → evict Q1, window = [Q2 .. Q21]
```

Eviction is triggered **only** by arrival of a new query.

```
client idle 1 second   → window unchanged
client idle 10 minutes → window unchanged
client idle 1 hour     → window unchanged
client idle 3 days     → window unchanged
```

There is **no TTL, no expiry job, no sliding time frame.** An attacker who sends one
query per hour still faces a fully populated window of their previous 20 queries.
This is the single design decision that makes slow attacks detectable.

### 5.3 Stored per window entry

| Field | Use |
|---|---|
| `seq` | Per-client monotonic counter — the ordering axis (not timestamp) |
| `text` | Raw query, for exact/lexical comparison |
| `normalized` | Lowercased, whitespace-collapsed, punctuation-stripped |
| `embedding` | 384-dim vector for semantic similarity |
| `numbers[]` | Extracted numeric literals, for sweep/boundary detection |
| `constraint_tokens[]` | Detected output-format terms ("in 50 words", "as JSON", "bullet points") |
| `created_at` | **Recorded for the admin UI and burst signal only — never for eviction or decay** |

### 5.4 Storage

- **Hot path:** in-process `dict[client_id, deque(maxlen=QUERY_WINDOW_SIZE)]` —
  O(1) push/evict, no DB round trip per request.
- **Cold path:** every query is also written to Postgres for history and the admin
  dashboard. The window is rebuilt from `ORDER BY seq DESC LIMIT 20` on cache miss
  or restart. **Rebuilding by `seq`, never by timestamp**, preserves query-based
  semantics across restarts.

---

## 6. Detection Signals

Eight independent detectors. Each is a small, readable function returning a score in
`[0.0, 1.0]` plus a human-readable `evidence` string. **No neural detector, no
trained classifier** — every alarm must be explainable in one sentence to a viva
examiner.

| # | Signal | Window | Detects | Sketch of method |
|---|---|---|---|---|
| 1 | `exact_repetition` | tight 10 | Attack 1 | Count of normalized-hash matches in window ÷ window size |
| 2 | `text_similarity` | full 20 | Attacks 1,2 | Max + mean token-level Jaccard / char n-gram similarity vs window |
| 3 | `semantic_similarity` | full 20 | Attacks 2,4 | Max + mean cosine similarity of MiniLM embeddings |
| 4 | `systematic_modification` | full 20 | Attack 2 | High similarity **but not identical** + a *small, consistent* edit region (diff of 1–3 tokens repeatedly, in the same position) |
| 5 | `value_progression` | full 20 | Attack 3 | Extract numerics; test for monotonic / fixed-step / arithmetic sequence across queries with an otherwise stable template |
| 6 | `constraint_progression` | full 20 | Attack 4 | Stable semantic core + rotating output-constraint vocabulary (length/format/detail/structure/style) — enumeration of the output space |
| 7 | `boundary_progression` | full 20 | Attack 5 | Values drifting monotonically toward extremes (0, negatives, max-int, empty, huge) or increasing distance from a normal-range centroid |
| 8 | `burst_rate` | tight 10 | Fast mode | Queries-per-second and inter-arrival variance. **The only time-aware signal.** Contributes at most `BURST_MAX_WEIGHT` so a slow attack is still caught by 1–7 |

### 6.1 Fast vs slow coverage

| | Signals that fire |
|---|---|
| **FAST attack** | 1–7 (text structure) **+ 8** (burst) → risk climbs quickly |
| **SLOW attack** | 1–7 only → risk climbs more slowly but **monotonically**, because the window never expires and risk never decays with time |

A slow attacker cannot outwait the firewall. They can only *change what they ask* —
and changing what they ask is exactly what defeats the extraction goal.

### 6.2 Signal interface

```python
class Signal(Protocol):
    name: str
    weight: float
    def evaluate(self, ctx: QueryContext) -> SignalResult: ...

@dataclass
class SignalResult:
    name: str
    score: float        # 0.0 – 1.0
    evidence: str       # "8 of last 10 queries are byte-identical"
    details: dict       # structured, for the admin dashboard
```

---

## 7. Risk Score Design

### 7.1 Model

- Range: `0.0 – 100.0`, per `client_id`.
- Persisted on the `clients` row.
- **Updated on query arrival only.**

```
weighted   = Σ (signal.score × signal.weight) / Σ weight      # 0.0 – 1.0
```

### 7.2 Update rule (query-based, no time term)

```python
if weighted >= SUSPICION_THRESHOLD:        # default 0.35
    delta = +GAIN_SCALE * weighted         # escalate: pattern continues
elif weighted <= BENIGN_THRESHOLD:         # default 0.15
    delta = -DECAY_STEP                    # dissimilar query → small relief
else:
    delta = 0.0                            # ambiguous → hold, do not forgive

risk = clamp(risk + delta, 0.0, 100.0)
```

Defaults: `GAIN_SCALE = 18.0`, `DECAY_STEP = 4.0`.

### 7.3 Query-based decay — the rules

1. Risk **only** changes inside `inspect()`, i.e. when a query arrives.
2. Risk **decreases only** when the arriving query is *sufficiently dissimilar* to
   the window (low semantic + lexical similarity, no progression signals).
3. **Doing nothing decays nothing.** No cron job, no background task, no
   `last_seen` arithmetic, no `risk * e^(-λt)`. If a client at risk 82 goes silent
   for a week, they return at risk 82.
4. Decay is **linear and small** (`-DECAY_STEP` per benign query), so escaping
   CRITICAL requires a sustained run of genuinely different questions — roughly
   `(risk - threshold) / DECAY_STEP` benign queries. A single innocent question
   cannot launder an extraction campaign.

**Forbidden in this codebase:** any decay expression containing elapsed time.

### 7.4 Worked traces

```
Attack 1 (exact repetition, FAST) — signals 1,2,3,8 all high
  q1  w=0.05  risk   0.0     ALLOW      (empty window, nothing to compare)
  q2  w=0.61  risk  11.0     ALLOW
  q3  w=0.74  risk  24.3     ALLOW
  q4  w=0.83  risk  39.2     MONITOR
  q5  w=0.88  risk  55.0     THROTTLE
  q7  w=0.91  risk  85.4     CRITICAL → BLOCK

Attack 3 (value sweep, SLOW, 90 s between queries) — signal 8 contributes ~0
  q1  w=0.04  risk   0.0     ALLOW
  q4  w=0.44  risk  20.6     ALLOW
  q8  w=0.63  risk  61.4     THROTTLE
  q11 w=0.69  risk  85.0     BLOCK
  ... slower to trigger, but it does trigger. Waiting does not help.

Normal user (related cybersecurity questions)
  q1 "what is SQL injection"                w=0.03  risk 0.0   ALLOW
  q2 "how do I prevent SQL injection"       w=0.29  risk 0.0   ALLOW   (ambiguous → hold)
  q3 "show me a prepared statement example" w=0.22  risk 0.0   ALLOW
  q4 "what about XSS"                       w=0.08  risk 0.0   ALLOW   (already floored)
```

Related follow-ups score in the *ambiguous* band: they are semantically close but
show **no systematic structure** — no fixed template, no numeric progression, no
constraint enumeration. Signals 4–7 are the discriminator between "a curious human"
and "someone enumerating a dataset."

---

## 8. Risk Actions

Four bands, all thresholds in `backend/app/core/config.py` and overridable by env.

| Band | Default range | Action | Behaviour |
|---|---|---|---|
| **LOW** | 0 – 29 | `ALLOW` | Forward to LLM. Normal response. |
| **MEDIUM** | 30 – 54 | `ALLOW + MONITOR` | Forward to LLM. Flag record, raise a `security_event`, surface on dashboard. User sees no difference. |
| **HIGH** | 55 – 79 | `THROTTLE` | Inject `THROTTLE_DELAY_SECONDS` (default 5.0) before forwarding; optionally cap `max_tokens`. Purpose: destroy harvest throughput. |
| **CRITICAL** | 80 – 100 | `BLOCK` | Refuse. **Never reaches the LLM.** Return a policy message + `retry_after`. Log a CRITICAL event. |

```python
RISK_THRESHOLD_MEDIUM   = 30.0
RISK_THRESHOLD_HIGH     = 55.0
RISK_THRESHOLD_CRITICAL = 80.0
THROTTLE_DELAY_SECONDS  = 5.0
```

A BLOCK is not permanent: the client's risk is still query-based, so a genuine user
misclassified as CRITICAL earns their way down via dissimilar queries. Blocked
queries **still enter the window** (the attempt is evidence).

---

## 9. Attack Simulator

### 9.1 Generator interface

Every strategy is a reusable query generator implementing one interface:

```python
class AttackStrategy(ABC):
    id: str            # "exact_repetition"
    name: str          # "Exact Query Repetition"
    description: str

    @abstractmethod
    def generate(self, count: int, seed: int | None = None) -> list[str]:
        """Return `count` queries realising this attack pattern."""

    def explain(self) -> str:
        """Which firewall signals this pattern is designed to trip."""
```

Registered in `attacker/registry.py` → `STRATEGIES: dict[str, AttackStrategy]`, so
adding a strategy is one file plus one registry entry.

### 9.2 The five patterns

| # | id | Pattern | Example sequence | Targets signals |
|---|---|---|---|---|
| 1 | `exact_repetition` | Same query verbatim | `Q, Q, Q, Q, Q` | 1, 2, 3 |
| 2 | `minimal_modification` | Same query, one small constraint changed each time | `Q+c1, Q+c2, Q+c3, …` | 2, 3, 4 |
| 3 | `value_sweep` | One input value swept systematically | `value=1, value=2, … value=N` | 5, 4 |
| 4 | `constraint_probing` | Same task, output requirements enumerated (length / format / detail / structure / explanation style) | `"…in 50 words"`, `"…as JSON"`, `"…as a table"`, `"…step by step"`, `"…ELI5"` | 6, 3 |
| 5 | `boundary_probing` | Input walked from normal toward extreme / edge values | `port 80 → 443 → 0 → -1 → 65535 → 65536` | 7, 5 |

Each generator owns a small template bank (cybersecurity-themed, to match the normal
user's domain) so attacks are not trivially separable by topic — the firewall must
detect **structure**, not vocabulary.

### 9.3 Fast / slow pacing

Pacing is orthogonal to strategy — any of the 5 runs in either mode.

```python
class Pacer(ABC):
    def delay(self) -> float: ...

class FastPacer(Pacer):
    """~0.0–0.05 s. Burst. Trips signal 8 in addition to the text signals."""

class SlowPacer(Pacer):
    """Human-like: random.uniform(MIN, MAX) with jitter, default 20–120 s.
       Signal 8 contributes ~0. Detection must come from text structure alone."""
```

`SLOW_DELAY_MIN` / `SLOW_DELAY_MAX` are configurable so demos can use 3–8 s instead
of realistic minutes.

### 9.4 Runner

`attacker/runner.py` drives `strategy × pacer × count` through the **public**
`/api/chat` path, streams per-query results (action, risk, dominant signal) to the
Attack Console via SSE or polling, and writes an `attack_runs` summary row:
queries sent, allowed, monitored, throttled, blocked, **queries-until-first-block**
(the headline effectiveness metric).

---

## 10. Normal-User Flow

**Route:** `/` → `UserChat.jsx`

1. On load, a `client_id` is created/restored from `localStorage`.
2. User types a cybersecurity/technical question → `POST /api/chat`.
3. Response is rendered as chat.
4. The user sees **only**: the answer, and — if throttled or blocked — a plain
   notice ("Response delayed" / "This request was blocked by usage policy").
5. The user **never** sees: risk score, signal breakdown, thresholds, other clients,
   or any dashboard route. `/api/admin/*` requires an admin token and is not
   reachable from this page.

### Legitimate-use protection

A real user asking several related questions must not be flagged. This is handled by
design, not by exception lists:

- Ambiguous band produces `delta = 0` — related questions **hold** risk, not raise it.
- Signals 4–7 (the heavy-weighted ones) require *systematic structure*: a stable
  template with a moving part. Human follow-ups vary the whole sentence.
- Signal 1 requires near-identical text; humans rephrase.
- The `ALLOW → MONITOR → THROTTLE → BLOCK` ladder means a misread costs a flag on a
  dashboard long before it costs a user their answer.

A documented benign transcript ships in `backend/tests/` as a regression test:
**it must end at risk ≈ 0 and never leave ALLOW.**

---

## 11. Admin Flow

**Route:** `/admin` → `AdminDashboard.jsx`, gated by an `X-Admin-Token` header
(shared secret in `.env`; sufficient for a local simulation, and documented as such).

Panels:

| Panel | Source |
|---|---|
| Total queries | `GET /api/admin/stats` |
| Suspicious queries (MONITOR+) | `GET /api/admin/stats` |
| Throttled / blocked counts | `GET /api/admin/stats` |
| Client risk table (id, risk, band, query count, last action) | `GET /api/admin/clients` |
| Per-client drill-down: last 20 window + risk trajectory | `GET /api/admin/clients/{id}` |
| Recent security events (severity, signal, evidence) | `GET /api/admin/events` |
| Full query history with filters | `GET /api/admin/queries` |
| Attack-run comparison (fast vs slow, queries-to-block) | `GET /api/admin/attack-runs` |

The drill-down is the demo centrepiece: for any query it shows all 8 signal scores
with their `evidence` strings, so every risk movement is traceable to a sentence.

---

## 12. API Structure

Full request/response schemas: `docs/API.md`.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/health` | — | Service + Ollama + DB liveness |
| `POST` | `/api/chat` | client | **The protected path.** Firewall → LLM → response |
| `GET` | `/api/attack/strategies` | — | List the 5 generators + descriptions |
| `POST` | `/api/attack/preview` | — | Generate queries without sending (inspect the pattern) |
| `POST` | `/api/attack/run` | — | Execute strategy × mode × count against `/api/chat` |
| `GET` | `/api/attack/runs/{id}` | — | Run progress / result |
| `GET` | `/api/admin/stats` | admin | Aggregate counters |
| `GET` | `/api/admin/clients` | admin | Client risk table |
| `GET` | `/api/admin/clients/{id}` | admin | Window, risk trajectory, signals |
| `GET` | `/api/admin/queries` | admin | Paged query history |
| `GET` | `/api/admin/events` | admin | Security event feed |
| `GET` | `/api/admin/attack-runs` | admin | Attack run summaries |
| `POST` | `/api/admin/clients/{id}/reset` | admin | Reset risk + window (demo convenience) |
| `GET`/`PUT` | `/api/admin/config` | admin | Read/tune thresholds live |

---

## 13. Database Schema

Full DDL: `db/init.sql`. Summary:

| Table | Key columns |
|---|---|
| `clients` | `client_id` PK, `kind` (user/attacker), `risk_score`, `risk_band`, `query_count`, `next_seq` |
| `queries` | `id`, `client_id` FK, **`seq`** (per-client order), `text`, `normalized`, `embedding vector(384)`, `action`, `risk_before`, `risk_after`, `blocked`, `latency_ms`, `attack_run_id` FK NULL |
| `signal_scores` | `query_id` FK, `signal_name`, `score`, `weight`, `evidence`, `details jsonb` |
| `security_events` | `id`, `client_id`, `query_id`, `severity`, `event_type`, `message`, `details jsonb` |
| `attack_runs` | `id`, `strategy`, `mode`, `count`, `client_id`, counts by action, `queries_to_first_block`, `started_at`, `finished_at` |

Notes:
- `pgvector` `vector(384)` matches all-MiniLM-L6-v2. An IVFFlat index exists but the
  hot path compares against ≤20 in-memory vectors, so ANN search is for admin
  analytics, not detection.
- **`seq`, not `created_at`, is the ordering key everywhere in detection.**
  Timestamps exist only for the burst signal and the dashboard.
- `UNIQUE (client_id, seq)` enforces window ordering integrity.

---

## 14. Tech Stack

| Layer | Choice |
|---|---|
| LLM | Llama 3.2 3B Instruct |
| Runtime | Ollama (`http://localhost:11434`) |
| Backend | Python 3.10+ · FastAPI · Uvicorn · SQLAlchemy · Pydantic v2 |
| Frontend | React 18 · Vite · React Router |
| Database | PostgreSQL 16 + pgvector |
| Embeddings | `sentence-transformers` · `all-MiniLM-L6-v2` (384-dim, local, CPU) |

Everything runs on localhost. No external network calls at runtime beyond the local
Ollama and Postgres sockets.

---

## 15. Configuration Surface

All tunables in `backend/app/core/config.py`, env-overridable via `backend/.env`:

```
QUERY_WINDOW_SIZE=20            TIGHT_WINDOW_SIZE=10
RISK_THRESHOLD_MEDIUM=30        RISK_THRESHOLD_HIGH=55
RISK_THRESHOLD_CRITICAL=80      THROTTLE_DELAY_SECONDS=5.0
SUSPICION_THRESHOLD=0.35        BENIGN_THRESHOLD=0.15
GAIN_SCALE=18.0                 DECAY_STEP=4.0
WEIGHT_EXACT_REPETITION=1.0     WEIGHT_TEXT_SIMILARITY=0.8
WEIGHT_SEMANTIC_SIMILARITY=0.9  WEIGHT_SYSTEMATIC_MODIFICATION=1.2
WEIGHT_VALUE_PROGRESSION=1.2    WEIGHT_CONSTRAINT_PROGRESSION=1.1
WEIGHT_BOUNDARY_PROGRESSION=1.1 WEIGHT_BURST_RATE=0.5
SLOW_DELAY_MIN=20.0             SLOW_DELAY_MAX=120.0
```

The heavier weights sit on signals 4–7 — the *structural* detectors — because those
are what separate an extraction campaign from a curious human, and they are exactly
the ones that keep working when the attacker slows down.

---

## 16. Implementation Order (next phase)

1. Config, DB models, `init.sql`, Alembic-free bootstrap.
2. Ollama client + embeddings encoder + `/api/health`.
3. `QueryWindow` (in-memory deque + DB rebuild by `seq`) — with unit tests proving
   time-invariance.
4. Signals 1–3 (repetition, lexical, semantic).
5. `RiskModel` + `ActionPolicy` + `/api/chat` end to end.
6. Signals 4–7 (structural) — the detection core.
7. Signal 8 (burst).
8. Attack strategies 1–5 + pacers + runner.
9. Admin endpoints.
10. Frontend: UserChat → AttackConsole → AdminDashboard.
11. Evaluation: fast vs slow, queries-to-block per strategy, benign false-positive run.
