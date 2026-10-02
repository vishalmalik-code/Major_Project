# LLM Model Extraction Detection Firewall

A local simulation of a **query-analysis firewall** that protects a self-hosted LLM
(**Llama 3.2 3B Instruct** via **Ollama**) from **model-extraction / model-cloning**
attacks — the kind of attack where someone harvests a large, structured set of
prompt→response pairs in order to train a clone of the model.

```
NORMAL USER / ATTACKER  →  FIREWALL  →  Llama 3.2 3B  →  RESPONSE
```

The firewall is the project. It inspects **query text and sequence**, not just
request rate, so a slow attacker who paces every request under any rate limit is
still caught.

---

## 1. Project purpose

Rate limiting alone cannot stop model extraction, because an attacker can simply
slow down. This project demonstrates a firewall that catches extraction attempts by
their **structure** — repetition, systematic parameter sweeps, output-format
enumeration, boundary probing — rather than their speed, using eight small,
explainable signals instead of a trained classifier. It also demonstrates, honestly,
where that approach succeeds and where it doesn't: see [§17 Known limitations](#17-known-limitations)
and the real evaluation numbers in [§16 Test results](#16-test-results).

---

## 2. Architecture

```
   NORMAL USER              ATTACKER SIMULATOR         ADMIN
   (React /chat)             (attacker.py CLI)      (React /admin)
        │                          │                       │
        │ POST /api/chat          │ POST /api/chat         │ GET/POST
        │ (client_id, query)      │ (real HTTP only)       │ /api/admin/*
        ▼                          ▼                       │ (X-Admin-Token)
   ╔════════════════════════════════════════╗              │
   ║              FIREWALL                   ║              │
   ║  1. load client's last-20 query window  ║              │
   ║  2. embed query (MiniLM)                ║◄─────────────┘
   ║  3. run 8 explainable signals           ║   reads persisted
   ║  4. fuse → query-based risk update      ║   queries/events/
   ║  5. map risk → ALLOW/MONITOR/           ║   clients — never
   ║             THROTTLE/BLOCK              ║   the live engine
   ║  6. persist + push into window          ║
   ╚═══════════════════╤══════════════════════╝
                       │ (BLOCK short-circuits here — LLM never called)
                       ▼
              Ollama · llama3.2:3b-instruct
                       │
                       ▼
                   RESPONSE
                       │
                       ▼
         PostgreSQL + pgvector (clients, queries,
         signal_scores, security_events)
```

Normal users and the attacker simulator are **the same kind of client** to the
firewall — both are plain HTTP callers of `POST /api/chat` with no privileged path.
The admin dashboard is a separate, token-gated read surface over what the firewall
already recorded; it cannot influence a live decision.

---

## 3. Technology stack

| Layer | Choice |
|---|---|
| LLM | Llama 3.2 3B Instruct |
| Runtime | Ollama (`http://localhost:11434`) |
| Backend | Python 3.10+ · FastAPI · Uvicorn · SQLAlchemy · Pydantic v2 |
| Frontend | React 18 · Vite · React Router · Recharts |
| Database | PostgreSQL 14/16 + `pgvector` |
| Embeddings | `sentence-transformers` · `all-MiniLM-L6-v2` (384-dim, local, CPU) |
| Simulators | Standalone Python CLIs (`attacker.py`, `normal_user.py`) — real HTTP only |

Nothing else: no ML training, no external services, no message queues, no
Kubernetes. Full rationale in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## 4. Llama 3.2 3B + Ollama setup

```bash
ollama pull llama3.2:3b-instruct-q4_K_M
ollama list                      # confirm it's there
```

The backend's only connection to Ollama is `backend/app/services/llm.py`
(`LLMService`) — a thin wrapper around `POST {OLLAMA_BASE_URL}/api/generate`. The
base URL and model name are both configurable via `backend/.env`
(`OLLAMA_BASE_URL`, `OLLAMA_MODEL`); nothing else in the codebase talks to Ollama
directly. It is only ever called for ALLOW, MONITOR, and THROTTLE decisions — a
BLOCK decision short-circuits before this module is reached.

**Model used for testing:** this repo was tested by the author against a
fine-tuned **Llama 3.2 3B** model served locally through Ollama. The model weights
are **not** included in this repository — pull the base model with the command
above (or point `OLLAMA_MODEL` in `backend/.env` at your own fine-tuned model).

---

## 5. How the firewall works

For every `POST /api/chat`, in order:

1. **Load the client's window** — the last 20 queries for this `client_id`,
   in-memory with a Postgres-backed rebuild on cache miss.
2. **Embed the query** with `all-MiniLM-L6-v2`.
3. **Run 8 signals** over the window (below).
4. **Fuse** the applicable signals into one weighted score, then update risk
   using the **query-based rule** (§9).
5. **Map risk to an action** (§10).
6. **Persist and push** the query into the window — even a BLOCKed query still
   counts as evidence for the next request.

### The eight signals

| # | Signal | Detects |
|---|---|---|
| 1 | `exact_repetition` | Attack 1 — near-identical text in the recent window |
| 2 | `text_similarity` | Attacks 1, 2 — lexical (token/n-gram) overlap |
| 3 | `semantic_similarity` | Attacks 2, 4 — MiniLM cosine similarity |
| 4 | `systematic_modification` | Attack 2 — a fixed template with one changing token |
| 5 | `value_progression` | Attack 3 — an arithmetic sequence in a stable template |
| 6 | `constraint_progression` | Attack 4 — one task, rotating output-format requests |
| 7 | `boundary_progression` | Attack 5 — values walking toward known edge cases |
| 8 | `burst_rate` | Fast-mode bursts — the **only** time-aware signal, capped low |

Every signal returns a score (0–1), a weight, and a one-sentence human-readable
`evidence` string — no signal's reasoning is opaque. Signals with nothing to
evaluate (e.g. no numeric literal for `value_progression` to check) **abstain**
rather than counting as "found nothing suspicious" — otherwise a sparse-evidence
attack like exact repetition, which only speaks to 3 of the 8 signals, would be
diluted toward "benign" by signals that had no data to look at.

---

## 6. The five attack patterns

| # | Pattern | Shape | Signals it targets |
|---|---|---|---|
| 1 | Exact Repetition | `Q, Q, Q, Q, Q` | 1, 2, 3 |
| 2 | Minimal Modification | `BASE+c1, BASE+c2, ...` (one token changes) | 2, 3, 4 |
| 3 | Systematic Value Sweep | `value=1, value=2, ... value=N` | 5, 4 |
| 4 | Output-Constraint Probing | same task, rotating "as JSON" / "in 50 words" / "step by step" / ... | 6, 3 |
| 5 | Boundary / Edge-Case Probing | `80 → 443 → 0 → -1 → 65535 → 65536` | 7, 5 |

All five share one cybersecurity-themed template bank with the normal-user
simulator — the firewall has to catch the *structure*, not the topic. Implemented
as reusable generators in `backend/app/attacker/strategies/`.

---

## 7. Fast vs slow attack modes

Every pattern runs in both:

- **FAST** — queries sent with a short delay (default 0.3s, `--delay`), which also
  trips the `burst_rate` signal.
- **SLOW** — human-like randomized delays (default 5–15s, `--min-delay`/`--max-delay`),
  under which `burst_rate` contributes ~0.

**The query sequence is identical between modes — only pacing changes.** This is
the project's central experiment: does slowing down evade detection? The real
evaluation results in §16 answer this directly, per pattern, not just in theory.

---

## 8. The 20-query window

```
Q1 ... Q20 arrive   → window = [Q1 .. Q20]
Q21 arrives         → evict Q1, window = [Q2 .. Q21]
```

**Query-count-based, never time-based.** Implemented as a `deque(maxlen=20)` per
client (`backend/app/firewall/window.py`). Waiting 1 second, 10 minutes, or 1 hour
between queries does not evict anything — only the arrival of a new query can. This
is enforced both behaviorally (tests prove a synthetic multi-hour gap changes
nothing) and mechanically (a test greps `window.py` for any time-based expression
and fails if it finds one).

---

## 9. Query-based risk decay

Risk (0–100 per client) changes **only** when a query arrives:

```python
if weighted_score >= SUSPICION_THRESHOLD:   # continues a suspicious pattern
    risk += GAIN_SCALE * weighted_score
elif weighted_score <= BENIGN_THRESHOLD:    # sufficiently dissimilar
    risk -= DECAY_STEP
else:                                        # ambiguous — hold, don't forgive
    risk unchanged
```

There is no timer, no background job, no "last activity" decay, no exponential
decay. A client at risk 82 who goes silent for a week returns at risk 82. Decay is
linear and small, so escaping CRITICAL takes a sustained run of genuinely different
questions — one innocent query cannot launder an extraction campaign. Full rationale
and worked examples in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §7.

---

## 10. Risk levels and actions

| Band | Default range | Action | Behaviour |
|---|---|---|---|
| LOW | 0–29 | `ALLOW` | Forwarded normally |
| MEDIUM | 30–54 | `ALLOW + MONITOR` | Forwarded; flagged; a security event is logged |
| HIGH | 55–79 | `THROTTLE` | Delayed (`THROTTLE_DELAY_SECONDS`, default 5s), then forwarded |
| CRITICAL | 80–100 | `BLOCK` | Refused — **the LLM is never called** |

All thresholds, weights, and delays are configurable in `backend/app/core/config.py`
/ `.env` — never hardcoded inline.

---

## 11. Normal-user simulation

Five personas, each a reusable, realistic query generator (not random noise) —
`backend/normal_user_cli/personas/`:

| Persona | Behavior |
|---|---|
| `casual_user` | Unrelated one-off questions, occasional incidental repeat |
| `student` | One topic, natural depth progression (intro → follow-up → clarification → example) |
| `developer` | Problem-driven — rephrases, asks for examples, changes requirements |
| `researcher` | One topic, analytical depth (comparisons, trade-offs, case studies) |
| `incident_responder` | One live incident, several related questions sent quickly — the persona most likely to *naturally* look bursty |

None of them deliberately enumerate a parameter space, rotate output formats
systematically, or apply single-token template substitution — that structural
shape is what distinguishes the five attacks, by design. Run standalone:

```bash
cd backend
python normal_user.py --list-personas
python normal_user.py --persona student --mode slow
python normal_user.py --persona incident_responder --mode fast --count 6
```

---

## 12. Admin dashboard

Two clearly separated experiences:

| Route | Who | Gate |
|---|---|---|
| `/chat` | Normal user — a simple ChatGPT-like UI | none (this is the public surface) |
| `/admin` | Security dashboard | `X-Admin-Token` header, enforced **server-side** on every `/api/admin/*` call regardless of what the frontend does |

`/chat` shows the answer and a small status tag (ALLOW/MONITOR/THROTTLE/BLOCK) —
never risk scores, signal weights, or other clients' data.

`/admin` shows: top KPIs; a client risk table (current risk, highest risk ever,
last decision, status); a query log across all clients; recent security events;
a per-client drill-down with the last-20 window **displayed in query order with an
explicit "this is a query count, not a time window" callout**, a risk-by-query-number
chart, and the full 8-signal breakdown for any selected query; and a real
attack-evaluation panel (§15) that only ever shows numbers from an actual
`evaluate.py` run — never fabricated.

---

## Project layout

```
Major_Project/
├── README.md
├── docs/                        ARCHITECTURE.md · API.md · DATABASE.md
├── db/init.sql                  PostgreSQL + pgvector schema
├── scripts/                     setup + run helpers
├── backend/
│   ├── app/
│   │   ├── main.py              FastAPI app
│   │   ├── core/config.py       every tunable threshold and weight
│   │   ├── api/routes/          chat · admin · attack (legacy) · health
│   │   ├── firewall/
│   │   │   ├── engine.py        6-step inspection pipeline
│   │   │   ├── window.py        query-based rolling window
│   │   │   ├── risk.py          signal fusion + query-based decay
│   │   │   ├── actions.py       risk band → action
│   │   │   └── signals/         8 explainable detectors
│   │   ├── attacker/            pure query-template generators (reused by the
│   │   │   │                     standalone CLI below); runner.py/pacing.py here
│   │   │   └── strategies/       are legacy in-process code, superseded
│   │   ├── embeddings/          all-MiniLM-L6-v2 encoder
│   │   ├── db/                  SQLAlchemy models + session
│   │   ├── schemas/             Pydantic request/response models
│   │   └── services/
│   │       ├── llm.py           LLMService — the backend's only Ollama connection
│   │       └── chat_service.py  orchestrates /api/chat: window, risk, persistence
│   ├── attacker.py              standalone attacker CLI (real HTTP only)
│   ├── attacker_cli/            its HTTP client, pacing, logger, runner
│   ├── normal_user.py           standalone normal-user CLI (real HTTP only)
│   ├── normal_user_cli/         its personas, pacing (reused), logger, runner
│   ├── evaluate.py              runs the full attacker+normal-user battery
│   ├── evaluation/               metrics, session specs, report builder
│   ├── attacker_logs/            per-run attacker logs (gitignored)
│   ├── normal_user_logs/         per-run normal-user logs (gitignored)
│   ├── evaluation_results/       aggregated JSONL + markdown reports (kept, tracked)
│   ├── requirements.txt · pytest.ini · .env.example
│   └── tests/
└── frontend/
    ├── package.json · vite.config.js · index.html
    └── src/
        ├── pages/                UserChat (/chat) · AdminDashboard (/admin) ·
        │                          AttackConsole (legacy, /attack)
        ├── components/            RiskBadge · ActionTag · SignalTable · RiskChart
        └── api/ · styles/
```

---

## 13. How to start the system

### Prerequisites

- Python 3.10+, Node 18+
- PostgreSQL 14+ with the `pgvector` extension
- [Ollama](https://ollama.com)

### Database

If your OS user has a role on the system Postgres cluster:

```bash
createdb llm_firewall
psql -d llm_firewall -c "CREATE EXTENSION IF NOT EXISTS vector;"
psql -d llm_firewall -f db/init.sql
```

Otherwise, no `sudo` required — run a small Postgres cluster owned entirely by
your user:

```bash
scripts/setup_local_postgres.sh
```

It initializes a cluster at `~/pgdata` on port 5433 with peer auth, creates
`llm_firewall`, enables `pgvector`, applies the schema, and prints the
`DATABASE_URL` to put in `backend/.env`.

### Backend

```bash
ollama pull llama3.2:3b-instruct-q4_K_M    # once
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                        # edit DATABASE_URL / ADMIN_TOKEN
uvicorn app.main:app --reload --port 8000
```

Health check: `curl http://localhost:8000/api/health` should report Ollama
reachable, the model available, and the database connected. API docs at
<http://localhost:8000/docs>.

### Frontend

```bash
cd frontend
npm install
npm run dev                                 # http://localhost:5173
```

`/chat` for the normal-user UI, `/admin` for the dashboard (token = your
backend's `ADMIN_TOKEN`, default `change-me-local-only`).

---

## 14. How to run the attacker simulator

Standalone CLI, real HTTP only — see §6/§7 above for the patterns and modes.

```bash
cd backend
python attacker.py --list-strategies

python attacker.py --strategy repetition --mode fast
python attacker.py --strategy repetition --mode slow
python attacker.py --strategy minimal_modification --mode fast
python attacker.py --strategy value_sweep --mode slow
python attacker.py --strategy output_constraint --mode fast
python attacker.py --strategy boundary --mode slow
```

Key flags: `--count`, `--delay` (fast), `--min-delay`/`--max-delay` (slow),
`--client-id`, `--base-topic`, `--on-block continue|stop`, `--target`. Every run
writes `attacker_logs/<client_id>.jsonl` + `<client_id>_summary.json`.

---

## 15. How to run the evaluation

```bash
cd backend
python evaluate.py                          # full battery, real HTTP, real Ollama
python evaluate.py --attacker-count 10 --normal-count 10 --seed 2024
```

Runs all 5 attack strategies × {fast, slow} and all 5 normal-user personas ×
{fast, slow} — 20 sessions — through the real `/api/chat` endpoint, and writes
`evaluation_results/<run_id>/{results.jsonl, report.md, meta.json}`. The admin
dashboard's "Attack evaluation" panel reads the latest run from this directory —
`GET /api/admin/evaluation` never fabricates a value; if no run exists yet, it
says so.

---

## 16. Test results

### Automated test suite

**93 / 93 backend tests passing** (`cd backend && pytest tests/ -q`), against the
real local Postgres and real Ollama — nothing here is mocked at the firewall
level. Breakdown:

| Area | File(s) | What it proves |
|---|---|---|
| Query window | `test_window_invariants.py` | Time-invariance, 20-query cap, seq-based (not timestamp-based) ordering |
| Risk decay | `test_risk_decay.py` | Query-based-only update rule; a mechanical grep guard fails the build if any time expression appears in `risk.py`/`window.py` |
| Signals | `test_signals_basic.py` | Each of the 8 signals fires correctly in isolation |
| Benign users | `test_benign_user.py` | A 6-question related transcript stays LOW/ALLOW throughout |
| Attack detection | `test_attack_detection.py` | All 5 strategies × {fast, slow} eventually BLOCK; SLOW still blocks with `burst_rate` zeroed out |
| LLM connection | `test_llm_service.py` | Real Ollama call succeeds |
| Full chat flow | `test_chat_flow.py` | Client isolation, 20-query eviction, ALLOW/MONITOR/THROTTLE/BLOCK all correctly gate the LLM, waiting changes nothing end-to-end |
| Attacker CLI | `test_attacker_cli.py` | No firewall-internals import, real HTTP round-trip, on-block continue/stop |
| Admin API | `test_admin_api.py` | Every `/api/admin/*` route 401s without a token and 200s with one; `/api/chat` never leaks signals |
| Final verification | `test_final_verification.py` | Sections 5–8 of the final integration pass, as single dedicated tests |

Frontend: `npm run build` succeeds (no syntax/import errors); see §17 for what
frontend verification does **not** cover.

### Most recent real evaluation run

`eval-20260823T213748-25185f`, seed `2024`, 10 queries/session, all 20 sessions
completed with no errors, all through real HTTP + real Ollama. Full report:
[`backend/evaluation_results/eval-20260823T213748-25185f/report.md`](backend/evaluation_results/eval-20260823T213748-25185f/report.md).

**Attack detection — 100% of sessions detected (reached MONITOR/THROTTLE/BLOCK), 70% reached BLOCK:**

| Strategy | Fast Detection | Slow Detection | Fast Block | Slow Block |
|---|---|---|---|---|
| Exact Repetition | Yes (@4) | Yes (@4) | Yes (@8) | Yes (@8) |
| Minimal Modification | Yes (@7) | Yes (@7) | No | No |
| Value Sweep | Yes (@4) | Yes (@4) | Yes (@8) | Yes (@8) |
| Output-Constraint Probing | Yes (@5) | Yes (@5) | Yes (@10) | No |
| Boundary Probing | Yes (@4) | Yes (@4) | Yes (@9) | Yes (@9) |

Slowing an attack down did not evade detection for any pattern — same detection
query in fast vs slow for every strategy. It also (honestly) did not reliably push
any pattern all the way to BLOCK within a 10-query session: **Minimal Modification
never reached BLOCK in either mode** at this session length, and Output-Constraint
Probing only blocked in FAST mode. See [§17 Known limitations](#17-known-limitations).

**Normal users — 0% false positive rate, all 10 persona×mode sessions:**

| Persona | Mode | Avg Risk | Peak Risk | Monitor | Throttle | Block |
|---|---|---|---|---|---|---|
| Casual User | FAST | 2.4 | 8.0 | 0 | 0 | 0 |
| Casual User | SLOW | 2.1 | 7.4 | 0 | 0 | 0 |
| Student | FAST | 2.0 | 13.3 | 0 | 0 | 0 |
| Student | SLOW | 0.0 | 0.0 | 0 | 0 | 0 |
| Developer | FAST | 4.7 | 13.4 | 0 | 0 | 0 |
| Developer | SLOW | 4.5 | 12.8 | 0 | 0 | 0 |
| Researcher | FAST | 4.1 | 20.5 | 0 | 0 | 0 |
| Researcher | SLOW | 2.6 | 12.8 | 0 | 0 | 0 |
| Incident Responder | FAST | 7.1 | 28.0 | 0 | 0 | 0 |
| Incident Responder | SLOW | 4.5 | 12.9 | 0 | 0 | 0 |

No persona ever reached MONITOR (risk stayed well under the 30-point threshold
even at peak) — including Incident Responder, the persona deliberately designed to
produce naturally fast, bursty traffic. See §17 for what this does and doesn't prove.

---

## 17. Known limitations

Reported honestly, not tuned away — thresholds and weights were deliberately left
untouched after seeing these results, per this phase's explicit instruction not to
retune based on evaluation output:

- **Minimal Modification never reached BLOCK** within a 10-query session, in
  either mode (it does reach MONITOR at query 7 and THROTTLE at query 10 — it
  *is* detected, just not blocked at this session length). Earlier, longer manual
  runs (≥12 queries, see `docs/ARCHITECTURE.md` §16 worked traces) do reach BLOCK
  for this pattern; a 10-query evaluation session is simply too short for its
  slower risk accumulation. This is the pattern's real, current behavior, not a
  measurement error.
- **Output-Constraint Probing blocked in FAST mode but not SLOW** (both reached
  THROTTLE). A genuine fast/slow asymmetry for this one pattern, not smoothed over.
- **The 0% false-positive rate is a single seed, single run, 10 queries/persona.**
  It's a real, unmocked result — not a statistical guarantee. A persona run with a
  different seed, a longer session, or a sequence that happens to concentrate many
  genuinely similar questions could score differently; the benign-transcript unit
  test (`test_benign_user.py`) is the reproducible regression guard, not this
  single evaluation run.
- **No frontend test framework or TypeScript.** The frontend is plain JavaScript
  with no Vitest/Jest/Playwright and no ESLint config in this repo. Frontend
  verification here is: a successful `npm run build` (catches syntax/import
  errors), a manual cross-check of every prop/field name the new dashboard code
  reads against the actual backend response schemas, and scripted `curl`-based
  checks of every route and the admin auth boundary. It is **not** a substitute
  for a human clicking through the UI in a real browser, which this environment
  cannot do.
- **The admin auth model is a single shared-secret header** (`X-Admin-Token`),
  adequate for a local single-operator demo and documented as such from the
  start — not a real multi-user auth system with sessions, roles, or audit-logged
  admin identity.
- **One evaluation run was interrupted and discarded.** A mid-run backend
  restart caused 5 of 20 sessions to fail with connection-refused errors; that
  partial run is kept on disk for transparency at
  `backend/evaluation_results/eval-20260823T211759-704c94-PARTIAL-serverrestart/`
  but is **not** the run cited anywhere in this README or the dashboard — only
  the clean, complete re-run (`eval-20260823T213748-25185f`) is.
- **SLOW-mode delays in the evaluation battery are reduced** (3–6s instead of the
  attacker CLI's real-world 5–15s default) to keep total evaluation wall-clock
  time practical. This changes timing only, not the query sequence or the
  detection logic being tested — see `evaluate.py --help` to run with realistic
  delays instead.
- **A legacy in-process attack path still exists** (`app/attacker/runner.py`,
  `app/api/routes/attack.py`, the `/attack` frontend page) from an earlier
  over-built iteration. It predates the standalone `attacker.py` CLI and does not
  meet that later requirement that the attacker behave as a fully external HTTP
  client with no access to firewall internals. It's left in place (dormant,
  clearly marked) rather than removed, since removing it wasn't asked for and
  would delete working, previously-reviewed code.

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Full system design: data flow, window, risk model, signals, attacks |
| [`docs/API.md`](docs/API.md) | Endpoint contracts, request/response shapes |
| [`docs/DATABASE.md`](docs/DATABASE.md) | Schema rationale, why `seq` and not `created_at` |
| [`db/init.sql`](db/init.sql) | Executable DDL |

---

## Scope fence

Deliberately **not** in this project: QLoRA, fine-tuning or any model training,
multiple LLMs, Kubernetes, microservices, ML pipelines, large datasets, cloud
services, or neural detectors. No time-based query-window expiration and no
time-based risk decay, anywhere — that is the project's central invariant, not an
oversight. Everything is local, and every detection decision is explainable in one
sentence.
