# Database Design

PostgreSQL 16 + pgvector. Executable DDL: [`db/init.sql`](../db/init.sql).

---

## The one rule

> **`seq` orders the window. `created_at` never does.**

`clients.next_seq` is a per-client monotonic counter incremented on every query.
`queries.seq` records it. Every window rebuild is:

```sql
SELECT * FROM queries WHERE client_id = $1 ORDER BY seq DESC LIMIT 20;
```

Never `ORDER BY created_at`, never `WHERE created_at > now() - interval '...'`.

`created_at` exists for exactly two consumers: the `burst_rate` signal (which needs
inter-arrival times and is deliberately the only time-aware detector, capped at a low
weight) and the admin dashboard's display columns. If a time expression appears
anywhere in `firewall/window.py` or `firewall/risk.py`, it is a bug.

`UNIQUE (client_id, seq)` makes ordering integrity a database invariant rather than
an application convention.

---

## Tables

### `clients`
One row per `client_id`. Holds the **current risk score** — the only mutable risk
state in the system. Because risk is query-based, this row is written **only** from
inside `FirewallEngine.inspect()`. No scheduled job, no trigger, nothing else
touches `risk_score`. A client that goes silent for a week is simply a row nobody
updated; it returns at exactly the risk it left at.

`next_seq` lives here so the counter and the risk update happen in one transaction.

### `queries`
The append-only log. Every inspected query lands here **including blocked ones** —
a blocked attempt is evidence and still enters the window (`response IS NULL`
distinguishes it).

Three precomputed columns exist so signals do not re-parse text on every comparison:

| Column | Consumed by |
|---|---|
| `normalized` | `exact_repetition`, `text_similarity` |
| `numbers[]` | `value_progression`, `boundary_progression` |
| `constraint_tokens[]` | `constraint_progression` |

`risk_before` / `risk_after` / `risk_delta` are stored per query so the admin
dashboard can plot a risk trajectory and show *which query* moved the needle —
without recomputing anything.

### `signal_scores`
One row per (query, signal) — 8 rows per inspected query. `evidence` is a required
human-readable sentence, not an optional nicety: it is the project's explainability
guarantee. `details` (JSONB) carries the structured backing data (matched indices,
detected step size, diff positions) for the drill-down UI.

### `security_events`
The dashboard feed. Raised on MONITOR, THROTTLE, BLOCK, and on band transitions in
either direction (`RISK_ESCALATED` / `RISK_REDUCED`), so the demo shows a client
climbing *and* earning their way back down.

### `attack_runs`
One row per simulator run, with per-action counts and `queries_to_first_block`
(NULL = never blocked). This single column is the fast-vs-slow comparison: the same
strategy in both modes should both eventually block, with SLOW taking more queries
and vastly more wall-clock time — demonstrating that pacing delays detection but
does not prevent it.

---

## Embeddings

`vector(384)` matches `all-MiniLM-L6-v2`. An IVFFlat cosine index exists, but note
what it is *not* for: the hot detection path compares the incoming query against at
most 20 vectors already held in memory, which is a trivial dot product loop. The
index serves admin-side analytics (nearest-neighbour lookups across full history).

---

## Retention

None. This is a local simulation; the log is the evidence. Reset per client via
`POST /api/admin/clients/{id}/reset`, or drop and re-run `init.sql` for a clean demo.

---

## Setup note

`db/init.sql` targets PostgreSQL 16 but runs on 14+ provided `pgvector` is
installed (`CREATE EXTENSION vector`). If the extension is unavailable, the only
blocked feature is the `semantic_similarity` signal's persistence — the in-memory
window still works, so the system degrades rather than fails.
