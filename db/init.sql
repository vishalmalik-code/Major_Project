-- LLM Model Extraction Detection Firewall — schema
-- PostgreSQL 16 + pgvector
--   createdb llm_firewall
--   psql -d llm_firewall -f db/init.sql
--
-- ORDERING RULE: detection orders queries by clients.next_seq / queries.seq.
-- created_at exists for the burst signal and the dashboard ONLY. Nothing in the
-- window or the risk model may be driven by elapsed time.

CREATE EXTENSION IF NOT EXISTS vector;

-- ---------------------------------------------------------------- clients ----
CREATE TABLE IF NOT EXISTS clients (
    client_id     TEXT PRIMARY KEY,
    kind          TEXT NOT NULL DEFAULT 'user'
                  CHECK (kind IN ('user', 'attacker')),
    label         TEXT,
    risk_score    DOUBLE PRECISION NOT NULL DEFAULT 0.0
                  CHECK (risk_score >= 0.0 AND risk_score <= 100.0),
    risk_band     TEXT NOT NULL DEFAULT 'LOW'
                  CHECK (risk_band IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    query_count   INTEGER NOT NULL DEFAULT 0,
    next_seq      INTEGER NOT NULL DEFAULT 1,   -- per-client monotonic counter
    blocked_count INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now()  -- display only
);

-- ------------------------------------------------------------ attack_runs ----
CREATE TABLE IF NOT EXISTS attack_runs (
    id                     TEXT PRIMARY KEY,
    strategy               TEXT NOT NULL CHECK (strategy IN (
                               'exact_repetition','minimal_modification',
                               'value_sweep','constraint_probing',
                               'boundary_probing')),
    mode                   TEXT NOT NULL CHECK (mode IN ('FAST','SLOW')),
    client_id              TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    requested_count        INTEGER NOT NULL,
    sent_count             INTEGER NOT NULL DEFAULT 0,
    allowed_count          INTEGER NOT NULL DEFAULT 0,
    monitored_count        INTEGER NOT NULL DEFAULT 0,
    throttled_count        INTEGER NOT NULL DEFAULT 0,
    blocked_count          INTEGER NOT NULL DEFAULT 0,
    queries_to_first_block INTEGER,              -- NULL = never blocked
    seed                   INTEGER,
    status                 TEXT NOT NULL DEFAULT 'running'
                           CHECK (status IN ('running','finished','aborted')),
    started_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at            TIMESTAMPTZ
);

-- ---------------------------------------------------------------- queries ----
CREATE TABLE IF NOT EXISTS queries (
    id             BIGSERIAL PRIMARY KEY,
    client_id      TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    seq            INTEGER NOT NULL,             -- ordering axis for the window
    text           TEXT NOT NULL,
    normalized     TEXT NOT NULL,                -- lowercased, collapsed, depunctuated
    embedding      vector(384),                  -- all-MiniLM-L6-v2
    numbers        DOUBLE PRECISION[] NOT NULL DEFAULT '{}',   -- for sweep/boundary
    constraint_tokens TEXT[]         NOT NULL DEFAULT '{}',    -- for constraint probing
    action         TEXT NOT NULL CHECK (action IN ('ALLOW','MONITOR','THROTTLE','BLOCK')),
    weighted_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,      -- fused signal score 0-1
    risk_before    DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    risk_after     DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    risk_delta     DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    response       TEXT,                         -- NULL when blocked
    latency_ms     INTEGER,
    attack_run_id  TEXT REFERENCES attack_runs(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),   -- burst signal + UI only
    UNIQUE (client_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_queries_client_seq  ON queries (client_id, seq DESC);
CREATE INDEX IF NOT EXISTS idx_queries_action      ON queries (action);
CREATE INDEX IF NOT EXISTS idx_queries_run         ON queries (attack_run_id);
-- ANN index for admin analytics only; the hot path compares <=20 in-memory vectors.
CREATE INDEX IF NOT EXISTS idx_queries_embedding
    ON queries USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

-- ---------------------------------------------------------- signal_scores ----
CREATE TABLE IF NOT EXISTS signal_scores (
    id          BIGSERIAL PRIMARY KEY,
    query_id    BIGINT NOT NULL REFERENCES queries(id) ON DELETE CASCADE,
    signal_name TEXT NOT NULL CHECK (signal_name IN (
                    'exact_repetition','text_similarity','semantic_similarity',
                    'systematic_modification','value_progression',
                    'constraint_progression','boundary_progression','burst_rate')),
    score       DOUBLE PRECISION NOT NULL CHECK (score >= 0.0 AND score <= 1.0),
    weight      DOUBLE PRECISION NOT NULL,
    evidence    TEXT NOT NULL,     -- one human-readable sentence; explainability
    details     JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (query_id, signal_name)
);

CREATE INDEX IF NOT EXISTS idx_signal_scores_query ON signal_scores (query_id);

-- -------------------------------------------------------- security_events ----
CREATE TABLE IF NOT EXISTS security_events (
    id         BIGSERIAL PRIMARY KEY,
    client_id  TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    query_id   BIGINT REFERENCES queries(id) ON DELETE SET NULL,
    severity   TEXT NOT NULL CHECK (severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
    event_type TEXT NOT NULL CHECK (event_type IN (
                   'MONITORED','THROTTLED','BLOCKED',
                   'RISK_ESCALATED','RISK_REDUCED','CLIENT_RESET')),
    message    TEXT NOT NULL,
    details    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_events_client   ON security_events (client_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events (severity);

-- ------------------------------------------------------------------ users ----
-- Account layer added for authenticated chat history. Deliberately separate
-- from `clients`: a user's `client_id` is the firewall's security identity
-- (risk/window, set once at registration and never reassigned), while
-- `conversations` below is purely a chat-history grouping. The two must stay
-- independent -- see conversations.user_id vs queries.client_id.
CREATE TABLE IF NOT EXISTS users (
    id             SERIAL PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    client_id      TEXT NOT NULL UNIQUE REFERENCES clients(client_id),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- --------------------------------------------------------------- sessions ----
-- Opaque bearer tokens, the same "shared secret in a header" philosophy the
-- existing X-Admin-Token gate already uses -- just minted per-login and
-- looked up in the DB instead of compared to one static config value.
CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);

-- ----------------------------------------------------------- conversations ----
CREATE TABLE IF NOT EXISTS conversations (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations (user_id, updated_at DESC);

-- `queries` already IS the message log (text = prompt, response = model
-- answer). Rather than duplicate that into a second `messages` table, this
-- adds one nullable grouping column: NULL for every non-chat query (attacker
-- runs, CLI tools, evaluate.py) and set only for authenticated /chat
-- messages. It has no effect on `seq`, the window, or risk -- those remain
-- keyed by client_id alone, exactly as before this file's previous version.
ALTER TABLE queries ADD COLUMN IF NOT EXISTS conversation_id INTEGER
    REFERENCES conversations(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_queries_conversation ON queries (conversation_id, seq);

-- Real-time attacker-to-chat targeting: which conversation turn originated
-- from the normal chat UI vs. the attacker console continuing that SAME
-- conversation/client_id. Display + admin-analytics only -- the firewall
-- window/risk model never reads this column, only client_id/seq (see the
-- ORDERING RULE at the top of this file).
ALTER TABLE queries ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'user';
ALTER TABLE queries DROP CONSTRAINT IF EXISTS ck_queries_source;
ALTER TABLE queries ADD CONSTRAINT ck_queries_source CHECK (source IN ('user', 'attacker'));

-- Optional profile fields collected by the signup form (first/last name +
-- email). Purely additive and nullable -- `username` remains the one actual
-- login identifier (see auth.py); these three are display/contact info only
-- and nothing in the firewall, session, or role logic reads them.
ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
