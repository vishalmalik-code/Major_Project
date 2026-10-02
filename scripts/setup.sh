#!/usr/bin/env bash
# One-shot local setup. Run from the repo root.
set -euo pipefail

echo "==> Ollama model"
ollama pull llama3.2:3b-instruct-q4_K_M

echo "==> Database"
if createdb llm_firewall 2>/dev/null; then
  psql -d llm_firewall -c "CREATE EXTENSION IF NOT EXISTS vector;"
  psql -d llm_firewall -f db/init.sql
else
  echo "    Could not create a database on the system Postgres cluster"
  echo "    (no role for $(whoami), or no permission to create one)."
  echo "    Falling back to a user-owned cluster -- see"
  echo "    scripts/setup_local_postgres.sh."
  ./scripts/setup_local_postgres.sh
fi

echo "==> Backend"
cd backend
python3 -m venv .venv
./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install -r requirements.txt
[ -f .env ] || cp .env.example .env
echo "==> Seeding the one admin account (see ADMIN_SEED_USERNAME/PASSWORD in .env)"
./.venv/bin/python scripts/seed_admin.py
cd ..

echo "==> Frontend"
cd frontend && npm install && cd ..

echo "==> Done. Start with: scripts/run_backend.sh and scripts/run_frontend.sh"
