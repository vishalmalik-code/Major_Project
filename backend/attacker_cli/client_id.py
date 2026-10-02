"""Generates unique, readable client_ids like `attacker-value_sweep-slow-003`
when the user doesn't supply one, so the firewall sees a fresh, independent
20-query window per run.

Sequence numbers are tracked in a small local counter file (not a database --
this tool has no DB access) so repeated runs of the same strategy/mode read
as 001, 002, 003... instead of colliding or needing manual bookkeeping.
"""

import json
from pathlib import Path

_COUNTER_FILE = Path(__file__).parent.parent / "attacker_logs" / ".client_id_counters.json"


def next_client_id(strategy: str, mode: str) -> str:
    _COUNTER_FILE.parent.mkdir(parents=True, exist_ok=True)
    counters = {}
    if _COUNTER_FILE.exists():
        try:
            counters = json.loads(_COUNTER_FILE.read_text())
        except json.JSONDecodeError:
            counters = {}

    key = f"{strategy}-{mode}"
    n = counters.get(key, 0) + 1
    counters[key] = n
    _COUNTER_FILE.write_text(json.dumps(counters, indent=2))

    return f"attacker-{strategy}-{mode}-{n:03d}"
