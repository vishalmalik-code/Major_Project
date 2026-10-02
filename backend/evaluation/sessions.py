"""Defines the full evaluation battery: all 5 attack strategies x {fast,slow}
and all 5 normal-user personas x {fast,slow} -- 20 sessions total.

Each SessionSpec carries everything needed to reproduce it exactly: a
derived, fixed seed (so re-running the evaluation regenerates the identical
query sequences), a stable client_id, and its query list generated up front
(query generation never touches the network, so it's cheap to do eagerly and
log alongside the results for full reproducibility).
"""

import zlib
from dataclasses import dataclass, field

from app.attacker.registry import STRATEGIES
from normal_user_cli.registry import PERSONAS


@dataclass
class SessionSpec:
    session_type: str      # "attacker" | "normal_user"
    label: str              # strategy id or persona id
    mode: str                # "fast" | "slow"
    client_id: str
    seed: int
    queries: list[str] = field(default_factory=list)


def derive_seed(base_seed: int, label: str) -> int:
    """Stable per-label seed derived from one base seed, so the whole battery
    is reproducible from a single --seed value."""
    return (base_seed + zlib.crc32(label.encode())) % 1_000_000


def build_battery(base_seed: int, attacker_count: int, normal_count: int,
                  run_tag: str) -> list[SessionSpec]:
    """`run_tag` should be SHORT (a few chars) -- it's embedded in every
    client_id, which the API enforces at 64 characters max (see
    app/schemas/chat.py ChatRequest.client_id). The full run_id (with
    timestamp) still appears in meta.json / results.jsonl for traceability;
    it just can't also live inside every client_id."""
    specs: list[SessionSpec] = []

    for strategy_id, strategy in STRATEGIES.items():
        for mode in ("fast", "slow"):
            seed = derive_seed(base_seed, f"attacker:{strategy_id}")
            queries = strategy.generate(attacker_count, seed=seed)
            specs.append(SessionSpec(
                session_type="attacker", label=strategy_id, mode=mode,
                client_id=f"ev{run_tag}-a-{strategy_id}-{mode}",
                seed=seed, queries=queries,
            ))

    for persona_id, persona in PERSONAS.items():
        for mode in ("fast", "slow"):
            seed = derive_seed(base_seed, f"normal_user:{persona_id}")
            queries = persona.generate(normal_count, seed=seed)
            specs.append(SessionSpec(
                session_type="normal_user", label=persona_id, mode=mode,
                client_id=f"ev{run_tag}-u-{persona_id}-{mode}",
                seed=seed, queries=queries,
            ))

    return specs
