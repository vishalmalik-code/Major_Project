"""Strategy registry. One entry per attack pattern; the API exposes this
directly at GET /api/attack/strategies."""

from app.attacker.base import AttackStrategy
from app.attacker.strategies.boundary_probing import BoundaryProbingStrategy
from app.attacker.strategies.constraint_probing import ConstraintProbingStrategy
from app.attacker.strategies.exact_repetition import ExactRepetitionStrategy
from app.attacker.strategies.minimal_modification import MinimalModificationStrategy
from app.attacker.strategies.value_sweep import ValueSweepStrategy

STRATEGIES: dict[str, AttackStrategy] = {
    s.id: s for s in (
        ExactRepetitionStrategy(),
        MinimalModificationStrategy(),
        ValueSweepStrategy(),
        ConstraintProbingStrategy(),
        BoundaryProbingStrategy(),
    )
}


def get(strategy_id: str) -> AttackStrategy:
    if strategy_id not in STRATEGIES:
        raise KeyError(f"unknown strategy: {strategy_id}")
    return STRATEGIES[strategy_id]


def listing() -> list[dict]:
    return [s.as_dict() for s in STRATEGIES.values()]


# CLI/UI-facing strategy names, shared by attacker.py and the attacker-console
# SSE endpoint so the mapping exists in exactly one place.
CLI_ALIASES: dict[str, str] = {
    "repetition": "exact_repetition",
    "minimal_modification": "minimal_modification",
    "value_sweep": "value_sweep",
    "output_constraint": "constraint_probing",
    "boundary": "boundary_probing",
}
