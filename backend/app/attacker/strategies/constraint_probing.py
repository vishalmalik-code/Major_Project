"""Attack 4 - Output-Constraint Probing: same task, output requirements varied.

    "...in 50 words"        (length)
    "...as JSON"            (format)
    "...exhaustively"       (detail)
    "...step by step"       (structure)
    "...explain like I am five"  (style)

The most valuable attack for cloning: it harvests the same knowledge in every
serialization a student model needs, teaching the clone the target's formatting
and style behaviour, not just its facts. Lexically the queries differ, so the
tell is a stable semantic core with a rotating constraint vocabulary.

generate(count) -> one task, `count` distinct constraints drawn across the five
families.
"""

import random

from app.attacker.base import AttackStrategy
from app.core.constants import StrategyId

_TASKS = [
    "Explain how buffer overflow attacks work",
    "Describe how a phishing attack is carried out",
    "Explain how ransomware encrypts a victim's files",
    "Describe how privilege escalation works on Linux",
]

_CONSTRAINTS = [
    "in 50 words",
    "as JSON",
    "as a table",
    "step by step",
    "like I'm five",
    "for an expert audience",
    "in one sentence",
    "with full reasoning",
    "as a numbered list",
    "briefly",
]


class ConstraintProbingStrategy(AttackStrategy):
    id = StrategyId.CONSTRAINT_PROBING.value
    name = "Output-Constraint Probing"
    description = "Keeps the task fixed while cycling output length, " \
                  "format, detail, structure, and style requirements."
    targets = ["constraint_progression", "semantic_similarity"]

    def generate(self, count: int, seed: int | None = None,
                topic: str | None = None) -> list[str]:
        rng = random.Random(seed)
        task = self._pick(rng, _TASKS, topic)
        constraints = _CONSTRAINTS[:]
        rng.shuffle(constraints)
        chosen = [constraints[i % len(constraints)] for i in range(count)]
        return [f"{task} {c}." for c in chosen]
