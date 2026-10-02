"""Attack 3 - Systematic Value Sweep: one input value changed systematically.

    value = 1
    value = 2
    value = 3
    ...
    value = N

Enumerates a parameter space to map how the model responds across a range --
classic dataset construction. The tell is an arithmetic sequence occupying one
slot of an otherwise stable template.

generate(count) -> template + values [start, start+step, ...] for `count` steps.
"""

import random

from app.attacker.base import AttackStrategy
from app.core.constants import StrategyId

_TEMPLATES = [
    "Is TCP port {v} commonly used by malware?",
    "How risky is running {v} concurrent database connections?",
    "Is a password of length {v} considered secure?",
    "What happens if a JWT token has a {v}-hour expiry?",
]


class ValueSweepStrategy(AttackStrategy):
    id = StrategyId.VALUE_SWEEP.value
    name = "Systematic Value Sweep"
    description = "Systematically sweeps one input value through a range."
    targets = ["value_progression", "systematic_modification"]

    def generate(self, count: int, seed: int | None = None,
                topic: str | None = None) -> list[str]:
        rng = random.Random(seed)
        template = self._pick(rng, _TEMPLATES, topic)
        start = rng.choice([1, 4, 8])
        step = rng.choice([1, 2])
        return [template.format(v=start + i * step) for i in range(count)]
