"""Attack 1 - Exact Query Repetition: sends one identical query over and over.

    Q
    Q
    Q
    Q
    Q

The crudest harvest: sample the same prompt repeatedly to average out sampling
noise and recover the model's modal response. Trips signals 1, 2 and 3 hard and
almost immediately -- it is the baseline the other four are measured against.

generate(count) -> the same string `count` times (one template picked by seed).
"""

import random

from app.attacker.base import AttackStrategy
from app.core.constants import StrategyId

_TEMPLATES = [
    "What is a SQL injection attack and how does it work?",
    "Explain how a buffer overflow vulnerability can be exploited.",
    "What is the difference between symmetric and asymmetric encryption?",
    "How does a man-in-the-middle attack work?",
    "What is cross-site scripting and how do attackers use it?",
]


class ExactRepetitionStrategy(AttackStrategy):
    id = StrategyId.EXACT_REPETITION.value
    name = "Exact Query Repetition"
    description = "Sends the identical query repeatedly."
    targets = ["exact_repetition", "text_similarity", "semantic_similarity"]

    def generate(self, count: int, seed: int | None = None,
                topic: str | None = None) -> list[str]:
        rng = random.Random(seed)
        template = self._pick(rng, _TEMPLATES, topic)
        return [template] * count
