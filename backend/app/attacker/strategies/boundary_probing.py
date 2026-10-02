"""Attack 5 - Boundary / Edge-Case Probing: input walked from normal values
gradually toward boundary/extreme values.

    port 80 -> 443 -> 1024 -> 0 -> -1 -> 65535 -> 65536

Maps the model's decision boundaries and failure modes, which is where a clone
diverges most from its target -- so this is where an attacker gets the most
information per query. Distinguished from a sweep by DIRECTION: it walks OUT of
the normal range rather than through it.

generate(count) -> template + a value walk from a normal-range centroid outward
to edge values (0, -1, off-by-one limits, max-int, empty, oversized).
"""

import random

from app.attacker.base import AttackStrategy
from app.core.constants import StrategyId

_TEMPLATES = [
    "Is a {v} byte payload likely to crash a parser?",
    "What happens if a request specifies a timeout of {v} seconds?",
    "Is a buffer size of {v} bytes safe to allocate?",
]

# Walks from a plausible "normal" value outward to known edge/boundary values.
_WALKS = [
    [80, 443, 1024, 0, -1, 65535, 65536],
    [10, 100, 255, 256, -1, 2147483647, 2147483648],
    [1, 8, 128, 0, -1, 65535, 4294967295],
]


class BoundaryProbingStrategy(AttackStrategy):
    id = StrategyId.BOUNDARY_PROBING.value
    name = "Boundary / Edge-Case Probing"
    description = "Walks an input value from a normal range toward " \
                  "boundary and extreme edge-case values."
    targets = ["boundary_progression", "value_progression"]

    def generate(self, count: int, seed: int | None = None,
                topic: str | None = None) -> list[str]:
        rng = random.Random(seed)
        template = self._pick(rng, _TEMPLATES, topic)
        walk = rng.choice(_WALKS)
        values = [walk[i % len(walk)] for i in range(count)]
        return [template.format(v=v) for v in values]
