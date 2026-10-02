"""Attack strategy interface.

Every one of the five patterns is a reusable query GENERATOR behind this single
interface, so the runner treats them uniformly and adding a sixth pattern is one
file plus one registry entry.

Generators own a small cybersecurity-themed template bank, matching the normal
user's domain on purpose: the firewall must detect STRUCTURE, not vocabulary. An
attack that was trivially separable by topic would prove nothing.
"""

import random
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from typing import TypeVar

T = TypeVar("T")


class AttackStrategy(ABC):
    id: str            # "value_sweep"
    name: str          # "Systematic Value Sweep"
    description: str
    targets: list[str] = []   # signal names this pattern is designed to trip

    @abstractmethod
    def generate(self, count: int, seed: int | None = None,
                topic: str | None = None) -> list[str]:
        """Return exactly `count` queries realising this attack pattern.

        Deterministic given `seed`, so a demo run is reproducible and the
        fast-vs-slow comparison holds the query text constant while varying
        only pacing.

        `topic` is an optional case-insensitive keyword hint (e.g. "jwt",
        "xss") used to pick which template/task in the bank to build the
        sequence around; if it matches nothing in the bank, generation falls
        back to the normal seed-driven random choice.
        """

    @staticmethod
    def _pick(rng: random.Random, items: Sequence[T], topic: str | None,
              text_of: Callable[[T], str] = str) -> T:
        """Pick one item from `items`, preferring ones matching `topic` (a
        case-insensitive substring match against `text_of(item)`) when given,
        else falling back to the seeded random choice."""
        if topic:
            matches = [it for it in items if topic.lower() in text_of(it).lower()]
            if matches:
                return rng.choice(matches)
        return rng.choice(items)

    def explain(self) -> str:
        """Which firewall signals this pattern should trip, and why."""
        return f"{self.name}: expected to trip {', '.join(self.targets)}."

    def as_dict(self) -> dict:
        return {"id": self.id, "name": self.name,
                "description": self.description, "targets": self.targets}
