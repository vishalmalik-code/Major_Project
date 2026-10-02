"""Normal-user persona interface -- deliberately parallel to
app.attacker.base.AttackStrategy, so the evaluation runner can treat attacker
sessions and normal-user sessions uniformly.

The crucial difference is behavioral, not structural: a persona's `generate()`
is allowed to produce related, rephrased, or even occasionally repeated
questions (real users do that), but it must never deliberately enumerate a
parameter space, rotate through a fixed set of output constraints, or apply a
single-token substitution to an otherwise-frozen template -- those systematic
shapes are what the five attack strategies do on purpose, and are exactly what
the firewall's structural signals (4-7) are built to catch.
"""

import random
from abc import ABC, abstractmethod
from collections.abc import Sequence


class Persona(ABC):
    id: str             # "student"
    name: str            # "Student"
    description: str
    traits: list[str] = []   # short bullet list, for --list-personas and the report

    @abstractmethod
    def generate(self, count: int, seed: int | None = None,
                topic: str | None = None) -> list[str]:
        """Return `count` queries realising this persona's natural behaviour.

        Deterministic given `seed`. `topic` optionally steers which subject
        area the persona focuses on (e.g. "jwt", "xss"); personas that pick a
        single topic per session (student, developer, researcher) honour it
        when it matches something in their bank, personas that hop between
        topics (casual_user) may ignore it.
        """

    @staticmethod
    def _cycle(rng: random.Random, items: Sequence[str], count: int) -> list[str]:
        """Take `count` items from `items` in order, wrapping around (with a
        light reshuffle each lap) if `count` exceeds the bank size -- so a
        long session still reads as "the same person, still on topic" rather
        than silently repeating verbatim from the second lap on."""
        out: list[str] = []
        pool = list(items)
        while len(out) < count:
            lap = pool[:]
            rng.shuffle(lap) if out else None  # keep first lap in natural order
            out.extend(lap)
        return out[:count]

    def as_dict(self) -> dict:
        return {"id": self.id, "name": self.name,
                "description": self.description, "traits": self.traits}
