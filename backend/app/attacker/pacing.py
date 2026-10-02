"""Pacing is ORTHOGONAL to strategy: any of the five patterns runs in either
mode. This is the experimental design of the whole project -- strategy and
pacing are the two independent variables, queries-to-first-block is the
measurement.

    FAST  trips the text signals (1-7) AND burst_rate (8)  -> risk climbs fast
    SLOW  trips the text signals (1-7) only                -> risk climbs
                                                              slower, but
                                                              monotonically
"""

import random
from abc import ABC, abstractmethod

from app.core.config import settings
from app.core.constants import AttackMode


class Pacer(ABC):
    mode: AttackMode

    @abstractmethod
    def delay(self) -> float:
        """Seconds to wait before sending the next query."""


class FastPacer(Pacer):
    """Burst. ~0 - FAST_DELAY_MAX seconds, near-zero inter-arrival variance --
    which is itself the tell that burst_rate looks for."""

    mode = AttackMode.FAST

    def __init__(self, rng: random.Random | None = None) -> None:
        self._rng = rng or random.Random()

    def delay(self) -> float:
        return self._rng.uniform(0.0, settings.fast_delay_max)


class SlowPacer(Pacer):
    """Human-like: uniform(SLOW_DELAY_MIN, SLOW_DELAY_MAX) with jitter, default
    20-120 s. burst_rate contributes ~0, so detection must come from query text
    alone. Lower the bounds in .env (e.g. 3-8 s) for a demo that fits in a
    presentation slot without changing what is being demonstrated."""

    mode = AttackMode.SLOW

    def __init__(self, rng: random.Random | None = None) -> None:
        self._rng = rng or random.Random()

    def delay(self) -> float:
        return self._rng.uniform(settings.slow_delay_min, settings.slow_delay_max)


def pacer_for(mode: AttackMode, seed: int | None = None) -> Pacer:
    rng = random.Random(seed) if seed is not None else None
    return FastPacer(rng) if mode is AttackMode.FAST else SlowPacer(rng)
