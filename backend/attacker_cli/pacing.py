"""FAST and SLOW pacing, entirely self-contained -- this module does NOT
import app.core.config (which holds the firewall's thresholds and signal
weights), so the attacker has no way to read firewall tuning even by accident.

The attack STRATEGY (which queries are sent, and in what order) is identical
in both modes. Only the delay between sends changes -- that is the whole
point of the fast/slow comparison.
"""

import random
from abc import ABC, abstractmethod


class Pacer(ABC):
    @abstractmethod
    def delay(self) -> float:
        """Seconds to wait before sending the next query."""


class FastPacer(Pacer):
    """Rapid sends. A single configurable delay (default 0.3s, prompt's
    suggested range is 0.1-1.0s), with light jitter so it isn't perfectly
    periodic."""

    def __init__(self, delay: float = 0.3) -> None:
        self.base_delay = max(0.0, delay)

    def delay(self) -> float:
        jitter = random.uniform(-0.05, 0.05) * self.base_delay
        return max(0.0, self.base_delay + jitter)


class SlowPacer(Pacer):
    """Human-like pacing: uniform(min_delay, max_delay) by default, with an
    occasional longer pause (as if the attacker got distracted) -- a fixed
    chance per query of a 2-4x multiplier on top of the normal delay."""

    def __init__(self, min_delay: float = 5.0, max_delay: float = 15.0,
                long_pause_chance: float = 0.12,
                long_pause_multiplier_range: tuple[float, float] = (2.0, 4.0)) -> None:
        self.min_delay = min_delay
        self.max_delay = max(min_delay, max_delay)
        self.long_pause_chance = long_pause_chance
        self.long_pause_multiplier_range = long_pause_multiplier_range

    def delay(self) -> float:
        base = random.uniform(self.min_delay, self.max_delay)
        if random.random() < self.long_pause_chance:
            multiplier = random.uniform(*self.long_pause_multiplier_range)
            return base * multiplier
        return base
