"""Signal interface.

Eight independent detectors, each a small readable function. NO neural
detector, NO trained classifier: every alarm must be explainable in one
sentence. `evidence` is a required field, not a nicety -- it is the project's
explainability guarantee and it is what the admin drill-down renders.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from app.firewall.window import WindowEntry


@dataclass
class QueryContext:
    """Everything a signal is allowed to look at."""

    client_id: str
    seq: int
    text: str
    normalized: str
    embedding: np.ndarray | None
    numbers: list[float]
    constraint_tokens: list[str]
    arrived_at_epoch: float          # burst_rate only
    window: list[WindowEntry]        # last QUERY_WINDOW_SIZE, oldest -> newest
    tight_window: list[WindowEntry]  # last TIGHT_WINDOW_SIZE


@dataclass
class SignalResult:
    name: str
    score: float                     # 0.0 - 1.0
    weight: float
    evidence: str                    # one human-readable sentence
    details: dict[str, Any] = field(default_factory=dict)
    applicable: bool = True          # False = "nothing to evaluate", not "benign"


class Signal(ABC):
    """Base class for all eight detectors."""

    name: str
    uses_tight_window: bool = False

    @property
    @abstractmethod
    def weight(self) -> float:
        """Read from settings so the admin can tune it live."""

    @abstractmethod
    def evaluate(self, ctx: QueryContext) -> SignalResult:
        """Score this query against the window. Must be pure and side-effect
        free -- signals never write to the DB or mutate the window."""

    def _empty(self, reason: str) -> SignalResult:
        """Result for 'nothing to evaluate' (empty window, no numeric literal
        in this query, no constraint phrase, etc).

        This is NOT the same as a real 0.0 finding. A signal that actively
        looked and found no evidence of its pattern (e.g.
        systematic_modification checking a window and finding no small,
        position-stable edits) IS applicable and its 0.0 is real information
        that should pull the fused score down. A signal with no data to look
        at (applicable=False) abstains instead -- otherwise sparse-evidence
        attacks (e.g. exact repetition, which only speaks to 3 of the 8
        signals) would be diluted toward "benign" by signals that had nothing
        to say either way.
        """
        return SignalResult(self.name, 0.0, self.weight, reason, applicable=False)
