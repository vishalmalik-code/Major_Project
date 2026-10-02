"""The eight detectors, in evaluation order.

    1-3  similarity family   repetition, lexical, semantic
    4-7  STRUCTURAL family   the detection core; heaviest weights; these are
                             what survive an attacker slowing down
    8    rate family         the only time-aware signal, capped low
"""

from app.firewall.signals.base import QueryContext, Signal, SignalResult
from app.firewall.signals.boundary_progression import BoundaryProgressionSignal
from app.firewall.signals.burst_rate import BurstRateSignal
from app.firewall.signals.constraint_progression import ConstraintProgressionSignal
from app.firewall.signals.exact_repetition import ExactRepetitionSignal
from app.firewall.signals.semantic_similarity import SemanticSimilaritySignal
from app.firewall.signals.systematic_modification import SystematicModificationSignal
from app.firewall.signals.text_similarity import TextSimilaritySignal
from app.firewall.signals.value_progression import ValueProgressionSignal


def default_signals() -> list[Signal]:
    return [
        ExactRepetitionSignal(),
        TextSimilaritySignal(),
        SemanticSimilaritySignal(),
        SystematicModificationSignal(),
        ValueProgressionSignal(),
        ConstraintProgressionSignal(),
        BoundaryProgressionSignal(),
        BurstRateSignal(),
    ]


__all__ = ["Signal", "SignalResult", "QueryContext", "default_signals"]
