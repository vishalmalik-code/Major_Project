"""Signal fusion and the query-based risk update.

THE RULES (all four are load-bearing):

  1. Risk changes ONLY inside a query inspection. Nothing else may write it.
  2. Risk DECREASES only when the arriving query is sufficiently dissimilar to
     the window -- low similarity AND no progression signals.
  3. Doing nothing decays nothing. There is no cron job, no background task, no
     `last_seen` arithmetic, no `risk * exp(-lambda * t)`. A client at risk 82
     who goes silent for a week returns at risk 82.
  4. Relief is linear and small, so escaping CRITICAL takes a sustained run of
     genuinely different questions. One innocent query cannot launder a
     campaign.

FORBIDDEN in this module: any expression containing elapsed time.
"""

from dataclasses import dataclass

from app.core.config import settings
from app.firewall.signals.base import SignalResult


@dataclass
class RiskUpdate:
    risk_before: float
    risk_after: float
    delta: float
    weighted_score: float       # fused signal score, 0.0 - 1.0
    reason: str                 # "escalated" | "held" | "relieved"
    dominant_signal: str | None


def combine(results: list[SignalResult]) -> float:
    """Weighted mean of APPLICABLE signal scores -> 0.0 - 1.0.

    Weighted mean (not max) so no single signal can convict alone, and not sum
    so the scale stays interpretable. Heaviest weights sit on the structural
    signals (systematic_modification, value_progression,
    constraint_progression, boundary_progression) because those survive an
    attacker slowing down; burst_rate is capped low for the same reason.

    Signals with `applicable=False` (nothing to evaluate -- e.g. no numeric
    literal for value_progression to sweep) are excluded from the denominator
    entirely. Without this, an attack that only speaks to 2-3 of the 8 signals
    (exact repetition, say) would be diluted toward "benign" by signals that
    had no data to look at, rather than ones that looked and found nothing.
    """
    applicable = [r for r in results if r.applicable]
    if not applicable:
        return 0.0
    total_weight = sum(r.weight for r in applicable)
    if total_weight <= 0:
        return 0.0
    return sum(r.score * r.weight for r in applicable) / total_weight


def dominant(results: list[SignalResult]) -> SignalResult | None:
    """The single signal contributing the most to the fused score, for the
    admin drill-down and the attack-run timeline's `top_signal`."""
    scored = [r for r in results if r.applicable and r.score > 0.0]
    if not scored:
        return None
    return max(scored, key=lambda r: r.score * r.weight)


def update(risk_before: float, weighted: float,
           results: list[SignalResult]) -> RiskUpdate:
    """Apply the query-based update rule.

        weighted >= SUSPICION_THRESHOLD  ->  delta = +GAIN_SCALE * weighted
        weighted <= BENIGN_THRESHOLD     ->  delta = -DECAY_STEP
        otherwise                        ->  delta = 0.0   (hold, do not forgive)

    The middle band matters for legitimate users: a human asking related
    follow-up questions scores as ambiguous, so their risk HOLDS rather than
    climbing. Related questions are not an attack; systematic structure is.
    """
    if weighted >= settings.suspicion_threshold:
        delta = settings.gain_scale * weighted
        reason = "escalated"
    elif weighted <= settings.benign_threshold:
        delta = -settings.decay_step
        reason = "relieved"
    else:
        delta = 0.0
        reason = "held"

    risk_after = clamp(risk_before + delta)
    return RiskUpdate(
        risk_before=risk_before,
        risk_after=risk_after,
        delta=risk_after - risk_before,
        weighted_score=weighted,
        reason=reason,
        dominant_signal=(dominant(results).name if dominant(results) else None),
    )


def clamp(risk: float) -> float:
    return max(0.0, min(100.0, risk))


__all__ = ["RiskUpdate", "combine", "dominant", "update", "clamp", "settings"]
