"""Risk band -> action. Four bands, all thresholds configurable.

    LOW      0  - 29   ALLOW              forward normally
    MEDIUM   30 - 54   ALLOW + MONITOR    forward, flag, raise an event
    HIGH     55 - 79   THROTTLE           delay, then forward
    CRITICAL 80 - 100  BLOCK              refuse; the LLM is never called
"""

from app.core.config import settings
from app.core.constants import Action, RiskBand

_BAND_TO_ACTION: dict[RiskBand, Action] = {
    RiskBand.LOW: Action.ALLOW,
    RiskBand.MEDIUM: Action.MONITOR,
    RiskBand.HIGH: Action.THROTTLE,
    RiskBand.CRITICAL: Action.BLOCK,
}


def band_for(risk: float) -> RiskBand:
    if risk >= settings.risk_threshold_critical:
        return RiskBand.CRITICAL
    if risk >= settings.risk_threshold_high:
        return RiskBand.HIGH
    if risk >= settings.risk_threshold_medium:
        return RiskBand.MEDIUM
    return RiskBand.LOW


def action_for(risk: float) -> Action:
    return _BAND_TO_ACTION[band_for(risk)]


def throttle_delay_for(risk: float) -> float:
    """Seconds to stall a THROTTLE'd request. Purpose is to destroy harvest
    throughput, not to punish -- the user still gets their answer."""
    return settings.throttle_delay_seconds if band_for(risk) is RiskBand.HIGH else 0.0


def queries_to_clear(risk: float) -> int:
    """How many sufficiently-dissimilar queries would bring a BLOCKed client
    back under CRITICAL. Reported to the client as `retry_after_queries`.

    Deliberately measured in QUERIES, not seconds: waiting changes nothing.
    """
    if risk < settings.risk_threshold_critical:
        return 0
    excess = risk - settings.risk_threshold_critical
    return int(-(-excess // settings.decay_step)) + 1
