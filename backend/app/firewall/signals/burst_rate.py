"""Signal 8 - burst / rate.  Targets FAST mode.

Window: tight (last 10).

THE ONLY TIME-AWARE SIGNAL IN THE SYSTEM, and deliberately the lowest-weighted
one. It reads `created_at_epoch` to compute queries-per-second and
inter-arrival variance (a script bursts with near-zero variance; a human is
irregular).

Its weight is capped so that it can never be necessary for a conviction. A SLOW
attacker scores ~0 here and is still caught by signals 1-7, because the query
window never expires and risk never decays with time. That is the central claim
of the project: rate limiting alone does not stop model extraction.

This signal reading a clock does NOT license the window or the risk model to do
the same.

Evidence example: "10 queries in 0.4 s, inter-arrival variance 0.001 - machine
-paced burst."
"""

import statistics

from app.core.config import settings
from app.core.constants import SignalName
from app.firewall.signals.base import QueryContext, Signal, SignalResult

MIN_ENTRIES = 3
BURST_INTERVAL_SECONDS = 1.0   # inter-arrival below this looks machine-paced
HUMAN_INTERVAL_SECONDS = 8.0   # inter-arrival above this looks unhurried


class BurstRateSignal(Signal):
    name = SignalName.BURST_RATE.value
    uses_tight_window = True

    @property
    def weight(self) -> float:
        return settings.weight_burst_rate

    def evaluate(self, ctx: QueryContext) -> SignalResult:
        window = ctx.tight_window
        timestamps = [e.created_at_epoch for e in window] + [ctx.arrived_at_epoch]
        if len(timestamps) < MIN_ENTRIES:
            return self._empty("Too few timestamped queries to judge rate.")

        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        intervals = [max(0.0, i) for i in intervals]
        mean_interval = sum(intervals) / len(intervals)
        variance = statistics.pvariance(intervals) if len(intervals) > 1 else 0.0

        if mean_interval >= HUMAN_INTERVAL_SECONDS:
            rate_score = 0.0
        elif mean_interval <= BURST_INTERVAL_SECONDS:
            rate_score = 1.0
        else:
            span = HUMAN_INTERVAL_SECONDS - BURST_INTERVAL_SECONDS
            rate_score = 1.0 - (mean_interval - BURST_INTERVAL_SECONDS) / span

        # Low variance at a fast pace is the strongest "machine" tell; a human
        # sending fast messages still has irregular gaps.
        low_variance_bonus = 1.0 if variance < 0.05 else 0.0
        score = min(1.0, 0.75 * rate_score + 0.25 * (rate_score * low_variance_bonus))

        span_seconds = timestamps[-1] - timestamps[0]
        evidence = (
            f"{len(timestamps)} queries in {span_seconds:.1f} s, mean interval "
            f"{mean_interval:.2f} s, inter-arrival variance {variance:.3f} - "
            f"{'machine-paced burst' if score > 0.6 else 'human-paced'}."
        )

        return SignalResult(
            self.name, score, self.weight, evidence,
            details={"mean_interval": round(mean_interval, 3),
                     "variance": round(variance, 4),
                     "span_seconds": round(span_seconds, 2)},
        )
