"""Signal 1 - exact repetition.  Targets attack pattern 1 (Exact Query Repetition).

Window: tight (last 10).

Method: hash `ctx.normalized` and count matches in the tight window.
    score = matches / len(tight_window), lightly super-linear so that a run of
    identical queries saturates fast.

Evidence example: "8 of the last 10 queries are byte-identical after
normalization."

Note this signal is intentionally strict -- it wants near-identical text.
Humans rephrase; only a script repeats verbatim.
"""

from app.core.config import settings
from app.core.constants import SignalName
from app.firewall.signals.base import QueryContext, Signal, SignalResult


class ExactRepetitionSignal(Signal):
    name = SignalName.EXACT_REPETITION.value
    uses_tight_window = True

    @property
    def weight(self) -> float:
        return settings.weight_exact_repetition

    def evaluate(self, ctx: QueryContext) -> SignalResult:
        window = ctx.tight_window
        if not window:
            return self._empty("Window is empty; nothing to compare.")

        matches = sum(1 for e in window if e.normalized == ctx.normalized)
        fraction = matches / len(window)
        # Lightly super-linear (fraction ** 0.7) so 1-2 stray repeats stay low
        # but a sustained run saturates toward 1.0 quickly.
        score = min(1.0, fraction ** 0.7) if matches else 0.0

        evidence = (
            f"{matches} of the last {len(window)} queries are byte-identical "
            f"after normalization."
            if matches
            else f"No exact repeats among the last {len(window)} queries."
        )

        return SignalResult(
            self.name, score, self.weight, evidence,
            details={"matches": matches, "window_size": len(window),
                     "fraction": round(fraction, 3)},
        )
