"""Signal 7 - boundary / edge-case progression.  Targets attack pattern 5
(Boundary / Edge-Case Probing).  STRUCTURAL signal.

Window: full (last 20).

Method: values drifting monotonically AWAY from a normal-range centroid toward
    extremes -- 0, negatives, off-by-one limits, max-int, empty string, very
    long input. Distinguished from signal 5 by DIRECTION rather than step: a
    sweep walks through a range, a boundary probe walks out of it.
    Track increasing distance-from-centroid, plus hits on a table of known
    edge values (0, -1, 1, 65535, 65536, 2**31-1, "", extremely long strings).

Evidence example: "Input walked 80 -> 443 -> 0 -> -1 -> 65535 -> 65536:
monotonic drift toward protocol boundary values."
"""

from app.core.config import settings
from app.core.constants import SignalName
from app.firewall.normalize import tokenize
from app.firewall.signals.base import QueryContext, Signal, SignalResult

MIN_SEQUENCE = 3
KNOWN_EDGE_VALUES = {0, -1, 1, 255, 256, 65535, 65536, 2**31 - 1, 2**31, 2**32 - 1}


def _template_key(tokens: list[str]) -> str:
    return " ".join("<NUM>" if _is_number(t) else t for t in tokens)


def _is_number(tok: str) -> bool:
    try:
        float(tok)
        return True
    except ValueError:
        return False


class BoundaryProgressionSignal(Signal):
    name = SignalName.BOUNDARY_PROGRESSION.value

    @property
    def weight(self) -> float:
        return settings.weight_boundary_progression

    def evaluate(self, ctx: QueryContext) -> SignalResult:
        if not ctx.numbers:
            return self._empty("Current query contains no numeric literal.")

        window = ctx.window
        entries = window + [ctx]
        if len(entries) < MIN_SEQUENCE:
            return self._empty("Window too short to detect a boundary walk.")

        groups: dict[str, list[tuple[int, float]]] = {}
        for idx, e in enumerate(entries):
            if len(e.numbers) != 1:
                continue
            key = _template_key(tokenize(e.normalized))
            groups.setdefault(key, []).append((idx, e.numbers[0]))

        best_score = 0.0
        best_evidence = (
            f"No numeric slot drifts toward boundary/extreme values among the "
            f"last {len(window)} queries."
        )
        best_details: dict = {}

        for key, pairs in groups.items():
            if len(pairs) < MIN_SEQUENCE:
                continue
            pairs.sort(key=lambda p: p[0])
            values = [v for _, v in pairs]

            centroid = sum(values[:max(1, len(values) // 2)]) / max(1, len(values) // 2)
            distances = [abs(v - centroid) for v in values]

            # Monotonically increasing distance from the initial centroid.
            increasing_steps = sum(
                1 for i in range(len(distances) - 1) if distances[i + 1] >= distances[i]
            )
            monotonic_fraction = increasing_steps / max(1, len(distances) - 1)

            edge_hits = sum(1 for v in values if v in KNOWN_EDGE_VALUES)
            edge_fraction = edge_hits / len(values)

            score = min(1.0, 0.55 * monotonic_fraction + 0.55 * edge_fraction)
            if score > best_score:
                best_score = score
                shown = " -> ".join(_fmt(v) for v in values[:8])
                reason = "toward known boundary values" if edge_hits else "away from typical range"
                best_evidence = (
                    f"Input walked {shown}: "
                    f"{'monotonic drift ' if monotonic_fraction > 0.6 else ''}"
                    f"{reason}."
                )
                best_details = {"sequence": values, "edge_hits": edge_hits,
                                "monotonic_fraction": round(monotonic_fraction, 3)}

        return SignalResult(self.name, best_score, self.weight, best_evidence,
                            details=best_details)


def _fmt(v: float) -> str:
    return str(int(v)) if v == int(v) else f"{v:g}"
