"""Signal 5 - value progression.  Targets attack pattern 3
(Systematic Value Sweep).  STRUCTURAL signal.

Window: full (last 20).

Method: over queries whose template is otherwise stable, extract `numbers[]`
    and test the sequence for
      - monotonicity,
      - a fixed step (arithmetic progression) or a consistent ratio,
      - low variance in step size.
    A stable template plus an arithmetic sequence is a sweep, not a question.

Evidence example: "Numeric slot swept 1, 2, 3, 4, 5, 6 (fixed step 1) across 6
queries sharing one template."
"""

import statistics

from app.core.config import settings
from app.core.constants import SignalName
from app.firewall.normalize import tokenize
from app.firewall.signals.base import QueryContext, Signal, SignalResult

MIN_SEQUENCE = 3


def _template_key(tokens: list[str]) -> str:
    """Tokens with numeric literals blanked out, so queries sharing a template
    but differing only in numbers collapse to the same key."""
    return " ".join("<NUM>" if _is_number(t) else t for t in tokens)


def _is_number(tok: str) -> bool:
    try:
        float(tok)
        return True
    except ValueError:
        return False


class ValueProgressionSignal(Signal):
    name = SignalName.VALUE_PROGRESSION.value

    @property
    def weight(self) -> float:
        return settings.weight_value_progression

    def evaluate(self, ctx: QueryContext) -> SignalResult:
        if not ctx.numbers:
            return self._empty("Current query contains no numeric literal.")

        window = ctx.window
        entries = window + [ctx]
        if len(entries) < MIN_SEQUENCE:
            return self._empty("Window too short to detect a numeric sweep.")

        # Group by template (numbers blanked), keep entries with exactly one
        # number so the "swept slot" is unambiguous.
        groups: dict[str, list[tuple[int, float]]] = {}
        for idx, e in enumerate(entries):
            if len(e.numbers) != 1:
                continue
            key = _template_key(tokenize(e.normalized))
            groups.setdefault(key, []).append((idx, e.numbers[0]))

        best_score = 0.0
        best_evidence = f"No numeric slot is swept across a shared template " \
                        f"among the last {len(window)} queries."
        best_details: dict = {"sequence": []}

        for key, pairs in groups.items():
            if len(pairs) < MIN_SEQUENCE:
                continue
            pairs.sort(key=lambda p: p[0])
            values = [v for _, v in pairs]
            steps = [values[i + 1] - values[i] for i in range(len(values) - 1)]

            monotonic = all(s > 0 for s in steps) or all(s < 0 for s in steps)
            if not monotonic or not steps:
                continue

            step_stdev = statistics.pstdev(steps) if len(steps) > 1 else 0.0
            mean_step = sum(abs(s) for s in steps) / len(steps)
            consistency = 1.0 - min(1.0, step_stdev / max(abs(mean_step), 1e-6))

            coverage = len(pairs) / len(entries)
            score = min(1.0, 0.6 * consistency + 0.4 * min(1.0, coverage * 1.5))

            if score > best_score:
                best_score = score
                shown = ", ".join(_fmt(v) for v in values[:8])
                step_desc = f"fixed step {_fmt(steps[0])}" if step_stdev < 1e-9 else "irregular step"
                best_evidence = (
                    f"Numeric slot swept {shown} ({step_desc}) across "
                    f"{len(pairs)} queries sharing one template."
                )
                best_details = {"sequence": values, "steps": steps,
                                "consistency": round(consistency, 3),
                                "coverage": round(coverage, 3)}

        return SignalResult(self.name, best_score, self.weight, best_evidence,
                            details=best_details)


def _fmt(v: float) -> str:
    return str(int(v)) if v == int(v) else f"{v:g}"
