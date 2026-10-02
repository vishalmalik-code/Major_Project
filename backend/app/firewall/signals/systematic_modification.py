"""Signal 4 - systematic modification.  Targets attack pattern 2
(Minimal Query Modification).

Window: full (last 20).  One of the four STRUCTURAL signals -- these carry the
heaviest weights because they are what separates an extraction campaign from a
curious human, and they keep working when the attacker slows down.

Method: high similarity BUT NOT identical, plus a small and CONSISTENT edit
    region. Token-diff each consecutive pair; look for
      - edit distance small and stable (1-3 tokens),
      - the changed tokens occupying the SAME position across pairs,
      - the surrounding template unchanged.
    A fixed template with one moving part is a dataset being enumerated. A
    human follow-up rewrites the whole sentence.

Evidence example: "9 of the last 10 queries share a fixed 14-token template
with a single substituted token at position 6."
"""

from app.core.config import settings
from app.core.constants import SignalName
from app.firewall.normalize import tokenize
from app.firewall.signals.base import QueryContext, Signal, SignalResult

MAX_EDIT_TOKENS = 3


def _diff_positions(a: list[str], b: list[str]) -> list[int] | None:
    """Positions where tokens differ, if `a` and `b` are the same length.
    Returns None if lengths differ (not a simple substitution)."""
    if len(a) != len(b):
        return None
    return [i for i, (x, y) in enumerate(zip(a, b)) if x != y]


class SystematicModificationSignal(Signal):
    name = SignalName.SYSTEMATIC_MODIFICATION.value

    @property
    def weight(self) -> float:
        return settings.weight_systematic_modification

    def evaluate(self, ctx: QueryContext) -> SignalResult:
        window = ctx.window
        if len(window) < 2:
            return self._empty("Window too short to detect a template pattern.")

        token_lists = [tokenize(e.normalized) for e in window]
        token_lists.append(tokenize(ctx.normalized))

        # Compare each consecutive pair for a small, position-stable diff.
        matches = 0
        position_sets: list[frozenset[int]] = []
        template_len = None
        for i in range(len(token_lists) - 1):
            a, b = token_lists[i], token_lists[i + 1]
            if a == b:
                continue  # exact repeats are signal 1's job, not this one
            diff = _diff_positions(a, b)
            if diff is None:
                continue  # different length -> not a simple substitution
            if 0 < len(diff) <= MAX_EDIT_TOKENS:
                matches += 1
                position_sets.append(frozenset(diff))
                template_len = len(a)

        total_pairs = len(token_lists) - 1
        if matches == 0:
            return SignalResult(
                self.name, 0.0, self.weight,
                "No consecutive-pair edits are both small and template-preserving.",
                details={"matches": 0, "pairs": total_pairs},
            )

        fraction = matches / total_pairs

        # Position consistency: do the changed slots line up across pairs?
        common = set.intersection(*[set(p) for p in position_sets]) if position_sets else set()
        position_consistent = len(common) > 0

        score = min(1.0, fraction * (1.0 if position_consistent else 0.6))

        pos_desc = (f"at position {sorted(common)[0]}"
                   if position_consistent else "at varying positions")
        evidence = (
            f"{matches} of {total_pairs} consecutive query pairs share a fixed "
            f"{template_len}-token template with a small substitution {pos_desc}."
        )

        return SignalResult(
            self.name, score, self.weight, evidence,
            details={"matches": matches, "pairs": total_pairs,
                     "position_consistent": position_consistent,
                     "template_len": template_len},
        )
