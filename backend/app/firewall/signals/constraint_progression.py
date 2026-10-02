"""Signal 6 - output-constraint progression.  Targets attack pattern 4
(Output-Constraint Probing).  STRUCTURAL signal.

Window: full (last 20).

Method: a stable SEMANTIC CORE (signal-3-style similarity high) combined with a
    ROTATING output-constraint vocabulary. Extract `constraint_tokens[]` across
    five families:
        length     "in 50 words", "one sentence", "in detail"
        format     "as JSON", "as a table", "as bullet points", "as YAML"
        detail     "briefly", "exhaustively", "with full reasoning"
        structure  "step by step", "numbered list", "with headings"
        style      "ELI5", "for an expert", "like a textbook"
    Score on how many distinct families/values are cycled while the underlying
    task stays fixed. That is enumeration of the output space -- harvesting the
    same knowledge in every serialization a clone would need.

Evidence example: "Same underlying task asked 7 times with 7 distinct output
constraints spanning 4 constraint families."
"""

import numpy as np

from app.core.config import settings
from app.core.constants import SignalName
from app.firewall.signals.base import QueryContext, Signal, SignalResult

SEMANTIC_CORE_THRESHOLD = 0.55  # cosine similarity treated as "same task"
MIN_ENTRIES = 2


class ConstraintProgressionSignal(Signal):
    name = SignalName.CONSTRAINT_PROGRESSION.value

    @property
    def weight(self) -> float:
        return settings.weight_constraint_progression

    def evaluate(self, ctx: QueryContext) -> SignalResult:
        window = [e for e in ctx.window if e.embedding is not None]
        if len(window) < MIN_ENTRIES or ctx.embedding is None or not ctx.constraint_tokens:
            return self._empty(
                "No output-constraint phrases detected, or window too short."
            )

        # Entries whose semantic core matches the incoming query.
        same_task = [
            e for e in window
            if float(np.dot(ctx.embedding, e.embedding)) >= SEMANTIC_CORE_THRESHOLD
        ]
        same_task_with_constraints = [e for e in same_task if e.constraint_tokens]

        if len(same_task_with_constraints) < 1:
            return self._empty(
                "No prior same-task query carried an output-constraint phrase."
            )

        all_tokens: set[str] = set(ctx.constraint_tokens)
        for e in same_task_with_constraints:
            all_tokens.update(e.constraint_tokens)

        families = {t.split(":", 1)[0] for t in all_tokens}
        n_asks = len(same_task_with_constraints) + 1  # + the incoming query

        # Score rewards many distinct constraint VALUES and many distinct
        # FAMILIES cycled over a stable task -- enumeration of the output
        # space, not one person picking one format once.
        value_score = min(1.0, (len(all_tokens) - 1) / 4)   # 5+ distinct values -> saturate
        family_score = min(1.0, (len(families) - 1) / 3)    # 4+ families -> saturate
        coverage = n_asks / (len(window) + 1)
        score = min(1.0, (0.5 * value_score + 0.3 * family_score) * max(0.4, coverage) * 2)
        score = max(0.0, min(1.0, score))

        evidence = (
            f"Same underlying task asked {n_asks} times with {len(all_tokens)} "
            f"distinct output constraints spanning {len(families)} constraint "
            f"families."
        )

        return SignalResult(
            self.name, score, self.weight, evidence,
            details={"same_task_count": n_asks, "distinct_values": len(all_tokens),
                     "families": sorted(families)},
        )
