"""Signal 3 - semantic similarity.  Targets attack patterns 2 and 4.

Window: full (last 20).

Method: cosine similarity of the all-MiniLM-L6-v2 embedding against the <=20
    window vectors (a trivial in-memory dot-product loop; pgvector ANN is for
    admin analytics, not this path). Report max and mean.

Catches paraphrase-based extraction that defeats signal 2. On its own it would
false-positive on a legitimate user drilling into one topic, which is exactly
why it carries moderate weight and the structural signals (4-7) carry more.

Evidence example: "Mean semantic similarity 0.91 across the window - all 20
queries occupy the same narrow region of embedding space."
"""

import numpy as np

from app.core.config import settings
from app.core.constants import SignalName
from app.firewall.signals.base import QueryContext, Signal, SignalResult


class SemanticSimilaritySignal(Signal):
    name = SignalName.SEMANTIC_SIMILARITY.value

    @property
    def weight(self) -> float:
        return settings.weight_semantic_similarity

    def evaluate(self, ctx: QueryContext) -> SignalResult:
        window = [e for e in ctx.window if e.embedding is not None]
        if not window or ctx.embedding is None:
            return self._empty("Window is empty or embeddings unavailable.")

        # Cosine similarity is bounded to [-1, 1] mathematically, but a
        # float32 dot product of two near-identical (or self-identical)
        # vectors can land a hair above 1.0 due to rounding -- clamp before
        # using it anywhere, since `score` is persisted under a DB
        # CHECK (score BETWEEN 0.0 AND 1.0) and an unclamped 1.0000001
        # violates it.
        sims = [max(-1.0, min(1.0, float(np.dot(ctx.embedding, e.embedding))))
               for e in window]
        max_sim = max(sims)
        mean_sim = sum(sims) / len(sims)
        # Clip negatives (near-orthogonal/opposite) to 0 before scoring --
        # cosine similarity can dip slightly negative for unrelated text and
        # that carries no extraction signal.
        score = max(0.0, min(1.0, 0.6 * max_sim + 0.4 * mean_sim))

        evidence = (
            f"Mean semantic similarity {mean_sim:.2f} across the last "
            f"{len(window)} queries (closest {max_sim:.2f})."
        )

        return SignalResult(
            self.name, score, self.weight, evidence,
            details={"max_similarity": round(max_sim, 3),
                     "mean_similarity": round(mean_sim, 3),
                     "window_size": len(window)},
        )
