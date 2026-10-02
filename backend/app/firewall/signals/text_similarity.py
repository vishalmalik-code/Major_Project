"""Signal 2 - lexical similarity.  Targets attack patterns 1 and 2.

Window: full (last 20).

Method: token-level Jaccard plus character 3-gram overlap of `normalized`
    against every window entry. Report max and mean; score blends them so that
    both "one near-duplicate" and "a uniformly similar batch" register.

Evidence example: "Mean lexical overlap with the last 20 queries is 0.87;
closest match differs by 2 tokens."
"""

from app.core.config import settings
from app.core.constants import SignalName
from app.firewall.normalize import tokenize
from app.firewall.signals.base import QueryContext, Signal, SignalResult


def _char_ngrams(s: str, n: int = 3) -> set[str]:
    if len(s) < n:
        return {s} if s else set()
    return {s[i:i + n] for i in range(len(s) - n + 1)}


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class TextSimilaritySignal(Signal):
    name = SignalName.TEXT_SIMILARITY.value

    @property
    def weight(self) -> float:
        return settings.weight_text_similarity

    def evaluate(self, ctx: QueryContext) -> SignalResult:
        window = ctx.window
        if not window:
            return self._empty("Window is empty; nothing to compare.")

        query_tokens = set(tokenize(ctx.normalized))
        query_ngrams = _char_ngrams(ctx.normalized)

        overlaps: list[float] = []
        closest_token_diff = None
        closest_overlap = -1.0

        for e in window:
            tok_sim = _jaccard(query_tokens, set(tokenize(e.normalized)))
            ngram_sim = _jaccard(query_ngrams, _char_ngrams(e.normalized))
            blended = 0.5 * tok_sim + 0.5 * ngram_sim
            overlaps.append(blended)
            if blended > closest_overlap:
                closest_overlap = blended
                closest_token_diff = abs(len(query_tokens) - len(set(tokenize(e.normalized))))

        max_sim = max(overlaps)
        mean_sim = sum(overlaps) / len(overlaps)
        # Blend max (catches a single near-duplicate) with mean (catches a
        # uniformly similar batch), weighted toward max since one strong hit
        # matters more than a diffuse similarity across the window.
        score = 0.7 * max_sim + 0.3 * mean_sim

        evidence = (
            f"Mean lexical overlap with the last {len(window)} queries is "
            f"{mean_sim:.2f}; closest match overlap {max_sim:.2f} "
            f"(token count differs by {closest_token_diff})."
        )

        return SignalResult(
            self.name, score, self.weight, evidence,
            details={"max_similarity": round(max_sim, 3),
                     "mean_similarity": round(mean_sim, 3),
                     "window_size": len(window)},
        )
