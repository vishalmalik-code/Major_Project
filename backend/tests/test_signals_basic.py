"""Focused tests for the five signal families the firewall analyzes
(prompt section 5, A-E), proven against the real signal implementations and
the real MiniLM encoder -- not fabricated SignalResults.

  A. exact repetition        -> items 8 ("a repeated query increases risk")
  B. text similarity          -> item 9 ("a highly similar query increases risk")
  C. semantic similarity       -> item 9
  D. fast/burst                -> item 10 ("a fast burst contributes to risk")
  E. pattern continuation      -> value/constraint/boundary progression signals
"""

from app.firewall.normalize import extract_constraint_tokens, extract_numbers, normalize
from app.firewall.signals.base import QueryContext
from app.firewall.signals.burst_rate import BurstRateSignal
from app.firewall.signals.exact_repetition import ExactRepetitionSignal
from app.firewall.signals.semantic_similarity import SemanticSimilaritySignal
from app.firewall.signals.text_similarity import TextSimilaritySignal
from app.firewall.signals.value_progression import ValueProgressionSignal
from app.firewall.window import WindowEntry


def _ctx(encoder, text_, window, arrived_at=0.0):
    return QueryContext(
        client_id="c", seq=len(window) + 1, text=text_, normalized=normalize(text_),
        embedding=encoder.encode(text_), numbers=extract_numbers(text_),
        constraint_tokens=extract_constraint_tokens(text_),
        arrived_at_epoch=arrived_at, window=window, tight_window=window[-10:],
    )


def _entry(encoder, seq, text_, t=0.0):
    return WindowEntry(
        seq=seq, text=text_, normalized=normalize(text_), embedding=encoder.encode(text_),
        numbers=extract_numbers(text_), constraint_tokens=extract_constraint_tokens(text_),
        created_at_epoch=t,
    )


# --- A. exact repetition -----------------------------------------------------

def test_repeated_query_scores_high_on_exact_repetition(encoder):
    """Item 8: a repeated query increases risk -- via a real 1.0-ish score on
    the signal built for exactly this."""
    window = [_entry(encoder, i, "What is a buffer overflow?") for i in range(1, 6)]
    ctx = _ctx(encoder, "What is a buffer overflow?", window)
    result = ExactRepetitionSignal().evaluate(ctx)
    assert result.score > 0.9
    assert "identical" in result.evidence


def test_novel_query_scores_zero_on_exact_repetition(encoder):
    window = [_entry(encoder, i, "What is a buffer overflow?") for i in range(1, 6)]
    ctx = _ctx(encoder, "How does DNS resolution work?", window)
    result = ExactRepetitionSignal().evaluate(ctx)
    assert result.score == 0.0


# --- B/C. text and semantic similarity ---------------------------------------

def test_highly_similar_paraphrase_scores_high_on_similarity_signals(encoder):
    """Item 9: a highly similar (paraphrased, not identical) query increases
    risk via text_similarity and/or semantic_similarity."""
    window = [_entry(encoder, i, q) for i, q in enumerate([
        "What is cross-site scripting and how does it work?",
        "How does cross site scripting XSS actually work?",
        "Explain how XSS attacks work in practice.",
    ], start=1)]
    ctx = _ctx(encoder, "Can you explain how cross-site scripting works?", window)

    text_result = TextSimilaritySignal().evaluate(ctx)
    semantic_result = SemanticSimilaritySignal().evaluate(ctx)
    assert semantic_result.score > 0.6, semantic_result.evidence
    assert text_result.score > 0.15, text_result.evidence


def test_unrelated_query_scores_low_on_similarity_signals(encoder):
    window = [_entry(encoder, i, q) for i, q in enumerate([
        "What is cross-site scripting?",
        "How does XSS work?",
        "Explain reflected vs stored XSS.",
    ], start=1)]
    ctx = _ctx(encoder, "What's a good recipe for banana bread?", window)

    text_result = TextSimilaritySignal().evaluate(ctx)
    semantic_result = SemanticSimilaritySignal().evaluate(ctx)
    assert text_result.score < 0.2
    assert semantic_result.score < 0.35


# --- D. fast/burst -------------------------------------------------------------

def test_fast_burst_scores_higher_than_slow_pacing(encoder):
    """Item 10: a fast burst contributes to risk. Same query content and
    count in both cases -- only the timestamp spacing differs -- so any
    score difference is attributable to burst_rate alone."""
    texts = [f"What is CVE-2024-{1000 + i}?" for i in range(6)]

    fast_window = [_entry(encoder, i + 1, t, tt) for i, (t, tt) in
                   enumerate(zip(texts, [0.0, 0.05, 0.10, 0.15, 0.20]))]
    fast_ctx = _ctx(encoder, texts[5], fast_window, arrived_at=0.25)
    fast_score = BurstRateSignal().evaluate(fast_ctx).score

    slow_window = [_entry(encoder, i + 1, t, tt) for i, (t, tt) in
                   enumerate(zip(texts, [0.0, 30.0, 60.0, 90.0, 120.0]))]
    slow_ctx = _ctx(encoder, texts[5], slow_window, arrived_at=150.0)
    slow_score = BurstRateSignal().evaluate(slow_ctx).score

    assert fast_score > slow_score
    assert fast_score > 0.5
    assert slow_score < 0.2


def test_burst_signal_is_inapplicable_with_too_few_timestamps(encoder):
    window = [_entry(encoder, 1, "hello", 0.0)]
    ctx = _ctx(encoder, "world", window, arrived_at=0.01)
    result = BurstRateSignal().evaluate(ctx)
    assert result.applicable is False


# --- E. pattern continuation ---------------------------------------------------

def test_value_progression_continues_a_numeric_pattern(encoder):
    """Example from the prompt: value progression 1 -> 2 -> 3 -> 4."""
    texts = [f"Is TCP port {i} reserved?" for i in range(1, 5)]
    window = [_entry(encoder, i + 1, t) for i, t in enumerate(texts)]
    ctx = _ctx(encoder, "Is TCP port 5 reserved?", window)
    result = ValueProgressionSignal().evaluate(ctx)
    assert result.score > 0.7, result.evidence
    assert "swept" in result.evidence


def test_numeric_parameter_progression_continues_the_pattern(encoder):
    """Example from the prompt: parameter progression 10 words -> 20 words ->
    30 words. Structurally this IS a numeric sweep inside a fixed template --
    the same shape as "1 -> 2 -> 3 -> 4" -- so value_progression is the signal
    that fires, not constraint_progression (which is for cycling between
    qualitatively DIFFERENT constraint types, e.g. JSON -> table -> bullets,
    not the same constraint type with an increasing number)."""
    texts = [
        "Summarize buffer overflow attacks in 10 words.",
        "Summarize buffer overflow attacks in 20 words.",
        "Summarize buffer overflow attacks in 30 words.",
    ]
    window = [_entry(encoder, i + 1, t) for i, t in enumerate(texts)]
    ctx = _ctx(encoder, "Summarize buffer overflow attacks in 40 words.", window)
    result = ValueProgressionSignal().evaluate(ctx)
    assert result.score > 0.7, result.evidence
    assert "swept" in result.evidence


def test_constraint_progression_continues_a_format_rotation_pattern(encoder):
    """Rotating between genuinely distinct output-constraint TYPES (not just a
    number inside the same type) while the underlying task stays fixed."""
    from app.firewall.signals.constraint_progression import ConstraintProgressionSignal

    texts = [
        "Explain buffer overflow attacks as JSON.",
        "Explain buffer overflow attacks as a table.",
        "Explain buffer overflow attacks step by step.",
    ]
    window = [_entry(encoder, i + 1, t) for i, t in enumerate(texts)]
    ctx = _ctx(encoder, "Explain buffer overflow attacks like I'm five.", window)
    result = ConstraintProgressionSignal().evaluate(ctx)
    assert result.score > 0.5, result.evidence


# --- regression: signal scores must stay within [0, 1] ------------------------

def test_semantic_similarity_score_never_exceeds_one_on_self_identical_query(encoder):
    """Regression: cosine similarity of a float32 embedding against itself
    (or a near-duplicate) can land a hair above 1.0 due to rounding, which
    used to reach the DB unclamped and violate signal_scores' CHECK
    (score BETWEEN 0.0 AND 1.0) -- a real 500 seen when a client resent an
    already-asked question. The signal must clamp before returning."""
    text_ = "What is authorization vs authentication?"
    window = [_entry(encoder, 1, text_)]
    ctx = _ctx(encoder, text_, window)  # identical text -> the exact trigger
    result = SemanticSimilaritySignal().evaluate(ctx)
    assert 0.0 <= result.score <= 1.0
