"""Detection coverage: all five patterns, both modes, using the real strategy
generators and the real signal pipeline (no DB / HTTP -- this simulates the
firewall's decision loop directly against in-memory structures).

THIS IS THE PROJECT'S CENTRAL CLAIM under test: text structure catches what
rate limiting cannot. `test_slow_mode_still_blocks_without_burst_signal`
proves it directly by zeroing burst_rate's contribution and confirming every
strategy still reaches BLOCK.
"""

import pytest

from app.attacker.registry import STRATEGIES
from app.core.constants import RiskBand
from app.firewall.actions import band_for
from app.firewall.normalize import extract_constraint_tokens, extract_numbers, normalize
from app.firewall.risk import combine, update
from app.firewall.signals import default_signals
from app.firewall.signals.base import QueryContext
from app.firewall.window import WindowEntry

MAX_QUERIES = 40


def _drive(encoder, strategy_id: str, queries: list[str], interval: float):
    """Run `queries` through the real signal pipeline sequentially, spaced
    `interval` seconds apart. Returns (final_band, queries_to_block, bands)."""
    signals = default_signals()
    window: list[WindowEntry] = []
    risk = 0.0
    t = 0.0
    queries_to_block = None
    bands = []

    for i, text in enumerate(queries):
        embedding = encoder.encode(text)
        ctx = QueryContext(
            client_id="attacker", seq=i + 1, text=text, normalized=normalize(text),
            embedding=embedding, numbers=extract_numbers(text),
            constraint_tokens=extract_constraint_tokens(text),
            arrived_at_epoch=t, window=window, tight_window=window[-10:],
        )
        results = [sig.evaluate(ctx) for sig in signals]
        weighted = combine(results)
        u = update(risk_before=risk, weighted=weighted, results=results)
        risk = u.risk_after
        band = band_for(risk)
        bands.append(band)

        if band == RiskBand.CRITICAL and queries_to_block is None:
            queries_to_block = i + 1

        window.append(WindowEntry(
            seq=i + 1, text=text, normalized=normalize(text), embedding=embedding,
            numbers=extract_numbers(text), constraint_tokens=extract_constraint_tokens(text),
            created_at_epoch=t,
        ))
        t += interval

    return bands[-1], queries_to_block, bands


@pytest.mark.parametrize("strategy_id", list(STRATEGIES.keys()))
@pytest.mark.parametrize("interval", [0.02, 60.0], ids=["FAST", "SLOW"])
def test_each_strategy_eventually_blocks(encoder, strategy_id, interval):
    strategy = STRATEGIES[strategy_id]
    queries = strategy.generate(MAX_QUERIES, seed=7)
    final_band, qtb, _ = _drive(encoder, strategy_id, queries, interval)
    assert qtb is not None, (
        f"{strategy_id} ({'FAST' if interval < 1 else 'SLOW'}) never reached "
        f"CRITICAL within {MAX_QUERIES} queries (final band {final_band})"
    )


@pytest.mark.parametrize("strategy_id", list(STRATEGIES.keys()))
def test_slow_mode_still_blocks_without_burst_signal(encoder, strategy_id, monkeypatch):
    """Zero burst_rate's weight entirely and confirm SLOW-paced attacks still
    reach BLOCK. If this fails, the firewall is secretly relying on rate
    limiting, which is exactly what the project must not do."""
    from app.core.config import settings
    monkeypatch.setattr(settings, "weight_burst_rate", 0.0)

    strategy = STRATEGIES[strategy_id]
    queries = strategy.generate(MAX_QUERIES, seed=7)
    final_band, qtb, _ = _drive(encoder, strategy_id, queries, interval=90.0)
    assert qtb is not None, (
        f"{strategy_id} did not block under SLOW pacing even with burst_rate "
        f"disabled -- detection is relying on rate, not text structure."
    )


def test_expected_signal_fires_strongly(encoder):
    """Each strategy's declared `targets` should include at least one signal
    that scores strongly (> 0.5) by the end of a run.

    Not "is it the single most-weighted signal": several attacks legitimately
    trip more than one structural signal at once (a boundary walk IS also a
    minimal modification, one token changing per query), and requiring strict
    numeric dominance would make the test fragile to weight tuning rather than
    a check that detection actually fired for the right reason.
    """
    signals = default_signals()
    for strategy_id, strategy in STRATEGIES.items():
        queries = strategy.generate(10, seed=7)
        window: list[WindowEntry] = []
        t = 0.0
        final_scores: dict[str, float] = {}
        for i, text in enumerate(queries):
            embedding = encoder.encode(text)
            ctx = QueryContext(
                client_id="attacker", seq=i + 1, text=text, normalized=normalize(text),
                embedding=embedding, numbers=extract_numbers(text),
                constraint_tokens=extract_constraint_tokens(text),
                arrived_at_epoch=t, window=window, tight_window=window[-10:],
            )
            results = [sig.evaluate(ctx) for sig in signals]
            final_scores = {r.name: r.score for r in results if r.applicable}
            window.append(WindowEntry(
                seq=i + 1, text=text, normalized=normalize(text), embedding=embedding,
                numbers=extract_numbers(text), constraint_tokens=extract_constraint_tokens(text),
                created_at_epoch=t,
            ))
            t += 30.0

        hit = any(final_scores.get(target, 0.0) > 0.5 for target in strategy.targets)
        assert hit, (
            f"{strategy_id}: none of its target signals {strategy.targets} "
            f"scored above 0.5; final scores were {final_scores}"
        )
