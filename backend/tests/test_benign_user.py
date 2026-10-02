"""False-positive regression: a legitimate user asking several RELATED
cybersecurity questions must never leave ALLOW.

This is the test that keeps the firewall honest: high semantic similarity
alone must not convict, or the system is useless to real users.
"""

from app.firewall.actions import action_for, band_for
from app.firewall.risk import combine, update
from app.core.constants import Action, RiskBand
from tests.conftest import BENIGN_TRANSCRIPT


def test_benign_transcript_stays_in_low_and_allow(make_entry, make_context, signals):
    window = []
    risk = 0.0
    t = 0.0
    for i, text in enumerate(BENIGN_TRANSCRIPT):
        ctx = make_context(text, window, seq=i + 1, arrived_at=t)
        results = [sig.evaluate(ctx) for sig in signals]
        weighted = combine(results)
        u = update(risk_before=risk, weighted=weighted, results=results)
        risk = u.risk_after

        assert band_for(risk) == RiskBand.LOW, (
            f"query {i+1} '{text}' pushed risk to {risk} ({band_for(risk)})"
        )
        assert action_for(risk) == Action.ALLOW

        window.append(make_entry(i + 1, text, t=t))
        t += 20.0  # spaced out like a real user, not a burst

    assert risk == 0.0, f"final risk should be floored at 0, got {risk}"


def test_structural_signals_stay_low_on_benign_transcript(make_entry, make_context, signals):
    """The STRUCTURAL signals (4-7) must not fire on topic-related-but-varied
    human questions -- that is the discriminator between a curious human and
    someone enumerating a dataset."""
    structural_names = {
        "systematic_modification", "value_progression",
        "constraint_progression", "boundary_progression",
    }
    window = []
    t = 0.0
    for i, text in enumerate(BENIGN_TRANSCRIPT):
        ctx = make_context(text, window, seq=i + 1, arrived_at=t)
        for sig in signals:
            if sig.name in structural_names:
                r = sig.evaluate(ctx)
                assert r.score < 0.3, f"{sig.name} scored {r.score} on '{text}'"
        window.append(make_entry(i + 1, text, t=t))
        t += 20.0
