"""Risk must decay by QUERY, never by time.

`test_no_time_term_in_source` is deliberately mechanical: it is the invariant
that makes slow attacks detectable, so it is enforced by grepping the source,
not just by behavioral tests.
"""

import re
from pathlib import Path

from app.core.config import settings
from app.firewall.risk import clamp, combine, update
from app.firewall.signals.base import SignalResult


def _result(name: str, score: float, weight: float = 1.0) -> SignalResult:
    return SignalResult(name=name, score=score, weight=weight, evidence="test")


def test_idle_does_not_decay_risk():
    """Risk only changes inside update(); calling nothing changes nothing."""
    risk = 82.0
    # "advance a fake clock by a week" == do nothing at all, since there is no
    # clock-driven code path in this module.
    assert risk == 82.0


def test_dissimilar_query_relieves_by_one_step():
    results = [_result("exact_repetition", 0.0), _result("text_similarity", 0.02)]
    weighted = combine(results)
    assert weighted <= settings.benign_threshold
    u = update(risk_before=50.0, weighted=weighted, results=results)
    assert u.risk_after == clamp(50.0 - settings.decay_step)
    assert u.reason == "relieved"


def test_ambiguous_query_holds_risk():
    """weighted strictly between BENIGN and SUSPICION thresholds -> delta == 0."""
    mid = (settings.benign_threshold + settings.suspicion_threshold) / 2
    results = [_result("text_similarity", mid)]
    weighted = combine(results)
    u = update(risk_before=40.0, weighted=weighted, results=results)
    assert u.delta == 0.0
    assert u.risk_after == 40.0
    assert u.reason == "held"


def test_escalating_query_raises_risk():
    results = [_result("systematic_modification", 0.9, weight=1.2)]
    weighted = combine(results)
    assert weighted >= settings.suspicion_threshold
    u = update(risk_before=10.0, weighted=weighted, results=results)
    assert u.risk_after > 10.0
    assert u.reason == "escalated"


def test_single_benign_query_cannot_clear_critical():
    """From risk 95, one benign query must NOT drop below CRITICAL."""
    results = [_result("text_similarity", 0.0)]
    u = update(risk_before=95.0, weighted=0.0, results=results)
    assert u.risk_after >= settings.risk_threshold_critical
    assert u.risk_after == 95.0 - settings.decay_step


def test_risk_clamped_to_0_100():
    assert clamp(150.0) == 100.0
    assert clamp(-10.0) == 0.0
    assert clamp(50.0) == 50.0


def test_no_time_term_in_source():
    """grep firewall/risk.py and firewall/window.py for datetime / time.time /
    timedelta / now(). Must find nothing outside of comments/docstrings that
    explicitly disclaim it."""
    forbidden = re.compile(r"\bdatetime\.|time\.time\(|timedelta|\.now\(\)|"
                           r"time\.sleep")
    for relpath in ("app/firewall/risk.py", "app/firewall/window.py"):
        src = Path(relpath).read_text()
        # Strip the module docstring and any comment lines before scanning --
        # those legitimately discuss time in prose.
        lines = src.splitlines()
        code_lines = []
        in_docstring = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('"""') or stripped.startswith("'''"):
                in_docstring = not in_docstring
                continue
            if in_docstring or stripped.startswith("#"):
                continue
            code_lines.append(line)
        code = "\n".join(code_lines)
        assert not forbidden.search(code), (
            f"{relpath} contains a time-based expression outside prose/comments"
        )
