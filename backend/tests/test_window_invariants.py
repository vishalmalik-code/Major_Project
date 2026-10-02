"""The window must be QUERY-BASED. These tests are the guardrail on the
project's core invariant.
"""

from app.firewall.window import QueryWindow, WindowEntry


def _entry(seq: int, created_at: float = 0.0) -> WindowEntry:
    return WindowEntry(seq=seq, text=f"q{seq}", normalized=f"q{seq}",
                       created_at_epoch=created_at)


def test_evicts_only_on_push():
    """push 21 queries -> window holds Q2..Q21, never Q1."""
    w = QueryWindow(size=20, tight_size=10)
    for i in range(1, 22):
        w.push("c1", _entry(i))
    window = w.get("c1")
    assert len(window) == 20
    assert [e.seq for e in window] == list(range(2, 22))
    assert 1 not in [e.seq for e in window]


def test_window_is_time_invariant():
    """push 5 queries, 'advance a clock' by an hour (i.e. do nothing), inspect
    the window: it must be byte-for-byte identical. No TTL, no expiry."""
    w = QueryWindow(size=20, tight_size=10)
    for i in range(1, 6):
        w.push("c1", _entry(i, created_at=1000.0 + i))
    before = list(w.get("c1"))

    # Simulate a huge time gap by doing nothing at all -- no query arrives.
    # There is no clock/tick method on QueryWindow because none should exist.
    after = list(w.get("c1"))

    assert before == after
    assert [e.seq for e in after] == [1, 2, 3, 4, 5]


def test_rebuild_orders_by_seq_not_timestamp():
    """Rows whose created_at ordering CONTRADICTS their seq ordering; the
    rebuilt window must follow seq."""
    w = QueryWindow(size=20, tight_size=10)
    # seq 1,2,3 but created_at deliberately reversed (3 is "oldest" in time)
    entries = [
        _entry(1, created_at=300.0),
        _entry(2, created_at=200.0),
        _entry(3, created_at=100.0),
    ]
    w.rebuild_from_db("c1", entries)
    assert [e.seq for e in w.get("c1")] == [1, 2, 3]


def test_tight_window_is_a_suffix():
    """get_tight() returns exactly the last TIGHT_WINDOW_SIZE of get()."""
    w = QueryWindow(size=20, tight_size=10)
    for i in range(1, 16):
        w.push("c1", _entry(i))
    full = w.get("c1")
    tight = w.get_tight("c1")
    assert len(tight) == 10
    assert tight == full[-10:]
    assert [e.seq for e in tight] == list(range(6, 16))


def test_window_isolated_per_client():
    w = QueryWindow(size=20, tight_size=10)
    w.push("a", _entry(1))
    w.push("b", _entry(1))
    w.push("b", _entry(2))
    assert len(w.get("a")) == 1
    assert len(w.get("b")) == 2


def test_reset_clears_only_named_client():
    w = QueryWindow(size=20, tight_size=10)
    w.push("a", _entry(1))
    w.push("b", _entry(1))
    w.reset("a")
    assert w.get("a") == []
    assert len(w.get("b")) == 1
