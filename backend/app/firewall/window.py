"""Per-client rolling query window.

THE DEFINING PROPERTY: this window is QUERY-BASED, never time-based.

    Q1..Q20 arrive  -> window = [Q1 .. Q20]
    Q21 arrives     -> evict Q1, window = [Q2 .. Q21]

Eviction is triggered ONLY by the arrival of a new query. If a client waits one
second, ten minutes, one hour, or three days, the window is byte-for-byte
identical when they return. There is no TTL, no expiry task, no sliding time
frame. This is what makes SLOW attacks detectable: an attacker cannot outwait
the window, only out-vary it -- and varying the query defeats the extraction.

If you are about to write `datetime`, `time.time()`, `now()`, or `timedelta`
in this module for anything other than recording `created_at` for the
burst_rate signal and the dashboard, stop: it is a bug.
"""

from collections import deque
from dataclasses import dataclass, field

import numpy as np

from app.core.config import settings


@dataclass
class WindowEntry:
    """One remembered query. `seq` is the ordering axis -- not `created_at`."""

    seq: int
    text: str
    normalized: str                       # lowercased, collapsed, depunctuated
    embedding: np.ndarray | None = None   # 384-dim, all-MiniLM-L6-v2
    numbers: list[float] = field(default_factory=list)
    constraint_tokens: list[str] = field(default_factory=list)
    created_at_epoch: float = 0.0         # burst signal + dashboard ONLY


class QueryWindow:
    """In-memory hot path (`deque(maxlen=N)`), Postgres as the cold store.

    On cache miss or process restart the window is rebuilt with
    `ORDER BY seq DESC LIMIT N` -- rebuilding by `seq`, never by timestamp,
    preserves query-based semantics across restarts.
    """

    def __init__(self, size: int | None = None, tight_size: int | None = None) -> None:
        self.size = size or settings.query_window_size
        self.tight_size = tight_size or settings.tight_window_size
        self._windows: dict[str, deque[WindowEntry]] = {}

    def get(self, client_id: str) -> list[WindowEntry]:
        """Full analysis window (oldest -> newest), up to `size` entries."""
        return list(self._windows.get(client_id, ()))

    def get_tight(self, client_id: str) -> list[WindowEntry]:
        """Recency slice (last `tight_size`) for repetition and burst signals."""
        full = self.get(client_id)
        return full[-self.tight_size:]

    def push(self, client_id: str, entry: WindowEntry) -> None:
        """Append; evict the oldest iff length would exceed `size`.

        This is the ONLY method that removes anything from a window. Eviction
        happens purely because `deque(maxlen=...)` drops the oldest item when a
        new one is appended past capacity -- never because of elapsed time.
        """
        dq = self._windows.get(client_id)
        if dq is None:
            dq = deque(maxlen=self.size)
            self._windows[client_id] = dq
        dq.append(entry)

    def rebuild_from_db(self, client_id: str, entries: list[WindowEntry]) -> None:
        """Warm the cache from `ORDER BY seq DESC LIMIT size` (reversed).

        `entries` must already be oldest -> newest and must be ordered by
        `seq`, never by `created_at`.
        """
        dq: deque[WindowEntry] = deque(maxlen=self.size)
        dq.extend(entries[-self.size:])
        self._windows[client_id] = dq

    def reset(self, client_id: str) -> None:
        """Admin/demo convenience only -- never called by the request path."""
        self._windows.pop(client_id, None)
