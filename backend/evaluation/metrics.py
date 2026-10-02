"""Per-session metrics computed from the raw query log a session produced.

Definitions (fixed here, once, so every report table uses the same rule):

  - "detected" (attacker sessions): the session reached MONITOR, THROTTLE, or
    BLOCK at least once. This is the configured definition the prompt asks
    for -- MONITOR counts as detection even though it doesn't disrupt the
    user, because it means the firewall noticed something.
  - "false positive" (normal-user sessions): the session reached BLOCK at
    least once. THROTTLE-or-worse is reported as a softer secondary signal
    since it still degrades a legitimate user's experience, but BLOCK is the
    headline false-positive metric ("a legitimate user should not be
    unnecessarily blocked").
"""

from dataclasses import dataclass

ACTIONS = ("ALLOW", "MONITOR", "THROTTLE", "BLOCK")


@dataclass
class SessionMetrics:
    total_queries: int
    allowed: int
    monitored: int
    throttled: int
    blocked: int
    errors: int
    first_detection_query: int | None   # first MONITOR/THROTTLE/BLOCK
    first_throttle_query: int | None
    first_block_query: int | None
    peak_risk: float | None
    avg_risk: float | None
    detected: bool                      # MONITOR/THROTTLE/BLOCK reached at least once
    reached_throttle_or_worse: bool
    reached_block: bool                 # == false positive, for normal-user sessions

    def as_dict(self) -> dict:
        return self.__dict__.copy()


def compute_metrics(rows: list[dict]) -> SessionMetrics:
    """`rows` are the JSONL-logged entries for one session, in query order."""
    counts = {a: 0 for a in ACTIONS}
    errors = 0
    first_detection = first_throttle = first_block = None
    risks: list[float] = []

    for row in rows:
        decision = row.get("decision")
        if decision not in ACTIONS:
            errors += 1
            continue
        counts[decision] += 1

        if row.get("risk_score") is not None:
            risks.append(row["risk_score"])

        if decision in ("MONITOR", "THROTTLE", "BLOCK") and first_detection is None:
            first_detection = row["query_number"]
        if decision == "THROTTLE" and first_throttle is None:
            first_throttle = row["query_number"]
        if decision == "BLOCK" and first_block is None:
            first_block = row["query_number"]

    return SessionMetrics(
        total_queries=len(rows),
        allowed=counts["ALLOW"], monitored=counts["MONITOR"],
        throttled=counts["THROTTLE"], blocked=counts["BLOCK"], errors=errors,
        first_detection_query=first_detection, first_throttle_query=first_throttle,
        first_block_query=first_block,
        peak_risk=max(risks) if risks else None,
        avg_risk=(sum(risks) / len(risks)) if risks else None,
        detected=first_detection is not None,
        reached_throttle_or_worse=(counts["THROTTLE"] + counts["BLOCK"]) > 0,
        reached_block=counts["BLOCK"] > 0,
    )
