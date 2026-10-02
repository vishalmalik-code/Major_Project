"""Builds the markdown comparison tables and narrative comparisons from a
completed evaluation battery's results.

Table shapes match the prompt exactly:

    | Type | Strategy | Mode | Queries | Detection | Throttle | Block | Avg Risk | Peak Risk |
    | Persona | Mode | Queries | Monitor | Throttle | Block | Avg Risk | Peak Risk |
"""

STRATEGY_NAMES = {
    "exact_repetition": "Exact Repetition",
    "minimal_modification": "Minimal Modification",
    "value_sweep": "Value Sweep",
    "constraint_probing": "Output-Constraint Probing",
    "boundary_probing": "Boundary Probing",
}
PERSONA_NAMES = {
    "casual_user": "Casual User",
    "student": "Student",
    "developer": "Developer",
    "researcher": "Researcher",
    "incident_responder": "Incident Responder",
}


def _fmt(v, digits=1):
    return f"{v:.{digits}f}" if isinstance(v, (int, float)) and v is not None else "n/a"


def attacker_table(results: list[dict]) -> str:
    rows = [r for r in results if r["session_type"] == "attacker"]
    rows.sort(key=lambda r: (r["label"], r["mode"]))
    lines = [
        "| Strategy | Mode | Queries | Detection | Throttle | Block | Avg Risk | Peak Risk |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        m = r["metrics"]
        detection = f"Yes (@{m['first_detection_query']})" if m["detected"] else "No"
        throttle = f"Yes (@{m['first_throttle_query']})" if m["throttled"] else "No"
        block = f"Yes (@{m['first_block_query']})" if m["blocked"] else "No"
        lines.append(
            f"| {STRATEGY_NAMES.get(r['label'], r['label'])} | {r['mode'].upper()} "
            f"| {r['query_count']} | {detection} | {throttle} | {block} "
            f"| {_fmt(m['avg_risk'])} | {_fmt(m['peak_risk'])} |"
        )
    return "\n".join(lines)


def normal_user_table(results: list[dict]) -> str:
    rows = [r for r in results if r["session_type"] == "normal_user"]
    rows.sort(key=lambda r: (r["label"], r["mode"]))
    lines = [
        "| Persona | Mode | Queries | Monitor | Throttle | Block | Avg Risk | Peak Risk |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        m = r["metrics"]
        lines.append(
            f"| {PERSONA_NAMES.get(r['label'], r['label'])} | {r['mode'].upper()} "
            f"| {r['query_count']} | {m['monitored']} | {m['throttled']} | {m['blocked']} "
            f"| {_fmt(m['avg_risk'])} | {_fmt(m['peak_risk'])} |"
        )
    return "\n".join(lines)


def attacker_aggregate_stats(results: list[dict]) -> dict:
    rows = [r for r in results if r["session_type"] == "attacker"]
    n = len(rows)
    if n == 0:
        return {}
    detected = [r for r in rows if r["metrics"]["detected"]]
    blocked = [r for r in rows if r["metrics"]["blocked"] > 0]
    throttled = [r for r in rows if r["metrics"]["throttled"] > 0]
    detect_queries = [r["metrics"]["first_detection_query"] for r in detected
                      if r["metrics"]["first_detection_query"] is not None]

    by_strategy: dict[str, dict] = {}
    for label in STRATEGY_NAMES:
        sub = [r for r in rows if r["label"] == label]
        sub_detected = [r for r in sub if r["metrics"]["detected"]]
        by_strategy[label] = {
            "sessions": len(sub),
            "detection_rate": 100.0 * len(sub_detected) / len(sub) if sub else None,
            "block_rate": 100.0 * sum(1 for r in sub if r["metrics"]["blocked"] > 0) / len(sub) if sub else None,
        }

    return {
        "sessions": n,
        "detection_rate_pct": 100.0 * len(detected) / n,
        "block_rate_pct": 100.0 * len(blocked) / n,
        "throttle_rate_pct": 100.0 * len(throttled) / n,
        "avg_queries_before_detection": (sum(detect_queries) / len(detect_queries)
                                         if detect_queries else None),
        "by_strategy": by_strategy,
    }


def normal_user_aggregate_stats(results: list[dict]) -> dict:
    rows = [r for r in results if r["session_type"] == "normal_user"]
    n = len(rows)
    if n == 0:
        return {}
    false_positive_blocked = [r for r in rows if r["metrics"]["blocked"] > 0]
    throttled_or_worse = [r for r in rows if r["metrics"]["reached_throttle_or_worse"]]

    by_persona: dict[str, dict] = {}
    for label in PERSONA_NAMES:
        sub = [r for r in rows if r["label"] == label]
        if not sub:
            continue
        total_q = sum(r["query_count"] for r in sub)
        pct_monitored = 100.0 * sum(r["metrics"]["monitored"] for r in sub) / total_q
        pct_throttled = 100.0 * sum(r["metrics"]["throttled"] for r in sub) / total_q
        pct_blocked = 100.0 * sum(r["metrics"]["blocked"] for r in sub) / total_q
        avg_risk_vals = [r["metrics"]["avg_risk"] for r in sub if r["metrics"]["avg_risk"] is not None]
        peak_risk_vals = [r["metrics"]["peak_risk"] for r in sub if r["metrics"]["peak_risk"] is not None]
        by_persona[label] = {
            "pct_monitored": pct_monitored, "pct_throttled": pct_throttled,
            "pct_blocked": pct_blocked,
            "avg_risk": sum(avg_risk_vals) / len(avg_risk_vals) if avg_risk_vals else None,
            "peak_risk": max(peak_risk_vals) if peak_risk_vals else None,
            "false_positive_blocked": any(r["metrics"]["blocked"] > 0 for r in sub),
        }

    return {
        "sessions": n,
        "false_positive_rate_pct": 100.0 * len(false_positive_blocked) / n,
        "throttle_or_worse_rate_pct": 100.0 * len(throttled_or_worse) / n,
        "by_persona": by_persona,
    }


def _mode_avg(results: list[dict], session_type: str, mode: str, field_: str) -> float | None:
    vals = [r["metrics"][field_] for r in results
           if r["session_type"] == session_type and r["mode"] == mode
           and r["metrics"][field_] is not None]
    return sum(vals) / len(vals) if vals else None


def build_report(results: list[dict], meta: dict) -> str:
    a_stats = attacker_aggregate_stats(results)
    u_stats = normal_user_aggregate_stats(results)

    out = []
    out.append("# Firewall Evaluation Report\n")
    out.append(f"Run: `{meta['run_id']}` · seed: `{meta['base_seed']}` · "
               f"target: `{meta['target']}` · generated: {meta['finished_at']}\n")

    if a_stats:
        out.append("## Attack sessions\n")
        out.append(attacker_table(results))
        out.append("")
        out.append(
            f"**Overall detection rate:** {a_stats['detection_rate_pct']:.0f}% "
            f"({sum(1 for r in results if r['session_type']=='attacker' and r['metrics']['detected'])}/"
            f"{a_stats['sessions']} sessions reached MONITOR, THROTTLE, or BLOCK)\n\n"
            f"**Block rate:** {a_stats['block_rate_pct']:.0f}% · "
            f"**Throttle rate:** {a_stats['throttle_rate_pct']:.0f}% · "
            f"**Avg queries before detection:** {_fmt(a_stats['avg_queries_before_detection'])}\n"
        )

        out.append("### Detection rate by strategy\n")
        out.append("| Strategy | Sessions | Detection rate | Block rate |")
        out.append("|---|---|---|---|")
        for label, s in a_stats["by_strategy"].items():
            if s["sessions"] == 0:
                continue
            out.append(f"| {STRATEGY_NAMES[label]} | {s['sessions']} "
                       f"| {_fmt(s['detection_rate'], 0)}% | {_fmt(s['block_rate'], 0)}% |")
        out.append("")

    if u_stats:
        out.append("## Normal-user sessions\n")
        out.append(normal_user_table(results))
        out.append("")
        out.append(
            f"**False positive rate (BLOCKed at least once):** "
            f"{u_stats['false_positive_rate_pct']:.0f}% "
            f"({sum(1 for r in results if r['session_type']=='normal_user' and r['metrics']['blocked']>0)}/"
            f"{u_stats['sessions']} sessions)\n\n"
            f"**Throttled-or-worse rate:** {u_stats['throttle_or_worse_rate_pct']:.0f}%\n"
        )

    if u_stats:
        out.append("### False positives by persona\n")
        out.append("| Persona | % Monitored | % Throttled | % Blocked | Avg Risk | Peak Risk | Blocked at least once |")
        out.append("|---|---|---|---|---|---|---|")
        for label, s in u_stats["by_persona"].items():
            out.append(
                f"| {PERSONA_NAMES[label]} | {_fmt(s['pct_monitored'],0)}% "
                f"| {_fmt(s['pct_throttled'],0)}% | {_fmt(s['pct_blocked'],0)}% "
                f"| {_fmt(s['avg_risk'])} | {_fmt(s['peak_risk'])} "
                f"| {'**YES**' if s['false_positive_blocked'] else 'no'} |"
            )
        out.append("")

    out.append("## Most important comparisons\n")

    fast_atk_risk = _mode_avg(results, "attacker", "fast", "avg_risk")
    fast_usr_risk = _mode_avg(results, "normal_user", "fast", "avg_risk")
    slow_atk_risk = _mode_avg(results, "attacker", "slow", "avg_risk")
    slow_usr_risk = _mode_avg(results, "normal_user", "slow", "avg_risk")

    out.append(f"**1. FAST attacker vs FAST legitimate user** -- "
              f"avg risk {_fmt(fast_atk_risk)} vs {_fmt(fast_usr_risk)}\n")
    out.append(f"**2. SLOW attacker vs SLOW legitimate user** -- "
              f"avg risk {_fmt(slow_atk_risk)} vs {_fmt(slow_usr_risk)}\n")

    out.append("**3. Each of the five attack patterns** -- see 'Detection rate by strategy' above.\n")

    def pair(label_a, label_b, name_a, name_b):
        a = [r for r in results if r["session_type"] == "attacker" and r["label"] == label_a]
        b = [r for r in results if r["session_type"] == "attacker" and r["label"] == label_b]
        a_risk = sum(r["metrics"]["avg_risk"] or 0 for r in a) / len(a) if a else None
        b_risk = sum(r["metrics"]["avg_risk"] or 0 for r in b) / len(b) if b else None
        return f"{name_a} avg risk {_fmt(a_risk)} vs {name_b} avg risk {_fmt(b_risk)}"

    out.append(f"**4. Exact repetition vs minimal modification** -- "
              f"{pair('exact_repetition', 'minimal_modification', 'exact repetition', 'minimal modification')}\n")

    value_sweep = [r for r in results if r["session_type"] == "attacker" and r["label"] == "value_sweep"]
    normal_technical = [r for r in results if r["session_type"] == "normal_user"
                        and r["label"] in ("student", "researcher")]
    vs_risk = sum(r["metrics"]["avg_risk"] or 0 for r in value_sweep) / len(value_sweep) if value_sweep else None
    nt_risk = (sum(r["metrics"]["avg_risk"] or 0 for r in normal_technical) / len(normal_technical)
              if normal_technical else None)
    out.append(f"**5. Systematic value sweep vs normal technical questions** -- "
              f"value sweep avg risk {_fmt(vs_risk)} vs student/researcher avg risk {_fmt(nt_risk)}\n")

    boundary = [r for r in results if r["session_type"] == "attacker" and r["label"] == "boundary_probing"]
    researcher = [r for r in results if r["session_type"] == "normal_user" and r["label"] == "researcher"]
    b_risk = sum(r["metrics"]["avg_risk"] or 0 for r in boundary) / len(boundary) if boundary else None
    r_risk = sum(r["metrics"]["avg_risk"] or 0 for r in researcher) / len(researcher) if researcher else None
    out.append(f"**6. Boundary probing vs legitimate technical exploration (researcher)** -- "
              f"boundary probing avg risk {_fmt(b_risk)} vs researcher avg risk {_fmt(r_risk)}\n")

    return "\n".join(out)
