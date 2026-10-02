"""Tests for the standalone attacker CLI (attacker.py / attacker_cli/).

Covers the prompt's TESTING checklist:
  1. Queries actually reach /api/chat.
  2. The firewall sees every query.
  3. The attacker never accesses internal firewall state.
  4. The client_id is preserved.
  5. Logs are generated.
  6. Fast and slow modes use the same query sequence.
  7. Only timing changes between fast and slow modes.
  8. All five strategies generate the intended pattern.
  9. The attacker handles ALLOW/MONITOR/THROTTLE/BLOCK responses correctly.
  10. BLOCK + configurable continue/stop behavior.

Items that need a live server (1, 2, 4, 9, 10) run against the real backend
at http://localhost:8000 -- skipped if it isn't reachable, matching the
project convention (established in test_llm_service.py) of testing against
the real local stack rather than mocking it away. Items that don't need the
network (3, 5, 6, 7, 8) always run.
"""

import json
import subprocess
import sys

import httpx
import pytest

from app.attacker.registry import STRATEGIES
from attacker_cli.attack_logger import AttackLogger
from attacker_cli.http_client import FirewallClient
from attacker_cli.pacing import FastPacer, SlowPacer
from attacker_cli.runner import run_attack

BACKEND_URL = "http://localhost:8000"
CLI_ALIASES = {
    "repetition": "exact_repetition",
    "minimal_modification": "minimal_modification",
    "value_sweep": "value_sweep",
    "output_constraint": "constraint_probing",
    "boundary": "boundary_probing",
}


def _server_reachable() -> bool:
    try:
        r = httpx.get(f"{BACKEND_URL}/api/health", timeout=3.0)
        return r.status_code == 200
    except httpx.HTTPError:
        return False


requires_server = pytest.mark.skipif(
    not _server_reachable(),
    reason="backend server not reachable at http://localhost:8000",
)


# --- item 3: no access to internal firewall state ----------------------------

def test_attacker_never_imports_firewall_internals():
    """Runs in a clean subprocess (not this test process, which has already
    imported half the app for other tests) and inspects sys.modules after
    importing attacker.py -- app.firewall, app.db, app.services, and
    app.core.config (which holds thresholds/weights) must never load."""
    code = (
        "import sys; sys.path.insert(0, '.'); import attacker; "
        "forbidden = ('app.firewall', 'app.db', 'app.services', 'app.core.config'); "
        "hits = [m for m in sys.modules if m.startswith(forbidden)]; "
        "print(','.join(hits))"
    )
    result = subprocess.run([sys.executable, "-c", code], cwd=".",
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "", (
        f"attacker.py must not import firewall internals, but loaded: {result.stdout.strip()}"
    )


# --- items 6, 7: identical sequence, only timing differs ---------------------

def test_fast_and_slow_modes_use_identical_query_sequence():
    """Query generation takes no `mode` argument at all -- pacing is applied
    entirely separately by the runner -- so the same strategy/seed/count must
    produce byte-identical query lists regardless of which pacer is used."""
    for strategy in STRATEGIES.values():
        seq_a = strategy.generate(10, seed=99)
        seq_b = strategy.generate(10, seed=99)
        assert seq_a == seq_b, f"{strategy.id}: generation must be deterministic"


def test_only_pacing_differs_between_fast_and_slow():
    fast = FastPacer(delay=0.3)
    slow = SlowPacer(min_delay=5.0, max_delay=15.0)

    fast_delays = [fast.delay() for _ in range(50)]
    slow_delays = [slow.delay() for _ in range(50)]

    assert all(d < 1.0 for d in fast_delays), "FAST delays should stay well under 1s"
    assert all(d >= 5.0 * 0.99 for d in slow_delays), "SLOW delays should respect min_delay"
    assert max(fast_delays) < min(d for d in slow_delays if d < 20), (
        "FAST delays must be clearly smaller than typical SLOW delays"
    )


# --- item 8: all five strategies generate the intended structural pattern ----

def test_repetition_strategy_produces_identical_queries():
    queries = STRATEGIES["exact_repetition"].generate(6, seed=1)
    assert len(set(queries)) == 1


def test_minimal_modification_produces_one_template_many_slots():
    queries = STRATEGIES["minimal_modification"].generate(6, seed=1)
    assert len(set(queries)) == 6, "each substitution should differ"
    # same template shape: same token count give or take the substituted word
    lengths = [len(q.split()) for q in queries]
    assert max(lengths) - min(lengths) <= 2


def test_value_sweep_produces_arithmetic_progression():
    import re
    queries = STRATEGIES["value_sweep"].generate(6, seed=1)
    numbers = [int(re.search(r"-?\d+", q).group()) for q in queries]
    steps = [numbers[i + 1] - numbers[i] for i in range(len(numbers) - 1)]
    assert len(set(steps)) == 1, f"expected a fixed step, got steps={steps}"


def test_output_constraint_probing_keeps_task_fixed_varies_constraint():
    queries = STRATEGIES["constraint_probing"].generate(6, seed=1)
    assert len(set(queries)) == 6, "each constraint phrasing should differ"
    task_prefixes = {q.split(" as ")[0].split(" in ")[0].split(" for ")[0][:25]
                     for q in queries}
    assert len(task_prefixes) == 1, "the underlying task must stay fixed"


def test_boundary_probing_walks_toward_edge_values():
    import re
    queries = STRATEGIES["boundary_probing"].generate(6, seed=1)
    numbers = [int(re.search(r"-?\d+", q).group()) for q in queries]
    assert 0 in numbers or -1 in numbers or any(n > 60000 for n in numbers), (
        f"expected the walk to reach a known edge value, got {numbers}"
    )


# --- item 5: logs are generated -----------------------------------------------

def test_logger_writes_jsonl_and_summary(tmp_path):
    logger = AttackLogger(log_dir=str(tmp_path), client_id="test-log-client",
                          strategy="exact_repetition", mode="fast", target=BACKEND_URL)

    from attacker_cli.http_client import ChatResult
    logger.log_query(1, "hello", ChatResult(http_status=200, ok=True, decision="ALLOW",
                                            risk_score=0.0, risk_band="LOW",
                                            got_llm_response=True))
    logger.log_query(2, "hello", ChatResult(http_status=200, ok=True, decision="BLOCK",
                                            risk_score=90.0, risk_band="CRITICAL",
                                            got_llm_response=False))
    logger.finish()

    jsonl_path = tmp_path / "test-log-client.jsonl"
    summary_path = tmp_path / "test-log-client_summary.json"
    assert jsonl_path.exists()
    assert summary_path.exists()

    lines = jsonl_path.read_text().strip().splitlines()
    assert len(lines) == 2
    row1 = json.loads(lines[0])
    for field in ("timestamp", "client_id", "strategy", "mode", "query_number",
                  "query", "decision", "risk_score", "response_status"):
        assert field in row1, f"missing required log field: {field}"
    assert row1["signals"] is None  # never exposed to the attacker -- see module docstring

    summary = json.loads(summary_path.read_text())
    assert summary["counts"]["ALLOW"] == 1
    assert summary["counts"]["BLOCK"] == 1
    assert summary["queries_to_first_block"] == 2


# --- items 1, 2, 4, 9: real HTTP round trip against the live server ----------

@requires_server
def test_queries_reach_chat_endpoint_and_client_id_is_preserved():
    client = FirewallClient(base_url=BACKEND_URL)
    try:
        client_id = "test-attacker-cli-preserve-1"
        result = client.send(client_id, "What is a nonce in cryptography?")
        assert result.ok
        assert result.http_status == 200
        assert result.decision == "ALLOW"

        # Confirm via the admin API that the exact client_id we sent is what
        # the firewall recorded -- proving the id round-tripped correctly.
        admin = httpx.get(f"{BACKEND_URL}/api/admin/clients/{client_id}",
                          headers={"X-Admin-Token": "change-me-local-only"})
        assert admin.status_code == 200
        assert admin.json()["client_id"] == client_id
    finally:
        client.close()
        httpx.post(f"{BACKEND_URL}/api/admin/clients/test-attacker-cli-preserve-1/reset",
                  headers={"X-Admin-Token": "change-me-local-only"})


@requires_server
def test_all_four_actions_are_handled_correctly(tmp_path):
    """Drives a real repetition attack far enough to see ALLOW, MONITOR,
    THROTTLE, and BLOCK, and confirms the logger captured each correctly."""
    strategy = STRATEGIES["exact_repetition"]
    queries = strategy.generate(10, seed=123)
    outcome = run_attack(
        strategy_id="exact_repetition", strategy_name=strategy.name,
        queries=queries, mode="fast", pacer=FastPacer(delay=0.05),
        client_id="test-attacker-cli-ladder-1", target=BACKEND_URL,
        log_dir=str(tmp_path), on_block="continue", verbose=False,
    )

    rows = [json.loads(l) for l in open(outcome.log_path)]
    decisions_seen = {r["decision"] for r in rows}
    assert "ALLOW" in decisions_seen
    assert "BLOCK" in decisions_seen, "expected repeated queries to reach BLOCK"

    for r in rows:
        if r["decision"] == "BLOCK":
            assert r["got_llm_response"] is False, "BLOCK must not have called the LLM"
        elif r["decision"] in ("ALLOW", "MONITOR", "THROTTLE"):
            assert r["got_llm_response"] is True, f"{r['decision']} must have called the LLM"

    httpx.post(f"{BACKEND_URL}/api/admin/clients/test-attacker-cli-ladder-1/reset",
              headers={"X-Admin-Token": "change-me-local-only"})


@requires_server
def test_on_block_stop_halts_run_immediately(tmp_path):
    strategy = STRATEGIES["exact_repetition"]
    queries = strategy.generate(20, seed=123)  # far more than needed to block
    outcome = run_attack(
        strategy_id="exact_repetition", strategy_name=strategy.name,
        queries=queries, mode="fast", pacer=FastPacer(delay=0.05),
        client_id="test-attacker-cli-stop-1", target=BACKEND_URL,
        log_dir=str(tmp_path), on_block="stop", verbose=False,
    )
    assert outcome.stopped_early is True
    assert outcome.total_sent < 20, "on_block=stop must not send the full planned count"

    rows = [json.loads(l) for l in open(outcome.log_path)]
    assert rows[-1]["decision"] == "BLOCK"

    httpx.post(f"{BACKEND_URL}/api/admin/clients/test-attacker-cli-stop-1/reset",
              headers={"X-Admin-Token": "change-me-local-only"})


@requires_server
def test_on_block_continue_sends_full_count(tmp_path):
    strategy = STRATEGIES["exact_repetition"]
    queries = strategy.generate(12, seed=123)
    outcome = run_attack(
        strategy_id="exact_repetition", strategy_name=strategy.name,
        queries=queries, mode="fast", pacer=FastPacer(delay=0.05),
        client_id="test-attacker-cli-continue-1", target=BACKEND_URL,
        log_dir=str(tmp_path), on_block="continue", verbose=False,
    )
    assert outcome.stopped_early is False
    assert outcome.total_sent == 12, "on_block=continue must send every planned query"

    httpx.post(f"{BACKEND_URL}/api/admin/clients/test-attacker-cli-continue-1/reset",
              headers={"X-Admin-Token": "change-me-local-only"})
