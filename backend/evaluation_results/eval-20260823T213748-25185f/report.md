# Firewall Evaluation Report

Run: `eval-20260823T213748-25185f` · seed: `2024` · target: `http://localhost:8000` · generated: 2026-08-24T05:47:29.388849+00:00

## Attack sessions

| Strategy | Mode | Queries | Detection | Throttle | Block | Avg Risk | Peak Risk |
|---|---|---|---|---|---|---|---|
| Boundary Probing | FAST | 10 | Yes (@4) | Yes (@7) | Yes (@9) | 47.7 | 94.0 |
| Boundary Probing | SLOW | 10 | Yes (@4) | Yes (@7) | Yes (@9) | 46.9 | 92.2 |
| Output-Constraint Probing | FAST | 10 | Yes (@5) | Yes (@8) | Yes (@10) | 40.9 | 81.0 |
| Output-Constraint Probing | SLOW | 10 | Yes (@5) | Yes (@9) | No | 35.3 | 68.6 |
| Exact Repetition | FAST | 10 | Yes (@4) | Yes (@6) | Yes (@8) | 56.1 | 100.0 |
| Exact Repetition | SLOW | 10 | Yes (@4) | Yes (@6) | Yes (@8) | 55.3 | 100.0 |
| Minimal Modification | FAST | 10 | Yes (@7) | Yes (@10) | No | 28.0 | 62.3 |
| Minimal Modification | SLOW | 10 | Yes (@7) | Yes (@10) | No | 26.7 | 59.1 |
| Value Sweep | FAST | 10 | Yes (@4) | Yes (@6) | Yes (@8) | 53.7 | 100.0 |
| Value Sweep | SLOW | 10 | Yes (@4) | Yes (@6) | Yes (@8) | 52.2 | 100.0 |

**Overall detection rate:** 100% (10/10 sessions reached MONITOR, THROTTLE, or BLOCK)

**Block rate:** 70% · **Throttle rate:** 100% · **Avg queries before detection:** 4.8

### Detection rate by strategy

| Strategy | Sessions | Detection rate | Block rate |
|---|---|---|---|
| Exact Repetition | 2 | 100% | 100% |
| Minimal Modification | 2 | 100% | 0% |
| Value Sweep | 2 | 100% | 100% |
| Output-Constraint Probing | 2 | 100% | 50% |
| Boundary Probing | 2 | 100% | 100% |

## Normal-user sessions

| Persona | Mode | Queries | Monitor | Throttle | Block | Avg Risk | Peak Risk |
|---|---|---|---|---|---|---|---|
| Casual User | FAST | 10 | 0 | 0 | 0 | 2.4 | 8.0 |
| Casual User | SLOW | 10 | 0 | 0 | 0 | 2.1 | 7.4 |
| Developer | FAST | 10 | 0 | 0 | 0 | 4.7 | 13.4 |
| Developer | SLOW | 10 | 0 | 0 | 0 | 4.5 | 12.8 |
| Incident Responder | FAST | 10 | 0 | 0 | 0 | 7.1 | 28.0 |
| Incident Responder | SLOW | 10 | 0 | 0 | 0 | 4.5 | 12.9 |
| Researcher | FAST | 10 | 0 | 0 | 0 | 4.1 | 20.5 |
| Researcher | SLOW | 10 | 0 | 0 | 0 | 2.6 | 12.8 |
| Student | FAST | 10 | 0 | 0 | 0 | 2.0 | 13.3 |
| Student | SLOW | 10 | 0 | 0 | 0 | 0.0 | 0.0 |

**False positive rate (BLOCKed at least once):** 0% (0/10 sessions)

**Throttled-or-worse rate:** 0%

### False positives by persona

| Persona | % Monitored | % Throttled | % Blocked | Avg Risk | Peak Risk | Blocked at least once |
|---|---|---|---|---|---|---|
| Casual User | 0% | 0% | 0% | 2.3 | 8.0 | no |
| Student | 0% | 0% | 0% | 1.0 | 13.3 | no |
| Developer | 0% | 0% | 0% | 4.6 | 13.4 | no |
| Researcher | 0% | 0% | 0% | 3.3 | 20.5 | no |
| Incident Responder | 0% | 0% | 0% | 5.8 | 28.0 | no |

## Most important comparisons

**1. FAST attacker vs FAST legitimate user** -- avg risk 45.3 vs 4.0

**2. SLOW attacker vs SLOW legitimate user** -- avg risk 43.3 vs 2.7

**3. Each of the five attack patterns** -- see 'Detection rate by strategy' above.

**4. Exact repetition vs minimal modification** -- exact repetition avg risk 55.7 vs minimal modification avg risk 27.4

**5. Systematic value sweep vs normal technical questions** -- value sweep avg risk 52.9 vs student/researcher avg risk 2.2

**6. Boundary probing vs legitimate technical exploration (researcher)** -- boundary probing avg risk 47.3 vs researcher avg risk 3.3
