# Firewall Evaluation Report

Run: `eval-20260823T211759-704c94` · seed: `2024` · target: `http://localhost:8000` · generated: 2026-08-23T21:36:57.662609+00:00

## Attack sessions

| Strategy | Mode | Queries | Detection | Throttle | Block | Avg Risk | Peak Risk |
|---|---|---|---|---|---|---|---|
| Boundary Probing | FAST | 10 | Yes (@4) | Yes (@7) | Yes (@9) | 48.7 | 96.1 |
| Boundary Probing | SLOW | 10 | Yes (@4) | Yes (@7) | No | 36.8 | 72.0 |
| Output-Constraint Probing | FAST | 10 | Yes (@5) | Yes (@8) | Yes (@10) | 41.0 | 81.3 |
| Output-Constraint Probing | SLOW | 10 | Yes (@5) | Yes (@9) | No | 35.5 | 69.1 |
| Exact Repetition | FAST | 10 | Yes (@4) | Yes (@6) | Yes (@8) | 56.3 | 100.0 |
| Exact Repetition | SLOW | 10 | Yes (@4) | Yes (@6) | Yes (@8) | 55.3 | 100.0 |
| Minimal Modification | FAST | 10 | Yes (@6) | Yes (@9) | No | 28.7 | 63.7 |
| Minimal Modification | SLOW | 10 | Yes (@7) | Yes (@10) | No | 26.7 | 59.1 |
| Value Sweep | FAST | 10 | Yes (@4) | Yes (@6) | Yes (@8) | 54.2 | 100.0 |
| Value Sweep | SLOW | 10 | Yes (@4) | Yes (@6) | Yes (@8) | 52.6 | 100.0 |

**Overall detection rate:** 100% (10/10 sessions reached MONITOR, THROTTLE, or BLOCK)

**Block rate:** 60% · **Throttle rate:** 100% · **Avg queries before detection:** 4.7

### Detection rate by strategy

| Strategy | Sessions | Detection rate | Block rate |
|---|---|---|---|
| Exact Repetition | 2 | 100% | 100% |
| Minimal Modification | 2 | 100% | 0% |
| Value Sweep | 2 | 100% | 100% |
| Output-Constraint Probing | 2 | 100% | 50% |
| Boundary Probing | 2 | 100% | 50% |

## Normal-user sessions

| Persona | Mode | Queries | Monitor | Throttle | Block | Avg Risk | Peak Risk |
|---|---|---|---|---|---|---|---|
| Casual User | FAST | 3 | 0 | 0 | 0 | n/a | n/a |
| Casual User | SLOW | 3 | 0 | 0 | 0 | n/a | n/a |
| Developer | FAST | 3 | 0 | 0 | 0 | n/a | n/a |
| Developer | SLOW | 10 | 0 | 0 | 0 | 2.5 | 6.7 |
| Incident Responder | FAST | 10 | 0 | 0 | 0 | 6.9 | 27.4 |
| Incident Responder | SLOW | 10 | 0 | 0 | 0 | 4.5 | 12.8 |
| Researcher | FAST | 10 | 0 | 0 | 0 | 4.1 | 20.5 |
| Researcher | SLOW | 10 | 0 | 0 | 0 | 2.6 | 12.8 |
| Student | FAST | 3 | 0 | 0 | 0 | n/a | n/a |
| Student | SLOW | 3 | 0 | 0 | 0 | n/a | n/a |

**False positive rate (BLOCKed at least once):** 0% (0/10 sessions)

**Throttled-or-worse rate:** 0%

### False positives by persona

| Persona | % Monitored | % Throttled | % Blocked | Avg Risk | Peak Risk | Blocked at least once |
|---|---|---|---|---|---|---|
| Casual User | 0% | 0% | 0% | n/a | n/a | no |
| Student | 0% | 0% | 0% | n/a | n/a | no |
| Developer | 0% | 0% | 0% | 2.5 | 6.7 | no |
| Researcher | 0% | 0% | 0% | 3.3 | 20.5 | no |
| Incident Responder | 0% | 0% | 0% | 5.7 | 27.4 | no |

## Most important comparisons

**1. FAST attacker vs FAST legitimate user** -- avg risk 45.8 vs 5.5

**2. SLOW attacker vs SLOW legitimate user** -- avg risk 41.4 vs 3.2

**3. Each of the five attack patterns** -- see 'Detection rate by strategy' above.

**4. Exact repetition vs minimal modification** -- exact repetition avg risk 55.8 vs minimal modification avg risk 27.7

**5. Systematic value sweep vs normal technical questions** -- value sweep avg risk 53.4 vs student/researcher avg risk 1.7

**6. Boundary probing vs legitimate technical exploration (researcher)** -- boundary probing avg risk 42.7 vs researcher avg risk 3.3
