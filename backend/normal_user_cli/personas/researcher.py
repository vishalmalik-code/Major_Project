"""Persona D - RESEARCHER: explores one topic more deeply than a student, but
naturally -- comparing approaches, asking about real-world incidents, probing
trade-offs -- rather than systematically enumerating every variation of a
parameter or output format.
"""

import random

from normal_user_cli.base import Persona

_TOPICS: dict[str, list[str]] = {
    "network security": [
        "What are the main differences between IDS and IPS systems in practice?",
        "How effective is network segmentation at limiting lateral movement in a breach?",
        "What's the real-world track record of zero-trust architectures so far?",
        "How do modern attackers typically get around traditional perimeter firewalls?",
        "What's the trade-off between deep packet inspection and encrypted traffic?",
        "Are there good case studies of network segmentation failing despite being in place?",
        "How do SOC teams usually triage alerts from network monitoring at scale?",
    ],
    "secure coding": [
        "What secure coding practices have the best evidence behind them for reducing vulnerabilities?",
        "How much do static analysis tools actually catch compared to manual review?",
        "What's the current thinking on memory-safe languages replacing C/C++ in critical systems?",
        "How do supply-chain attacks on dependencies typically get discovered?",
        "What made certain widely-used libraries a target for such attacks historically?",
        "Is there good research comparing secure-by-design frameworks against retrofitted security?",
        "How do code review practices differ between open-source and enterprise projects on this front?",
    ],
    "authentication": [
        "How has passwordless authentication adoption actually gone in production systems?",
        "What are the documented weaknesses of SMS-based two-factor authentication?",
        "How do passkeys compare to traditional FIDO2 hardware keys in practice?",
        "What's known about how attackers defeat multi-factor authentication in the wild?",
        "Are there good studies on user behavior around password reuse despite warnings?",
        "How do enterprises typically handle authentication for legacy systems that can't be modernized?",
        "What's the current state of biometric authentication's false-acceptance rates?",
    ],
    "sql injection": [
        "How has the prevalence of SQL injection changed over the last decade of vulnerability reports?",
        "What made SQL injection so persistent despite parameterized queries being well known?",
        "Are there notable breaches where SQL injection was the root cause worth studying?",
        "How do modern WAFs actually perform at catching novel SQL injection payloads?",
        "What's the relationship between ORMs and the decline in classic SQL injection bugs?",
        "How do second-order SQL injection attacks typically get missed in code review?",
        "What does the research say about automated SQL injection detection tools' false-negative rates?",
    ],
}


class ResearcherPersona(Persona):
    id = "researcher"
    name = "Researcher"
    description = "Explores one topic in depth naturally -- comparisons, trade-offs, case studies."
    traits = ["single topic per session", "analytical depth", "non-enumerative"]

    def generate(self, count: int, seed: int | None = None,
                topic: str | None = None) -> list[str]:
        rng = random.Random(seed)
        key = self._pick_topic(rng, topic)
        return self._cycle(rng, _TOPICS[key], count)

    def _pick_topic(self, rng: random.Random, topic: str | None) -> str:
        if topic:
            matches = [k for k in _TOPICS if topic.lower() in k]
            if matches:
                return rng.choice(matches)
        return rng.choice(list(_TOPICS.keys()))
