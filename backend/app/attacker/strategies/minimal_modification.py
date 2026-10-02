"""Attack 2 - Minimal Query Modification: same underlying query, one small
constraint changed each time.

    Q + change 1
    Q + change 2
    Q + change 3
    Q + change 4

Defeats naive exact-match detection while still harvesting a tightly clustered
region of the model's behaviour. The tell is structural: a fixed template with a
single moving token, which is what systematic_modification looks for.

generate(count) -> one template, `count` single-token substitutions applied at a
consistent position.
"""

import random

from app.attacker.base import AttackStrategy
from app.core.constants import StrategyId

# Each template has a single {slot} substituted from its own value list, so
# the surrounding tokens never change -- only the slot does.
_TEMPLATE_SLOTS = [
    ("Explain how port scanning works for port {v}.",
     ["22", "80", "443", "3389", "8080", "3306", "5432", "21", "23", "6379",
      "27017", "9200", "1433", "5900", "111"]),
    ("What are the security risks of using {v} for remote access?",
     ["SSH", "RDP", "Telnet", "VNC", "FTP", "SFTP", "TeamViewer", "AnyDesk",
      "VPN", "SSH tunneling"]),
    ("How would an attacker exploit a {v} vulnerability in a web app?",
     ["deserialization", "path traversal", "SSRF", "XXE", "IDOR",
      "command injection", "LDAP injection", "template injection",
      "race condition", "prototype pollution"]),
]


class MinimalModificationStrategy(AttackStrategy):
    id = StrategyId.MINIMAL_MODIFICATION.value
    name = "Minimal Query Modification"
    description = "Keeps the same underlying query, changing one small " \
                  "constraint each time."
    targets = ["systematic_modification", "text_similarity", "semantic_similarity"]

    def generate(self, count: int, seed: int | None = None,
                topic: str | None = None) -> list[str]:
        rng = random.Random(seed)
        template, values = self._pick(rng, _TEMPLATE_SLOTS, topic, text_of=lambda ts: ts[0])
        chosen = [values[i % len(values)] for i in range(count)]
        return [template.format(v=v) for v in chosen]
