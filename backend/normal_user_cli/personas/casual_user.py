"""Persona A - CASUAL_USER: asks unrelated technical questions occasionally.

No topic anchor, no follow-through -- each question is essentially a fresh
visit. Low similarity between consecutive queries is the norm, but real casual
users do occasionally land on the same popular question twice (e.g. "what is
XSS" is a common opener), so a small chance of an incidental repeat is built
in -- it must look like coincidence, not a strategy.
"""

import random

from normal_user_cli.base import Persona

_QUESTIONS = [
    "What is SQL injection?",
    "How does two-factor authentication work?",
    "What's the difference between HTTP and HTTPS?",
    "What is a JWT and where is it used?",
    "Can you explain what cross-site scripting is?",
    "What does TLS actually protect against?",
    "Why shouldn't I store passwords in plain text?",
    "What is CSRF?",
    "What's a VPN and do I actually need one?",
    "How do firewalls decide what traffic to block?",
    "What's the point of input validation?",
    "Is it safe to use public Wi-Fi for online banking?",
    "What is a man-in-the-middle attack?",
    "What does 'least privilege' mean in security?",
    "How does DNS work, roughly?",
    "What is a zero-day vulnerability?",
    "What's the difference between authentication and authorization?",
    "Why do websites ask me to enable cookies?",
    "What is a brute-force attack?",
    "What's the deal with password managers -- are they safe?",
    "What does encryption at rest mean?",
    "How do certificate authorities work?",
    "What's a honeypot in security terms?",
    "Why is my browser warning me about a site's certificate?",
    "What's the difference between a virus and a worm?",
]


class CasualUserPersona(Persona):
    id = "casual_user"
    name = "Casual User"
    description = "Asks unrelated technical questions occasionally, with no topic anchor."
    traits = ["low topic continuity", "occasional incidental repeat", "no follow-through"]

    def generate(self, count: int, seed: int | None = None,
                topic: str | None = None) -> list[str]:
        rng = random.Random(seed)
        pool = _QUESTIONS[:]
        rng.shuffle(pool)
        out: list[str] = []
        for i in range(count):
            # ~12% chance of asking something already asked this session --
            # coincidence, not a pattern.
            if out and rng.random() < 0.12:
                out.append(rng.choice(out))
            else:
                out.append(pool[i % len(pool)])
        return out
