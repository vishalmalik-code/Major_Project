"""Persona C - DEVELOPER: asks technical questions while solving a real
problem. May rephrase a question, ask for an example, change requirements
mid-stream, or ask a follow-up -- all in the developer's own words each time,
which is the point: a real developer's rephrase changes the whole sentence,
not one token in a frozen template.
"""

import random

from normal_user_cli.base import Persona

_CONTEXTS: dict[str, list[str]] = {
    "auth": [
        "I'm building a login system -- what's the standard way to hash passwords?",
        "Should I be using bcrypt or argon2 for password hashing these days?",
        "Can you show me roughly what that looks like in code?",
        "What if I also need to support 'remember me' -- does that change the approach?",
        "How long should a session actually last before I force a re-login?",
        "What's the right way to handle failed login attempts without locking people out too aggressively?",
    ],
    "input_validation": [
        "I've got a form that takes a username and email -- how should I validate that server-side?",
        "Is client-side validation basically pointless then?",
        "Can you give me an example of sanitizing a text field before it hits the database?",
        "What if the field also needs to allow some HTML, like a bio or description?",
        "How would you handle file uploads safely on top of this?",
        "What are the most common mistakes people make with input validation?",
    ],
    "tls_setup": [
        "I'm setting up HTTPS for a small API -- what do I actually need to get started?",
        "Do I need a paid certificate or is Let's Encrypt fine for production?",
        "How do I configure automatic renewal so it doesn't expire on me?",
        "What if I'm running this behind a load balancer -- where does TLS termination happen?",
        "Should I redirect all HTTP traffic to HTTPS, or is that overkill for an internal API?",
        "What TLS version should I require at minimum?",
    ],
    "api_design": [
        "I'm designing a REST API -- what's the best way to handle authorization for different user roles?",
        "Should that be role-based or more fine-grained, like per-resource permissions?",
        "Can you sketch an example of how the middleware for that might look?",
        "What if an endpoint needs different permission levels depending on the HTTP method?",
        "How should I return errors when someone hits an endpoint they're not authorized for?",
        "Is rate limiting something I should build myself or use a library for?",
    ],
}


class DeveloperPersona(Persona):
    id = "developer"
    name = "Developer"
    description = "Solves a real problem: rephrases, asks for examples, changes requirements."
    traits = ["problem-driven", "whole-sentence rephrasing", "requirement changes mid-session"]

    def generate(self, count: int, seed: int | None = None,
                topic: str | None = None) -> list[str]:
        rng = random.Random(seed)
        key = self._pick_context(rng, topic)
        return self._cycle(rng, _CONTEXTS[key], count)

    def _pick_context(self, rng: random.Random, topic: str | None) -> str:
        if topic:
            matches = [k for k in _CONTEXTS if topic.lower() in k]
            if matches:
                return rng.choice(matches)
        return rng.choice(list(_CONTEXTS.keys()))
