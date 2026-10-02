"""Persona E - INCIDENT_RESPONDER: investigating a live technical issue, so
sends several related questions in quick succession. Important persona
because it may naturally produce FAST-looking traffic even though it's
entirely legitimate -- this is a deliberate stress test of the firewall's
burst_rate signal, which is why it's capped at low weight and never allowed
to convict alone.
"""

import random

from normal_user_cli.base import Persona

_SCENARIOS: dict[str, list[str]] = {
    "login anomaly": [
        "We're seeing repeated failed login attempts from one account -- what could cause that?",
        "Could this be a credential-stuffing attempt rather than someone forgetting their password?",
        "What log fields should I check to tell the difference?",
        "If it is credential stuffing, what's the right immediate response?",
        "Should we force a password reset for the affected account right away?",
        "What would you recommend to prevent this going forward?",
    ],
    "suspicious outbound traffic": [
        "We noticed unusual outbound connections from an internal server -- where should I start?",
        "What would indicate this is C2 traffic versus something benign?",
        "How do I check what process on that host initiated the connections?",
        "If it turns out to be compromised, what's the right containment step first?",
        "Should we isolate the host from the network immediately or capture more data first?",
        "What should go in the incident timeline at this stage?",
    ],
    "possible injection in logs": [
        "I'm seeing strange characters in our web server logs that look like SQL syntax -- is this an injection attempt?",
        "How can I tell if any of these attempts actually succeeded?",
        "What should I check in the database logs to confirm or rule it out?",
        "If it did succeed, what's the immediate priority -- patching or assessing damage?",
        "How do we figure out what data might have been exposed?",
        "What's the right way to document this for the post-incident report?",
    ],
    "phishing report": [
        "A user reported a phishing email that asked them to reset their password -- what's the first step?",
        "How do I check whether they actually clicked the link or entered credentials?",
        "Should we assume the account is compromised until proven otherwise?",
        "What's the fastest way to check if other users received the same email?",
        "Do we need to force a password reset even if they say they didn't click it?",
        "What should go into the alert we send to the rest of the team?",
    ],
}


class IncidentResponderPersona(Persona):
    id = "incident_responder"
    name = "Incident Responder"
    description = "Investigating a live issue -- several related questions, sent quickly."
    traits = ["single incident per session", "naturally fast cadence", "triage-driven"]

    def generate(self, count: int, seed: int | None = None,
                topic: str | None = None) -> list[str]:
        rng = random.Random(seed)
        key = self._pick_scenario(rng, topic)
        return self._cycle(rng, _SCENARIOS[key], count)

    def _pick_scenario(self, rng: random.Random, topic: str | None) -> str:
        if topic:
            matches = [k for k in _SCENARIOS if topic.lower() in k]
            if matches:
                return rng.choice(matches)
        return rng.choice(list(_SCENARIOS.keys()))
