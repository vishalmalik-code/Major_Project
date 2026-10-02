"""Persona registry, mirroring app.attacker.registry so the evaluation runner
can treat both session types uniformly."""

from normal_user_cli.base import Persona
from normal_user_cli.personas.casual_user import CasualUserPersona
from normal_user_cli.personas.developer import DeveloperPersona
from normal_user_cli.personas.incident_responder import IncidentResponderPersona
from normal_user_cli.personas.researcher import ResearcherPersona
from normal_user_cli.personas.student import StudentPersona

PERSONAS: dict[str, Persona] = {
    p.id: p for p in (
        CasualUserPersona(),
        StudentPersona(),
        DeveloperPersona(),
        ResearcherPersona(),
        IncidentResponderPersona(),
    )
}


def get(persona_id: str) -> Persona:
    if persona_id not in PERSONAS:
        raise KeyError(f"unknown persona: {persona_id}")
    return PERSONAS[persona_id]


def listing() -> list[dict]:
    return [p.as_dict() for p in PERSONAS.values()]
