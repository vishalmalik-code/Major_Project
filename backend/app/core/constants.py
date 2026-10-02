"""Shared enums. Kept free of dependencies so any module can import them."""

from enum import Enum


class Action(str, Enum):
    ALLOW = "ALLOW"        # LOW      - forward normally
    MONITOR = "MONITOR"    # MEDIUM   - forward, flag, raise event
    THROTTLE = "THROTTLE"  # HIGH     - delay, then forward
    BLOCK = "BLOCK"        # CRITICAL - refuse, never reach the LLM


class RiskBand(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventType(str, Enum):
    MONITORED = "MONITORED"
    THROTTLED = "THROTTLED"
    BLOCKED = "BLOCKED"
    RISK_ESCALATED = "RISK_ESCALATED"
    RISK_REDUCED = "RISK_REDUCED"
    CLIENT_RESET = "CLIENT_RESET"


class SignalName(str, Enum):
    EXACT_REPETITION = "exact_repetition"
    TEXT_SIMILARITY = "text_similarity"
    SEMANTIC_SIMILARITY = "semantic_similarity"
    SYSTEMATIC_MODIFICATION = "systematic_modification"
    VALUE_PROGRESSION = "value_progression"
    CONSTRAINT_PROGRESSION = "constraint_progression"
    BOUNDARY_PROGRESSION = "boundary_progression"
    BURST_RATE = "burst_rate"


class AttackMode(str, Enum):
    FAST = "FAST"
    SLOW = "SLOW"


class StrategyId(str, Enum):
    EXACT_REPETITION = "exact_repetition"
    MINIMAL_MODIFICATION = "minimal_modification"
    VALUE_SWEEP = "value_sweep"
    CONSTRAINT_PROBING = "constraint_probing"
    BOUNDARY_PROBING = "boundary_probing"


class MessageSource(str, Enum):
    """Who originated a `queries` row when it's filed under a conversation --
    display/analytics only, never consulted by the firewall (see
    ChatService.handle's `source` param and Query.source)."""

    USER = "user"
    ATTACKER = "attacker"
