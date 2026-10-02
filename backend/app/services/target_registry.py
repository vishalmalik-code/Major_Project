"""The "target session handshake" for the attacker-console -> live-chat
demonstration.

Holds, in memory, whichever authenticated user's conversation was most
recently active in /chat (opened, created, or sent to -- see the three call
sites in app/api/routes/conversations.py, the only writers). The attacker
console reads it through a narrow, read-only surface
(GET /api/attacker-console/target and the auto-targeting branch of
GET /api/attacker-console/stream) that never accepts a client-supplied
user_id/client_id/conversation_id -- it can only ever receive whatever a real
logged-in user's own browser, using its own bearer token, put here.

Single global pointer, not one per user: this is a local, single-operator
simulation tool (the whole project's documented "demonstration boundary, not
a production auth system" philosophy -- see app/api/deps.py's module
docstring), and the attacker console's UI has no concept of "pick a user" --
it was built, by this project's own design, to need no login at all. Tracking
only the most-recently-active target is therefore not a shortcut; it is the
correct model for "one operator, two browser tabs, one demonstration in
progress at a time." See the PROMPT's own section 25 and the final report's
"Limitations" for the write-up of this tradeoff.

`is_valid_pair` is the actual authorization check: POST /api/chat (a route
with no auth of its own, by long-standing design -- every CLI tool and the
attacker console hit it directly) only ever tags a query with a
conversation_id if that EXACT (client_id, conversation_id) pair is the one
currently registered here. A caller cannot get an arbitrary query filed into
someone else's chat history by guessing a conversation_id; it must match the
pair a real authenticated session just set.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ActiveTarget:
    user_id: int
    client_id: str
    conversation_id: int


class TargetRegistry:
    def __init__(self) -> None:
        self._target: ActiveTarget | None = None

    def set_active(self, *, user_id: int, client_id: str, conversation_id: int) -> None:
        self._target = ActiveTarget(
            user_id=user_id, client_id=client_id, conversation_id=conversation_id)

    def get_active(self) -> ActiveTarget | None:
        return self._target

    def is_valid_pair(self, client_id: str, conversation_id: int) -> bool:
        t = self._target
        return t is not None and t.client_id == client_id and t.conversation_id == conversation_id
