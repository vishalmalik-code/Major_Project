"""In-process pub/sub so an open /chat browser tab can be told, live, about a
new message filed under its conversation -- without polling and without a new
piece of infrastructure (no Redis, no message broker).

One `ConversationEventBus` instance lives on `app.state` for the process's
lifetime (see app/main.py). ChatService.handle() publishes to it right after
a query is committed for a conversation; the SSE route in
app/api/routes/conversations.py subscribes for the lifetime of one browser
connection. Single-process, single-event-loop app (see scripts/run_backend.sh
-- one uvicorn worker), so a plain dict of asyncio.Queues is enough; nothing
here needs to survive a restart or be shared across processes.
"""

import asyncio


class ConversationEventBus:
    def __init__(self) -> None:
        self._subscribers: dict[int, list[asyncio.Queue]] = {}

    def subscribe(self, conversation_id: int) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(conversation_id, []).append(queue)
        return queue

    def unsubscribe(self, conversation_id: int, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(conversation_id)
        if not subs:
            return
        if queue in subs:
            subs.remove(queue)
        if not subs:
            self._subscribers.pop(conversation_id, None)

    def publish(self, conversation_id: int, event: str, data: dict) -> None:
        for queue in self._subscribers.get(conversation_id, []):
            queue.put_nowait((event, data))


class BroadcastBus:
    """Same idea as ConversationEventBus, but a single global channel with no
    per-id keying -- for /admin, which watches every client/query/security
    event in the system, not one conversation. Every admin browser tab
    subscribes to the same feed; ChatService.handle() publishes ONE event
    per firewall decision (query + risk + decision + the security event, if
    any) here, covering the "message created / response created / blocked /
    security event / risk updated" event list in a single, un-overcomplicated
    payload -- see PROMPT section on event types explicitly allowing this."""

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue] = []

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        if queue in self._subscribers:
            self._subscribers.remove(queue)

    def publish(self, event: str, data: dict) -> None:
        for queue in self._subscribers:
            queue.put_nowait((event, data))
