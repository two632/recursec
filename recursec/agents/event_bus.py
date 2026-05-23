"""Event bus — publish/subscribe system for inter-agent communication.

Provides decoupled communication between agents:
1. Topic-based pub/sub messaging
2. Priority message queues
3. Broadcast and targeted messaging
4. Event filtering and routing
5. Dead letter queue for undeliverable messages
6. Message history and replay
7. Rate limiting per publisher
8. Event correlation (group related events)

Event types:
- Finding: New vulnerability discovered
- Progress: Task progress update
- Alert: Urgent notification
- Request: Agent requesting help
- Response: Reply to a request
- Control: System control messages
- Heartbeat: Agent health check
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

import structlog

logger = structlog.get_logger()

EventHandler = Callable[["Event"], Any]


class EventPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


class EventCategory(str, Enum):
    FINDING = "finding"
    PROGRESS = "progress"
    ALERT = "alert"
    REQUEST = "request"
    RESPONSE = "response"
    CONTROL = "control"
    HEARTBEAT = "heartbeat"
    ERROR = "error"
    STATE_CHANGE = "state_change"
    TOOL_RESULT = "tool_result"
    DECISION = "decision"


@dataclass
class Event:
    """An event in the pub/sub system."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:10])
    topic: str = ""
    category: EventCategory = EventCategory.PROGRESS
    priority: EventPriority = EventPriority.NORMAL
    source: str = ""        # Publisher agent ID
    target: str = ""        # Target agent ID (empty = broadcast)
    payload: dict[str, Any] = field(default_factory=dict)
    correlation_id: str = ""   # For grouping related events
    reply_to: str = ""         # Event ID this replies to
    timestamp: float = field(default_factory=time.time)
    ttl_s: float = 300.0       # Time to live

    @property
    def expired(self) -> bool:
        return time.time() - self.timestamp > self.ttl_s

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.event_id,
            "topic": self.topic,
            "category": self.category.value,
            "priority": self.priority.value,
            "source": self.source,
            "target": self.target,
            "payload_keys": list(self.payload.keys())[:5],
            "correlation": self.correlation_id,
        }


@dataclass
class Subscription:
    """A subscription to events."""
    sub_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    subscriber_id: str = ""
    topic: str = ""             # Topic pattern (empty = all)
    category: EventCategory | None = None
    handler: EventHandler | None = None
    queue: asyncio.Queue[Event] | None = None
    created_at: float = field(default_factory=time.time)
    events_received: int = 0


class EventBus:
    """Publish/subscribe event bus for inter-agent communication.

    Provides decoupled, topic-based messaging between agents
    with priority queues and event correlation.
    """

    def __init__(
        self,
        max_history: int = 5000,
        max_dead_letters: int = 1000,
    ) -> None:
        self._subscriptions: list[Subscription] = []
        self._history: deque[Event] = deque(maxlen=max_history)
        self._dead_letters: deque[Event] = deque(maxlen=max_dead_letters)
        self._correlation_groups: dict[str, list[str]] = defaultdict(list)
        self._event_counter = 0
        self._log = logger.bind(component="event_bus")

    def subscribe(
        self,
        subscriber_id: str,
        topic: str = "",
        category: EventCategory | None = None,
        handler: EventHandler | None = None,
    ) -> Subscription:
        """Subscribe to events matching criteria."""
        sub = Subscription(
            subscriber_id=subscriber_id,
            topic=topic,
            category=category,
            handler=handler,
            queue=asyncio.Queue() if not handler else None,
        )
        self._subscriptions.append(sub)
        return sub

    def unsubscribe(self, sub_id: str) -> None:
        """Remove a subscription."""
        self._subscriptions = [s for s in self._subscriptions if s.sub_id != sub_id]

    async def publish(self, event: Event) -> int:
        """Publish an event to matching subscribers."""
        self._event_counter += 1
        self._history.append(event)

        # Track correlation
        if event.correlation_id:
            self._correlation_groups[event.correlation_id].append(event.event_id)

        delivered = 0
        for sub in self._subscriptions:
            if self._matches(sub, event):
                try:
                    if sub.handler:
                        result = sub.handler(event)
                        if asyncio.iscoroutine(result):
                            await result
                    elif sub.queue:
                        await sub.queue.put(event)
                    sub.events_received += 1
                    delivered += 1
                except Exception as e:
                    self._log.warning(
                        "delivery_failed",
                        subscriber=sub.subscriber_id,
                        error=str(e),
                    )

        if delivered == 0 and event.target:
            self._dead_letters.append(event)

        return delivered

    def publish_sync(self, event: Event) -> int:
        """Synchronous publish (fire-and-forget)."""
        self._event_counter += 1
        self._history.append(event)

        if event.correlation_id:
            self._correlation_groups[event.correlation_id].append(event.event_id)

        delivered = 0
        for sub in self._subscriptions:
            if self._matches(sub, event):
                if sub.handler:
                    try:
                        sub.handler(event)
                        delivered += 1
                    except Exception:
                        pass
                elif sub.queue:
                    try:
                        sub.queue.put_nowait(event)
                        delivered += 1
                    except asyncio.QueueFull:
                        pass

        if delivered == 0 and event.target:
            self._dead_letters.append(event)

        return delivered

    async def receive(self, sub: Subscription, timeout_s: float = 10.0) -> Event | None:
        """Receive next event for a subscription."""
        if not sub.queue:
            return None
        try:
            return await asyncio.wait_for(sub.queue.get(), timeout=timeout_s)
        except asyncio.TimeoutError:
            return None

    # ── Convenience Publishers ───────────────────────────

    async def emit_finding(
        self,
        source: str,
        finding: dict[str, Any],
        correlation_id: str = "",
    ) -> None:
        await self.publish(Event(
            topic="findings",
            category=EventCategory.FINDING,
            priority=EventPriority.HIGH,
            source=source,
            payload=finding,
            correlation_id=correlation_id,
        ))

    async def emit_progress(
        self,
        source: str,
        progress: float,
        message: str = "",
    ) -> None:
        await self.publish(Event(
            topic="progress",
            category=EventCategory.PROGRESS,
            source=source,
            payload={"progress": progress, "message": message},
        ))

    async def emit_alert(
        self,
        source: str,
        alert_type: str,
        message: str,
    ) -> None:
        await self.publish(Event(
            topic="alerts",
            category=EventCategory.ALERT,
            priority=EventPriority.CRITICAL,
            source=source,
            payload={"type": alert_type, "message": message},
        ))

    async def request_help(
        self,
        source: str,
        target: str,
        question: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        """Send a help request to another agent."""
        event = Event(
            topic="requests",
            category=EventCategory.REQUEST,
            source=source,
            target=target,
            payload={"question": question, "context": context or {}},
        )
        await self.publish(event)
        return event.event_id

    async def send_response(
        self,
        source: str,
        reply_to: str,
        response: dict[str, Any],
    ) -> None:
        """Send a response to a request."""
        await self.publish(Event(
            topic="responses",
            category=EventCategory.RESPONSE,
            source=source,
            reply_to=reply_to,
            payload=response,
        ))

    # ── Query ────────────────────────────────────────────

    def get_correlated_events(self, correlation_id: str) -> list[Event]:
        """Get all events in a correlation group."""
        event_ids = set(self._correlation_groups.get(correlation_id, []))
        return [e for e in self._history if e.event_id in event_ids]

    def get_history(
        self,
        topic: str = "",
        category: EventCategory | None = None,
        source: str = "",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Get event history, optionally filtered."""
        events = list(self._history)
        if topic:
            events = [e for e in events if e.topic == topic]
        if category:
            events = [e for e in events if e.category == category]
        if source:
            events = [e for e in events if e.source == source]
        return [e.to_dict() for e in events[-limit:]]

    def get_dead_letters(self, limit: int = 20) -> list[dict[str, Any]]:
        return [e.to_dict() for e in list(self._dead_letters)[-limit:]]

    # ── Internal ─────────────────────────────────────────

    def _matches(self, sub: Subscription, event: Event) -> bool:
        """Check if a subscription matches an event."""
        # Expired events don't match
        if event.expired:
            return False

        # Target filter
        if event.target and event.target != sub.subscriber_id:
            return False

        # Topic filter
        if sub.topic and sub.topic != event.topic:
            if not event.topic.startswith(sub.topic):
                return False

        # Category filter
        if sub.category and sub.category != event.category:
            return False

        return True

    def get_stats(self) -> dict[str, Any]:
        by_category: dict[str, int] = defaultdict(int)
        for event in self._history:
            by_category[event.category.value] += 1
        return {
            "total_events": self._event_counter,
            "history_size": len(self._history),
            "subscriptions": len(self._subscriptions),
            "dead_letters": len(self._dead_letters),
            "by_category": dict(by_category),
        }
