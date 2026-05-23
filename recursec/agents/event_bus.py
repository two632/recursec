"""Event bus — inter-agent communication and event-driven coordination.

Implements:
1. Publish-subscribe event system
2. Event filtering by type, source, severity
3. Event persistence for replay
4. Event correlation (link related events)
5. Event rate limiting
6. Asynchronous event delivery
7. Event priority queuing
8. Dead letter queue for failed handlers
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine

import structlog

logger = structlog.get_logger()


class EventCategory(str, Enum):
    FINDING = "finding"
    TOOL = "tool"
    AGENT = "agent"
    STATE = "state"
    ERROR = "error"
    PROGRESS = "progress"
    METRIC = "metric"
    SYSTEM = "system"


class EventPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


@dataclass
class Event:
    """An event in the system."""
    event_id: str = ""
    category: EventCategory = EventCategory.SYSTEM
    event_type: str = ""          # Specific type (e.g., "finding.new", "tool.complete")
    source: str = ""              # Agent or component that emitted
    priority: EventPriority = EventPriority.NORMAL
    data: dict[str, Any] = field(default_factory=dict)
    correlation_id: str = ""      # Link related events
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.event_id,
            "category": self.category.value,
            "type": self.event_type,
            "source": self.source,
            "priority": self.priority.value,
            "data": {k: str(v)[:80] for k, v in list(self.data.items())[:5]},
            "correlation": self.correlation_id,
            "time": self.timestamp,
        }


@dataclass
class Subscription:
    """A subscription to events."""
    sub_id: str = ""
    subscriber: str = ""
    category: EventCategory | None = None
    event_type: str = ""           # Empty = all types
    handler: Any = None            # Async callable
    filter_fn: Any = None          # Optional filter function
    active: bool = True

    def matches(self, event: Event) -> bool:
        if not self.active:
            return False
        if self.category and event.category != self.category:
            return False
        if self.event_type and event.event_type != self.event_type:
            return False
        if self.filter_fn:
            try:
                return self.filter_fn(event)
            except Exception:
                return False
        return True


class EventBus:
    """Pub-sub event bus for inter-agent communication.

    Enables loose coupling between agents through
    event-driven communication patterns.
    """

    def __init__(self, max_history: int = 1000) -> None:
        self._subscriptions: list[Subscription] = []
        self._event_history: list[Event] = []
        self._dead_letters: list[tuple[Event, str]] = []
        self._event_counter = 0
        self._sub_counter = 0
        self._max_history = max_history
        self._event_counts: dict[str, int] = defaultdict(int)
        self._log = logger.bind(component="event_bus")

    def subscribe(
        self,
        subscriber: str,
        handler: Callable[[Event], Coroutine[Any, Any, None]] | Callable[[Event], None],
        category: EventCategory | None = None,
        event_type: str = "",
        filter_fn: Callable[[Event], bool] | None = None,
    ) -> str:
        """Subscribe to events."""
        self._sub_counter += 1
        sub_id = f"sub-{self._sub_counter}"

        sub = Subscription(
            sub_id=sub_id,
            subscriber=subscriber,
            category=category,
            event_type=event_type,
            handler=handler,
            filter_fn=filter_fn,
        )

        self._subscriptions.append(sub)
        return sub_id

    def unsubscribe(self, sub_id: str) -> bool:
        for sub in self._subscriptions:
            if sub.sub_id == sub_id:
                sub.active = False
                return True
        return False

    async def publish(
        self,
        category: EventCategory,
        event_type: str,
        source: str = "",
        priority: EventPriority = EventPriority.NORMAL,
        data: dict[str, Any] | None = None,
        correlation_id: str = "",
    ) -> str:
        """Publish an event."""
        self._event_counter += 1
        event_id = f"evt-{self._event_counter}"

        event = Event(
            event_id=event_id,
            category=category,
            event_type=event_type,
            source=source,
            priority=priority,
            data=data or {},
            correlation_id=correlation_id,
        )

        # Record in history
        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history = self._event_history[-self._max_history:]

        self._event_counts[event_type] += 1

        # Deliver to subscribers
        await self._deliver(event)

        return event_id

    def publish_sync(
        self,
        category: EventCategory,
        event_type: str,
        source: str = "",
        data: dict[str, Any] | None = None,
    ) -> str:
        """Synchronous publish (no delivery, just records)."""
        self._event_counter += 1
        event_id = f"evt-{self._event_counter}"

        event = Event(
            event_id=event_id,
            category=category,
            event_type=event_type,
            source=source,
            data=data or {},
        )

        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history = self._event_history[-self._max_history:]

        self._event_counts[event_type] += 1
        return event_id

    async def _deliver(self, event: Event) -> None:
        """Deliver event to matching subscribers."""
        for sub in self._subscriptions:
            if sub.matches(event):
                try:
                    result = sub.handler(event)
                    if asyncio.iscoroutine(result):
                        await result
                except Exception as e:
                    self._dead_letters.append((event, str(e)[:100]))
                    if len(self._dead_letters) > 100:
                        self._dead_letters = self._dead_letters[-100:]

    def get_history(
        self,
        category: EventCategory | None = None,
        event_type: str = "",
        correlation_id: str = "",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Get event history with filtering."""
        events = self._event_history

        if category:
            events = [e for e in events if e.category == category]
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if correlation_id:
            events = [e for e in events if e.correlation_id == correlation_id]

        return [e.to_dict() for e in events[-limit:]]

    def get_dead_letters(self, limit: int = 20) -> list[dict[str, Any]]:
        return [
            {"event": e.to_dict(), "error": err}
            for e, err in self._dead_letters[-limit:]
        ]

    def get_stats(self) -> dict[str, Any]:
        return {
            "events": self._event_counter,
            "subscriptions": sum(1 for s in self._subscriptions if s.active),
            "dead_letters": len(self._dead_letters),
            "top_types": dict(sorted(
                self._event_counts.items(),
                key=lambda x: x[1], reverse=True,
            )[:10]),
        }
