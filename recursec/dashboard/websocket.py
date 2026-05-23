"""WebSocket real-time event system for the RecurSec dashboard.

Provides:
- Real-time scan progress updates
- Agent spawn/completion notifications
- Finding alerts
- Model health status
- Log streaming
- Task queue updates
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class EventType(str, Enum):
    SCAN_STARTED = "scan.started"
    SCAN_PROGRESS = "scan.progress"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"

    AGENT_SPAWNED = "agent.spawned"
    AGENT_COMPLETED = "agent.completed"
    AGENT_FAILED = "agent.failed"

    FINDING_NEW = "finding.new"
    FINDING_CRITICAL = "finding.critical"
    FINDING_VALIDATED = "finding.validated"

    MODEL_HEALTHY = "model.healthy"
    MODEL_UNHEALTHY = "model.unhealthy"
    MODEL_LOADED = "model.loaded"

    TASK_QUEUED = "task.queued"
    TASK_STARTED = "task.started"
    TASK_COMPLETED = "task.completed"

    LOG = "log"
    METRICS = "metrics"
    HEARTBEAT = "heartbeat"


class Event:
    """A real-time event."""

    def __init__(
        self,
        event_type: EventType,
        data: dict[str, Any] | None = None,
        message: str = "",
    ) -> None:
        self.type = event_type
        self.data = data or {}
        self.message = message
        self.timestamp = time.time()

    def to_json(self) -> str:
        return json.dumps({
            "type": self.type.value,
            "data": self.data,
            "message": self.message,
            "timestamp": self.timestamp,
        })


class EventBus:
    """Central event bus for broadcasting events to WebSocket clients."""

    def __init__(self, history_size: int = 500) -> None:
        self._subscribers: list[asyncio.Queue[Event]] = []
        self._history: deque[Event] = deque(maxlen=history_size)
        self._event_counts: dict[str, int] = {}
        self._running = False

    def subscribe(self) -> asyncio.Queue[Event]:
        """Subscribe to events. Returns a queue that receives events."""
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=100)
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Event]) -> None:
        """Unsubscribe from events."""
        if queue in self._subscribers:
            self._subscribers.remove(queue)

    async def publish(self, event: Event) -> None:
        """Publish an event to all subscribers."""
        self._history.append(event)
        self._event_counts[event.type.value] = self._event_counts.get(event.type.value, 0) + 1

        # Broadcast to all subscribers
        disconnected: list[asyncio.Queue[Event]] = []
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Drop events if subscriber can't keep up
                disconnected.append(queue)

        for q in disconnected:
            self._subscribers.remove(q)

    def emit(self, event_type: EventType, data: dict[str, Any] | None = None, message: str = "") -> None:
        """Synchronous emit — schedules publish on the event loop."""
        event = Event(event_type, data, message)
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.publish(event))
        except RuntimeError:
            # No running event loop, store in history only
            self._history.append(event)

    def get_history(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get recent event history."""
        events = list(self._history)[-limit:]
        return [
            {"type": e.type.value, "data": e.data, "message": e.message, "timestamp": e.timestamp}
            for e in events
        ]

    def get_stats(self) -> dict[str, Any]:
        """Get event statistics."""
        return {
            "subscribers": len(self._subscribers),
            "history_size": len(self._history),
            "event_counts": dict(self._event_counts),
        }

    async def start_heartbeat(self, interval: float = 30.0) -> None:
        """Start periodic heartbeat events."""
        self._running = True
        while self._running:
            await self.publish(Event(
                EventType.HEARTBEAT,
                data={"subscribers": len(self._subscribers)},
                message="heartbeat",
            ))
            await asyncio.sleep(interval)

    def stop(self) -> None:
        self._running = False


# Global event bus instance
_event_bus = EventBus()


def get_event_bus() -> EventBus:
    """Get the global event bus instance."""
    return _event_bus


def register_websocket(app: Any) -> None:
    """Register WebSocket endpoint on a FastAPI app."""
    from fastapi import WebSocket, WebSocketDisconnect

    event_bus = get_event_bus()

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        await websocket.accept()
        queue = event_bus.subscribe()

        # Send recent history
        for event in event_bus.get_history(50):
            try:
                await websocket.send_json(event)
            except Exception:
                break

        try:
            while True:
                event = await queue.get()
                try:
                    await websocket.send_text(event.to_json())
                except Exception:
                    break
        except WebSocketDisconnect:
            pass
        finally:
            event_bus.unsubscribe(queue)

    @app.get("/api/events/history")
    async def event_history(limit: int = 100) -> dict[str, Any]:
        return {"events": event_bus.get_history(limit)}

    @app.get("/api/events/stats")
    async def event_stats() -> dict[str, Any]:
        return event_bus.get_stats()
