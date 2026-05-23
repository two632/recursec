"""Inter-agent message bus — communication between agents.

Implements:
1. Pub/sub messaging between agents
2. Topic-based message routing
3. Request/response patterns
4. Broadcast messages
5. Message priority queue
6. Message history and audit log
7. Dead letter handling
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MessageType(str, Enum):
    TASK_ASSIGN = "task_assign"
    TASK_COMPLETE = "task_complete"
    TASK_FAILED = "task_failed"
    FINDING = "finding"
    REQUEST = "request"
    RESPONSE = "response"
    STATUS_UPDATE = "status_update"
    BROADCAST = "broadcast"
    HEARTBEAT = "heartbeat"
    BUDGET_WARNING = "budget_warning"
    CONVERGENCE_ALERT = "convergence_alert"
    ERROR = "error"


class MessagePriority(str, Enum):
    CRITICAL = "critical"    # Finding, error
    HIGH = "high"            # Task assign/complete
    NORMAL = "normal"        # Status update
    LOW = "low"              # Heartbeat


class DeliveryStatus(str, Enum):
    QUEUED = "queued"
    DELIVERED = "delivered"
    ACKNOWLEDGED = "acknowledged"
    DEAD_LETTER = "dead_letter"


@dataclass
class Message:
    """A message between agents."""
    message_id: str = ""
    msg_type: MessageType = MessageType.STATUS_UPDATE
    priority: MessagePriority = MessagePriority.NORMAL
    sender_id: str = ""
    recipient_id: str = ""       # Empty = broadcast
    topic: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    reply_to: str = ""           # Message ID this replies to
    status: DeliveryStatus = DeliveryStatus.QUEUED
    created_at: float = field(default_factory=time.time)
    delivered_at: float = 0.0
    ttl_s: float = 300.0         # Time to live

    @property
    def expired(self) -> bool:
        return time.time() - self.created_at > self.ttl_s

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.message_id[:10],
            "type": self.msg_type.value,
            "from": self.sender_id[:10],
            "to": self.recipient_id[:10] or "broadcast",
            "topic": self.topic[:15],
            "status": self.status.value,
        }


@dataclass
class Subscription:
    """A topic subscription."""
    agent_id: str = ""
    topic: str = ""
    msg_types: list[MessageType] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id[:10],
            "topic": self.topic[:15],
            "types": [t.value for t in self.msg_types],
        }


PRIORITY_ORDER = {
    MessagePriority.CRITICAL: 0,
    MessagePriority.HIGH: 1,
    MessagePriority.NORMAL: 2,
    MessagePriority.LOW: 3,
}

# ── Message type to priority mapping ─────────────────────────

DEFAULT_PRIORITIES: dict[str, MessagePriority] = {
    "finding": MessagePriority.CRITICAL,
    "error": MessagePriority.CRITICAL,
    "task_assign": MessagePriority.HIGH,
    "task_complete": MessagePriority.HIGH,
    "task_failed": MessagePriority.HIGH,
    "budget_warning": MessagePriority.HIGH,
    "convergence_alert": MessagePriority.HIGH,
    "request": MessagePriority.NORMAL,
    "response": MessagePriority.NORMAL,
    "status_update": MessagePriority.NORMAL,
    "broadcast": MessagePriority.NORMAL,
    "heartbeat": MessagePriority.LOW,
}


class MessageBus:
    """Inter-agent communication bus.

    Provides pub/sub, direct messaging,
    and broadcast capabilities for agent
    coordination.
    """

    def __init__(
        self,
        max_queue_size: int = 1000,
        dead_letter_size: int = 100,
    ) -> None:
        self._queues: dict[str, deque[Message]] = defaultdict(
            lambda: deque(maxlen=max_queue_size),
        )
        self._subscriptions: dict[str, list[Subscription]] = defaultdict(list)
        self._history: list[Message] = []
        self._dead_letters: deque[Message] = deque(maxlen=dead_letter_size)
        self._counter = 0
        self._log = logger.bind(component="message_bus")

    def send(
        self,
        sender_id: str,
        recipient_id: str,
        msg_type: MessageType,
        payload: dict[str, Any] | None = None,
        topic: str = "",
        reply_to: str = "",
        priority: MessagePriority | None = None,
        ttl_s: float = 300.0,
    ) -> Message:
        """Send a message to a specific agent."""
        self._counter += 1
        prio = priority or DEFAULT_PRIORITIES.get(
            msg_type.value, MessagePriority.NORMAL,
        )

        msg = Message(
            message_id=f"msg-{self._counter}",
            msg_type=msg_type,
            priority=prio,
            sender_id=sender_id,
            recipient_id=recipient_id,
            topic=topic,
            payload=payload or {},
            reply_to=reply_to,
            ttl_s=ttl_s,
        )

        self._queues[recipient_id].append(msg)
        self._history.append(msg)
        return msg

    def broadcast(
        self,
        sender_id: str,
        msg_type: MessageType,
        payload: dict[str, Any] | None = None,
        topic: str = "",
    ) -> Message:
        """Broadcast a message to all agents."""
        self._counter += 1
        msg = Message(
            message_id=f"msg-{self._counter}",
            msg_type=msg_type,
            priority=DEFAULT_PRIORITIES.get(msg_type.value, MessagePriority.NORMAL),
            sender_id=sender_id,
            recipient_id="",
            topic=topic,
            payload=payload or {},
        )

        # Deliver to all queues
        for agent_id in list(self._queues.keys()):
            if agent_id != sender_id:
                self._queues[agent_id].append(msg)

        self._history.append(msg)
        return msg

    def publish(
        self,
        sender_id: str,
        topic: str,
        msg_type: MessageType,
        payload: dict[str, Any] | None = None,
    ) -> Message:
        """Publish a message to topic subscribers."""
        self._counter += 1
        msg = Message(
            message_id=f"msg-{self._counter}",
            msg_type=msg_type,
            priority=DEFAULT_PRIORITIES.get(msg_type.value, MessagePriority.NORMAL),
            sender_id=sender_id,
            topic=topic,
            payload=payload or {},
        )

        # Deliver to subscribers
        for sub in self._subscriptions.get(topic, []):
            if sub.agent_id == sender_id:
                continue
            if sub.msg_types and msg_type not in sub.msg_types:
                continue
            self._queues[sub.agent_id].append(msg)

        self._history.append(msg)
        return msg

    def subscribe(
        self,
        agent_id: str,
        topic: str,
        msg_types: list[MessageType] | None = None,
    ) -> Subscription:
        """Subscribe an agent to a topic."""
        sub = Subscription(
            agent_id=agent_id,
            topic=topic,
            msg_types=msg_types or [],
        )
        self._subscriptions[topic].append(sub)
        # Ensure queue exists
        _ = self._queues[agent_id]
        return sub

    def receive(
        self,
        agent_id: str,
        max_messages: int = 10,
    ) -> list[Message]:
        """Receive messages for an agent."""
        queue = self._queues.get(agent_id)
        if not queue:
            return []

        messages: list[Message] = []
        expired: list[Message] = []

        while queue and len(messages) < max_messages:
            msg = queue.popleft()
            if msg.expired:
                expired.append(msg)
                continue
            msg.status = DeliveryStatus.DELIVERED
            msg.delivered_at = time.time()
            messages.append(msg)

        # Move expired to dead letters
        for exp in expired:
            exp.status = DeliveryStatus.DEAD_LETTER
            self._dead_letters.append(exp)

        # Sort by priority
        messages.sort(key=lambda m: PRIORITY_ORDER.get(m.priority, 2))
        return messages

    def acknowledge(self, message_id: str) -> None:
        """Acknowledge message receipt."""
        for msg in self._history:
            if msg.message_id == message_id:
                msg.status = DeliveryStatus.ACKNOWLEDGED
                break

    def get_pending_count(self, agent_id: str) -> int:
        """Get number of pending messages for an agent."""
        return len(self._queues.get(agent_id, []))

    def get_stats(self) -> dict[str, Any]:
        total_pending = sum(len(q) for q in self._queues.values())
        type_counts: dict[str, int] = defaultdict(int)
        for msg in self._history[-100:]:
            type_counts[msg.msg_type.value] += 1

        return {
            "total_messages": len(self._history),
            "agents_registered": len(self._queues),
            "total_pending": total_pending,
            "dead_letters": len(self._dead_letters),
            "subscriptions": sum(
                len(subs) for subs in self._subscriptions.values()
            ),
            "recent_types": dict(type_counts),
        }
