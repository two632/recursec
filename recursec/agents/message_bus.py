"""Message bus — inter-agent communication backbone.

Implements:
1. Publish/subscribe messaging
2. Point-to-point messaging
3. Request/response patterns
4. Message routing by topic
5. Message priority queues
6. Dead letter handling
7. Message TTL and expiry
8. Backpressure management
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

import structlog

logger = structlog.get_logger()


class MessageType(str, Enum):
    REQUEST = "request"
    RESPONSE = "response"
    EVENT = "event"
    BROADCAST = "broadcast"
    COMMAND = "command"
    HEARTBEAT = "heartbeat"


class MessagePriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


@dataclass
class Message:
    """An inter-agent message."""
    message_id: str = ""
    message_type: MessageType = MessageType.EVENT
    priority: MessagePriority = MessagePriority.NORMAL
    sender: str = ""
    recipient: str = ""            # Empty for broadcast/pub
    topic: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    correlation_id: str = ""       # Links request/response
    ttl_s: float = 300.0           # Time to live
    created_at: float = field(default_factory=time.time)
    delivered_at: float = 0.0
    acknowledged: bool = False

    @property
    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.ttl_s

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.message_id,
            "type": self.message_type.value,
            "priority": self.priority.value,
            "sender": self.sender[:15],
            "recipient": self.recipient[:15],
            "topic": self.topic[:20],
            "expired": self.is_expired,
        }


@dataclass
class Subscription:
    """A topic subscription."""
    subscriber: str = ""
    topic: str = ""
    handler: Callable[[Message], None] | None = None
    filter_fn: Callable[[Message], bool] | None = None
    created_at: float = field(default_factory=time.time)


class MessageBus:
    """Inter-agent communication backbone.

    Supports pub/sub, point-to-point, and request/response
    patterns with priority queues and backpressure.
    """

    def __init__(
        self,
        max_queue_size: int = 1000,
        max_dead_letters: int = 100,
    ) -> None:
        # Per-agent message queues
        self._queues: dict[str, deque[Message]] = defaultdict(deque)
        # Topic subscriptions
        self._subscriptions: dict[str, list[Subscription]] = defaultdict(list)
        # Pending responses
        self._pending_responses: dict[str, Message] = {}
        # Dead letter queue
        self._dead_letters: deque[Message] = deque(maxlen=max_dead_letters)
        self._msg_counter = 0
        self._max_queue = max_queue_size
        self._total_sent = 0
        self._total_delivered = 0
        self._total_expired = 0
        self._log = logger.bind(component="message_bus")

    def send(
        self,
        sender: str,
        recipient: str,
        topic: str,
        payload: dict[str, Any],
        message_type: MessageType = MessageType.REQUEST,
        priority: MessagePriority = MessagePriority.NORMAL,
        ttl_s: float = 300.0,
        correlation_id: str = "",
    ) -> str:
        """Send a point-to-point message."""
        self._msg_counter += 1
        msg_id = f"msg-{self._msg_counter}"

        msg = Message(
            message_id=msg_id,
            message_type=message_type,
            priority=priority,
            sender=sender,
            recipient=recipient,
            topic=topic,
            payload=payload,
            correlation_id=correlation_id,
            ttl_s=ttl_s,
        )

        self._enqueue(recipient, msg)
        self._total_sent += 1

        return msg_id

    def publish(
        self,
        sender: str,
        topic: str,
        payload: dict[str, Any],
        priority: MessagePriority = MessagePriority.NORMAL,
    ) -> str:
        """Publish a message to a topic (all subscribers)."""
        self._msg_counter += 1
        msg_id = f"msg-{self._msg_counter}"

        msg = Message(
            message_id=msg_id,
            message_type=MessageType.EVENT,
            priority=priority,
            sender=sender,
            topic=topic,
            payload=payload,
        )

        # Deliver to all subscribers
        subs = self._subscriptions.get(topic, [])
        for sub in subs:
            if sub.filter_fn and not sub.filter_fn(msg):
                continue

            self._enqueue(sub.subscriber, msg)

            if sub.handler:
                try:
                    sub.handler(msg)
                except Exception:
                    pass

        self._total_sent += 1
        return msg_id

    def subscribe(
        self,
        subscriber: str,
        topic: str,
        handler: Callable[[Message], None] | None = None,
        filter_fn: Callable[[Message], bool] | None = None,
    ) -> None:
        """Subscribe to a topic."""
        sub = Subscription(
            subscriber=subscriber,
            topic=topic,
            handler=handler,
            filter_fn=filter_fn,
        )
        self._subscriptions[topic].append(sub)

    def unsubscribe(self, subscriber: str, topic: str) -> None:
        """Unsubscribe from a topic."""
        if topic in self._subscriptions:
            self._subscriptions[topic] = [
                s for s in self._subscriptions[topic]
                if s.subscriber != subscriber
            ]

    def receive(
        self,
        agent_id: str,
        max_messages: int = 10,
    ) -> list[Message]:
        """Receive messages for an agent."""
        queue = self._queues.get(agent_id)
        if not queue:
            return []

        messages = []
        while queue and len(messages) < max_messages:
            msg = queue.popleft()

            if msg.is_expired:
                self._dead_letters.append(msg)
                self._total_expired += 1
                continue

            msg.delivered_at = time.time()
            messages.append(msg)
            self._total_delivered += 1

        return messages

    def request_response(
        self,
        sender: str,
        recipient: str,
        topic: str,
        payload: dict[str, Any],
        timeout_s: float = 30.0,
    ) -> str:
        """Send a request and get a correlation ID for the response."""
        self._msg_counter += 1
        correlation_id = f"corr-{self._msg_counter}"

        self.send(
            sender=sender,
            recipient=recipient,
            topic=topic,
            payload=payload,
            message_type=MessageType.REQUEST,
            correlation_id=correlation_id,
            ttl_s=timeout_s,
        )

        return correlation_id

    def respond(
        self,
        sender: str,
        correlation_id: str,
        payload: dict[str, Any],
    ) -> str:
        """Send a response to a request."""
        # Find the original request to get the sender
        original_sender = ""
        for queue in self._queues.values():
            for msg in queue:
                if msg.correlation_id == correlation_id:
                    original_sender = msg.sender
                    break

        if not original_sender:
            # Check delivered messages — store response for pickup
            self._msg_counter += 1
            msg_id = f"msg-{self._msg_counter}"
            msg = Message(
                message_id=msg_id,
                message_type=MessageType.RESPONSE,
                sender=sender,
                correlation_id=correlation_id,
                payload=payload,
            )
            self._pending_responses[correlation_id] = msg
            return msg_id

        return self.send(
            sender=sender,
            recipient=original_sender,
            topic="response",
            payload=payload,
            message_type=MessageType.RESPONSE,
            correlation_id=correlation_id,
        )

    def get_response(self, correlation_id: str) -> Message | None:
        """Get a pending response by correlation ID."""
        return self._pending_responses.pop(correlation_id, None)

    def acknowledge(self, message_id: str) -> None:
        """Acknowledge a message."""
        # Walk queues to find and mark acknowledged
        for queue in self._queues.values():
            for msg in queue:
                if msg.message_id == message_id:
                    msg.acknowledged = True
                    return

    def broadcast(
        self,
        sender: str,
        payload: dict[str, Any],
        priority: MessagePriority = MessagePriority.NORMAL,
    ) -> str:
        """Broadcast to all agents."""
        self._msg_counter += 1
        msg_id = f"msg-{self._msg_counter}"

        msg = Message(
            message_id=msg_id,
            message_type=MessageType.BROADCAST,
            priority=priority,
            sender=sender,
            topic="broadcast",
            payload=payload,
        )

        for agent_id in self._queues:
            if agent_id != sender:
                self._enqueue(agent_id, msg)

        self._total_sent += 1
        return msg_id

    def _enqueue(self, agent_id: str, msg: Message) -> bool:
        """Enqueue a message for an agent."""
        queue = self._queues[agent_id]

        # Backpressure: drop lowest priority if full
        if len(queue) >= self._max_queue:
            # Find lowest priority message
            lowest_idx = 0
            lowest_priority = 10
            priority_order = {
                MessagePriority.CRITICAL: 4,
                MessagePriority.HIGH: 3,
                MessagePriority.NORMAL: 2,
                MessagePriority.LOW: 1,
            }
            for i, existing in enumerate(queue):
                p = priority_order.get(existing.priority, 2)
                if p < lowest_priority:
                    lowest_priority = p
                    lowest_idx = i

            msg_priority = priority_order.get(msg.priority, 2)
            if msg_priority > lowest_priority:
                dropped = queue[lowest_idx]
                del queue[lowest_idx]
                self._dead_letters.append(dropped)
            else:
                self._dead_letters.append(msg)
                return False

        queue.append(msg)
        return True

    def get_queue_sizes(self) -> dict[str, int]:
        return {agent: len(q) for agent, q in self._queues.items()}

    def cleanup_expired(self) -> int:
        """Remove expired messages from all queues."""
        removed = 0
        for agent_id in list(self._queues.keys()):
            queue = self._queues[agent_id]
            new_queue: deque[Message] = deque()
            for msg in queue:
                if msg.is_expired:
                    self._dead_letters.append(msg)
                    removed += 1
                    self._total_expired += 1
                else:
                    new_queue.append(msg)
            self._queues[agent_id] = new_queue
        return removed

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_sent": self._total_sent,
            "total_delivered": self._total_delivered,
            "total_expired": self._total_expired,
            "dead_letters": len(self._dead_letters),
            "queues": len(self._queues),
            "subscriptions": sum(len(s) for s in self._subscriptions.values()),
            "pending_responses": len(self._pending_responses),
        }
