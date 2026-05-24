"""Agent message bus — structured inter-agent communication.

Implements:
1. Typed message passing between agents
2. Publish-subscribe topics
3. Request-response patterns
4. Broadcast to agent groups
5. Message routing and filtering
6. Message history and audit trail
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

import structlog

logger = structlog.get_logger()


class MessageType(str, Enum):
    TASK = "task"               # Task assignment
    RESULT = "result"           # Task result
    FINDING = "finding"         # Security finding
    STATUS = "status"           # Status update
    REQUEST = "request"         # Request for info
    RESPONSE = "response"       # Response to request
    ALERT = "alert"             # Urgent notification
    BROADCAST = "broadcast"     # To all agents
    HEARTBEAT = "heartbeat"     # Alive signal
    SHUTDOWN = "shutdown"       # Shutdown signal


class MessagePriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


PRIORITY_VALUES: dict[MessagePriority, int] = {
    MessagePriority.CRITICAL: 4,
    MessagePriority.HIGH: 3,
    MessagePriority.NORMAL: 2,
    MessagePriority.LOW: 1,
}


@dataclass
class AgentMessage:
    """A message between agents."""
    message_id: str = ""
    msg_type: MessageType = MessageType.STATUS
    priority: MessagePriority = MessagePriority.NORMAL
    sender_id: str = ""
    receiver_id: str = ""        # Empty = broadcast
    topic: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    reply_to: str = ""           # message_id being replied to
    ttl: int = 300               # Time-to-live in seconds
    timestamp: float = field(default_factory=time.time)
    delivered: bool = False
    read: bool = False

    @property
    def is_expired(self) -> bool:
        return time.time() - self.timestamp > self.ttl

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.message_id[:10],
            "type": self.msg_type.value[:6],
            "from": self.sender_id[:10],
            "to": self.receiver_id[:10] or "ALL",
            "topic": self.topic[:12],
        }


@dataclass
class Subscription:
    """A topic subscription."""
    subscriber_id: str = ""
    topic: str = ""
    msg_types: list[MessageType] = field(default_factory=list)
    callback: Callable[[AgentMessage], None] | None = None


class AgentMessageBus:
    """Structured message passing between agents.

    Supports direct messaging, pub-sub topics,
    request-response, and broadcast patterns.
    """

    def __init__(self, max_history: int = 1000) -> None:
        self._messages: deque[AgentMessage] = deque(maxlen=max_history)
        self._queues: dict[str, deque[AgentMessage]] = {}  # agent_id → inbox
        self._subscriptions: dict[str, list[Subscription]] = {}  # topic → subs
        self._msg_counter = 0
        self._delivered_count = 0
        self._log = logger.bind(component="msg_bus")

    def register_agent(self, agent_id: str) -> None:
        """Register an agent with an inbox."""
        if agent_id not in self._queues:
            self._queues[agent_id] = deque(maxlen=200)

    def unregister_agent(self, agent_id: str) -> None:
        """Remove an agent."""
        self._queues.pop(agent_id, None)
        # Remove subscriptions
        for topic in list(self._subscriptions.keys()):
            self._subscriptions[topic] = [
                s for s in self._subscriptions[topic]
                if s.subscriber_id != agent_id
            ]

    def subscribe(
        self,
        agent_id: str,
        topic: str,
        msg_types: list[MessageType] | None = None,
        callback: Callable[[AgentMessage], None] | None = None,
    ) -> None:
        """Subscribe an agent to a topic."""
        sub = Subscription(
            subscriber_id=agent_id,
            topic=topic,
            msg_types=msg_types or [],
            callback=callback,
        )
        self._subscriptions.setdefault(topic, []).append(sub)

    def send(
        self,
        sender_id: str,
        receiver_id: str = "",
        msg_type: MessageType = MessageType.STATUS,
        priority: MessagePriority = MessagePriority.NORMAL,
        topic: str = "",
        payload: dict[str, Any] | None = None,
        reply_to: str = "",
    ) -> AgentMessage:
        """Send a message."""
        self._msg_counter += 1

        msg = AgentMessage(
            message_id=f"msg-{self._msg_counter}",
            msg_type=msg_type,
            priority=priority,
            sender_id=sender_id,
            receiver_id=receiver_id,
            topic=topic,
            payload=payload or {},
            reply_to=reply_to,
        )

        self._messages.append(msg)

        # Direct message
        if receiver_id and receiver_id in self._queues:
            self._queues[receiver_id].append(msg)
            msg.delivered = True
            self._delivered_count += 1

        # Broadcast (no receiver)
        elif not receiver_id:
            for agent_id, queue in self._queues.items():
                if agent_id != sender_id:
                    queue.append(msg)
                    self._delivered_count += 1
            msg.delivered = True

        # Topic-based delivery
        if topic and topic in self._subscriptions:
            for sub in self._subscriptions[topic]:
                if sub.subscriber_id == sender_id:
                    continue
                if sub.msg_types and msg_type not in sub.msg_types:
                    continue

                # Deliver to subscriber inbox
                if sub.subscriber_id in self._queues:
                    self._queues[sub.subscriber_id].append(msg)
                    self._delivered_count += 1

                # Invoke callback if registered
                if sub.callback:
                    try:
                        sub.callback(msg)
                    except Exception:
                        pass

        return msg

    def receive(
        self,
        agent_id: str,
        msg_type: MessageType | None = None,
        topic: str = "",
        max_messages: int = 10,
    ) -> list[AgentMessage]:
        """Receive messages from inbox."""
        queue = self._queues.get(agent_id)
        if not queue:
            return []

        received = []
        remaining: deque[AgentMessage] = deque()

        for msg in queue:
            if msg.is_expired:
                continue

            matches = True
            if msg_type and msg.msg_type != msg_type:
                matches = False
            if topic and msg.topic != topic:
                matches = False

            if matches and len(received) < max_messages:
                msg.read = True
                received.append(msg)
            else:
                remaining.append(msg)

        self._queues[agent_id] = remaining

        # Sort by priority
        received.sort(
            key=lambda m: PRIORITY_VALUES.get(m.priority, 2),
            reverse=True,
        )

        return received

    def peek(self, agent_id: str) -> int:
        """Check number of pending messages."""
        queue = self._queues.get(agent_id)
        if not queue:
            return 0
        return len([m for m in queue if not m.is_expired])

    def send_finding(
        self,
        sender_id: str,
        finding: dict[str, Any],
        severity: str = "medium",
    ) -> AgentMessage:
        """Convenience: send a finding to the findings topic."""
        priority = MessagePriority.NORMAL
        if severity in ("critical", "high"):
            priority = MessagePriority.HIGH

        return self.send(
            sender_id=sender_id,
            msg_type=MessageType.FINDING,
            priority=priority,
            topic="findings",
            payload=finding,
        )

    def request(
        self,
        sender_id: str,
        receiver_id: str,
        topic: str,
        payload: dict[str, Any] | None = None,
    ) -> AgentMessage:
        """Send a request message."""
        return self.send(
            sender_id=sender_id,
            receiver_id=receiver_id,
            msg_type=MessageType.REQUEST,
            topic=topic,
            payload=payload or {},
        )

    def respond(
        self,
        sender_id: str,
        original_msg: AgentMessage,
        payload: dict[str, Any] | None = None,
    ) -> AgentMessage:
        """Respond to a request."""
        return self.send(
            sender_id=sender_id,
            receiver_id=original_msg.sender_id,
            msg_type=MessageType.RESPONSE,
            topic=original_msg.topic,
            payload=payload or {},
            reply_to=original_msg.message_id,
        )

    def build_bus_prompt(self, agent_id: str = "") -> str:
        """Build message bus context for LLM."""
        lines = ["## Message Bus\n"]
        lines.append(f"Agents: {len(self._queues)}")
        lines.append(f"Topics: {len(self._subscriptions)}")
        lines.append(f"Total messages: {len(self._messages)}")

        if agent_id:
            pending = self.peek(agent_id)
            lines.append(f"\nInbox ({agent_id[:10]}): {pending} pending")

            recent = list(self._queues.get(agent_id, []))[-3:]
            for msg in recent:
                lines.append(
                    f"  [{msg.priority.value[:4]}] {msg.msg_type.value[:6]} "
                    f"from {msg.sender_id[:10]}"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for m in self._messages:
            t = m.msg_type.value
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "agents": len(self._queues),
            "topics": len(self._subscriptions),
            "total_messages": len(self._messages),
            "delivered": self._delivered_count,
            "by_type": type_counts,
        }
