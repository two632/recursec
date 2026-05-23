"""Agent communication bus — inter-agent message passing.

Implements:
1. Typed message passing between agents
2. Publish-subscribe topics
3. Request-response patterns
4. Broadcast messages
5. Priority-based message queuing
6. Message history and replay
7. Communication context for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MessageType(str, Enum):
    TASK = "task"               # Task assignment
    RESULT = "result"           # Task completion result
    FINDING = "finding"         # Security finding
    QUERY = "query"             # Information request
    RESPONSE = "response"       # Query response
    STATUS = "status"           # Status update
    ALERT = "alert"             # Urgent notification
    BROADCAST = "broadcast"     # Message to all agents


class MessagePriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


@dataclass
class AgentMessage:
    """A message between agents."""
    msg_id: str = ""
    msg_type: MessageType = MessageType.STATUS
    priority: MessagePriority = MessagePriority.NORMAL
    sender_id: str = ""
    recipient_id: str = ""     # Empty for broadcasts
    topic: str = ""
    content: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    reply_to: str = ""         # msg_id of message being replied to
    delivered: bool = False
    read: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.msg_id[:8],
            "type": self.msg_type.value[:6],
            "from": self.sender_id[:8],
            "to": self.recipient_id[:8] if self.recipient_id else "all",
            "topic": self.topic[:15],
            "read": self.read,
        }


class AgentCommBus:
    """Inter-agent communication bus.

    Provides typed message passing, pub-sub topics,
    request-response, and broadcast for agent coordination.
    """

    def __init__(self, max_queue_size: int = 1000) -> None:
        self._messages: list[AgentMessage] = []
        self._queues: dict[str, list[AgentMessage]] = {}  # agent_id → messages
        self._subscriptions: dict[str, set[str]] = {}      # topic → {agent_ids}
        self._max_queue = max_queue_size
        self._counter = 0
        self._log = logger.bind(component="agent_comm_bus")

    def send(
        self,
        sender_id: str,
        recipient_id: str,
        msg_type: MessageType,
        content: str,
        topic: str = "",
        payload: dict[str, Any] | None = None,
        priority: MessagePriority = MessagePriority.NORMAL,
        reply_to: str = "",
    ) -> AgentMessage:
        """Send a message to a specific agent."""
        self._counter += 1
        msg = AgentMessage(
            msg_id=f"msg-{self._counter}",
            msg_type=msg_type,
            priority=priority,
            sender_id=sender_id,
            recipient_id=recipient_id,
            topic=topic,
            content=content,
            payload=payload or {},
            reply_to=reply_to,
        )

        self._messages.append(msg)
        self._enqueue(recipient_id, msg)

        return msg

    def broadcast(
        self,
        sender_id: str,
        content: str,
        topic: str = "",
        payload: dict[str, Any] | None = None,
        priority: MessagePriority = MessagePriority.NORMAL,
    ) -> AgentMessage:
        """Broadcast a message to all agents."""
        self._counter += 1
        msg = AgentMessage(
            msg_id=f"msg-{self._counter}",
            msg_type=MessageType.BROADCAST,
            priority=priority,
            sender_id=sender_id,
            topic=topic,
            content=content,
            payload=payload or {},
        )

        self._messages.append(msg)

        # Deliver to all queues
        for agent_id in self._queues:
            if agent_id != sender_id:
                self._enqueue(agent_id, msg)

        return msg

    def publish(
        self,
        sender_id: str,
        topic: str,
        content: str,
        payload: dict[str, Any] | None = None,
    ) -> AgentMessage:
        """Publish to a topic (deliver to all subscribers)."""
        self._counter += 1
        msg = AgentMessage(
            msg_id=f"msg-{self._counter}",
            msg_type=MessageType.STATUS,
            sender_id=sender_id,
            topic=topic,
            content=content,
            payload=payload or {},
        )

        self._messages.append(msg)

        # Deliver to subscribers
        subscribers = self._subscriptions.get(topic, set())
        for agent_id in subscribers:
            if agent_id != sender_id:
                self._enqueue(agent_id, msg)

        return msg

    def subscribe(self, agent_id: str, topic: str) -> None:
        """Subscribe an agent to a topic."""
        self._subscriptions.setdefault(topic, set()).add(agent_id)

    def unsubscribe(self, agent_id: str, topic: str) -> None:
        """Unsubscribe an agent from a topic."""
        subs = self._subscriptions.get(topic, set())
        subs.discard(agent_id)

    def receive(
        self,
        agent_id: str,
        msg_type: MessageType | None = None,
        max_messages: int = 10,
    ) -> list[AgentMessage]:
        """Receive messages for an agent."""
        queue = self._queues.get(agent_id, [])
        results: list[AgentMessage] = []

        for msg in queue:
            if msg.read:
                continue
            if msg_type and msg.msg_type != msg_type:
                continue
            msg.read = True
            msg.delivered = True
            results.append(msg)
            if len(results) >= max_messages:
                break

        return results

    def register_agent(self, agent_id: str) -> None:
        """Register an agent to receive messages."""
        if agent_id not in self._queues:
            self._queues[agent_id] = []

    def get_unread_count(self, agent_id: str) -> int:
        """Get count of unread messages for an agent."""
        queue = self._queues.get(agent_id, [])
        return sum(1 for m in queue if not m.read)

    def build_comm_prompt(self, agent_id: str = "") -> str:
        """Build communication context for LLM."""
        lines = ["## Agent Communication\n"]

        lines.append(
            f"Agents: {len(self._queues)} | "
            f"Messages: {len(self._messages)} | "
            f"Topics: {len(self._subscriptions)}"
        )

        if agent_id:
            unread = self.get_unread_count(agent_id)
            lines.append(f"\nYour inbox: {unread} unread")

            # Show recent unread
            queue = self._queues.get(agent_id, [])
            unread_msgs = [m for m in queue if not m.read]
            if unread_msgs:
                lines.append("Recent messages:")
                for m in unread_msgs[:5]:
                    lines.append(
                        f"  [{m.priority.value[0].upper()}] "
                        f"{m.sender_id[:8]} → {m.content[:30]}"
                    )

        return "\n".join(lines)

    def _enqueue(self, agent_id: str, msg: AgentMessage) -> None:
        """Add message to agent's queue."""
        self._queues.setdefault(agent_id, [])
        queue = self._queues[agent_id]

        # Enforce max queue size (remove oldest low-priority)
        while len(queue) >= self._max_queue:
            # Find lowest priority read message
            for i, m in enumerate(queue):
                if m.read and m.priority.value in ("low", "normal"):
                    queue.pop(i)
                    break
            else:
                queue.pop(0)

        queue.append(msg)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for m in self._messages:
            type_counts[m.msg_type.value] = type_counts.get(m.msg_type.value, 0) + 1

        return {
            "total_messages": len(self._messages),
            "agents": len(self._queues),
            "topics": len(self._subscriptions),
            "by_type": type_counts,
        }
