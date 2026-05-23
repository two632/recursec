"""Agent messaging — inter-agent communication protocol.

Implements:
1. Typed message passing between agents
2. Request/response patterns
3. Broadcast and multicast
4. Priority message queuing
5. Message routing by role
6. Conversation threading
7. Delivery guarantees (at-least-once)
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MessageType(str, Enum):
    TASK_ASSIGN = "task_assign"
    TASK_RESULT = "task_result"
    FINDING = "finding"
    QUERY = "query"
    RESPONSE = "response"
    STATUS_UPDATE = "status_update"
    CONTEXT_SHARE = "context_share"
    ESCALATION = "escalation"
    ABORT = "abort"
    HEARTBEAT = "heartbeat"


class MessagePriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


class DeliveryStatus(str, Enum):
    QUEUED = "queued"
    DELIVERED = "delivered"
    ACKNOWLEDGED = "acknowledged"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class AgentMessage:
    """A message between agents."""
    message_id: str = ""
    msg_type: MessageType = MessageType.QUERY
    priority: MessagePriority = MessagePriority.NORMAL
    sender_id: str = ""
    receiver_id: str = ""           # Empty = broadcast
    receiver_role: str = ""         # Role-based routing
    thread_id: str = ""             # Conversation thread
    parent_msg_id: str = ""         # Reply-to
    content: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    delivery: DeliveryStatus = DeliveryStatus.QUEUED
    created_at: float = field(default_factory=time.time)
    delivered_at: float = 0.0
    ttl_s: float = 300.0            # Time to live
    retry_count: int = 0

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl_s

    @property
    def priority_score(self) -> int:
        return {
            MessagePriority.CRITICAL: 4,
            MessagePriority.HIGH: 3,
            MessagePriority.NORMAL: 2,
            MessagePriority.LOW: 1,
        }.get(self.priority, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.message_id[:10],
            "type": self.msg_type.value,
            "from": self.sender_id[:10],
            "to": self.receiver_id[:10] or self.receiver_role[:10] or "broadcast",
            "delivery": self.delivery.value,
        }


@dataclass
class MessageThread:
    """A conversation thread between agents."""
    thread_id: str = ""
    participants: list[str] = field(default_factory=list)
    message_ids: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    topic: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.thread_id[:10],
            "participants": len(self.participants),
            "messages": len(self.message_ids),
            "topic": self.topic[:20],
        }


@dataclass
class AgentMailbox:
    """Per-agent message queue."""
    agent_id: str = ""
    agent_role: str = ""
    inbox: deque[str] = field(default_factory=deque)
    processed: int = 0
    last_read: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id[:10],
            "role": self.agent_role[:10],
            "pending": len(self.inbox),
            "processed": self.processed,
        }


class AgentMessageBus:
    """Message bus for inter-agent communication.

    Routes messages between agents by ID or role,
    handles priority queuing, threading, and
    delivery guarantees.
    """

    MAX_RETRY = 3

    def __init__(self) -> None:
        self._messages: dict[str, AgentMessage] = {}
        self._mailboxes: dict[str, AgentMailbox] = {}
        self._threads: dict[str, MessageThread] = {}
        self._role_registry: dict[str, list[str]] = {}  # role → [agent_ids]
        self._counter = 0
        self._log = logger.bind(component="agent_messaging")

    def register_agent(self, agent_id: str, role: str = "") -> AgentMailbox:
        """Register an agent with the message bus."""
        mailbox = AgentMailbox(agent_id=agent_id, agent_role=role)
        self._mailboxes[agent_id] = mailbox

        if role:
            self._role_registry.setdefault(role, []).append(agent_id)

        return mailbox

    def unregister_agent(self, agent_id: str) -> None:
        """Remove an agent from the message bus."""
        mailbox = self._mailboxes.pop(agent_id, None)
        if mailbox and mailbox.agent_role:
            agents = self._role_registry.get(mailbox.agent_role, [])
            if agent_id in agents:
                agents.remove(agent_id)

    def send(
        self,
        sender_id: str,
        msg_type: MessageType,
        content: str,
        receiver_id: str = "",
        receiver_role: str = "",
        priority: MessagePriority = MessagePriority.NORMAL,
        thread_id: str = "",
        parent_msg_id: str = "",
        payload: dict[str, Any] | None = None,
        ttl_s: float = 300.0,
    ) -> AgentMessage:
        """Send a message."""
        self._counter += 1
        msg = AgentMessage(
            message_id=f"msg-{self._counter}",
            msg_type=msg_type,
            priority=priority,
            sender_id=sender_id,
            receiver_id=receiver_id,
            receiver_role=receiver_role,
            thread_id=thread_id or f"thread-{self._counter}",
            parent_msg_id=parent_msg_id,
            content=content,
            payload=payload or {},
            ttl_s=ttl_s,
        )

        self._messages[msg.message_id] = msg

        # Track thread
        thread = self._threads.get(msg.thread_id)
        if not thread:
            thread = MessageThread(
                thread_id=msg.thread_id,
                topic=content[:50],
            )
            self._threads[msg.thread_id] = thread
        thread.message_ids.append(msg.message_id)
        if sender_id not in thread.participants:
            thread.participants.append(sender_id)

        # Route message
        self._route(msg)

        return msg

    def receive(
        self,
        agent_id: str,
        limit: int = 10,
        msg_types: list[MessageType] | None = None,
    ) -> list[AgentMessage]:
        """Receive messages for an agent."""
        mailbox = self._mailboxes.get(agent_id)
        if not mailbox:
            return []

        received: list[AgentMessage] = []
        remaining: deque[str] = deque()

        while mailbox.inbox and len(received) < limit:
            msg_id = mailbox.inbox.popleft()
            msg = self._messages.get(msg_id)
            if not msg:
                continue
            if msg.is_expired:
                msg.delivery = DeliveryStatus.EXPIRED
                continue
            if msg_types and msg.msg_type not in msg_types:
                remaining.append(msg_id)
                continue

            msg.delivery = DeliveryStatus.DELIVERED
            msg.delivered_at = time.time()
            received.append(msg)
            mailbox.processed += 1

        # Put back unmatched
        remaining.extend(mailbox.inbox)
        mailbox.inbox = remaining
        mailbox.last_read = time.time()

        # Sort by priority
        received.sort(key=lambda m: m.priority_score, reverse=True)
        return received

    def acknowledge(self, message_id: str) -> None:
        """Acknowledge a message."""
        msg = self._messages.get(message_id)
        if msg:
            msg.delivery = DeliveryStatus.ACKNOWLEDGED

    def broadcast(
        self,
        sender_id: str,
        msg_type: MessageType,
        content: str,
        priority: MessagePriority = MessagePriority.NORMAL,
    ) -> list[AgentMessage]:
        """Broadcast a message to all agents."""
        messages: list[AgentMessage] = []
        for agent_id in self._mailboxes:
            if agent_id == sender_id:
                continue
            msg = self.send(
                sender_id=sender_id,
                msg_type=msg_type,
                content=content,
                receiver_id=agent_id,
                priority=priority,
            )
            messages.append(msg)
        return messages

    def get_thread(self, thread_id: str) -> list[AgentMessage]:
        """Get all messages in a thread."""
        thread = self._threads.get(thread_id)
        if not thread:
            return []
        return [
            self._messages[mid]
            for mid in thread.message_ids
            if mid in self._messages
        ]

    def build_messaging_prompt(self, agent_id: str) -> str:
        """Build messaging context for LLM."""
        lines = ["## Messages\n"]

        mailbox = self._mailboxes.get(agent_id)
        if not mailbox:
            lines.append("No mailbox registered.")
            return "\n".join(lines)

        pending = len(mailbox.inbox)
        lines.append(f"Pending messages: {pending}")
        lines.append(f"Processed: {mailbox.processed}")

        # Show most recent unread
        if mailbox.inbox:
            lines.append("\nRecent unread:")
            for msg_id in list(mailbox.inbox)[:3]:
                msg = self._messages.get(msg_id)
                if msg:
                    lines.append(
                        f"  [{msg.msg_type.value}] from {msg.sender_id[:10]}: "
                        f"{msg.content[:40]}"
                    )

        return "\n".join(lines)

    def _route(self, msg: AgentMessage) -> None:
        """Route a message to the appropriate mailbox(es)."""
        targets: list[str] = []

        if msg.receiver_id:
            targets = [msg.receiver_id]
        elif msg.receiver_role:
            targets = self._role_registry.get(msg.receiver_role, [])
        else:
            # Broadcast to all except sender
            targets = [
                aid for aid in self._mailboxes
                if aid != msg.sender_id
            ]

        for target_id in targets:
            mailbox = self._mailboxes.get(target_id)
            if mailbox:
                mailbox.inbox.append(msg.message_id)
            else:
                msg.delivery = DeliveryStatus.FAILED

    def retry_failed(self) -> int:
        """Retry failed message deliveries."""
        retried = 0
        for msg in self._messages.values():
            if msg.delivery == DeliveryStatus.FAILED and msg.retry_count < self.MAX_RETRY:
                msg.retry_count += 1
                self._route(msg)
                retried += 1
        return retried

    def get_stats(self) -> dict[str, Any]:
        delivery_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}
        for msg in self._messages.values():
            delivery_counts[msg.delivery.value] = delivery_counts.get(msg.delivery.value, 0) + 1
            type_counts[msg.msg_type.value] = type_counts.get(msg.msg_type.value, 0) + 1

        return {
            "total_messages": len(self._messages),
            "agents": len(self._mailboxes),
            "threads": len(self._threads),
            "by_delivery": delivery_counts,
            "by_type": type_counts,
        }
