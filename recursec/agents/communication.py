"""Inter-agent communication protocol — message passing between agents.

Implements a structured message bus for agent-to-agent communication.
Agents can:
- Send direct messages to specific agents
- Broadcast to all agents of a certain type
- Subscribe to topic channels
- Share findings, requests, and coordination signals
- Implement request/response patterns
- Priority-based message ordering

Message types:
- FINDING: Share a discovered vulnerability
- REQUEST: Ask another agent to do something
- RESPONSE: Reply to a request
- COORDINATION: Sync signal (start, pause, resume, stop)
- CONTEXT: Share context/information
- QUERY: Ask a question (expects response)
- ALERT: Urgent notification (e.g., critical finding)
- STATUS: Agent status update
- DELEGATION: Delegate a task to another agent
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine

import structlog

logger = structlog.get_logger()


class MessageType(str, Enum):
    FINDING = "finding"
    REQUEST = "request"
    RESPONSE = "response"
    COORDINATION = "coordination"
    CONTEXT = "context"
    QUERY = "query"
    ALERT = "alert"
    STATUS = "status"
    DELEGATION = "delegation"
    FEEDBACK = "feedback"


class MessagePriority(int, Enum):
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


class CoordinationSignal(str, Enum):
    START = "start"
    PAUSE = "pause"
    RESUME = "resume"
    STOP = "stop"
    CHECKPOINT = "checkpoint"
    REPLAN = "replan"
    ESCALATE = "escalate"


@dataclass
class AgentMessage:
    """A message between agents."""
    message_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    sender_id: str = ""
    receiver_id: str = ""  # Empty = broadcast
    message_type: MessageType = MessageType.CONTEXT
    priority: MessagePriority = MessagePriority.NORMAL
    topic: str = ""  # Channel/topic for pub-sub
    subject: str = ""
    body: dict[str, Any] = field(default_factory=dict)
    reply_to: str = ""  # message_id this is replying to
    correlation_id: str = ""  # Groups related messages
    timestamp: float = field(default_factory=time.time)
    ttl_s: float = 300.0  # Time-to-live in seconds
    requires_ack: bool = False
    acked: bool = False

    @property
    def is_expired(self) -> bool:
        return time.time() - self.timestamp > self.ttl_s

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.message_id, "sender": self.sender_id,
            "receiver": self.receiver_id, "type": self.message_type.value,
            "priority": self.priority.value, "topic": self.topic,
            "subject": self.subject, "body": self.body,
            "reply_to": self.reply_to, "correlation_id": self.correlation_id,
            "timestamp": self.timestamp,
        }

    @classmethod
    def finding(cls, sender: str, finding_data: dict[str, Any], severity: str = "medium") -> AgentMessage:
        """Create a finding message."""
        priority = {
            "critical": MessagePriority.CRITICAL, "high": MessagePriority.HIGH,
            "medium": MessagePriority.NORMAL, "low": MessagePriority.LOW,
        }.get(severity, MessagePriority.NORMAL)

        return cls(
            sender_id=sender, message_type=MessageType.FINDING,
            priority=priority, topic="findings",
            subject=finding_data.get("title", "Finding"),
            body=finding_data,
        )

    @classmethod
    def request(cls, sender: str, receiver: str, action: str, params: dict[str, Any] | None = None) -> AgentMessage:
        """Create a request message."""
        return cls(
            sender_id=sender, receiver_id=receiver,
            message_type=MessageType.REQUEST,
            subject=action, body=params or {},
            requires_ack=True,
            correlation_id=str(uuid.uuid4())[:8],
        )

    @classmethod
    def delegation(cls, sender: str, receiver: str, task: dict[str, Any]) -> AgentMessage:
        """Create a delegation message."""
        return cls(
            sender_id=sender, receiver_id=receiver,
            message_type=MessageType.DELEGATION,
            priority=MessagePriority.HIGH,
            subject=task.get("name", "delegated_task"),
            body=task, requires_ack=True,
            correlation_id=str(uuid.uuid4())[:8],
        )

    @classmethod
    def alert(cls, sender: str, title: str, details: dict[str, Any] | None = None) -> AgentMessage:
        """Create an alert message (broadcast)."""
        return cls(
            sender_id=sender, message_type=MessageType.ALERT,
            priority=MessagePriority.CRITICAL,
            topic="alerts", subject=title,
            body=details or {},
        )

    @classmethod
    def coordination(cls, sender: str, signal: CoordinationSignal, data: dict[str, Any] | None = None) -> AgentMessage:
        """Create a coordination signal."""
        return cls(
            sender_id=sender, message_type=MessageType.COORDINATION,
            priority=MessagePriority.HIGH,
            topic="coordination", subject=signal.value,
            body=data or {},
        )

    def reply(self, sender: str, body: dict[str, Any]) -> AgentMessage:
        """Create a reply to this message."""
        return AgentMessage(
            sender_id=sender, receiver_id=self.sender_id,
            message_type=MessageType.RESPONSE,
            reply_to=self.message_id,
            correlation_id=self.correlation_id,
            subject=f"Re: {self.subject}",
            body=body,
        )


MessageHandler = Callable[[AgentMessage], Coroutine[Any, Any, None]]


class MessageBus:
    """Central message bus for inter-agent communication.

    Features:
    - Direct messaging (agent → agent)
    - Broadcast messaging (agent → all)
    - Topic-based pub-sub
    - Priority queuing
    - Request/response correlation
    - Message TTL and expiry
    - Delivery tracking
    - Message history
    """

    def __init__(self, max_history: int = 2000) -> None:
        # Per-agent message queues
        self._queues: dict[str, asyncio.PriorityQueue[tuple[int, float, AgentMessage]]] = {}
        # Topic subscribers: topic → set of agent_ids
        self._topic_subscribers: dict[str, set[str]] = defaultdict(set)
        # Message handlers: agent_id → list of handlers
        self._handlers: dict[str, list[MessageHandler]] = defaultdict(list)
        # Type-specific handlers: (agent_id, message_type) → handler
        self._type_handlers: dict[tuple[str, MessageType], MessageHandler] = {}
        # Pending requests awaiting responses: correlation_id → Future
        self._pending_requests: dict[str, asyncio.Future[AgentMessage]] = {}
        # History
        self._history: list[AgentMessage] = []
        self._max_history = max_history
        # Stats
        self._stats: dict[str, int] = defaultdict(int)

    def register_agent(self, agent_id: str) -> None:
        """Register an agent on the message bus."""
        if agent_id not in self._queues:
            self._queues[agent_id] = asyncio.PriorityQueue()

    def unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent."""
        self._queues.pop(agent_id, None)
        self._handlers.pop(agent_id, None)
        for topic in list(self._topic_subscribers.keys()):
            self._topic_subscribers[topic].discard(agent_id)

    def subscribe(self, agent_id: str, topic: str) -> None:
        """Subscribe an agent to a topic."""
        self.register_agent(agent_id)
        self._topic_subscribers[topic].add(agent_id)

    def unsubscribe(self, agent_id: str, topic: str) -> None:
        """Unsubscribe an agent from a topic."""
        self._topic_subscribers[topic].discard(agent_id)

    def add_handler(self, agent_id: str, handler: MessageHandler) -> None:
        """Add a message handler for an agent."""
        self._handlers[agent_id].append(handler)

    def add_type_handler(
        self, agent_id: str, message_type: MessageType, handler: MessageHandler,
    ) -> None:
        """Add a type-specific handler."""
        self._type_handlers[(agent_id, message_type)] = handler

    async def send(self, message: AgentMessage) -> None:
        """Send a message through the bus."""
        self._stats["total_sent"] += 1
        self._stats[f"type_{message.message_type.value}"] += 1
        self._history.append(message)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        if message.receiver_id:
            # Direct message
            await self._deliver(message.receiver_id, message)
        elif message.topic:
            # Topic broadcast
            subscribers = self._topic_subscribers.get(message.topic, set())
            for agent_id in subscribers:
                if agent_id != message.sender_id:
                    await self._deliver(agent_id, message)
        else:
            # Global broadcast
            for agent_id in self._queues:
                if agent_id != message.sender_id:
                    await self._deliver(agent_id, message)

        # Check if this is a response to a pending request
        if message.message_type == MessageType.RESPONSE and message.correlation_id:
            future = self._pending_requests.pop(message.correlation_id, None)
            if future and not future.done():
                future.set_result(message)

    async def _deliver(self, agent_id: str, message: AgentMessage) -> None:
        """Deliver message to an agent's queue and invoke handlers."""
        if message.is_expired:
            self._stats["expired"] += 1
            return

        queue = self._queues.get(agent_id)
        if queue:
            # Priority queue: (priority, timestamp, message)
            await queue.put((message.priority.value, message.timestamp, message))
            self._stats["delivered"] += 1

        # Invoke type-specific handler
        type_handler = self._type_handlers.get((agent_id, message.message_type))
        if type_handler:
            try:
                await type_handler(message)
            except Exception as e:
                logger.error("handler_error", agent=agent_id, error=str(e))

        # Invoke general handlers
        for handler in self._handlers.get(agent_id, []):
            try:
                await handler(message)
            except Exception as e:
                logger.error("handler_error", agent=agent_id, error=str(e))

    async def receive(self, agent_id: str, timeout: float = 5.0) -> AgentMessage | None:
        """Receive the next message for an agent."""
        queue = self._queues.get(agent_id)
        if not queue:
            return None
        try:
            _, _, message = await asyncio.wait_for(queue.get(), timeout=timeout)
            return message
        except asyncio.TimeoutError:
            return None

    async def receive_all(self, agent_id: str) -> list[AgentMessage]:
        """Receive all pending messages for an agent."""
        queue = self._queues.get(agent_id)
        if not queue:
            return []
        messages = []
        while not queue.empty():
            try:
                _, _, msg = queue.get_nowait()
                messages.append(msg)
            except asyncio.QueueEmpty:
                break
        return messages

    async def request_response(
        self, message: AgentMessage, timeout: float = 30.0,
    ) -> AgentMessage | None:
        """Send a request and wait for the correlated response."""
        if not message.correlation_id:
            message.correlation_id = str(uuid.uuid4())[:8]
        message.requires_ack = True

        future: asyncio.Future[AgentMessage] = asyncio.get_running_loop().create_future()
        self._pending_requests[message.correlation_id] = future

        await self.send(message)

        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending_requests.pop(message.correlation_id, None)
            self._stats["timeouts"] += 1
            return None

    def get_pending_count(self, agent_id: str) -> int:
        queue = self._queues.get(agent_id)
        return queue.qsize() if queue else 0

    def get_history(self, limit: int = 100, agent_id: str = "", topic: str = "", message_type: str = "") -> list[dict[str, Any]]:
        """Get message history with optional filtering."""
        msgs = self._history
        if agent_id:
            msgs = [m for m in msgs if m.sender_id == agent_id or m.receiver_id == agent_id]
        if topic:
            msgs = [m for m in msgs if m.topic == topic]
        if message_type:
            msgs = [m for m in msgs if m.message_type.value == message_type]
        return [m.to_dict() for m in msgs[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        return {
            "registered_agents": len(self._queues),
            "topics": {t: len(s) for t, s in self._topic_subscribers.items()},
            "pending_requests": len(self._pending_requests),
            **dict(self._stats),
        }


class ConversationThread:
    """Manages a multi-turn conversation between agents."""

    def __init__(self, thread_id: str = "", participants: list[str] | None = None) -> None:
        self.thread_id = thread_id or str(uuid.uuid4())[:8]
        self.participants = set(participants or [])
        self.messages: list[AgentMessage] = []
        self.created_at = time.time()
        self.topic = ""
        self.resolved = False

    def add_message(self, message: AgentMessage) -> None:
        message.correlation_id = self.thread_id
        self.messages.append(message)
        self.participants.add(message.sender_id)
        if message.receiver_id:
            self.participants.add(message.receiver_id)

    def get_context(self, max_messages: int = 20) -> str:
        """Get thread context as a formatted string for LLM consumption."""
        lines = []
        for msg in self.messages[-max_messages:]:
            lines.append(f"[{msg.sender_id}] ({msg.message_type.value}): {msg.subject}")
            if msg.body:
                body_str = json.dumps(msg.body)[:300]
                lines.append(f"  {body_str}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "thread_id": self.thread_id,
            "participants": sorted(self.participants),
            "message_count": len(self.messages),
            "topic": self.topic,
            "resolved": self.resolved,
        }
