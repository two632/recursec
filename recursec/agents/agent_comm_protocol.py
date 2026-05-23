"""Agent communication protocol — structured inter-agent messaging.

Implements:
1. Typed message passing between agents
2. Request/response patterns
3. Event broadcasting
4. Result aggregation
5. Message routing
6. Message history
7. Priority queues
8. Dead letter handling
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
    # Commands
    TASK_ASSIGN = "task_assign"         # Parent → child: do this task
    TASK_COMPLETE = "task_complete"       # Child → parent: here's the result
    TASK_FAILED = "task_failed"          # Child → parent: I failed

    # Data
    FINDING_REPORT = "finding_report"     # Any → coordinator: found something
    TOOL_OUTPUT = "tool_output"          # Any → any: tool finished
    KNOWLEDGE_SHARE = "knowledge_share"   # Any → any: useful context

    # Control
    STATUS_REQUEST = "status_request"     # Any → any: what's your status?
    STATUS_RESPONSE = "status_response"   # Response to status request
    CANCEL = "cancel"                    # Parent → child: stop work
    PAUSE = "pause"                      # Any → child: pause
    RESUME = "resume"                    # Any → child: resume

    # Coordination
    CONSENSUS_REQUEST = "consensus_request"  # Coordinator → agents: vote on this
    CONSENSUS_VOTE = "consensus_vote"       # Agent → coordinator: my vote
    DEBATE_CHALLENGE = "debate_challenge"    # Agent → agent: I disagree
    DEBATE_RESPONSE = "debate_response"      # Response to challenge

    # Events
    PHASE_CHANGE = "phase_change"         # Broadcast: phase changed
    STAGNATION = "stagnation_alert"       # Broadcast: stagnation detected
    BUDGET_WARNING = "budget_warning"      # Broadcast: running low


class MessagePriority(str, Enum):
    URGENT = "urgent"     # Critical findings, cancellations
    HIGH = "high"         # Task assignments, completions
    NORMAL = "normal"     # Standard messages
    LOW = "low"           # Status updates, knowledge sharing


@dataclass
class AgentMessage:
    """A message between agents."""
    message_id: str = ""
    msg_type: MessageType = MessageType.KNOWLEDGE_SHARE
    sender: str = ""
    recipient: str = ""             # Empty = broadcast
    priority: MessagePriority = MessagePriority.NORMAL
    payload: dict[str, Any] = field(default_factory=dict)
    reply_to: str = ""              # ID of message being replied to
    timestamp: float = field(default_factory=time.time)
    delivered: bool = False
    delivery_time: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.message_id[:10],
            "type": self.msg_type.value,
            "from": self.sender[:10],
            "to": self.recipient[:10] or "broadcast",
            "priority": self.priority.value,
            "delivered": self.delivered,
        }


@dataclass
class MessageQueue:
    """A priority queue of messages for an agent."""
    agent_id: str = ""
    urgent: deque[AgentMessage] = field(default_factory=deque)
    high: deque[AgentMessage] = field(default_factory=deque)
    normal: deque[AgentMessage] = field(default_factory=deque)
    low: deque[AgentMessage] = field(default_factory=deque)

    @property
    def total(self) -> int:
        return len(self.urgent) + len(self.high) + len(self.normal) + len(self.low)

    def enqueue(self, msg: AgentMessage) -> None:
        """Add a message to the appropriate queue."""
        if msg.priority == MessagePriority.URGENT:
            self.urgent.append(msg)
        elif msg.priority == MessagePriority.HIGH:
            self.high.append(msg)
        elif msg.priority == MessagePriority.LOW:
            self.low.append(msg)
        else:
            self.normal.append(msg)

    def dequeue(self) -> AgentMessage | None:
        """Get the next message (highest priority first)."""
        for q in (self.urgent, self.high, self.normal, self.low):
            if q:
                return q.popleft()
        return None

    def peek(self) -> AgentMessage | None:
        """Look at the next message without removing it."""
        for q in (self.urgent, self.high, self.normal, self.low):
            if q:
                return q[0]
        return None


class AgentCommProtocol:
    """Inter-agent communication protocol.

    Routes messages between agents with priority queuing,
    broadcasting, and message history tracking.
    """

    def __init__(self) -> None:
        self._queues: dict[str, MessageQueue] = {}
        self._message_counter = 0
        self._history: list[AgentMessage] = []
        self._dead_letters: list[AgentMessage] = []
        self._subscribers: dict[MessageType, list[str]] = defaultdict(list)
        self._log = logger.bind(component="agent_comm")

    def register_agent(self, agent_id: str) -> None:
        """Register an agent for message receiving."""
        if agent_id not in self._queues:
            self._queues[agent_id] = MessageQueue(agent_id=agent_id)

    def unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent."""
        if agent_id in self._queues:
            # Move pending messages to dead letters
            queue = self._queues[agent_id]
            while queue.total > 0:
                msg = queue.dequeue()
                if msg:
                    self._dead_letters.append(msg)
            del self._queues[agent_id]

    def subscribe(self, agent_id: str, msg_type: MessageType) -> None:
        """Subscribe to a message type (for broadcasts)."""
        if agent_id not in self._subscribers[msg_type]:
            self._subscribers[msg_type].append(agent_id)

    def send(
        self,
        sender: str,
        recipient: str,
        msg_type: MessageType,
        payload: dict[str, Any] | None = None,
        priority: MessagePriority = MessagePriority.NORMAL,
        reply_to: str = "",
    ) -> AgentMessage:
        """Send a message to an agent."""
        self._message_counter += 1

        msg = AgentMessage(
            message_id=f"msg-{self._message_counter}",
            msg_type=msg_type,
            sender=sender,
            recipient=recipient,
            priority=priority,
            payload=payload or {},
            reply_to=reply_to,
        )

        if recipient:
            # Direct message
            queue = self._queues.get(recipient)
            if queue:
                queue.enqueue(msg)
                msg.delivered = True
                msg.delivery_time = time.time()
            else:
                self._dead_letters.append(msg)
        else:
            # Broadcast to subscribers
            subscribers = self._subscribers.get(msg_type, [])
            for sub_id in subscribers:
                if sub_id == sender:
                    continue
                queue = self._queues.get(sub_id)
                if queue:
                    # Create copy for each recipient
                    broadcast_msg = AgentMessage(
                        message_id=f"{msg.message_id}-{sub_id[:5]}",
                        msg_type=msg.msg_type,
                        sender=sender,
                        recipient=sub_id,
                        priority=priority,
                        payload=payload or {},
                        delivered=True,
                        delivery_time=time.time(),
                    )
                    queue.enqueue(broadcast_msg)

        self._history.append(msg)
        return msg

    def broadcast(
        self,
        sender: str,
        msg_type: MessageType,
        payload: dict[str, Any] | None = None,
        priority: MessagePriority = MessagePriority.NORMAL,
    ) -> AgentMessage:
        """Broadcast to all registered agents."""
        return self.send(
            sender=sender,
            recipient="",
            msg_type=msg_type,
            payload=payload,
            priority=priority,
        )

    def receive(self, agent_id: str) -> AgentMessage | None:
        """Receive the next message for an agent."""
        queue = self._queues.get(agent_id)
        if not queue:
            return None
        return queue.dequeue()

    def receive_all(self, agent_id: str) -> list[AgentMessage]:
        """Receive all pending messages for an agent."""
        queue = self._queues.get(agent_id)
        if not queue:
            return []

        messages = []
        while queue.total > 0:
            msg = queue.dequeue()
            if msg:
                messages.append(msg)
        return messages

    def pending_count(self, agent_id: str) -> int:
        """Get number of pending messages for an agent."""
        queue = self._queues.get(agent_id)
        return queue.total if queue else 0

    def get_conversation(
        self,
        agent_a: str,
        agent_b: str,
    ) -> list[AgentMessage]:
        """Get message history between two agents."""
        return [
            m for m in self._history
            if (m.sender == agent_a and m.recipient == agent_b)
            or (m.sender == agent_b and m.recipient == agent_a)
        ]

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for m in self._history:
            type_counts[m.msg_type.value] += 1

        return {
            "agents": len(self._queues),
            "messages_sent": len(self._history),
            "dead_letters": len(self._dead_letters),
            "pending_total": sum(q.total for q in self._queues.values()),
            "by_type": dict(type_counts),
        }
