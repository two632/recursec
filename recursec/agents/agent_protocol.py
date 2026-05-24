"""Agent communication protocol — structured message passing between agents.

Defines:
1. Message types and formats for inter-agent communication
2. Request/response patterns (task delegation, result aggregation)
3. Event broadcasting (findings, status updates, errors)
4. Agent discovery and capability advertisement
5. Conversation threading for multi-turn agent interactions
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MessageType(str, Enum):
    TASK_REQUEST = "task_request"
    TASK_RESPONSE = "task_response"
    FINDING_REPORT = "finding_report"
    STATUS_UPDATE = "status_update"
    ERROR_REPORT = "error_report"
    CAPABILITY_QUERY = "capability_query"
    CAPABILITY_RESPONSE = "capability_response"
    KNOWLEDGE_SHARE = "knowledge_share"
    STRATEGY_CHANGE = "strategy_change"
    ESCALATION = "escalation"
    HEARTBEAT = "heartbeat"
    TERMINATION = "termination"


class MessagePriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


class DeliveryMode(str, Enum):
    DIRECT = "direct"
    BROADCAST = "broadcast"
    MULTICAST = "multicast"
    REPLY = "reply"


@dataclass
class AgentMessage:
    """A message in the agent communication protocol."""
    message_id: str = ""
    message_type: MessageType = MessageType.STATUS_UPDATE
    sender_id: str = ""
    recipient_id: str = ""
    delivery_mode: DeliveryMode = DeliveryMode.DIRECT
    priority: MessagePriority = MessagePriority.NORMAL
    thread_id: str = ""
    reply_to: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    ttl_s: float = 300.0

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.timestamp) > self.ttl_s

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.message_id[:8],
            "type": self.message_type.value[:12],
            "from": self.sender_id[:8],
            "to": self.recipient_id[:8],
            "priority": self.priority.value[:4],
        }


@dataclass
class TaskRequest:
    """A task delegation request."""
    task_id: str = ""
    description: str = ""
    intent: str = ""
    target: str = ""
    required_role: str = ""
    required_tools: list[str] = field(default_factory=list)
    required_kbs: list[str] = field(default_factory=list)
    token_budget: int = 4096
    timeout_s: float = 120.0
    parent_task_id: str = ""
    depth: int = 0
    max_depth: int = 3

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:8],
            "intent": self.intent[:12],
            "role": self.required_role[:10],
            "depth": f"{self.depth}/{self.max_depth}",
        }


@dataclass
class TaskResponse:
    """A task completion response."""
    task_id: str = ""
    status: str = "completed"
    findings: list[dict[str, Any]] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    tokens_used: int = 0
    duration_s: float = 0.0
    confidence: float = 0.0
    error_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:8],
            "status": self.status[:8],
            "findings": len(self.findings),
            "confidence": f"{self.confidence:.2f}",
        }


@dataclass
class FindingReport:
    """A security finding broadcast."""
    finding_id: str = ""
    title: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cve: str = ""
    target: str = ""
    tool_used: str = ""
    discovered_by: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id[:8],
            "severity": self.severity[:4],
            "confidence": f"{self.confidence:.2f}",
            "title": self.title[:25],
        }


@dataclass
class AgentCapability:
    """An agent's advertised capabilities."""
    agent_id: str = ""
    role: str = ""
    tools: list[str] = field(default_factory=list)
    kbs: list[str] = field(default_factory=list)
    model: str = ""
    max_context: int = 4096
    current_load: float = 0.0
    specialties: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:8],
            "role": self.role[:10],
            "tools": len(self.tools),
            "load": f"{self.current_load:.1f}",
        }


@dataclass
class ConversationThread:
    """A multi-turn conversation between agents."""
    thread_id: str = ""
    participants: list[str] = field(default_factory=list)
    messages: list[AgentMessage] = field(default_factory=list)
    topic: str = ""
    started_at: float = field(default_factory=time.time)
    status: str = "active"

    @property
    def message_count(self) -> int:
        return len(self.messages)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.thread_id[:8],
            "participants": len(self.participants),
            "messages": self.message_count,
            "status": self.status[:6],
        }


class AgentProtocol:
    """Agent communication protocol implementation."""

    def __init__(self) -> None:
        self._messages: list[AgentMessage] = []
        self._threads: dict[str, ConversationThread] = {}
        self._capabilities: dict[str, AgentCapability] = {}
        self._message_counter = 0
        self._thread_counter = 0
        self._log = logger.bind(component="agent_protocol")

    def create_message(
        self,
        msg_type: MessageType,
        sender_id: str,
        recipient_id: str,
        payload: dict[str, Any],
        priority: MessagePriority = MessagePriority.NORMAL,
        delivery_mode: DeliveryMode = DeliveryMode.DIRECT,
        thread_id: str = "",
        reply_to: str = "",
    ) -> AgentMessage:
        """Create and store a new message."""
        self._message_counter += 1
        msg = AgentMessage(
            message_id=f"msg-{self._message_counter}",
            message_type=msg_type,
            sender_id=sender_id,
            recipient_id=recipient_id,
            delivery_mode=delivery_mode,
            priority=priority,
            thread_id=thread_id,
            reply_to=reply_to,
            payload=payload,
        )
        self._messages.append(msg)

        # Add to thread
        if thread_id and thread_id in self._threads:
            self._threads[thread_id].messages.append(msg)

        # Trim old messages
        if len(self._messages) > 5000:
            self._messages = self._messages[-2500:]

        return msg

    def create_thread(
        self,
        participants: list[str],
        topic: str,
    ) -> ConversationThread:
        """Create a new conversation thread."""
        self._thread_counter += 1
        thread = ConversationThread(
            thread_id=f"thread-{self._thread_counter}",
            participants=participants,
            topic=topic,
        )
        self._threads[thread.thread_id] = thread
        return thread

    def register_capability(
        self, capability: AgentCapability,
    ) -> None:
        """Register an agent's capabilities."""
        self._capabilities[capability.agent_id] = capability

    def find_capable_agent(
        self,
        required_role: str = "",
        required_tools: list[str] | None = None,
        required_kbs: list[str] | None = None,
    ) -> AgentCapability | None:
        """Find an agent matching requirements."""
        best: AgentCapability | None = None
        best_score = -1.0

        for cap in self._capabilities.values():
            score = 0.0
            if required_role and cap.role == required_role:
                score += 1.0
            if required_tools:
                overlap = len(set(required_tools) & set(cap.tools))
                score += overlap / len(required_tools)
            if required_kbs:
                overlap = len(set(required_kbs) & set(cap.kbs))
                score += overlap / len(required_kbs)
            # Prefer less loaded agents
            score -= cap.current_load * 0.5

            if score > best_score:
                best_score = score
                best = cap

        return best

    def get_thread_messages(
        self, thread_id: str,
    ) -> list[AgentMessage]:
        """Get all messages in a thread."""
        thread = self._threads.get(thread_id)
        if not thread:
            return []
        return thread.messages

    def get_agent_messages(
        self,
        agent_id: str,
        msg_type: MessageType | None = None,
    ) -> list[AgentMessage]:
        """Get messages for/from an agent."""
        result = []
        for msg in self._messages:
            if msg.recipient_id == agent_id or msg.sender_id == agent_id:
                if msg_type is None or msg.message_type == msg_type:
                    result.append(msg)
        return result

    def broadcast_finding(
        self,
        sender_id: str,
        finding: FindingReport,
    ) -> AgentMessage:
        """Broadcast a finding to all agents."""
        return self.create_message(
            msg_type=MessageType.FINDING_REPORT,
            sender_id=sender_id,
            recipient_id="*",
            payload=finding.to_dict(),
            priority=MessagePriority.HIGH if finding.severity in ("critical", "high") else MessagePriority.NORMAL,
            delivery_mode=DeliveryMode.BROADCAST,
        )

    def delegate_task(
        self,
        sender_id: str,
        task: TaskRequest,
        thread_id: str = "",
    ) -> AgentMessage:
        """Delegate a task to a capable agent."""
        # Find capable agent
        agent = self.find_capable_agent(
            required_role=task.required_role,
            required_tools=task.required_tools,
            required_kbs=task.required_kbs,
        )
        recipient = agent.agent_id if agent else "coordinator"

        return self.create_message(
            msg_type=MessageType.TASK_REQUEST,
            sender_id=sender_id,
            recipient_id=recipient,
            payload=task.to_dict(),
            priority=MessagePriority.HIGH,
            thread_id=thread_id,
        )

    def get_stats(self) -> dict[str, Any]:
        """Get protocol statistics."""
        type_counts: dict[str, int] = {}
        for msg in self._messages:
            key = msg.message_type.value
            type_counts[key] = type_counts.get(key, 0) + 1

        return {
            "total_messages": len(self._messages),
            "threads": len(self._threads),
            "registered_agents": len(self._capabilities),
            "by_type": type_counts,
        }
