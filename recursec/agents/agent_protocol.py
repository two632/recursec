"""Agent communication protocol — structured messaging between agents.

Defines the protocol for inter-agent communication:
1. Message types and formats
2. Request/response patterns
3. Task delegation messages
4. Finding sharing
5. Status reporting
6. Help requests and responses
7. Escalation protocol
8. Message validation and routing
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MessageType(str, Enum):
    # Task management
    TASK_ASSIGN = "task_assign"
    TASK_ACCEPT = "task_accept"
    TASK_REJECT = "task_reject"
    TASK_COMPLETE = "task_complete"
    TASK_FAILED = "task_failed"
    TASK_PROGRESS = "task_progress"

    # Findings
    FINDING_NEW = "finding_new"
    FINDING_VALIDATED = "finding_validated"
    FINDING_INVALIDATED = "finding_invalidated"

    # Requests
    HELP_REQUEST = "help_request"
    HELP_RESPONSE = "help_response"
    INFO_REQUEST = "info_request"
    INFO_RESPONSE = "info_response"

    # Control
    STATUS_REQUEST = "status_request"
    STATUS_RESPONSE = "status_response"
    PAUSE = "pause"
    RESUME = "resume"
    TERMINATE = "terminate"
    HEARTBEAT = "heartbeat"

    # Escalation
    ESCALATE = "escalate"
    ESCALATE_ACK = "escalate_ack"

    # Knowledge sharing
    KNOWLEDGE_SHARE = "knowledge_share"
    CONTEXT_UPDATE = "context_update"


class MessagePriority(str, Enum):
    URGENT = "urgent"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


@dataclass
class AgentMessage:
    """A structured message between agents."""
    message_id: str = field(default_factory=lambda: str(uuid.uuid4())[:10])
    message_type: MessageType = MessageType.STATUS_REQUEST
    priority: MessagePriority = MessagePriority.NORMAL
    sender: str = ""
    recipient: str = ""           # Empty = broadcast
    reply_to: str = ""            # Original message ID for replies
    correlation_id: str = ""      # Group related messages
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    ttl_s: float = 300.0
    requires_ack: bool = False

    @property
    def expired(self) -> bool:
        return time.time() - self.timestamp > self.ttl_s

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.message_id,
            "type": self.message_type.value,
            "priority": self.priority.value,
            "from": self.sender,
            "to": self.recipient,
            "reply_to": self.reply_to,
            "payload_keys": list(self.payload.keys())[:5],
        }

    def to_json(self) -> str:
        return json.dumps({
            "id": self.message_id,
            "type": self.message_type.value,
            "priority": self.priority.value,
            "sender": self.sender,
            "recipient": self.recipient,
            "reply_to": self.reply_to,
            "correlation_id": self.correlation_id,
            "payload": self.payload,
            "timestamp": self.timestamp,
        })

    @classmethod
    def from_json(cls, data: str) -> AgentMessage:
        d = json.loads(data)
        try:
            msg_type = MessageType(d.get("type", "status_request"))
        except ValueError:
            msg_type = MessageType.STATUS_REQUEST
        try:
            priority = MessagePriority(d.get("priority", "normal"))
        except ValueError:
            priority = MessagePriority.NORMAL
        return cls(
            message_id=d.get("id", ""),
            message_type=msg_type,
            priority=priority,
            sender=d.get("sender", ""),
            recipient=d.get("recipient", ""),
            reply_to=d.get("reply_to", ""),
            correlation_id=d.get("correlation_id", ""),
            payload=d.get("payload", {}),
            timestamp=d.get("timestamp", time.time()),
        )


class MessageFactory:
    """Factory for creating common message types."""

    @staticmethod
    def task_assign(
        sender: str,
        recipient: str,
        task_name: str,
        task_description: str,
        target: str = "",
        tools: list[str] | None = None,
        priority: MessagePriority = MessagePriority.NORMAL,
    ) -> AgentMessage:
        return AgentMessage(
            message_type=MessageType.TASK_ASSIGN,
            priority=priority,
            sender=sender,
            recipient=recipient,
            requires_ack=True,
            payload={
                "task_name": task_name,
                "description": task_description,
                "target": target,
                "tools": tools or [],
            },
        )

    @staticmethod
    def task_complete(
        sender: str,
        recipient: str,
        task_id: str,
        findings: list[dict[str, Any]] | None = None,
        result: dict[str, Any] | None = None,
    ) -> AgentMessage:
        return AgentMessage(
            message_type=MessageType.TASK_COMPLETE,
            sender=sender,
            recipient=recipient,
            payload={
                "task_id": task_id,
                "findings": findings or [],
                "result": result or {},
                "findings_count": len(findings) if findings else 0,
            },
        )

    @staticmethod
    def task_failed(
        sender: str,
        recipient: str,
        task_id: str,
        error: str = "",
    ) -> AgentMessage:
        return AgentMessage(
            message_type=MessageType.TASK_FAILED,
            priority=MessagePriority.HIGH,
            sender=sender,
            recipient=recipient,
            payload={"task_id": task_id, "error": error},
        )

    @staticmethod
    def finding(
        sender: str,
        finding: dict[str, Any],
    ) -> AgentMessage:
        severity = finding.get("severity", "medium").lower()
        priority = (
            MessagePriority.URGENT if severity == "critical"
            else MessagePriority.HIGH if severity == "high"
            else MessagePriority.NORMAL
        )
        return AgentMessage(
            message_type=MessageType.FINDING_NEW,
            priority=priority,
            sender=sender,
            payload=finding,
        )

    @staticmethod
    def help_request(
        sender: str,
        question: str,
        context: dict[str, Any] | None = None,
        target: str = "",
    ) -> AgentMessage:
        return AgentMessage(
            message_type=MessageType.HELP_REQUEST,
            priority=MessagePriority.HIGH,
            sender=sender,
            target=target,
            requires_ack=True,
            payload={"question": question, "context": context or {}},
        )

    @staticmethod
    def help_response(
        sender: str,
        recipient: str,
        reply_to: str,
        answer: str,
        suggestions: list[str] | None = None,
    ) -> AgentMessage:
        return AgentMessage(
            message_type=MessageType.HELP_RESPONSE,
            sender=sender,
            recipient=recipient,
            reply_to=reply_to,
            payload={"answer": answer, "suggestions": suggestions or []},
        )

    @staticmethod
    def status_report(
        sender: str,
        status: str,
        progress: float = 0.0,
        findings_count: int = 0,
        details: dict[str, Any] | None = None,
    ) -> AgentMessage:
        return AgentMessage(
            message_type=MessageType.STATUS_RESPONSE,
            sender=sender,
            payload={
                "status": status, "progress": progress,
                "findings": findings_count,
                **(details or {}),
            },
        )

    @staticmethod
    def escalate(
        sender: str,
        reason: str,
        finding: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> AgentMessage:
        return AgentMessage(
            message_type=MessageType.ESCALATE,
            priority=MessagePriority.URGENT,
            sender=sender,
            requires_ack=True,
            payload={
                "reason": reason,
                "finding": finding or {},
                "context": context or {},
            },
        )

    @staticmethod
    def knowledge_share(
        sender: str,
        knowledge_type: str,
        content: dict[str, Any],
    ) -> AgentMessage:
        return AgentMessage(
            message_type=MessageType.KNOWLEDGE_SHARE,
            sender=sender,
            payload={
                "knowledge_type": knowledge_type,
                "content": content,
            },
        )

    @staticmethod
    def heartbeat(sender: str) -> AgentMessage:
        return AgentMessage(
            message_type=MessageType.HEARTBEAT,
            priority=MessagePriority.LOW,
            sender=sender,
            ttl_s=60.0,
            payload={"timestamp": time.time()},
        )


class ProtocolValidator:
    """Validates messages conform to protocol."""

    REQUIRED_FIELDS: dict[str, list[str]] = {
        MessageType.TASK_ASSIGN.value: ["task_name", "description"],
        MessageType.TASK_COMPLETE.value: ["task_id"],
        MessageType.TASK_FAILED.value: ["task_id"],
        MessageType.FINDING_NEW.value: ["title", "severity"],
        MessageType.HELP_REQUEST.value: ["question"],
        MessageType.HELP_RESPONSE.value: ["answer"],
        MessageType.ESCALATE.value: ["reason"],
    }

    @classmethod
    def validate(cls, message: AgentMessage) -> tuple[bool, str]:
        """Validate a message. Returns (valid, error_message)."""
        if not message.sender:
            return False, "Message must have a sender"

        if message.expired:
            return False, "Message has expired"

        required = cls.REQUIRED_FIELDS.get(message.message_type.value, [])
        for field_name in required:
            if field_name not in message.payload:
                return False, f"Missing required field: {field_name}"

        return True, ""
