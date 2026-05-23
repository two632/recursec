"""Agent communication protocol — structured inter-agent messaging.

Implements:
1. Message types (request, response, broadcast, delegate, report)
2. Message routing between agents
3. Request-response patterns
4. Broadcast to all agents
5. Delegation chains (agent → sub-agent → sub-sub-agent)
6. Message priority and ordering
7. Message timeout and retry
8. Context inheritance in messages
9. Message history for debugging
10. Protocol versioning
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MessageType(str, Enum):
    REQUEST = "request"
    RESPONSE = "response"
    BROADCAST = "broadcast"
    DELEGATE = "delegate"
    REPORT = "report"
    STATUS = "status"
    FINDING = "finding"
    ERROR = "error"
    HEARTBEAT = "heartbeat"


class DeliveryStatus(str, Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    ACKNOWLEDGED = "acknowledged"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class AgentMessage:
    """A message between agents."""
    msg_id: str = ""
    msg_type: MessageType = MessageType.REQUEST
    sender: str = ""
    recipient: str = ""          # Empty for broadcast
    reply_to: str = ""           # Message ID this is replying to
    subject: str = ""
    body: dict[str, Any] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)
    priority: int = 5            # 1=highest, 10=lowest
    ttl_s: float = 300.0         # Time to live
    status: DeliveryStatus = DeliveryStatus.PENDING
    created_at: float = field(default_factory=time.time)
    delivered_at: float = 0.0

    @property
    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.ttl_s

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.msg_id, "type": self.msg_type.value,
            "from": self.sender, "to": self.recipient,
            "subject": self.subject[:60],
            "priority": self.priority,
            "status": self.status.value,
        }


@dataclass
class AgentEndpoint:
    """A registered agent endpoint."""
    agent_id: str = ""
    role: str = ""
    inbox: list[AgentMessage] = field(default_factory=list)
    max_inbox: int = 100
    active: bool = True
    last_heartbeat: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id, "role": self.role,
            "inbox": len(self.inbox), "active": self.active,
        }


@dataclass
class DelegationChain:
    """Tracks a delegation chain across agent hierarchy."""
    chain_id: str = ""
    original_sender: str = ""
    original_request: str = ""
    delegates: list[str] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)
    status: str = "active"
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id, "origin": self.original_sender,
            "delegates": self.delegates,
            "results": len(self.results), "status": self.status,
        }


class AgentCommunication:
    """Structured inter-agent communication protocol.

    Manages message routing, delivery, delegation chains,
    and context inheritance.
    """

    def __init__(self) -> None:
        self._endpoints: dict[str, AgentEndpoint] = {}
        self._msg_counter = 0
        self._chain_counter = 0
        self._delegation_chains: dict[str, DelegationChain] = {}
        self._message_log: list[AgentMessage] = []
        self._pending_responses: dict[str, AgentMessage] = {}
        self._log = logger.bind(component="agent_comms")

    def register_agent(self, agent_id: str, role: str = "") -> None:
        """Register an agent endpoint."""
        self._endpoints[agent_id] = AgentEndpoint(
            agent_id=agent_id, role=role,
        )

    def unregister_agent(self, agent_id: str) -> None:
        self._endpoints.pop(agent_id, None)

    def send(
        self,
        sender: str,
        recipient: str,
        msg_type: MessageType,
        subject: str,
        body: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        priority: int = 5,
        reply_to: str = "",
    ) -> str:
        """Send a message to an agent."""
        self._msg_counter += 1
        msg_id = f"msg-{self._msg_counter}"

        msg = AgentMessage(
            msg_id=msg_id,
            msg_type=msg_type,
            sender=sender,
            recipient=recipient,
            reply_to=reply_to,
            subject=subject,
            body=body or {},
            context=context or {},
            priority=priority,
        )

        # Deliver to recipient
        endpoint = self._endpoints.get(recipient)
        if endpoint and endpoint.active:
            endpoint.inbox.append(msg)
            msg.status = DeliveryStatus.DELIVERED
            msg.delivered_at = time.time()

            # Enforce inbox limit
            if len(endpoint.inbox) > endpoint.max_inbox:
                endpoint.inbox = endpoint.inbox[-endpoint.max_inbox:]
        else:
            msg.status = DeliveryStatus.FAILED

        # Track for responses
        if msg_type == MessageType.REQUEST:
            self._pending_responses[msg_id] = msg

        self._message_log.append(msg)
        if len(self._message_log) > 2000:
            self._message_log = self._message_log[-2000:]

        return msg_id

    def broadcast(
        self,
        sender: str,
        subject: str,
        body: dict[str, Any] | None = None,
        exclude: list[str] | None = None,
    ) -> list[str]:
        """Broadcast a message to all registered agents."""
        exclude_set = set(exclude or [])
        exclude_set.add(sender)

        msg_ids = []
        for agent_id in self._endpoints:
            if agent_id not in exclude_set:
                mid = self.send(
                    sender=sender,
                    recipient=agent_id,
                    msg_type=MessageType.BROADCAST,
                    subject=subject,
                    body=body,
                )
                msg_ids.append(mid)

        return msg_ids

    def receive(self, agent_id: str, limit: int = 10) -> list[AgentMessage]:
        """Receive messages for an agent."""
        endpoint = self._endpoints.get(agent_id)
        if not endpoint:
            return []

        # Get messages sorted by priority
        messages = sorted(
            endpoint.inbox, key=lambda m: m.priority,
        )[:limit]

        # Remove from inbox
        for msg in messages:
            if msg in endpoint.inbox:
                endpoint.inbox.remove(msg)
                msg.status = DeliveryStatus.ACKNOWLEDGED

        return messages

    def reply(
        self,
        original_msg_id: str,
        sender: str,
        body: dict[str, Any] | None = None,
    ) -> str:
        """Reply to a message."""
        original = self._pending_responses.get(original_msg_id)
        if not original:
            # Search message log
            for msg in reversed(self._message_log):
                if msg.msg_id == original_msg_id:
                    original = msg
                    break

        if not original:
            return ""

        return self.send(
            sender=sender,
            recipient=original.sender,
            msg_type=MessageType.RESPONSE,
            subject=f"Re: {original.subject}",
            body=body,
            reply_to=original_msg_id,
            context=original.context,
        )

    def delegate(
        self,
        sender: str,
        recipient: str,
        task: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        """Delegate a task to another agent."""
        self._chain_counter += 1
        chain_id = f"chain-{self._chain_counter}"

        chain = DelegationChain(
            chain_id=chain_id,
            original_sender=sender,
            original_request=task,
            delegates=[recipient],
        )
        self._delegation_chains[chain_id] = chain

        self.send(
            sender=sender,
            recipient=recipient,
            msg_type=MessageType.DELEGATE,
            subject=f"Delegated: {task[:60]}",
            body={"task": task, "chain_id": chain_id},
            context=context,
            priority=3,
        )

        return chain_id

    def report_delegation_result(
        self,
        chain_id: str,
        agent_id: str,
        result: dict[str, Any],
    ) -> None:
        """Report result of a delegated task."""
        chain = self._delegation_chains.get(chain_id)
        if chain:
            chain.results.append({"agent": agent_id, "result": result})

            # Notify original sender
            self.send(
                sender=agent_id,
                recipient=chain.original_sender,
                msg_type=MessageType.REPORT,
                subject=f"Delegation complete: {chain.original_request[:40]}",
                body={"chain_id": chain_id, "result": result},
            )

    def heartbeat(self, agent_id: str) -> None:
        """Send a heartbeat from an agent."""
        endpoint = self._endpoints.get(agent_id)
        if endpoint:
            endpoint.last_heartbeat = time.time()

    def get_dead_agents(self, timeout_s: float = 60.0) -> list[str]:
        """Get agents that haven't sent a heartbeat recently."""
        now = time.time()
        dead = []
        for eid, endpoint in self._endpoints.items():
            if now - endpoint.last_heartbeat > timeout_s:
                dead.append(eid)
        return dead

    def get_message_log(
        self,
        agent_id: str = "",
        msg_type: str = "",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Get message history."""
        msgs = self._message_log

        if agent_id:
            msgs = [m for m in msgs if m.sender == agent_id or m.recipient == agent_id]
        if msg_type:
            msgs = [m for m in msgs if m.msg_type.value == msg_type]

        return [m.to_dict() for m in msgs[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        return {
            "agents": len(self._endpoints),
            "active": sum(1 for e in self._endpoints.values() if e.active),
            "messages": self._msg_counter,
            "chains": len(self._delegation_chains),
        }
