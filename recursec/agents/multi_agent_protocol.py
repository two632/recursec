"""Multi-agent protocol — formal communication protocol for agent collaboration.

Implements:
1. Message types and format standardization
2. Request-response patterns
3. Task delegation protocol
4. Finding sharing protocol
5. Consensus protocols (voting, leader-based)
6. Agent registration and discovery
7. Heartbeat and liveness checking
8. Protocol version negotiation
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ProtocolMessageType(str, Enum):
    # Discovery
    REGISTER = "register"
    UNREGISTER = "unregister"
    DISCOVER = "discover"
    HEARTBEAT = "heartbeat"
    # Task management
    TASK_ASSIGN = "task_assign"
    TASK_ACCEPT = "task_accept"
    TASK_REJECT = "task_reject"
    TASK_COMPLETE = "task_complete"
    TASK_FAILED = "task_failed"
    TASK_PROGRESS = "task_progress"
    # Finding sharing
    FINDING_REPORT = "finding_report"
    FINDING_VALIDATE = "finding_validate"
    FINDING_CONFIRM = "finding_confirm"
    FINDING_REJECT = "finding_reject"
    # Consensus
    VOTE_REQUEST = "vote_request"
    VOTE_CAST = "vote_cast"
    VOTE_RESULT = "vote_result"
    # Control
    PAUSE = "pause"
    RESUME = "resume"
    TERMINATE = "terminate"
    STATUS_REQUEST = "status_request"
    STATUS_RESPONSE = "status_response"


class AgentRole(str, Enum):
    COORDINATOR = "coordinator"
    RECON = "recon"
    SCANNER = "scanner"
    ANALYZER = "analyzer"
    EXPLOITER = "exploiter"
    VALIDATOR = "validator"
    REPORTER = "reporter"


@dataclass
class ProtocolMessage:
    """A protocol message between agents."""
    message_id: str = ""
    msg_type: ProtocolMessageType = ProtocolMessageType.HEARTBEAT
    sender_id: str = ""
    recipient_id: str = ""          # "" means broadcast
    payload: dict[str, Any] = field(default_factory=dict)
    correlation_id: str = ""        # Links request-response
    timestamp: float = field(default_factory=time.time)
    ttl: int = 60                   # Seconds before expiry
    protocol_version: str = "1.0"

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.timestamp) > self.ttl

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.message_id,
            "type": self.msg_type.value,
            "from": self.sender_id[:15],
            "to": self.recipient_id[:15] or "broadcast",
            "corr": self.correlation_id[:15],
        }


@dataclass
class RegisteredAgent:
    """A registered agent in the protocol."""
    agent_id: str = ""
    role: AgentRole = AgentRole.RECON
    capabilities: list[str] = field(default_factory=list)
    model_id: str = ""
    status: str = "active"
    last_heartbeat: float = field(default_factory=time.time)
    current_task: str = ""
    message_count: int = 0

    @property
    def is_alive(self) -> bool:
        return (time.time() - self.last_heartbeat) < 120

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:15],
            "role": self.role.value,
            "caps": self.capabilities[:3],
            "status": self.status,
            "alive": self.is_alive,
            "messages": self.message_count,
        }


@dataclass
class VoteSession:
    """A consensus voting session."""
    session_id: str = ""
    topic: str = ""
    options: list[str] = field(default_factory=list)
    votes: dict[str, str] = field(default_factory=dict)
    required_votes: int = 1
    deadline: float = 0.0
    result: str = ""
    decided: bool = False

    @property
    def is_expired(self) -> bool:
        return time.time() > self.deadline if self.deadline > 0 else False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.session_id,
            "topic": self.topic[:30],
            "votes": len(self.votes),
            "required": self.required_votes,
            "decided": self.decided,
            "result": self.result[:20],
        }


class MultiAgentProtocol:
    """Formal communication protocol for agent collaboration.

    Provides standardized message passing, consensus,
    task delegation, and agent discovery.
    """

    def __init__(self) -> None:
        self._agents: dict[str, RegisteredAgent] = {}
        self._messages: list[ProtocolMessage] = []
        self._pending: dict[str, ProtocolMessage] = {}  # correlation_id → pending request
        self._votes: dict[str, VoteSession] = {}
        self._message_counter = 0
        self._vote_counter = 0
        self._log = logger.bind(component="multi_agent_protocol")

    def register(
        self,
        agent_id: str,
        role: AgentRole,
        capabilities: list[str] | None = None,
        model_id: str = "",
    ) -> RegisteredAgent:
        """Register an agent."""
        agent = RegisteredAgent(
            agent_id=agent_id,
            role=role,
            capabilities=capabilities or [],
            model_id=model_id,
        )
        self._agents[agent_id] = agent
        return agent

    def unregister(self, agent_id: str) -> None:
        """Unregister an agent."""
        self._agents.pop(agent_id, None)

    def send(
        self,
        msg_type: ProtocolMessageType,
        sender_id: str,
        recipient_id: str = "",
        payload: dict[str, Any] | None = None,
        correlation_id: str = "",
    ) -> ProtocolMessage:
        """Send a protocol message."""
        self._message_counter += 1
        msg = ProtocolMessage(
            message_id=f"pm-{self._message_counter}",
            msg_type=msg_type,
            sender_id=sender_id,
            recipient_id=recipient_id,
            payload=payload or {},
            correlation_id=correlation_id or f"pm-{self._message_counter}",
        )

        self._messages.append(msg)
        if len(self._messages) > 1000:
            self._messages = self._messages[-1000:]

        # Update sender stats
        sender = self._agents.get(sender_id)
        if sender:
            sender.message_count += 1

        return msg

    def heartbeat(self, agent_id: str) -> None:
        """Record agent heartbeat."""
        agent = self._agents.get(agent_id)
        if agent:
            agent.last_heartbeat = time.time()

    def assign_task(
        self,
        from_id: str,
        to_id: str,
        task: str,
        details: dict[str, Any] | None = None,
    ) -> ProtocolMessage:
        """Assign a task to an agent."""
        msg = self.send(
            msg_type=ProtocolMessageType.TASK_ASSIGN,
            sender_id=from_id,
            recipient_id=to_id,
            payload={"task": task, "details": details or {}},
        )

        agent = self._agents.get(to_id)
        if agent:
            agent.current_task = task

        return msg

    def report_finding(
        self,
        agent_id: str,
        finding: dict[str, Any],
    ) -> ProtocolMessage:
        """Report a finding to all agents."""
        return self.send(
            msg_type=ProtocolMessageType.FINDING_REPORT,
            sender_id=agent_id,
            payload={"finding": finding},
        )

    def start_vote(
        self,
        topic: str,
        options: list[str],
        required_votes: int = 0,
        timeout_s: int = 60,
    ) -> VoteSession:
        """Start a consensus vote."""
        self._vote_counter += 1

        if required_votes <= 0:
            alive = sum(1 for a in self._agents.values() if a.is_alive)
            required_votes = max(1, alive // 2 + 1)  # Majority

        session = VoteSession(
            session_id=f"vote-{self._vote_counter}",
            topic=topic,
            options=options,
            required_votes=required_votes,
            deadline=time.time() + timeout_s,
        )

        self._votes[session.session_id] = session
        return session

    def cast_vote(
        self,
        session_id: str,
        agent_id: str,
        choice: str,
    ) -> bool:
        """Cast a vote."""
        session = self._votes.get(session_id)
        if not session or session.decided or session.is_expired:
            return False

        if choice not in session.options:
            return False

        session.votes[agent_id] = choice

        # Check if we have enough votes
        if len(session.votes) >= session.required_votes:
            self._tally_votes(session)

        return True

    @staticmethod
    def _tally_votes(session: VoteSession) -> None:
        """Tally votes and determine result."""
        counts: dict[str, int] = defaultdict(int)
        for choice in session.votes.values():
            counts[choice] += 1

        winner = max(counts, key=counts.get)
        session.result = winner
        session.decided = True

    def discover(
        self,
        role: AgentRole | None = None,
        capability: str = "",
        alive_only: bool = True,
    ) -> list[RegisteredAgent]:
        """Discover agents matching criteria."""
        results = []

        for agent in self._agents.values():
            if alive_only and not agent.is_alive:
                continue
            if role and agent.role != role:
                continue
            if capability and capability not in agent.capabilities:
                continue
            results.append(agent)

        return results

    def get_stale_agents(self, timeout_s: int = 120) -> list[str]:
        """Get agents that haven't sent a heartbeat recently."""
        stale = []
        for agent in self._agents.values():
            if (time.time() - agent.last_heartbeat) > timeout_s:
                stale.append(agent.agent_id)
        return stale

    def get_stats(self) -> dict[str, Any]:
        alive = sum(1 for a in self._agents.values() if a.is_alive)
        return {
            "agents": len(self._agents),
            "alive": alive,
            "messages": len(self._messages),
            "votes": len(self._votes),
            "decided_votes": sum(1 for v in self._votes.values() if v.decided),
        }
