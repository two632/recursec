"""Agent collaboration protocol — structured inter-agent communication.

Enables agents to collaborate effectively:
1. Shared blackboard — agents write/read findings to a shared space
2. Request-response — agent asks another agent for specific information
3. Broadcast — agent shares critical finding with all agents
4. Negotiation — agents negotiate task ownership
5. Voting — agents vote on conflicting findings
6. Delegation — parent delegates with context to child
7. Escalation — child escalates complex issue to parent
8. Handoff — agent passes task to better-suited agent

This is what makes multi-agent actually work vs just
running tools in parallel with no coordination.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MessageType(str, Enum):
    REQUEST = "request"
    RESPONSE = "response"
    BROADCAST = "broadcast"
    DELEGATION = "delegation"
    ESCALATION = "escalation"
    HANDOFF = "handoff"
    VOTE_REQUEST = "vote_request"
    VOTE_CAST = "vote_cast"
    BLACKBOARD_WRITE = "blackboard_write"
    BLACKBOARD_READ = "blackboard_read"
    NEGOTIATION = "negotiation"
    ACK = "ack"
    NACK = "nack"


class MessagePriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


@dataclass
class AgentMessage:
    """A message between agents."""
    msg_id: str = ""
    msg_type: MessageType = MessageType.REQUEST
    sender_id: str = ""
    receiver_id: str = ""
    content: dict[str, Any] = field(default_factory=dict)
    priority: MessagePriority = MessagePriority.NORMAL
    reply_to: str = ""
    timestamp: float = field(default_factory=time.time)
    ttl_s: float = 300.0
    requires_ack: bool = False

    @property
    def is_expired(self) -> bool:
        return time.time() - self.timestamp > self.ttl_s

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.msg_id[:8],
            "type": self.msg_type.value[:10],
            "from": self.sender_id[:8],
            "to": self.receiver_id[:8],
            "priority": self.priority.value[:6],
        }


@dataclass
class BlackboardEntry:
    """An entry on the shared blackboard."""
    key: str = ""
    value: Any = None
    author_id: str = ""
    entry_type: str = ""
    timestamp: float = field(default_factory=time.time)
    version: int = 1
    readers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key[:20],
            "type": self.entry_type[:10],
            "author": self.author_id[:8],
            "ver": self.version,
            "readers": len(self.readers),
        }


@dataclass
class VoteSession:
    """A voting session for resolving disagreements."""
    session_id: str = ""
    topic: str = ""
    options: list[str] = field(default_factory=list)
    votes: dict[str, str] = field(default_factory=dict)
    deadline: float = 0.0
    status: str = "open"
    winner: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.session_id[:8],
            "topic": self.topic[:25],
            "votes": len(self.votes),
            "status": self.status[:6],
        }


@dataclass
class NegotiationSession:
    """A negotiation session for task ownership."""
    session_id: str = ""
    task_description: str = ""
    candidates: list[str] = field(default_factory=list)
    bids: dict[str, float] = field(default_factory=dict)
    winner_id: str = ""
    status: str = "open"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.session_id[:8],
            "task": self.task_description[:20],
            "bids": len(self.bids),
            "winner": self.winner_id[:8],
        }


class SharedBlackboard:
    """Shared knowledge space for agent collaboration."""

    def __init__(self) -> None:
        self._entries: dict[str, BlackboardEntry] = {}
        self._by_type: dict[str, list[str]] = defaultdict(list)

    def write(self, key: str, value: Any, author_id: str, entry_type: str = "finding") -> BlackboardEntry:
        if key in self._entries:
            entry = self._entries[key]
            entry.value = value
            entry.version += 1
            entry.timestamp = time.time()
        else:
            entry = BlackboardEntry(
                key=key,
                value=value,
                author_id=author_id,
                entry_type=entry_type,
            )
            self._entries[key] = entry
            self._by_type[entry_type].append(key)
        return entry

    def read(self, key: str, reader_id: str = "") -> Any:
        entry = self._entries.get(key)
        if entry:
            if reader_id:
                entry.readers.append(reader_id)
            return entry.value
        return None

    def query_by_type(self, entry_type: str) -> list[BlackboardEntry]:
        keys = self._by_type.get(entry_type, [])
        return [self._entries[k] for k in keys if k in self._entries]

    def get_all(self) -> list[BlackboardEntry]:
        return list(self._entries.values())

    @property
    def size(self) -> int:
        return len(self._entries)


class MessageRouter:
    """Routes messages between agents."""

    def __init__(self) -> None:
        self._queues: dict[str, list[AgentMessage]] = defaultdict(list)
        self._broadcast_log: list[AgentMessage] = []
        self._msg_counter = 0
        self._total_routed = 0

    def send(self, msg: AgentMessage) -> str:
        self._msg_counter += 1
        msg.msg_id = f"msg-{self._msg_counter}"
        self._total_routed += 1

        if msg.msg_type == MessageType.BROADCAST:
            self._broadcast_log.append(msg)
            for queue_id in self._queues:
                if queue_id != msg.sender_id:
                    self._queues[queue_id].append(msg)
        else:
            self._queues[msg.receiver_id].append(msg)

        return msg.msg_id

    def receive(self, agent_id: str, msg_type: MessageType | None = None) -> list[AgentMessage]:
        queue = self._queues.get(agent_id, [])
        if msg_type:
            messages = [m for m in queue if m.msg_type == msg_type and not m.is_expired]
        else:
            messages = [m for m in queue if not m.is_expired]
        self._queues[agent_id] = [m for m in queue if m not in messages]
        return messages

    def register_agent(self, agent_id: str) -> None:
        if agent_id not in self._queues:
            self._queues[agent_id] = []

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "agents": len(self._queues),
            "total_routed": self._total_routed,
            "broadcasts": len(self._broadcast_log),
            "pending": sum(len(q) for q in self._queues.values()),
        }


class VotingSystem:
    """Voting system for resolving conflicting findings."""

    def __init__(self) -> None:
        self._sessions: dict[str, VoteSession] = {}
        self._counter = 0

    def create_vote(self, topic: str, options: list[str], deadline_s: float = 60.0) -> VoteSession:
        self._counter += 1
        session = VoteSession(
            session_id=f"vote-{self._counter}",
            topic=topic,
            options=options,
            deadline=time.time() + deadline_s,
        )
        self._sessions[session.session_id] = session
        return session

    def cast_vote(self, session_id: str, voter_id: str, choice: str) -> bool:
        session = self._sessions.get(session_id)
        if not session or session.status != "open":
            return False
        if choice not in session.options:
            return False
        session.votes[voter_id] = choice
        return True

    def tally(self, session_id: str) -> str:
        session = self._sessions.get(session_id)
        if not session:
            return ""
        counts: dict[str, int] = defaultdict(int)
        for choice in session.votes.values():
            counts[choice] += 1
        if not counts:
            return ""
        winner = max(counts, key=counts.get)
        session.winner = winner
        session.status = "closed"
        return winner


class NegotiationManager:
    """Manages task ownership negotiation."""

    def __init__(self) -> None:
        self._sessions: dict[str, NegotiationSession] = {}
        self._counter = 0

    def create_negotiation(self, task: str, candidates: list[str]) -> NegotiationSession:
        self._counter += 1
        session = NegotiationSession(
            session_id=f"neg-{self._counter}",
            task_description=task,
            candidates=candidates,
        )
        self._sessions[session.session_id] = session
        return session

    def submit_bid(self, session_id: str, agent_id: str, capability_score: float) -> bool:
        session = self._sessions.get(session_id)
        if not session or session.status != "open":
            return False
        if agent_id not in session.candidates:
            return False
        session.bids[agent_id] = capability_score
        return True

    def resolve(self, session_id: str) -> str:
        session = self._sessions.get(session_id)
        if not session or not session.bids:
            return ""
        winner = max(session.bids, key=session.bids.get)
        session.winner_id = winner
        session.status = "resolved"
        return winner


class AgentCollaboration:
    """Unified collaboration system."""

    def __init__(self) -> None:
        self.blackboard = SharedBlackboard()
        self.router = MessageRouter()
        self.voting = VotingSystem()
        self.negotiation = NegotiationManager()
        self._log = logger.bind(component="collaboration")

    def delegate_task(self, parent_id: str, child_id: str, task: dict[str, Any]) -> str:
        """Parent delegates a task to a child agent."""
        msg = AgentMessage(
            msg_type=MessageType.DELEGATION,
            sender_id=parent_id,
            receiver_id=child_id,
            content=task,
            priority=MessagePriority.HIGH,
            requires_ack=True,
        )
        return self.router.send(msg)

    def escalate_issue(self, child_id: str, parent_id: str, issue: dict[str, Any]) -> str:
        """Child escalates an issue to parent."""
        msg = AgentMessage(
            msg_type=MessageType.ESCALATION,
            sender_id=child_id,
            receiver_id=parent_id,
            content=issue,
            priority=MessagePriority.HIGH,
        )
        return self.router.send(msg)

    def handoff_task(self, from_id: str, to_id: str, task: dict[str, Any], reason: str = "") -> str:
        """Hand off a task to a better-suited agent."""
        msg = AgentMessage(
            msg_type=MessageType.HANDOFF,
            sender_id=from_id,
            receiver_id=to_id,
            content={**task, "handoff_reason": reason},
            priority=MessagePriority.NORMAL,
        )
        return self.router.send(msg)

    def broadcast_finding(self, sender_id: str, finding: dict[str, Any]) -> str:
        """Broadcast a critical finding to all agents."""
        msg = AgentMessage(
            msg_type=MessageType.BROADCAST,
            sender_id=sender_id,
            content=finding,
            priority=MessagePriority.CRITICAL,
        )
        self.blackboard.write(
            key=f"finding-{msg.msg_id}",
            value=finding,
            author_id=sender_id,
            entry_type="finding",
        )
        return self.router.send(msg)

    def request_info(self, requester_id: str, provider_id: str, query: dict[str, Any]) -> str:
        """Request information from another agent."""
        msg = AgentMessage(
            msg_type=MessageType.REQUEST,
            sender_id=requester_id,
            receiver_id=provider_id,
            content=query,
            requires_ack=True,
        )
        return self.router.send(msg)

    def build_collaboration_prompt(self) -> str:
        """Build LLM prompt with collaboration state."""
        lines = ["## Agent Collaboration State"]

        bb_entries = self.blackboard.get_all()
        if bb_entries:
            lines.append(f"\nShared findings: {len(bb_entries)}")
            for entry in bb_entries[-5:]:
                lines.append(f"  - [{entry.entry_type}] {entry.key[:30]} (by {entry.author_id[:8]})")

        stats = self.router.stats
        lines.append(f"\nMessages: {stats['total_routed']} routed, {stats['pending']} pending")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "blackboard_size": self.blackboard.size,
            "router": self.router.stats,
        }
