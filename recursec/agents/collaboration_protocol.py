"""Agent collaboration protocol — structured knowledge sharing.

Implements:
1. Shared knowledge pool between agents
2. Finding handoff protocol
3. Context transfer between agents
4. Agent capability advertising
5. Collaborative analysis sessions
6. Collaboration prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ShareType(str, Enum):
    FINDING = "finding"           # Security finding
    CONTEXT = "context"           # Assessment context
    CREDENTIAL = "credential"     # Discovered credential
    ENDPOINT = "endpoint"         # Discovered endpoint
    SERVICE = "service"           # Discovered service
    TECHNIQUE = "technique"       # Effective technique
    FAILURE = "failure"           # Failed approach
    INSIGHT = "insight"           # Analysis insight


class HandoffReason(str, Enum):
    SPECIALIZATION = "specialization"  # Need specialist
    DEPTH_LIMIT = "depth_limit"        # Recursion depth reached
    TOOL_REQUIRED = "tool_required"    # Need specific tool
    KNOWLEDGE_GAP = "knowledge_gap"    # Need domain knowledge
    VALIDATION = "validation"          # Need cross-validation
    ESCALATION = "escalation"          # Severity requires escalation


@dataclass
class SharedKnowledge:
    """A piece of shared knowledge."""
    knowledge_id: str = ""
    share_type: ShareType = ShareType.FINDING
    source_agent: str = ""
    content: dict[str, Any] = field(default_factory=dict)
    relevance_tags: list[str] = field(default_factory=list)
    confidence: float = 0.5
    consumed_by: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.share_type.value[:8],
            "source": self.source_agent[:10],
            "conf": f"{self.confidence:.2f}",
            "tags": len(self.relevance_tags),
        }


@dataclass
class AgentHandoff:
    """A task handoff between agents."""
    handoff_id: str = ""
    from_agent: str = ""
    to_agent: str = ""
    reason: HandoffReason = HandoffReason.SPECIALIZATION
    task: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    findings_so_far: list[dict[str, Any]] = field(default_factory=list)
    accepted: bool = False
    completed: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_agent[:10],
            "to": self.to_agent[:10],
            "reason": self.reason.value[:12],
            "accepted": self.accepted,
        }


@dataclass
class CollaborationSession:
    """A multi-agent collaboration session."""
    session_id: str = ""
    topic: str = ""
    participants: list[str] = field(default_factory=list)
    shared_pool: list[str] = field(default_factory=list)  # knowledge_ids
    conclusions: list[str] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "topic": self.topic[:20],
            "agents": len(self.participants),
            "shared": len(self.shared_pool),
        }


class CollaborationProtocol:
    """Structured inter-agent knowledge sharing.

    Manages shared knowledge pools, handoffs,
    and collaborative analysis sessions.
    """

    def __init__(self, max_pool_size: int = 500) -> None:
        self._pool: dict[str, SharedKnowledge] = {}
        self._handoffs: dict[str, AgentHandoff] = {}
        self._sessions: dict[str, CollaborationSession] = {}
        self._knowledge_counter = 0
        self._handoff_counter = 0
        self._session_counter = 0
        self._max_pool = max_pool_size
        self._log = logger.bind(component="collab")

    def share(
        self,
        source_agent: str,
        share_type: ShareType,
        content: dict[str, Any],
        relevance_tags: list[str] | None = None,
        confidence: float = 0.5,
    ) -> SharedKnowledge:
        """Share knowledge to the pool."""
        self._knowledge_counter += 1

        knowledge = SharedKnowledge(
            knowledge_id=f"sk-{self._knowledge_counter}",
            share_type=share_type,
            source_agent=source_agent,
            content=content,
            relevance_tags=relevance_tags or [],
            confidence=confidence,
        )
        self._pool[knowledge.knowledge_id] = knowledge

        # Evict old entries if over limit
        if len(self._pool) > self._max_pool:
            oldest_id = min(
                self._pool,
                key=lambda k: self._pool[k].timestamp,
            )
            del self._pool[oldest_id]

        return knowledge

    def query(
        self,
        agent_id: str,
        share_type: ShareType | None = None,
        tags: list[str] | None = None,
        min_confidence: float = 0.0,
        max_results: int = 10,
    ) -> list[SharedKnowledge]:
        """Query the shared knowledge pool."""
        results = []

        for knowledge in self._pool.values():
            if share_type and knowledge.share_type != share_type:
                continue
            if knowledge.confidence < min_confidence:
                continue
            if tags:
                overlap = set(tags) & set(knowledge.relevance_tags)
                if not overlap:
                    continue

            results.append(knowledge)

        # Sort by confidence
        results.sort(key=lambda k: k.confidence, reverse=True)

        # Mark as consumed
        for k in results[:max_results]:
            if agent_id not in k.consumed_by:
                k.consumed_by.append(agent_id)

        return results[:max_results]

    def handoff(
        self,
        from_agent: str,
        to_agent: str,
        reason: HandoffReason,
        task: str,
        context: dict[str, Any] | None = None,
        findings: list[dict[str, Any]] | None = None,
    ) -> AgentHandoff:
        """Create a task handoff."""
        self._handoff_counter += 1

        ho = AgentHandoff(
            handoff_id=f"ho-{self._handoff_counter}",
            from_agent=from_agent,
            to_agent=to_agent,
            reason=reason,
            task=task,
            context=context or {},
            findings_so_far=findings or [],
        )
        self._handoffs[ho.handoff_id] = ho
        return ho

    def accept_handoff(self, handoff_id: str) -> None:
        """Accept a handoff."""
        ho = self._handoffs.get(handoff_id)
        if ho:
            ho.accepted = True

    def complete_handoff(
        self,
        handoff_id: str,
        result: dict[str, Any] | None = None,
    ) -> None:
        """Complete a handoff."""
        ho = self._handoffs.get(handoff_id)
        if ho:
            ho.completed = True
            if result:
                ho.context["result"] = result

    def start_session(
        self,
        topic: str,
        participants: list[str],
    ) -> CollaborationSession:
        """Start a collaborative analysis session."""
        self._session_counter += 1

        session = CollaborationSession(
            session_id=f"cs-{self._session_counter}",
            topic=topic,
            participants=participants,
        )
        self._sessions[session.session_id] = session
        return session

    def add_to_session(
        self,
        session_id: str,
        knowledge_id: str,
    ) -> None:
        """Add shared knowledge to a session."""
        session = self._sessions.get(session_id)
        if session:
            session.shared_pool.append(knowledge_id)

    def conclude_session(
        self,
        session_id: str,
        conclusions: list[str],
    ) -> None:
        """End a session with conclusions."""
        session = self._sessions.get(session_id)
        if session:
            session.conclusions = conclusions
            session.ended_at = time.time()

    def build_collaboration_prompt(self, agent_id: str = "") -> str:
        """Build collaboration context for LLM."""
        lines = ["## Collaboration\n"]
        lines.append(f"Shared knowledge: {len(self._pool)}")
        lines.append(f"Handoffs: {len(self._handoffs)}")
        lines.append(f"Sessions: {len(self._sessions)}")

        # Recent shared knowledge
        recent = sorted(
            self._pool.values(),
            key=lambda k: k.timestamp,
            reverse=True,
        )[:5]
        if recent:
            lines.append("\nRecent shared:")
            for k in recent:
                lines.append(
                    f"  [{k.share_type.value[:6]}] "
                    f"from {k.source_agent[:8]} "
                    f"(conf={k.confidence:.2f})"
                )

        # Pending handoffs for this agent
        if agent_id:
            pending = [
                h for h in self._handoffs.values()
                if h.to_agent == agent_id and not h.completed
            ]
            if pending:
                lines.append(f"\nPending handoffs ({len(pending)}):")
                for h in pending[:3]:
                    lines.append(
                        f"  from {h.from_agent[:8]}: "
                        f"{h.task[:25]}"
                    )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for k in self._pool.values():
            type_counts[k.share_type.value] = type_counts.get(k.share_type.value, 0) + 1

        return {
            "pool_size": len(self._pool),
            "handoffs": len(self._handoffs),
            "sessions": len(self._sessions),
            "by_type": type_counts,
        }
