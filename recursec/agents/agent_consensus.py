"""Agent consensus mechanism — multi-model voting.

Implements:
1. Voting protocols (majority, weighted, unanimous)
2. Confidence aggregation across models
3. Disagreement resolution
4. Quorum requirements
5. Vote history and audit trail
6. Consensus prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class VoteProtocol(str, Enum):
    MAJORITY = "majority"           # >50% agree
    SUPERMAJORITY = "supermajority"  # >66% agree
    UNANIMOUS = "unanimous"         # 100% agree
    WEIGHTED = "weighted"           # Weight by model quality
    CONFIDENCE = "confidence"       # Highest aggregate confidence


class VoteOutcome(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    NO_QUORUM = "no_quorum"
    TIE = "tie"
    INSUFFICIENT = "insufficient"


class VotePosition(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    ABSTAIN = "abstain"


@dataclass
class Vote:
    """A single vote from a model/agent."""
    voter_id: str = ""
    model_id: str = ""
    position: VotePosition = VotePosition.ABSTAIN
    confidence: float = 0.5
    reasoning: str = ""
    weight: float = 1.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "voter": self.voter_id[:10],
            "pos": self.position.value[:4],
            "conf": f"{self.confidence:.2f}",
        }


@dataclass
class ConsensusSession:
    """A consensus-building session."""
    session_id: str = ""
    topic: str = ""
    protocol: VoteProtocol = VoteProtocol.MAJORITY
    quorum: int = 3
    votes: list[Vote] = field(default_factory=list)
    outcome: VoteOutcome = VoteOutcome.INSUFFICIENT
    resolved: bool = False
    created_at: float = field(default_factory=time.time)
    resolved_at: float = 0.0

    @property
    def vote_count(self) -> int:
        return len([v for v in self.votes if v.position != VotePosition.ABSTAIN])

    @property
    def has_quorum(self) -> bool:
        return self.vote_count >= self.quorum

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.session_id[:10],
            "topic": self.topic[:20],
            "votes": self.vote_count,
            "outcome": self.outcome.value[:6],
        }


class AgentConsensus:
    """Multi-model voting and consensus engine.

    Manages consensus sessions with configurable
    voting protocols, quorum, and weight systems.
    """

    def __init__(
        self,
        default_quorum: int = 3,
        default_protocol: VoteProtocol = VoteProtocol.MAJORITY,
    ) -> None:
        self._sessions: dict[str, ConsensusSession] = {}
        self._session_counter = 0
        self._default_quorum = default_quorum
        self._default_protocol = default_protocol
        self._model_weights: dict[str, float] = {}
        self._log = logger.bind(component="consensus")

    def set_model_weight(self, model_id: str, weight: float) -> None:
        """Set voting weight for a model."""
        self._model_weights[model_id] = max(0.1, min(5.0, weight))

    def create_session(
        self,
        topic: str,
        protocol: VoteProtocol | None = None,
        quorum: int | None = None,
    ) -> ConsensusSession:
        """Create a new consensus session."""
        self._session_counter += 1
        session = ConsensusSession(
            session_id=f"cons-{self._session_counter}",
            topic=topic,
            protocol=protocol or self._default_protocol,
            quorum=quorum or self._default_quorum,
        )
        self._sessions[session.session_id] = session
        return session

    def cast_vote(
        self,
        session_id: str,
        voter_id: str,
        model_id: str = "",
        position: VotePosition = VotePosition.APPROVE,
        confidence: float = 0.5,
        reasoning: str = "",
    ) -> Vote | None:
        """Cast a vote in a session."""
        session = self._sessions.get(session_id)
        if not session or session.resolved:
            return None

        # Check for duplicate voter
        for existing in session.votes:
            if existing.voter_id == voter_id:
                return None

        weight = self._model_weights.get(model_id, 1.0)

        vote = Vote(
            voter_id=voter_id,
            model_id=model_id,
            position=position,
            confidence=confidence,
            reasoning=reasoning,
            weight=weight,
        )
        session.votes.append(vote)

        # Auto-resolve if quorum reached
        if session.has_quorum:
            self._resolve(session)

        return vote

    def _resolve(self, session: ConsensusSession) -> VoteOutcome:
        """Resolve a consensus session."""
        active_votes = [v for v in session.votes if v.position != VotePosition.ABSTAIN]

        if len(active_votes) < session.quorum:
            session.outcome = VoteOutcome.NO_QUORUM
            return session.outcome

        if session.protocol == VoteProtocol.MAJORITY:
            outcome = self._resolve_majority(active_votes, 0.5)
        elif session.protocol == VoteProtocol.SUPERMAJORITY:
            outcome = self._resolve_majority(active_votes, 0.66)
        elif session.protocol == VoteProtocol.UNANIMOUS:
            outcome = self._resolve_unanimous(active_votes)
        elif session.protocol == VoteProtocol.WEIGHTED:
            outcome = self._resolve_weighted(active_votes)
        elif session.protocol == VoteProtocol.CONFIDENCE:
            outcome = self._resolve_confidence(active_votes)
        else:
            outcome = self._resolve_majority(active_votes, 0.5)

        session.outcome = outcome
        session.resolved = True
        session.resolved_at = time.time()
        return outcome

    def _resolve_majority(self, votes: list[Vote], threshold: float) -> VoteOutcome:
        """Resolve with simple/super majority."""
        approves = sum(1 for v in votes if v.position == VotePosition.APPROVE)
        total = len(votes)
        ratio = approves / total if total > 0 else 0

        if ratio > threshold:
            return VoteOutcome.APPROVED
        if ratio < (1 - threshold):
            return VoteOutcome.REJECTED
        return VoteOutcome.TIE

    def _resolve_unanimous(self, votes: list[Vote]) -> VoteOutcome:
        """Resolve with unanimous agreement."""
        all_approve = all(v.position == VotePosition.APPROVE for v in votes)
        all_reject = all(v.position == VotePosition.REJECT for v in votes)

        if all_approve:
            return VoteOutcome.APPROVED
        if all_reject:
            return VoteOutcome.REJECTED
        return VoteOutcome.REJECTED  # Any disagreement = rejected

    def _resolve_weighted(self, votes: list[Vote]) -> VoteOutcome:
        """Resolve with weighted voting."""
        approve_weight = sum(v.weight for v in votes if v.position == VotePosition.APPROVE)
        reject_weight = sum(v.weight for v in votes if v.position == VotePosition.REJECT)
        total_weight = approve_weight + reject_weight

        if total_weight == 0:
            return VoteOutcome.TIE

        ratio = approve_weight / total_weight

        if ratio > 0.5:
            return VoteOutcome.APPROVED
        if ratio < 0.5:
            return VoteOutcome.REJECTED
        return VoteOutcome.TIE

    def _resolve_confidence(self, votes: list[Vote]) -> VoteOutcome:
        """Resolve by aggregate confidence."""
        approve_conf = sum(
            v.confidence * v.weight
            for v in votes if v.position == VotePosition.APPROVE
        )
        reject_conf = sum(
            v.confidence * v.weight
            for v in votes if v.position == VotePosition.REJECT
        )

        if approve_conf > reject_conf:
            return VoteOutcome.APPROVED
        if reject_conf > approve_conf:
            return VoteOutcome.REJECTED
        return VoteOutcome.TIE

    def force_resolve(self, session_id: str) -> VoteOutcome:
        """Force resolution even without quorum."""
        session = self._sessions.get(session_id)
        if not session or session.resolved:
            return VoteOutcome.INSUFFICIENT
        return self._resolve(session)

    def build_consensus_prompt(self, session_id: str = "") -> str:
        """Build consensus context for LLM."""
        lines = ["## Consensus\n"]

        if session_id and session_id in self._sessions:
            session = self._sessions[session_id]
            lines.append(f"Topic: {session.topic[:30]}")
            lines.append(f"Protocol: {session.protocol.value}")
            lines.append(f"Votes: {session.vote_count}/{session.quorum}")
            lines.append(f"Outcome: {session.outcome.value}")

            for v in session.votes:
                lines.append(
                    f"  {v.voter_id[:10]}: {v.position.value} "
                    f"(c={v.confidence:.2f}, w={v.weight:.1f})"
                )
            if not session.resolved:
                lines.append("\nAwaiting more votes.")
        else:
            active = [s for s in self._sessions.values() if not s.resolved]
            resolved = [s for s in self._sessions.values() if s.resolved]
            lines.append(f"Active: {len(active)} | Resolved: {len(resolved)}")

            for s in active:
                lines.append(f"  {s.topic[:20]} ({s.vote_count}/{s.quorum})")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        resolved = [s for s in self._sessions.values() if s.resolved]
        outcome_counts: dict[str, int] = {}
        for s in resolved:
            o = s.outcome.value
            outcome_counts[o] = outcome_counts.get(o, 0) + 1

        return {
            "sessions": len(self._sessions),
            "resolved": len(resolved),
            "outcomes": outcome_counts,
        }
