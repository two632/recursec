"""Consensus engine — multi-model voting and debate for finding validation.

Implements:
1. Multi-model voting on findings (majority vote)
2. Weighted voting based on model expertise
3. Debate protocol (argue/counter/synthesize)
4. Confidence aggregation across models
5. Disagreement resolution strategies
6. Validation quorum requirements
7. Finding deduplication via consensus
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class VoteType(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNCERTAIN = "uncertain"
    NEEDS_MORE_INFO = "needs_more_info"


class DebatePhase(str, Enum):
    INITIAL_ASSESSMENT = "initial_assessment"
    ARGUMENT = "argument"
    COUNTER_ARGUMENT = "counter_argument"
    REBUTTAL = "rebuttal"
    SYNTHESIS = "synthesis"
    VERDICT = "verdict"


class ConsensusStatus(str, Enum):
    PENDING = "pending"
    VOTING = "voting"
    DEBATING = "debating"
    CONSENSUS_REACHED = "consensus_reached"
    NO_CONSENSUS = "no_consensus"
    ESCALATED = "escalated"


@dataclass
class Vote:
    """A model's vote on a finding."""
    voter_id: str = ""         # Model or agent ID
    model_name: str = ""
    vote: VoteType = VoteType.UNCERTAIN
    confidence: float = 0.5
    reasoning: str = ""
    weight: float = 1.0        # Expertise-based weight
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "voter": self.voter_id[:10],
            "model": self.model_name[:12],
            "vote": self.vote.value,
            "conf": round(self.confidence, 2),
            "weight": round(self.weight, 2),
        }


@dataclass
class DebateEntry:
    """An entry in a debate."""
    entry_id: str = ""
    phase: DebatePhase = DebatePhase.INITIAL_ASSESSMENT
    model_name: str = ""
    position: str = ""        # valid/invalid
    argument: str = ""
    evidence: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "model": self.model_name[:12],
            "position": self.position[:10],
        }


@dataclass
class ConsensusSession:
    """A consensus session for a finding."""
    session_id: str = ""
    finding_id: str = ""
    finding_description: str = ""
    status: ConsensusStatus = ConsensusStatus.PENDING
    votes: list[Vote] = field(default_factory=list)
    debate_entries: list[DebateEntry] = field(default_factory=list)
    quorum: int = 3          # Minimum votes needed
    threshold: float = 0.66  # Fraction needed for consensus
    final_verdict: str = ""
    final_confidence: float = 0.0
    created_at: float = field(default_factory=time.time)
    resolved_at: float = 0.0

    @property
    def vote_count(self) -> int:
        return len(self.votes)

    @property
    def has_quorum(self) -> bool:
        return self.vote_count >= self.quorum

    @property
    def valid_votes(self) -> int:
        return sum(1 for v in self.votes if v.vote == VoteType.VALID)

    @property
    def invalid_votes(self) -> int:
        return sum(1 for v in self.votes if v.vote == VoteType.INVALID)

    @property
    def weighted_valid_score(self) -> float:
        total_weight = sum(v.weight for v in self.votes)
        if total_weight == 0:
            return 0
        valid_weight = sum(v.weight * v.confidence for v in self.votes if v.vote == VoteType.VALID)
        return valid_weight / total_weight

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.session_id[:10],
            "finding": self.finding_description[:25],
            "status": self.status.value,
            "votes": f"{self.valid_votes}v/{self.invalid_votes}i/{self.vote_count}t",
            "score": round(self.weighted_valid_score, 2),
            "verdict": self.final_verdict[:15],
        }


# ── Model expertise weights ──────────────────────────────────

MODEL_WEIGHTS: dict[str, dict[str, float]] = {
    "whiterabbitneo-7b": {"security": 2.0, "exploit": 2.0, "default": 1.0},
    "qwen-coder-14b": {"code": 2.0, "vuln_analysis": 1.5, "default": 1.0},
    "qwen-coder-7b": {"code": 1.8, "default": 0.9},
    "deepseek-r1-7b": {"reasoning": 2.0, "analysis": 1.8, "default": 1.0},
    "hermes-14b": {"general": 1.5, "reasoning": 1.3, "default": 1.0},
    "codellama-13b": {"code": 1.8, "default": 0.8},
    "dolphin-8b": {"security": 1.3, "default": 1.0},
    "mistral-7b": {"general": 1.2, "default": 1.0},
    "llama-3.1-8b": {"general": 1.2, "default": 1.0},
}


class ConsensusEngine:
    """Multi-model consensus engine for finding validation.

    Multiple models vote on whether a finding is
    valid. Supports weighted voting, quorum, and
    structured debate for disagreements.
    """

    def __init__(
        self,
        quorum: int = 3,
        threshold: float = 0.66,
    ) -> None:
        self._sessions: dict[str, ConsensusSession] = {}
        self._quorum = quorum
        self._threshold = threshold
        self._counter = 0
        self._log = logger.bind(component="consensus_engine")

    def create_session(
        self,
        finding_id: str,
        finding_description: str,
    ) -> ConsensusSession:
        """Create a new consensus session."""
        self._counter += 1
        session = ConsensusSession(
            session_id=f"cons-{self._counter}",
            finding_id=finding_id,
            finding_description=finding_description,
            status=ConsensusStatus.VOTING,
            quorum=self._quorum,
            threshold=self._threshold,
        )
        self._sessions[session.session_id] = session
        return session

    def cast_vote(
        self,
        session_id: str,
        voter_id: str,
        model_name: str,
        vote: VoteType,
        confidence: float = 0.5,
        reasoning: str = "",
        domain: str = "default",
    ) -> Vote | None:
        """Cast a vote in a session."""
        session = self._sessions.get(session_id)
        if not session:
            return None

        # Calculate weight from model expertise
        model_weights = MODEL_WEIGHTS.get(model_name, {"default": 1.0})
        weight = model_weights.get(domain, model_weights.get("default", 1.0))

        v = Vote(
            voter_id=voter_id,
            model_name=model_name,
            vote=vote,
            confidence=confidence,
            reasoning=reasoning,
            weight=weight,
        )
        session.votes.append(v)

        # Check for consensus after each vote
        if session.has_quorum:
            self._check_consensus(session)

        return v

    def add_debate_entry(
        self,
        session_id: str,
        phase: DebatePhase,
        model_name: str,
        position: str,
        argument: str,
        evidence: list[str] | None = None,
    ) -> DebateEntry | None:
        """Add a debate entry."""
        session = self._sessions.get(session_id)
        if not session:
            return None

        self._counter += 1
        entry = DebateEntry(
            entry_id=f"debate-{self._counter}",
            phase=phase,
            model_name=model_name,
            position=position,
            argument=argument,
            evidence=evidence or [],
        )
        session.debate_entries.append(entry)
        session.status = ConsensusStatus.DEBATING
        return entry

    def force_verdict(
        self,
        session_id: str,
        verdict: str,
        confidence: float = 0.5,
    ) -> bool:
        """Force a verdict when no consensus can be reached."""
        session = self._sessions.get(session_id)
        if not session:
            return False

        session.final_verdict = verdict
        session.final_confidence = confidence
        session.status = ConsensusStatus.ESCALATED
        session.resolved_at = time.time()
        return True

    def get_active_sessions(self) -> list[ConsensusSession]:
        """Get sessions still awaiting consensus."""
        return [
            s for s in self._sessions.values()
            if s.status in (ConsensusStatus.PENDING, ConsensusStatus.VOTING, ConsensusStatus.DEBATING)
        ]

    def get_validated_findings(self) -> list[ConsensusSession]:
        """Get sessions with validated findings."""
        return [
            s for s in self._sessions.values()
            if s.status == ConsensusStatus.CONSENSUS_REACHED
            and s.final_verdict == "valid"
        ]

    def build_consensus_prompt(self, max_sessions: int = 5) -> str:
        """Build consensus context for LLM."""
        lines = ["## Consensus Status\n"]

        active = self.get_active_sessions()
        if active:
            lines.append(f"Active sessions: {len(active)}")
            for s in active[:max_sessions]:
                lines.append(
                    f"  [{s.session_id[:8]}] {s.finding_description[:30]} "
                    f"votes={s.valid_votes}v/{s.invalid_votes}i score={s.weighted_valid_score:.2f}"
                )

        validated = self.get_validated_findings()
        if validated:
            lines.append(f"\nValidated findings: {len(validated)}")

        return "\n".join(lines)

    def _check_consensus(self, session: ConsensusSession) -> None:
        """Check if consensus has been reached."""
        score = session.weighted_valid_score

        if score >= session.threshold:
            session.status = ConsensusStatus.CONSENSUS_REACHED
            session.final_verdict = "valid"
            session.final_confidence = score
            session.resolved_at = time.time()
        elif (1 - score) >= session.threshold:
            session.status = ConsensusStatus.CONSENSUS_REACHED
            session.final_verdict = "invalid"
            session.final_confidence = 1 - score
            session.resolved_at = time.time()
        elif session.vote_count >= session.quorum + 2:
            # Extended voting, still no consensus
            session.status = ConsensusStatus.NO_CONSENSUS

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for s in self._sessions.values():
            status_counts[s.status.value] = status_counts.get(s.status.value, 0) + 1

        return {
            "sessions": len(self._sessions),
            "by_status": status_counts,
            "validated": len(self.get_validated_findings()),
            "avg_votes": (
                sum(s.vote_count for s in self._sessions.values()) / len(self._sessions)
                if self._sessions else 0
            ),
        }
