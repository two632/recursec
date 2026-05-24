"""Consensus engine — multi-model voting for high-stakes decisions.

Implements:
1. Multi-model parallel query
2. Weighted voting based on model expertise
3. Confidence-threshold consensus
4. Disagreement resolution
5. Evidence aggregation
6. Consensus prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class VoteType(str, Enum):
    AGREE = "agree"
    DISAGREE = "disagree"
    ABSTAIN = "abstain"
    PARTIAL = "partial"


class ConsensusStatus(str, Enum):
    UNANIMOUS = "unanimous"       # All agree
    MAJORITY = "majority"         # >50% agree
    SUPERMAJORITY = "supermajority"  # >66% agree
    SPLIT = "split"               # No clear majority
    INSUFFICIENT = "insufficient"  # Not enough votes


@dataclass
class Vote:
    """A single model's vote."""
    model_id: str = ""
    model_name: str = ""
    vote: VoteType = VoteType.ABSTAIN
    confidence: float = 0.5
    reasoning: str = ""
    evidence: list[str] = field(default_factory=list)
    weight: float = 1.0
    response_time_ms: float = 0.0

    @property
    def weighted_score(self) -> float:
        scores = {
            VoteType.AGREE: 1.0,
            VoteType.PARTIAL: 0.5,
            VoteType.ABSTAIN: 0.0,
            VoteType.DISAGREE: -1.0,
        }
        return scores.get(self.vote, 0.0) * self.confidence * self.weight

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_name[:12],
            "vote": self.vote.value[:6],
            "conf": f"{self.confidence:.0%}",
            "weight": f"{self.weight:.1f}",
        }


@dataclass
class ConsensusResult:
    """Result of a consensus vote."""
    question: str = ""
    votes: list[Vote] = field(default_factory=list)
    status: ConsensusStatus = ConsensusStatus.INSUFFICIENT
    agreement_ratio: float = 0.0
    weighted_score: float = 0.0
    final_answer: str = ""
    confidence: float = 0.0
    dissenting_reasons: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value[:8],
            "agree": f"{self.agreement_ratio:.0%}",
            "score": f"{self.weighted_score:.2f}",
            "conf": f"{self.confidence:.0%}",
            "votes": len(self.votes),
        }


@dataclass
class ConsensusRequest:
    """A request for multi-model consensus."""
    request_id: str = ""
    question: str = ""
    context: str = ""
    min_votes: int = 3
    threshold: float = 0.66       # Required agreement ratio
    domain: str = ""              # Task domain for model selection
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.request_id[:10],
            "question": self.question[:25],
            "min": self.min_votes,
            "threshold": f"{self.threshold:.0%}",
        }


class ConsensusEngine:
    """Multi-model voting for high-stakes decisions.

    Queries multiple models in parallel and aggregates
    their responses using weighted voting to reach
    consensus on critical security decisions.
    """

    def __init__(self) -> None:
        self._history: list[ConsensusResult] = []
        self._request_counter = 0
        self._log = logger.bind(component="consensus")

    def create_request(
        self,
        question: str,
        context: str = "",
        min_votes: int = 3,
        threshold: float = 0.66,
        domain: str = "",
    ) -> ConsensusRequest:
        """Create a consensus request."""
        self._request_counter += 1
        return ConsensusRequest(
            request_id=f"cons-{self._request_counter}",
            question=question,
            context=context,
            min_votes=min_votes,
            threshold=threshold,
            domain=domain,
        )

    def tally(
        self,
        request: ConsensusRequest,
        votes: list[Vote],
    ) -> ConsensusResult:
        """Tally votes and determine consensus."""
        result = ConsensusResult(
            question=request.question,
            votes=votes,
        )

        if len(votes) < request.min_votes:
            result.status = ConsensusStatus.INSUFFICIENT
            self._history.append(result)
            return result

        # Count votes
        agree_count = sum(1 for v in votes if v.vote == VoteType.AGREE)
        total_voting = sum(1 for v in votes if v.vote != VoteType.ABSTAIN)

        if total_voting == 0:
            result.status = ConsensusStatus.INSUFFICIENT
            self._history.append(result)
            return result

        # Agreement ratio
        result.agreement_ratio = agree_count / total_voting

        # Weighted score
        result.weighted_score = sum(v.weighted_score for v in votes)

        # Determine status
        if result.agreement_ratio == 1.0:
            result.status = ConsensusStatus.UNANIMOUS
        elif result.agreement_ratio >= 0.66:
            result.status = ConsensusStatus.SUPERMAJORITY
        elif result.agreement_ratio > 0.5:
            result.status = ConsensusStatus.MAJORITY
        else:
            result.status = ConsensusStatus.SPLIT

        # Final answer from highest-confidence agreeing vote
        agree_votes = [v for v in votes if v.vote in (VoteType.AGREE, VoteType.PARTIAL)]
        if agree_votes:
            best = max(agree_votes, key=lambda v: v.confidence * v.weight)
            result.final_answer = best.reasoning

        # Dissenting reasons
        result.dissenting_reasons = [
            v.reasoning for v in votes
            if v.vote == VoteType.DISAGREE and v.reasoning
        ]

        # Overall confidence
        if votes:
            result.confidence = sum(
                v.confidence * v.weight for v in votes
            ) / sum(v.weight for v in votes)

        self._history.append(result)
        return result

    def meets_threshold(
        self,
        result: ConsensusResult,
        threshold: float = 0.66,
    ) -> bool:
        """Check if consensus meets a threshold."""
        return (
            result.agreement_ratio >= threshold
            and result.status != ConsensusStatus.INSUFFICIENT
        )

    def build_consensus_prompt(self) -> str:
        """Build consensus context for LLM."""
        lines = ["## Consensus Engine\n"]

        lines.append(f"Total decisions: {len(self._history)}")

        if self._history:
            # Recent decisions
            recent = self._history[-3:]
            lines.append("\nRecent decisions:")
            for r in recent:
                lines.append(
                    f"  [{r.status.value[:8]}] {r.question[:30]} "
                    f"agree={r.agreement_ratio:.0%} "
                    f"conf={r.confidence:.0%}"
                )

            # Stats
            unanimous = sum(1 for r in self._history if r.status == ConsensusStatus.UNANIMOUS)
            split = sum(1 for r in self._history if r.status == ConsensusStatus.SPLIT)
            lines.append(f"\nUnanimous: {unanimous} | Split: {split}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for r in self._history:
            s = r.status.value
            status_counts[s] = status_counts.get(s, 0) + 1

        avg_agreement = 0.0
        if self._history:
            avg_agreement = sum(r.agreement_ratio for r in self._history) / len(self._history)

        return {
            "total_decisions": len(self._history),
            "by_status": status_counts,
            "avg_agreement": avg_agreement,
        }
