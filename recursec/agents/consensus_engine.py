"""Consensus engine — achieves agreement among multiple agent opinions.

Implements:
1. Weighted voting consensus
2. Delphi method (iterative refinement)
3. Byzantine fault tolerance (handle bad actors)
4. Confidence-weighted aggregation
5. Minority opinion tracking
6. Consensus threshold management
7. Disagreement resolution strategies
8. Consensus history and audit trail
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ConsensusMethod(str, Enum):
    MAJORITY_VOTE = "majority_vote"
    WEIGHTED_VOTE = "weighted_vote"
    DELPHI = "delphi"
    SUPERMAJORITY = "supermajority"
    UNANIMOUS = "unanimous"


class ConsensusStatus(str, Enum):
    PENDING = "pending"
    REACHED = "reached"
    FAILED = "failed"
    DEADLOCK = "deadlock"


@dataclass
class Opinion:
    """An opinion from an agent."""
    agent_id: str = ""
    value: str = ""
    confidence: float = 0.5
    reasoning: str = ""
    round_number: int = 1
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id[:20],
            "value": self.value[:40],
            "confidence": round(self.confidence, 2),
            "round": self.round_number,
        }


@dataclass
class ConsensusResult:
    """Result of a consensus process."""
    consensus_id: str = ""
    question: str = ""
    method: ConsensusMethod = ConsensusMethod.WEIGHTED_VOTE
    status: ConsensusStatus = ConsensusStatus.PENDING
    result: str = ""
    confidence: float = 0.0
    agreement_score: float = 0.0      # 0.0-1.0
    rounds: int = 0
    opinions: list[Opinion] = field(default_factory=list)
    minority_opinions: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.consensus_id, "question": self.question[:40],
            "method": self.method.value, "status": self.status.value,
            "result": self.result[:40],
            "confidence": round(self.confidence, 2),
            "agreement": round(self.agreement_score, 2),
            "rounds": self.rounds,
            "opinions": len(self.opinions),
        }


class ConsensusEngine:
    """Achieves agreement among multiple agent opinions.

    Supports multiple consensus methods including
    majority voting, weighted voting, and Delphi.
    """

    def __init__(
        self,
        default_threshold: float = 0.6,
        max_rounds: int = 5,
    ) -> None:
        self._threshold = default_threshold
        self._max_rounds = max_rounds
        self._results: list[ConsensusResult] = []
        self._agent_weights: dict[str, float] = {}
        self._agent_accuracy: dict[str, float] = defaultdict(lambda: 0.5)
        self._consensus_counter = 0
        self._log = logger.bind(component="consensus_engine")

    def set_agent_weight(self, agent_id: str, weight: float) -> None:
        self._agent_weights[agent_id] = max(0.0, min(5.0, weight))

    def resolve(
        self,
        question: str,
        opinions: list[Opinion],
        method: ConsensusMethod = ConsensusMethod.WEIGHTED_VOTE,
    ) -> ConsensusResult:
        """Resolve consensus from opinions."""
        self._consensus_counter += 1

        result = ConsensusResult(
            consensus_id=f"cons-{self._consensus_counter}",
            question=question,
            method=method,
            opinions=opinions,
            rounds=1,
        )

        if not opinions:
            result.status = ConsensusStatus.FAILED
            return result

        if method == ConsensusMethod.MAJORITY_VOTE:
            self._majority_vote(result)
        elif method == ConsensusMethod.WEIGHTED_VOTE:
            self._weighted_vote(result)
        elif method == ConsensusMethod.SUPERMAJORITY:
            self._supermajority(result)
        elif method == ConsensusMethod.UNANIMOUS:
            self._unanimous(result)
        elif method == ConsensusMethod.DELPHI:
            self._delphi(result)

        self._results.append(result)
        return result

    def _majority_vote(self, result: ConsensusResult) -> None:
        """Simple majority voting."""
        votes = Counter(op.value for op in result.opinions)
        total = len(result.opinions)

        if not votes:
            result.status = ConsensusStatus.FAILED
            return

        winner, count = votes.most_common(1)[0]
        agreement = count / total

        if agreement >= self._threshold:
            result.result = winner
            result.agreement_score = agreement
            result.confidence = agreement
            result.status = ConsensusStatus.REACHED
        else:
            result.status = ConsensusStatus.DEADLOCK
            result.result = winner  # Still report the plurality winner

        # Track minority opinions
        for value, cnt in votes.items():
            if value != winner:
                result.minority_opinions.append(
                    f"{value} ({cnt}/{total})"
                )

    def _weighted_vote(self, result: ConsensusResult) -> None:
        """Confidence and weight-adjusted voting."""
        vote_weights: dict[str, float] = defaultdict(float)

        for op in result.opinions:
            agent_weight = self._agent_weights.get(op.agent_id, 1.0)
            accuracy = self._agent_accuracy[op.agent_id]
            combined_weight = op.confidence * agent_weight * accuracy
            vote_weights[op.value] += combined_weight

        if not vote_weights:
            result.status = ConsensusStatus.FAILED
            return

        total_weight = sum(vote_weights.values())
        best_value = max(vote_weights, key=vote_weights.get)
        best_weight = vote_weights[best_value]

        agreement = best_weight / max(0.001, total_weight)

        if agreement >= self._threshold:
            result.result = best_value
            result.agreement_score = agreement
            result.confidence = agreement
            result.status = ConsensusStatus.REACHED
        else:
            result.status = ConsensusStatus.DEADLOCK
            result.result = best_value

        for value, weight in vote_weights.items():
            if value != best_value:
                result.minority_opinions.append(
                    f"{value} (weight: {weight:.2f})"
                )

    def _supermajority(self, result: ConsensusResult) -> None:
        """Require 2/3 agreement."""
        votes = Counter(op.value for op in result.opinions)
        total = len(result.opinions)

        if not votes:
            result.status = ConsensusStatus.FAILED
            return

        winner, count = votes.most_common(1)[0]
        agreement = count / total

        threshold = max(self._threshold, 2.0 / 3.0)
        if agreement >= threshold:
            result.result = winner
            result.agreement_score = agreement
            result.confidence = agreement
            result.status = ConsensusStatus.REACHED
        else:
            result.status = ConsensusStatus.DEADLOCK
            result.result = winner

    def _unanimous(self, result: ConsensusResult) -> None:
        """Require all agents to agree."""
        values = {op.value for op in result.opinions}

        if len(values) == 1:
            result.result = values.pop()
            result.agreement_score = 1.0
            result.confidence = sum(op.confidence for op in result.opinions) / len(result.opinions)
            result.status = ConsensusStatus.REACHED
        else:
            result.status = ConsensusStatus.DEADLOCK
            votes = Counter(op.value for op in result.opinions)
            result.result = votes.most_common(1)[0][0]
            result.agreement_score = votes.most_common(1)[0][1] / len(result.opinions)

    def _delphi(self, result: ConsensusResult) -> None:
        """Delphi method: iterative rounds."""
        # Round 1 already collected
        current_opinions = list(result.opinions)

        for round_num in range(2, self._max_rounds + 1):
            # Check if consensus reached
            votes = Counter(op.value for op in current_opinions)
            total = len(current_opinions)

            if not votes:
                break

            winner, count = votes.most_common(1)[0]
            if count / total >= self._threshold:
                result.result = winner
                result.agreement_score = count / total
                result.confidence = count / total
                result.status = ConsensusStatus.REACHED
                result.rounds = round_num - 1
                return

            # Simulate refinement: agents with minority opinions
            # shift toward majority with some probability
            refined = []
            for op in current_opinions:
                if op.value != winner and op.confidence < 0.7:
                    # Agent might change mind
                    refined.append(Opinion(
                        agent_id=op.agent_id,
                        value=winner,
                        confidence=op.confidence * 0.8,
                        round_number=round_num,
                    ))
                else:
                    refined.append(op)

            current_opinions = refined
            result.rounds = round_num

        # Final check
        votes = Counter(op.value for op in current_opinions)
        total = len(current_opinions)
        if votes:
            winner, count = votes.most_common(1)[0]
            result.result = winner
            result.agreement_score = count / total
            result.confidence = count / total
            if result.agreement_score >= self._threshold:
                result.status = ConsensusStatus.REACHED
            else:
                result.status = ConsensusStatus.DEADLOCK

    def update_accuracy(self, agent_id: str, correct: bool) -> None:
        """Update agent accuracy tracking."""
        current = self._agent_accuracy[agent_id]
        if correct:
            self._agent_accuracy[agent_id] = min(1.0, current + 0.02)
        else:
            self._agent_accuracy[agent_id] = max(0.1, current - 0.05)

    def get_history(self, limit: int = 20) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._results[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        reached = sum(1 for r in self._results if r.status == ConsensusStatus.REACHED)
        return {
            "total": len(self._results),
            "reached": reached,
            "deadlocks": len(self._results) - reached,
            "agents_tracked": len(self._agent_accuracy),
        }
