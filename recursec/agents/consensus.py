"""Agent consensus engine — multi-agent agreement protocols.

When multiple agents observe the same evidence, this engine
reaches consensus on what it means:

1. Voting: Simple majority or supermajority
2. Weighted voting: Expertise-weighted votes
3. Bayesian aggregation: Combine probability estimates
4. Delphi method: Iterative anonymous consensus
5. Auction: Agents bid on which approach to take
6. Market: Internal prediction market for outcomes

Consensus types:
- Severity consensus: Is this critical or just medium?
- Validity consensus: Is this a real finding or false positive?
- Strategy consensus: Which approach should we take next?
- Priority consensus: What should we focus on?
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
    SIMPLE_MAJORITY = "simple_majority"
    SUPERMAJORITY = "supermajority"
    WEIGHTED_VOTE = "weighted_vote"
    BAYESIAN_AGGREGATION = "bayesian_aggregation"
    DELPHI = "delphi"
    AUCTION = "auction"
    UNANIMOUS = "unanimous"


class VoteType(str, Enum):
    CATEGORICAL = "categorical"   # Choose one option
    ORDINAL = "ordinal"           # Rank options
    SCALAR = "scalar"             # Numeric value
    BINARY = "binary"             # Yes/No


@dataclass
class Vote:
    """A single vote from an agent."""
    voter_id: str = ""
    voter_role: str = ""
    vote_value: Any = None
    confidence: float = 0.5
    reasoning: str = ""
    weight: float = 1.0  # Expertise weight
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "voter": self.voter_id, "role": self.voter_role,
            "value": self.vote_value,
            "confidence": round(self.confidence, 2),
            "weight": round(self.weight, 2),
        }


@dataclass
class ConsensusResult:
    """Result of a consensus process."""
    question: str = ""
    method: ConsensusMethod = ConsensusMethod.SIMPLE_MAJORITY
    decision: Any = None
    confidence: float = 0.0
    agreement_level: float = 0.0  # 0.0 = no agreement, 1.0 = full agreement
    votes: list[Vote] = field(default_factory=list)
    rounds: int = 1
    dissenting_voters: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "question": self.question[:200],
            "method": self.method.value,
            "decision": str(self.decision)[:200],
            "confidence": round(self.confidence, 3),
            "agreement": round(self.agreement_level, 3),
            "total_votes": len(self.votes),
            "rounds": self.rounds,
            "dissenters": len(self.dissenting_voters),
        }


# Expert weights by role and question type
ROLE_EXPERTISE: dict[str, dict[str, float]] = {
    "recon": {"target_assessment": 2.0, "strategy": 1.5, "severity": 0.8},
    "vuln_scan": {"severity": 2.0, "validity": 1.8, "priority": 1.5},
    "exploit": {"severity": 1.8, "validity": 2.0, "feasibility": 2.0},
    "code_audit": {"severity": 1.5, "code_quality": 2.0, "validity": 1.5},
    "network": {"network_risk": 2.0, "severity": 1.3, "strategy": 1.5},
    "forensics": {"validity": 2.0, "severity": 1.5, "timeline": 2.0},
    "validator": {"validity": 2.5, "false_positive": 2.5, "severity": 1.5},
}


class ConsensusEngine:
    """Multi-agent consensus engine for collaborative decision-making."""

    def __init__(self) -> None:
        self._history: list[ConsensusResult] = []
        self._log = logger.bind(component="consensus")

    def reach_consensus(
        self,
        question: str,
        votes: list[Vote],
        method: ConsensusMethod = ConsensusMethod.WEIGHTED_VOTE,
        question_type: str = "general",
        threshold: float = 0.5,
    ) -> ConsensusResult:
        """Reach consensus from a set of votes."""
        if not votes:
            return ConsensusResult(question=question, method=method)

        # Apply expertise weights
        self._apply_weights(votes, question_type)

        # Run consensus method
        if method == ConsensusMethod.SIMPLE_MAJORITY:
            result = self._simple_majority(question, votes)
        elif method == ConsensusMethod.SUPERMAJORITY:
            result = self._supermajority(question, votes, threshold=0.67)
        elif method == ConsensusMethod.WEIGHTED_VOTE:
            result = self._weighted_vote(question, votes)
        elif method == ConsensusMethod.BAYESIAN_AGGREGATION:
            result = self._bayesian_aggregation(question, votes)
        elif method == ConsensusMethod.UNANIMOUS:
            result = self._unanimous(question, votes)
        else:
            result = self._weighted_vote(question, votes)

        result.method = method
        self._history.append(result)

        self._log.info(
            "consensus_reached",
            method=method.value,
            decision=str(result.decision)[:50],
            agreement=round(result.agreement_level, 2),
        )

        return result

    def delphi_round(
        self,
        question: str,
        votes: list[Vote],
        question_type: str = "general",
        max_rounds: int = 3,
        convergence_threshold: float = 0.8,
    ) -> ConsensusResult:
        """Run a Delphi-method consensus (iterative anonymous voting).

        Returns after convergence or max rounds.
        """
        current_votes = votes
        rounds_completed = 0

        for round_num in range(max_rounds):
            rounds_completed += 1

            # Apply weights
            self._apply_weights(current_votes, question_type)

            # Calculate current consensus
            result = self._weighted_vote(question, current_votes)

            # Check convergence
            if result.agreement_level >= convergence_threshold:
                result.rounds = rounds_completed
                result.method = ConsensusMethod.DELPHI
                self._history.append(result)
                return result

            # Next round: voters adjust toward group median
            current_votes = self._adjust_votes_toward_median(current_votes)

        # Max rounds reached
        result = self._weighted_vote(question, current_votes)
        result.rounds = rounds_completed
        result.method = ConsensusMethod.DELPHI
        self._history.append(result)
        return result

    def auction(
        self,
        question: str,
        options: list[str],
        bids: list[tuple[str, str, float]],  # (voter_id, option, bid_amount)
    ) -> ConsensusResult:
        """Auction-based consensus: agents bid on preferred options."""
        result = ConsensusResult(
            question=question,
            method=ConsensusMethod.AUCTION,
        )

        # Aggregate bids per option
        option_bids: dict[str, float] = defaultdict(float)
        for voter_id, option, bid in bids:
            option_bids[option] += bid
            result.votes.append(Vote(
                voter_id=voter_id,
                vote_value=option,
                confidence=bid / max(b[2] for b in bids) if bids else 0.5,
            ))

        # Winner is highest total bid
        if option_bids:
            winner = max(option_bids, key=option_bids.get)  # type: ignore[arg-type]
            total = sum(option_bids.values())
            result.decision = winner
            result.confidence = option_bids[winner] / max(1.0, total)
            result.agreement_level = option_bids[winner] / max(1.0, total)

        self._history.append(result)
        return result

    # ── Consensus Methods ────────────────────────────────

    def _simple_majority(self, question: str, votes: list[Vote]) -> ConsensusResult:
        """Simple majority voting."""
        result = ConsensusResult(question=question, votes=votes)
        counter = Counter(v.vote_value for v in votes)
        if counter:
            winner, count = counter.most_common(1)[0]
            result.decision = winner
            result.agreement_level = count / len(votes)
            result.confidence = result.agreement_level

            # Identify dissenters
            result.dissenting_voters = [
                v.voter_id for v in votes if v.vote_value != winner
            ]

        return result

    def _supermajority(
        self, question: str, votes: list[Vote], threshold: float = 0.67,
    ) -> ConsensusResult:
        """Supermajority voting (requires 2/3 agreement)."""
        result = self._simple_majority(question, votes)
        if result.agreement_level < threshold:
            result.decision = None
            result.confidence = 0.0
        return result

    def _weighted_vote(self, question: str, votes: list[Vote]) -> ConsensusResult:
        """Expertise-weighted voting."""
        result = ConsensusResult(question=question, votes=votes)

        # Aggregate weighted votes per option
        weighted_counts: dict[Any, float] = defaultdict(float)
        total_weight = 0.0

        for vote in votes:
            effective_weight = vote.weight * vote.confidence
            weighted_counts[vote.vote_value] += effective_weight
            total_weight += effective_weight

        if weighted_counts and total_weight > 0:
            winner = max(weighted_counts, key=weighted_counts.get)  # type: ignore[arg-type]
            result.decision = winner
            result.confidence = weighted_counts[winner] / total_weight
            result.agreement_level = weighted_counts[winner] / total_weight
            result.dissenting_voters = [
                v.voter_id for v in votes if v.vote_value != winner
            ]

        return result

    def _bayesian_aggregation(self, question: str, votes: list[Vote]) -> ConsensusResult:
        """Bayesian probability aggregation for scalar votes.

        Combines probability estimates from multiple agents:
        P(H|E1,E2,...) ∝ P(H) * Π P(Ei|H)

        For scalar confidence values, we use log-odds pooling.
        """
        result = ConsensusResult(question=question, votes=votes)

        # Extract confidence values
        confidences = [v.confidence for v in votes if isinstance(v.confidence, (int, float))]
        weights = [v.weight for v in votes if isinstance(v.confidence, (int, float))]

        if not confidences:
            return result

        # Log-odds pooling (optimal Bayesian aggregation for probabilities)
        import math
        total_log_odds = 0.0
        total_weight = sum(weights) or 1.0

        for conf, weight in zip(confidences, weights):
            # Clamp to avoid log(0)
            conf = max(0.01, min(0.99, conf))
            log_odds = math.log(conf / (1.0 - conf))
            total_log_odds += (weight / total_weight) * log_odds

        # Convert back to probability
        aggregated = 1.0 / (1.0 + math.exp(-total_log_odds))

        result.decision = aggregated
        result.confidence = aggregated
        result.agreement_level = 1.0 - (max(confidences) - min(confidences))

        return result

    def _unanimous(self, question: str, votes: list[Vote]) -> ConsensusResult:
        """Require unanimous agreement."""
        result = ConsensusResult(question=question, votes=votes)
        values = set(v.vote_value for v in votes)
        if len(values) == 1:
            result.decision = values.pop()
            result.agreement_level = 1.0
            result.confidence = min(v.confidence for v in votes)
        else:
            result.decision = None
            result.agreement_level = 0.0
            result.confidence = 0.0
            result.dissenting_voters = [v.voter_id for v in votes]
        return result

    # ── Helpers ──────────────────────────────────────────

    def _apply_weights(self, votes: list[Vote], question_type: str) -> None:
        """Apply expertise weights to votes based on voter role."""
        for vote in votes:
            expertise = ROLE_EXPERTISE.get(vote.voter_role, {})
            vote.weight = expertise.get(question_type, 1.0)

    def _adjust_votes_toward_median(self, votes: list[Vote]) -> list[Vote]:
        """Delphi method: adjust votes toward group median."""
        # For scalar votes
        scalar_votes = [v for v in votes if isinstance(v.confidence, (int, float))]
        if not scalar_votes:
            return votes

        confidences = sorted(v.confidence for v in scalar_votes)
        median = confidences[len(confidences) // 2]

        for vote in scalar_votes:
            # Move 30% toward median
            vote.confidence = vote.confidence + 0.3 * (median - vote.confidence)

        return votes

    def get_history(self, limit: int = 10) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._history[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        if not self._history:
            return {"total_decisions": 0}
        avg_agreement = sum(r.agreement_level for r in self._history) / len(self._history)
        by_method: dict[str, int] = defaultdict(int)
        for r in self._history:
            by_method[r.method.value] += 1
        return {
            "total_decisions": len(self._history),
            "avg_agreement": round(avg_agreement, 3),
            "by_method": dict(by_method),
        }
