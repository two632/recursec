"""Multi-agent consensus engine — finding verification through agreement.

Implements:
1. Multiple model voting on findings
2. Weighted consensus based on model expertise
3. Confidence calibration
4. Disagreement resolution
5. Majority/supermajority/unanimous modes
6. Finding deduplication with consensus
7. Evidence aggregation
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ConsensusMode(str, Enum):
    MAJORITY = "majority"           # >50% agree
    SUPERMAJORITY = "supermajority"  # >66% agree
    UNANIMOUS = "unanimous"          # 100% agree
    WEIGHTED = "weighted"            # Weighted by model expertise
    QUORUM = "quorum"               # Min N votes agree


class VoteOutcome(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_VERIFICATION = "needs_verification"
    ABSTAIN = "abstain"


class ConsensusResult(str, Enum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    PENDING = "pending"


@dataclass
class Vote:
    """A vote from a model on a finding."""
    voter_id: str = ""
    model: str = ""
    outcome: VoteOutcome = VoteOutcome.ABSTAIN
    confidence: float = 0.5
    reasoning: str = ""
    evidence: str = ""
    weight: float = 1.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "voter": self.voter_id[:10],
            "model": self.model[:15],
            "outcome": self.outcome.value,
            "confidence": round(self.confidence, 2),
            "weight": round(self.weight, 2),
        }


@dataclass
class ConsensusItem:
    """A finding submitted for consensus."""
    item_id: str = ""
    finding_title: str = ""
    finding_severity: str = ""
    finding_description: str = ""
    finding_evidence: str = ""
    votes: list[Vote] = field(default_factory=list)
    result: ConsensusResult = ConsensusResult.PENDING
    final_confidence: float = 0.0
    aggregated_evidence: list[str] = field(default_factory=list)
    resolved_at: float = 0.0

    @property
    def vote_count(self) -> int:
        return len([v for v in self.votes if v.outcome != VoteOutcome.ABSTAIN])

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.item_id[:10],
            "title": self.finding_title[:25],
            "severity": self.finding_severity[:8],
            "result": self.result.value,
            "votes": self.vote_count,
            "confidence": round(self.final_confidence, 2),
        }


# ── Model expertise weights ──────────────────────────────────

MODEL_EXPERTISE: dict[str, dict[str, float]] = {
    "whiterabbitneo-7b": {
        "security": 2.0, "web_vuln": 1.8, "network": 1.5, "default": 1.0,
    },
    "qwen-coder-14b": {
        "code_vuln": 2.0, "security": 1.5, "web_vuln": 1.3, "default": 1.0,
    },
    "qwen-coder-7b": {
        "code_vuln": 1.8, "security": 1.3, "default": 0.8,
    },
    "deepseek-r1-7b": {
        "reasoning": 2.0, "analysis": 1.8, "security": 1.0, "default": 1.0,
    },
    "hermes-14b": {
        "analysis": 1.5, "reasoning": 1.3, "security": 1.0, "default": 1.0,
    },
    "dolphin-8b": {
        "security": 1.2, "web_vuln": 1.2, "default": 1.0,
    },
    "codellama-13b": {
        "code_vuln": 1.8, "default": 0.8,
    },
    "mistral-7b": {
        "analysis": 1.2, "default": 1.0,
    },
    "llama-3.1-8b": {
        "analysis": 1.2, "default": 1.0,
    },
}


class ConsensusEngine:
    """Multi-agent consensus for finding verification.

    Uses multiple models to vote on findings,
    with expertise-weighted consensus.
    """

    def __init__(
        self,
        mode: ConsensusMode = ConsensusMode.WEIGHTED,
        quorum_size: int = 3,
    ) -> None:
        self._items: dict[str, ConsensusItem] = {}
        self._counter = 0
        self._mode = mode
        self._quorum_size = quorum_size
        self._log = logger.bind(component="consensus_engine")

    def submit_finding(
        self,
        title: str,
        severity: str,
        description: str = "",
        evidence: str = "",
    ) -> ConsensusItem:
        """Submit a finding for consensus."""
        self._counter += 1
        item = ConsensusItem(
            item_id=f"cons-{self._counter}",
            finding_title=title,
            finding_severity=severity,
            finding_description=description,
            finding_evidence=evidence,
        )
        self._items[item.item_id] = item
        return item

    def cast_vote(
        self,
        item_id: str,
        model: str,
        outcome: VoteOutcome,
        confidence: float = 0.5,
        reasoning: str = "",
        evidence: str = "",
    ) -> Vote | None:
        """Cast a vote on a finding."""
        item = self._items.get(item_id)
        if not item:
            return None

        # Calculate weight based on model expertise and finding category
        weight = self._get_weight(model, item.finding_severity)

        self._counter += 1
        vote = Vote(
            voter_id=f"vote-{self._counter}",
            model=model,
            outcome=outcome,
            confidence=confidence,
            reasoning=reasoning,
            evidence=evidence,
            weight=weight,
        )
        item.votes.append(vote)

        # Collect evidence
        if evidence:
            item.aggregated_evidence.append(evidence)

        return vote

    def resolve(self, item_id: str) -> ConsensusResult:
        """Resolve consensus for a finding."""
        item = self._items.get(item_id)
        if not item:
            return ConsensusResult.INCONCLUSIVE

        active_votes = [v for v in item.votes if v.outcome != VoteOutcome.ABSTAIN]
        if not active_votes:
            return ConsensusResult.PENDING

        if self._mode == ConsensusMode.WEIGHTED:
            result = self._resolve_weighted(item, active_votes)
        elif self._mode == ConsensusMode.MAJORITY:
            result = self._resolve_majority(active_votes, threshold=0.5)
        elif self._mode == ConsensusMode.SUPERMAJORITY:
            result = self._resolve_majority(active_votes, threshold=0.66)
        elif self._mode == ConsensusMode.UNANIMOUS:
            result = self._resolve_unanimous(active_votes)
        elif self._mode == ConsensusMode.QUORUM:
            result = self._resolve_quorum(active_votes)
        else:
            result = ConsensusResult.INCONCLUSIVE

        item.result = result
        item.resolved_at = time.time()

        # Calculate final confidence
        item.final_confidence = self._calculate_confidence(active_votes)

        return result

    def _resolve_weighted(
        self,
        item: ConsensusItem,
        votes: list[Vote],
    ) -> ConsensusResult:
        """Resolve using expertise-weighted voting."""
        tp_weight = sum(v.weight * v.confidence for v in votes if v.outcome == VoteOutcome.TRUE_POSITIVE)
        fp_weight = sum(v.weight * v.confidence for v in votes if v.outcome == VoteOutcome.FALSE_POSITIVE)
        total_weight = tp_weight + fp_weight

        if total_weight == 0:
            return ConsensusResult.INCONCLUSIVE

        tp_ratio = tp_weight / total_weight

        if tp_ratio >= 0.6:
            return ConsensusResult.CONFIRMED
        elif tp_ratio <= 0.3:
            return ConsensusResult.REJECTED
        return ConsensusResult.INCONCLUSIVE

    def _resolve_majority(
        self,
        votes: list[Vote],
        threshold: float,
    ) -> ConsensusResult:
        """Resolve using simple or supermajority voting."""
        tp_count = sum(1 for v in votes if v.outcome == VoteOutcome.TRUE_POSITIVE)
        total = len(votes)

        if tp_count / total >= threshold:
            return ConsensusResult.CONFIRMED
        elif (total - tp_count) / total >= threshold:
            return ConsensusResult.REJECTED
        return ConsensusResult.INCONCLUSIVE

    def _resolve_unanimous(self, votes: list[Vote]) -> ConsensusResult:
        """Resolve using unanimous voting."""
        outcomes = {v.outcome for v in votes}
        if len(outcomes) == 1:
            if VoteOutcome.TRUE_POSITIVE in outcomes:
                return ConsensusResult.CONFIRMED
            if VoteOutcome.FALSE_POSITIVE in outcomes:
                return ConsensusResult.REJECTED
        return ConsensusResult.INCONCLUSIVE

    def _resolve_quorum(self, votes: list[Vote]) -> ConsensusResult:
        """Resolve using quorum voting."""
        if len(votes) < self._quorum_size:
            return ConsensusResult.PENDING

        tp_count = sum(1 for v in votes if v.outcome == VoteOutcome.TRUE_POSITIVE)
        if tp_count >= self._quorum_size:
            return ConsensusResult.CONFIRMED

        fp_count = sum(1 for v in votes if v.outcome == VoteOutcome.FALSE_POSITIVE)
        if fp_count >= self._quorum_size:
            return ConsensusResult.REJECTED

        return ConsensusResult.INCONCLUSIVE

    def _calculate_confidence(self, votes: list[Vote]) -> float:
        """Calculate overall confidence from votes."""
        if not votes:
            return 0.0

        total_weight = sum(v.weight for v in votes)
        if total_weight == 0:
            return 0.0

        weighted_confidence = sum(v.confidence * v.weight for v in votes) / total_weight

        # Agreement bonus: higher confidence if votes agree
        outcomes = [v.outcome for v in votes]
        tp_count = outcomes.count(VoteOutcome.TRUE_POSITIVE)
        fp_count = outcomes.count(VoteOutcome.FALSE_POSITIVE)
        total = len(outcomes)

        agreement = max(tp_count, fp_count) / total if total > 0 else 0
        agreement_bonus = agreement * 0.2

        return min(1.0, weighted_confidence + agreement_bonus)

    def _get_weight(self, model: str, severity: str) -> float:
        """Get expertise weight for a model on a finding type."""
        model_weights = MODEL_EXPERTISE.get(model, {"default": 1.0})

        # Map severity to expertise category
        severity_map = {
            "critical": "security",
            "high": "security",
            "medium": "web_vuln",
            "low": "analysis",
        }
        category = severity_map.get(severity, "default")

        return model_weights.get(category, model_weights.get("default", 1.0))

    def get_confirmed_findings(self) -> list[ConsensusItem]:
        """Get all confirmed findings."""
        return [
            item for item in self._items.values()
            if item.result == ConsensusResult.CONFIRMED
        ]

    def get_stats(self) -> dict[str, Any]:
        result_counts: dict[str, int] = defaultdict(int)
        for item in self._items.values():
            result_counts[item.result.value] += 1

        total_votes = sum(len(i.votes) for i in self._items.values())

        return {
            "items": len(self._items),
            "total_votes": total_votes,
            "mode": self._mode.value,
            "by_result": dict(result_counts),
            "avg_votes": round(total_votes / max(1, len(self._items)), 1),
        }
