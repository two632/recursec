"""Model ensemble — multi-model consensus and voting.

Implements:
1. Multi-model query dispatch
2. Majority voting for decisions
3. Weighted consensus by expertise
4. Answer aggregation strategies
5. Disagreement detection and resolution
6. Model diversity scoring
7. Ensemble confidence calculation
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AggregationStrategy(str, Enum):
    MAJORITY_VOTE = "majority_vote"
    WEIGHTED_VOTE = "weighted_vote"
    BEST_OF_N = "best_of_n"
    UNANIMOUS = "unanimous"
    FIRST_CONFIDENT = "first_confident"


class VoteOutcome(str, Enum):
    CONSENSUS = "consensus"
    MAJORITY = "majority"
    SPLIT = "split"
    UNANIMOUS = "unanimous"
    DEADLOCK = "deadlock"


@dataclass
class ModelResponse:
    """A response from a single model."""
    model_id: str = ""
    response: str = ""
    confidence: float = 0.5
    latency_ms: float = 0.0
    tokens_used: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "confidence": round(self.confidence, 2),
            "tokens": self.tokens_used,
        }


@dataclass
class EnsembleResult:
    """Result of an ensemble query."""
    query_id: str = ""
    strategy: AggregationStrategy = AggregationStrategy.WEIGHTED_VOTE
    outcome: VoteOutcome = VoteOutcome.CONSENSUS
    final_answer: str = ""
    confidence: float = 0.0
    responses: list[ModelResponse] = field(default_factory=list)
    agreement_ratio: float = 0.0
    total_tokens: int = 0
    total_latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_id": self.query_id[:10],
            "strategy": self.strategy.value,
            "outcome": self.outcome.value,
            "confidence": round(self.confidence, 2),
            "agreement": round(self.agreement_ratio, 2),
            "models": len(self.responses),
            "total_tokens": self.total_tokens,
        }


# ── Model expertise weights ─────────────────────────────────

MODEL_EXPERTISE: dict[str, dict[str, float]] = {
    "whiterabbitneo-7b": {
        "security": 2.0, "exploitation": 2.0, "vuln_analysis": 1.8,
    },
    "qwen-coder-14b": {
        "code_audit": 2.0, "code_review": 1.8, "exploit_dev": 1.5,
    },
    "qwen-coder-7b": {
        "code_audit": 1.5, "code_review": 1.5, "general": 1.0,
    },
    "deepseek-r1-7b": {
        "reasoning": 2.0, "analysis": 1.8, "planning": 1.5,
    },
    "deepseek-math-7b": {
        "crypto": 1.8, "analysis": 1.5, "reasoning": 1.3,
    },
    "hermes-14b": {
        "general": 1.5, "planning": 1.3, "security": 1.2,
    },
    "llama-3.1-8b": {
        "general": 1.3, "reasoning": 1.2, "instruction": 1.3,
    },
    "dolphin-8b": {
        "uncensored": 2.0, "security": 1.5, "exploitation": 1.5,
    },
    "mistral-7b": {
        "general": 1.2, "instruction": 1.3, "fast": 1.5,
    },
    "codellama-13b": {
        "code_audit": 1.5, "code_review": 1.5, "exploit_dev": 1.2,
    },
    "codellama-7b": {
        "code_audit": 1.2, "code_review": 1.2, "general": 1.0,
    },
    "yi-9b-200k": {
        "long_context": 2.0, "analysis": 1.3, "general": 1.1,
    },
    "phi-3.5-mini": {
        "fast": 2.0, "triage": 1.5, "general": 1.0,
    },
}

DEFAULT_WEIGHT = 1.0


def _get_model_weight(model_id: str, domain: str) -> float:
    """Get model weight for a domain."""
    expertise = MODEL_EXPERTISE.get(model_id, {})
    return expertise.get(domain, DEFAULT_WEIGHT)


def _extract_decision(response: str) -> str:
    """Extract the key decision from a response."""
    # Look for common decision markers
    response_lower = response.lower()
    for marker in ["conclusion:", "decision:", "answer:", "verdict:", "finding:"]:
        idx = response_lower.find(marker)
        if idx >= 0:
            # Take the line after the marker
            rest = response[idx + len(marker):].strip()
            end = rest.find('\n')
            if end > 0:
                return rest[:end].strip()
            return rest[:100].strip()
    # Fall back to first sentence
    end = response.find('.')
    if end > 0:
        return response[:end + 1].strip()
    return response[:100].strip()


def _hash_decision(decision: str) -> str:
    """Hash a decision for grouping."""
    normalized = decision.lower().strip()
    return hashlib.md5(normalized.encode()).hexdigest()[:8]


class ModelEnsemble:
    """Manages multi-model ensemble queries.

    Dispatches queries to multiple models,
    aggregates responses using configurable
    strategies, and detects disagreements.
    """

    def __init__(self) -> None:
        self._results: list[EnsembleResult] = []
        self._query_counter = 0
        self._log = logger.bind(component="model_ensemble")

    def aggregate(
        self,
        responses: list[ModelResponse],
        strategy: AggregationStrategy = AggregationStrategy.WEIGHTED_VOTE,
        domain: str = "general",
    ) -> EnsembleResult:
        """Aggregate model responses."""
        self._query_counter += 1
        query_id = f"ens-{self._query_counter}"

        if not responses:
            return EnsembleResult(query_id=query_id, strategy=strategy)

        if strategy == AggregationStrategy.MAJORITY_VOTE:
            result = self._majority_vote(responses, query_id)
        elif strategy == AggregationStrategy.WEIGHTED_VOTE:
            result = self._weighted_vote(responses, query_id, domain)
        elif strategy == AggregationStrategy.BEST_OF_N:
            result = self._best_of_n(responses, query_id, domain)
        elif strategy == AggregationStrategy.FIRST_CONFIDENT:
            result = self._first_confident(responses, query_id)
        elif strategy == AggregationStrategy.UNANIMOUS:
            result = self._unanimous(responses, query_id)
        else:
            result = self._weighted_vote(responses, query_id, domain)

        result.strategy = strategy
        result.responses = responses
        result.total_tokens = sum(r.tokens_used for r in responses)
        result.total_latency_ms = max(
            (r.latency_ms for r in responses), default=0
        )

        self._results.append(result)
        return result

    def _majority_vote(
        self,
        responses: list[ModelResponse],
        query_id: str,
    ) -> EnsembleResult:
        """Simple majority vote."""
        decisions: dict[str, list[ModelResponse]] = {}
        for r in responses:
            decision = _extract_decision(r.response)
            key = _hash_decision(decision)
            decisions.setdefault(key, []).append(r)

        if not decisions:
            return EnsembleResult(query_id=query_id)

        # Find majority
        majority_key = max(decisions, key=lambda k: len(decisions[k]))
        majority_group = decisions[majority_key]
        agreement = len(majority_group) / len(responses)

        # Pick highest confidence from majority
        best = max(majority_group, key=lambda r: r.confidence)

        outcome = VoteOutcome.UNANIMOUS if agreement == 1.0 else (
            VoteOutcome.CONSENSUS if agreement >= 0.75 else (
                VoteOutcome.MAJORITY if agreement > 0.5 else VoteOutcome.SPLIT
            )
        )

        return EnsembleResult(
            query_id=query_id,
            outcome=outcome,
            final_answer=best.response,
            confidence=best.confidence * agreement,
            agreement_ratio=agreement,
        )

    def _weighted_vote(
        self,
        responses: list[ModelResponse],
        query_id: str,
        domain: str,
    ) -> EnsembleResult:
        """Expertise-weighted voting."""
        decisions: dict[str, tuple[float, ModelResponse]] = {}

        for r in responses:
            decision = _extract_decision(r.response)
            key = _hash_decision(decision)
            weight = _get_model_weight(r.model_id, domain)
            score = r.confidence * weight

            existing = decisions.get(key)
            if not existing or score > existing[0]:
                decisions[key] = (score, r)

        if not decisions:
            return EnsembleResult(query_id=query_id)

        # Pick highest weighted score
        best_key = max(decisions, key=lambda k: decisions[k][0])
        best_score, best_response = decisions[best_key]

        total_weight = sum(
            _get_model_weight(r.model_id, domain) for r in responses
        )
        agreement = best_score / total_weight if total_weight > 0 else 0

        return EnsembleResult(
            query_id=query_id,
            outcome=VoteOutcome.CONSENSUS if agreement >= 0.6 else VoteOutcome.SPLIT,
            final_answer=best_response.response,
            confidence=min(1.0, best_score / max(1, len(responses))),
            agreement_ratio=agreement,
        )

    def _best_of_n(
        self,
        responses: list[ModelResponse],
        query_id: str,
        domain: str,
    ) -> EnsembleResult:
        """Pick the best response by weighted confidence."""
        scored = [
            (r.confidence * _get_model_weight(r.model_id, domain), r)
            for r in responses
        ]
        scored.sort(key=lambda x: x[0], reverse=True)
        best_score, best = scored[0]

        return EnsembleResult(
            query_id=query_id,
            outcome=VoteOutcome.CONSENSUS,
            final_answer=best.response,
            confidence=best.confidence,
            agreement_ratio=1.0 / len(responses),
        )

    def _first_confident(
        self,
        responses: list[ModelResponse],
        query_id: str,
    ) -> EnsembleResult:
        """Take the first response above confidence threshold."""
        threshold = 0.8
        for r in sorted(responses, key=lambda r: r.latency_ms):
            if r.confidence >= threshold:
                return EnsembleResult(
                    query_id=query_id,
                    outcome=VoteOutcome.CONSENSUS,
                    final_answer=r.response,
                    confidence=r.confidence,
                    agreement_ratio=1.0,
                )

        # Fall back to highest confidence
        best = max(responses, key=lambda r: r.confidence)
        return EnsembleResult(
            query_id=query_id,
            outcome=VoteOutcome.SPLIT,
            final_answer=best.response,
            confidence=best.confidence,
            agreement_ratio=0.5,
        )

    def _unanimous(
        self,
        responses: list[ModelResponse],
        query_id: str,
    ) -> EnsembleResult:
        """Require unanimous agreement."""
        decisions = set()
        for r in responses:
            decision = _extract_decision(r.response)
            decisions.add(_hash_decision(decision))

        if len(decisions) == 1:
            best = max(responses, key=lambda r: r.confidence)
            return EnsembleResult(
                query_id=query_id,
                outcome=VoteOutcome.UNANIMOUS,
                final_answer=best.response,
                confidence=best.confidence,
                agreement_ratio=1.0,
            )

        return EnsembleResult(
            query_id=query_id,
            outcome=VoteOutcome.DEADLOCK,
            final_answer="",
            confidence=0.0,
            agreement_ratio=1.0 / len(decisions) if decisions else 0,
        )

    def build_ensemble_prompt(self, result: EnsembleResult) -> str:
        """Build ensemble context for LLM."""
        lines = [f"## Ensemble Result ({result.outcome.value})\n"]
        lines.append(f"Strategy: {result.strategy.value}")
        lines.append(f"Agreement: {result.agreement_ratio:.0%}")
        lines.append(f"Confidence: {result.confidence:.0%}")
        lines.append(f"Models queried: {len(result.responses)}")

        if result.outcome in (VoteOutcome.SPLIT, VoteOutcome.DEADLOCK):
            lines.append("\nDisagreement detected — models gave different answers.")
            lines.append("Consider spawning a debate agent or trying a different approach.")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        outcome_counts: dict[str, int] = {}
        for r in self._results:
            outcome_counts[r.outcome.value] = outcome_counts.get(r.outcome.value, 0) + 1

        return {
            "total_queries": len(self._results),
            "by_outcome": outcome_counts,
            "avg_agreement": (
                sum(r.agreement_ratio for r in self._results) / len(self._results)
                if self._results else 0
            ),
        }
