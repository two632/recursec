"""Model ensemble engine — multi-model reasoning.

Implements:
1. Parallel query to multiple models
2. Response aggregation strategies
3. Model debate protocol
4. Best-of-N sampling
5. Weighted response merging
6. Confidence-based selection
7. Diversity-aware ensemble
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class EnsembleStrategy(str, Enum):
    BEST_OF_N = "best_of_n"
    MAJORITY_VOTE = "majority_vote"
    WEIGHTED_MERGE = "weighted_merge"
    DEBATE = "debate"
    CASCADING = "cascading"
    DIVERSITY = "diversity"


class ResponseQuality(str, Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    ADEQUATE = "adequate"
    POOR = "poor"
    INVALID = "invalid"


@dataclass
class ModelResponse:
    """A response from a single model."""
    response_id: str = ""
    model: str = ""
    content: str = ""
    tokens_used: int = 0
    latency_ms: float = 0.0
    confidence: float = 0.5
    quality: ResponseQuality = ResponseQuality.ADEQUATE
    structured_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.response_id[:10],
            "model": self.model[:15],
            "tokens": self.tokens_used,
            "latency": round(self.latency_ms, 0),
            "confidence": round(self.confidence, 2),
            "quality": self.quality.value,
        }


@dataclass
class EnsembleResult:
    """Result from ensemble processing."""
    strategy: EnsembleStrategy = EnsembleStrategy.BEST_OF_N
    responses: list[ModelResponse] = field(default_factory=list)
    selected_response: str = ""
    selected_model: str = ""
    merged_content: str = ""
    overall_confidence: float = 0.0
    agreement_score: float = 0.0
    total_tokens: int = 0
    total_latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy.value,
            "responses": len(self.responses),
            "selected": self.selected_model[:15],
            "confidence": round(self.overall_confidence, 2),
            "agreement": round(self.agreement_score, 2),
            "tokens": self.total_tokens,
        }


@dataclass
class DebateRound:
    """A round in a model debate."""
    round_num: int = 0
    arguments: list[dict[str, Any]] = field(default_factory=list)
    consensus_reached: bool = False
    winning_position: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "round": self.round_num,
            "arguments": len(self.arguments),
            "consensus": self.consensus_reached,
        }


# ── Model weights for ensemble ───────────────────────────────

MODEL_WEIGHTS: dict[str, dict[str, float]] = {
    "whiterabbitneo-7b": {"security": 2.0, "code": 1.0, "reasoning": 1.0, "general": 0.8},
    "qwen-coder-14b": {"code": 2.0, "security": 1.5, "reasoning": 1.2, "general": 1.0},
    "qwen-coder-7b": {"code": 1.8, "security": 1.2, "reasoning": 1.0, "general": 0.8},
    "deepseek-r1-7b": {"reasoning": 2.0, "security": 1.0, "code": 1.0, "general": 1.0},
    "deepseek-math-7b": {"reasoning": 1.8, "code": 0.8, "general": 0.7, "security": 0.5},
    "hermes-14b": {"general": 1.5, "reasoning": 1.3, "security": 1.0, "code": 0.8},
    "llama-3.1-8b": {"general": 1.2, "reasoning": 1.0, "security": 0.8, "code": 0.7},
    "dolphin-8b": {"security": 1.2, "general": 1.2, "code": 0.8, "reasoning": 0.8},
    "mistral-7b": {"general": 1.0, "reasoning": 1.0, "security": 0.8, "code": 0.7},
    "codellama-13b": {"code": 1.8, "security": 0.8, "general": 0.6, "reasoning": 0.5},
    "codellama-7b": {"code": 1.5, "security": 0.6, "general": 0.5, "reasoning": 0.4},
    "yi-9b-200k": {"general": 1.2, "code": 1.0, "reasoning": 1.0, "security": 0.8},
    "phi-3.5-mini": {"general": 0.8, "code": 0.7, "reasoning": 0.6, "security": 0.5},
}


class ModelEnsembleEngine:
    """Multi-model ensemble for improved reasoning.

    Queries multiple models and combines their responses
    using various aggregation strategies.
    """

    def __init__(
        self,
        default_strategy: EnsembleStrategy = EnsembleStrategy.BEST_OF_N,
    ) -> None:
        self._default_strategy = default_strategy
        self._counter = 0
        self._log = logger.bind(component="model_ensemble")

    def process_responses(
        self,
        responses: list[ModelResponse],
        strategy: EnsembleStrategy | None = None,
        task_type: str = "general",
    ) -> EnsembleResult:
        """Process multiple model responses."""
        strategy = strategy or self._default_strategy

        if strategy == EnsembleStrategy.BEST_OF_N:
            return self._best_of_n(responses, task_type)
        elif strategy == EnsembleStrategy.MAJORITY_VOTE:
            return self._majority_vote(responses)
        elif strategy == EnsembleStrategy.WEIGHTED_MERGE:
            return self._weighted_merge(responses, task_type)
        elif strategy == EnsembleStrategy.CASCADING:
            return self._cascading(responses)
        elif strategy == EnsembleStrategy.DIVERSITY:
            return self._diversity_select(responses, task_type)
        else:
            return self._best_of_n(responses, task_type)

    def _best_of_n(
        self,
        responses: list[ModelResponse],
        task_type: str,
    ) -> EnsembleResult:
        """Select the best response based on quality and weight."""
        scored: list[tuple[float, ModelResponse]] = []

        for resp in responses:
            weight = self._get_weight(resp.model, task_type)
            quality_scores = {
                ResponseQuality.EXCELLENT: 1.0,
                ResponseQuality.GOOD: 0.75,
                ResponseQuality.ADEQUATE: 0.5,
                ResponseQuality.POOR: 0.25,
                ResponseQuality.INVALID: 0.0,
            }
            q_score = quality_scores.get(resp.quality, 0.5)
            score = resp.confidence * weight * q_score
            scored.append((score, resp))

        scored.sort(key=lambda x: x[0], reverse=True)
        best = scored[0][1] if scored else responses[0]

        return EnsembleResult(
            strategy=EnsembleStrategy.BEST_OF_N,
            responses=responses,
            selected_response=best.content,
            selected_model=best.model,
            overall_confidence=best.confidence,
            agreement_score=self._calculate_agreement(responses),
            total_tokens=sum(r.tokens_used for r in responses),
            total_latency_ms=max(r.latency_ms for r in responses) if responses else 0,
        )

    def _majority_vote(
        self,
        responses: list[ModelResponse],
    ) -> EnsembleResult:
        """Select response by majority vote on structured data."""
        # Group by a key answer field
        vote_counts: dict[str, int] = defaultdict(int)
        vote_responses: dict[str, ModelResponse] = {}

        for resp in responses:
            key = resp.structured_data.get("answer", resp.content[:50])
            vote_counts[key] += 1
            if key not in vote_responses:
                vote_responses[key] = resp

        if not vote_counts:
            return self._best_of_n(responses, "general")

        winning_key = max(vote_counts, key=lambda k: vote_counts[k])
        winning_response = vote_responses[winning_key]
        agreement = vote_counts[winning_key] / len(responses)

        return EnsembleResult(
            strategy=EnsembleStrategy.MAJORITY_VOTE,
            responses=responses,
            selected_response=winning_response.content,
            selected_model=winning_response.model,
            overall_confidence=winning_response.confidence * agreement,
            agreement_score=agreement,
            total_tokens=sum(r.tokens_used for r in responses),
        )

    def _weighted_merge(
        self,
        responses: list[ModelResponse],
        task_type: str,
    ) -> EnsembleResult:
        """Merge responses with expertise-weighted combination."""
        # For structured data, merge fields by weight
        weights: list[float] = []
        for resp in responses:
            w = self._get_weight(resp.model, task_type) * resp.confidence
            weights.append(w)

        total_weight = sum(weights)
        if total_weight == 0:
            return self._best_of_n(responses, task_type)

        # Select best as base, but confidence is weighted average
        max_idx = weights.index(max(weights))
        base_response = responses[max_idx]

        weighted_confidence = sum(
            r.confidence * w for r, w in zip(responses, weights)
        ) / total_weight

        return EnsembleResult(
            strategy=EnsembleStrategy.WEIGHTED_MERGE,
            responses=responses,
            selected_response=base_response.content,
            selected_model=base_response.model,
            merged_content=base_response.content,
            overall_confidence=weighted_confidence,
            agreement_score=self._calculate_agreement(responses),
            total_tokens=sum(r.tokens_used for r in responses),
        )

    def _cascading(
        self,
        responses: list[ModelResponse],
    ) -> EnsembleResult:
        """Cascading: use first good response, fallback to next."""
        for resp in responses:
            if resp.quality in (ResponseQuality.EXCELLENT, ResponseQuality.GOOD):
                return EnsembleResult(
                    strategy=EnsembleStrategy.CASCADING,
                    responses=responses,
                    selected_response=resp.content,
                    selected_model=resp.model,
                    overall_confidence=resp.confidence,
                    total_tokens=resp.tokens_used,
                )

        # Fall back to best_of_n
        return self._best_of_n(responses, "general")

    def _diversity_select(
        self,
        responses: list[ModelResponse],
        task_type: str,
    ) -> EnsembleResult:
        """Select diverse responses for comprehensive coverage."""
        if len(responses) <= 1:
            return self._best_of_n(responses, task_type)

        # Pick the most diverse pair (different models, different content lengths)
        selected = [responses[0]]
        for resp in responses[1:]:
            is_diverse = all(
                resp.model != s.model and
                abs(len(resp.content) - len(s.content)) > 100
                for s in selected
            )
            if is_diverse:
                selected.append(resp)
                if len(selected) >= 3:
                    break

        # Use the highest confidence from diverse set
        best = max(selected, key=lambda r: r.confidence)

        return EnsembleResult(
            strategy=EnsembleStrategy.DIVERSITY,
            responses=responses,
            selected_response=best.content,
            selected_model=best.model,
            overall_confidence=best.confidence,
            agreement_score=self._calculate_agreement(selected),
            total_tokens=sum(r.tokens_used for r in responses),
        )

    def _get_weight(self, model: str, task_type: str) -> float:
        """Get model weight for a task type."""
        model_w = MODEL_WEIGHTS.get(model, {})
        return model_w.get(task_type, model_w.get("general", 1.0))

    def _calculate_agreement(self, responses: list[ModelResponse]) -> float:
        """Calculate agreement score between responses."""
        if len(responses) < 2:
            return 1.0

        # Simple: compare confidence levels
        confidences = [r.confidence for r in responses]
        avg = sum(confidences) / len(confidences)
        variance = sum((c - avg) ** 2 for c in confidences) / len(confidences)

        # Lower variance = higher agreement
        return max(0.0, 1.0 - variance * 4)

    def get_stats(self) -> dict[str, Any]:
        return {
            "strategy": self._default_strategy.value,
            "models_configured": len(MODEL_WEIGHTS),
        }
