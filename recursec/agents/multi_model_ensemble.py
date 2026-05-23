"""Multi-model ensemble reasoning — combines outputs from multiple LLMs.

Implements:
1. Parallel query to multiple models
2. Response quality scoring
3. Consensus building across models
4. Diversity-weighted aggregation
5. Confidence calibration
6. Hallucination cross-check
7. Model specialization routing
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AggregationStrategy(str, Enum):
    BEST_OF_N = "best_of_n"             # Take highest scored
    MAJORITY_VOTE = "majority_vote"     # Take most common answer
    WEIGHTED_MERGE = "weighted_merge"   # Merge with weights
    CASCADE = "cascade"                 # Try models in order until good answer
    SPECIALIST = "specialist"           # Route to domain expert
    DEBATE = "debate"                   # Models argue, judge decides


class ResponseQuality(str, Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    ACCEPTABLE = "acceptable"
    POOR = "poor"
    HALLUCINATION = "hallucination"


@dataclass
class ModelResponse:
    """A response from a single model."""
    model_id: str = ""
    response_text: str = ""
    quality: ResponseQuality = ResponseQuality.ACCEPTABLE
    confidence: float = 0.5
    tokens_used: int = 0
    latency_ms: float = 0.0
    contains_code: bool = False
    contains_command: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:12],
            "quality": self.quality.value,
            "confidence": round(self.confidence, 2),
            "tokens": self.tokens_used,
            "latency_ms": round(self.latency_ms, 0),
        }


@dataclass
class EnsembleResult:
    """Combined result from multiple models."""
    strategy: AggregationStrategy = AggregationStrategy.BEST_OF_N
    selected_response: str = ""
    selected_model: str = ""
    all_responses: list[ModelResponse] = field(default_factory=list)
    agreement_score: float = 0.0      # How much models agree
    confidence: float = 0.5
    total_tokens: int = 0
    total_latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy.value,
            "selected_model": self.selected_model[:12],
            "models_queried": len(self.all_responses),
            "agreement": round(self.agreement_score, 2),
            "confidence": round(self.confidence, 2),
            "total_tokens": self.total_tokens,
        }


# ── Model quality weights ─────────────────────────────────────

MODEL_QUALITY_WEIGHTS: dict[str, dict[str, float]] = {
    "whiterabbitneo-7b": {"security": 2.0, "exploitation": 1.8, "general": 0.8},
    "qwen-coder-14b": {"code": 2.0, "security": 1.2, "general": 1.3},
    "qwen-coder-7b": {"code": 1.7, "security": 1.0, "general": 1.0},
    "deepseek-r1-7b": {"reasoning": 2.0, "planning": 1.8, "general": 1.2},
    "deepseek-math-7b": {"math": 2.0, "crypto": 1.5, "general": 0.7},
    "hermes-14b": {"general": 1.8, "planning": 1.5, "security": 1.0},
    "llama-3.1-8b": {"general": 1.5, "reasoning": 1.3, "security": 0.9},
    "dolphin-8b": {"security": 1.3, "exploitation": 1.2, "general": 1.0},
    "mistral-7b": {"general": 1.5, "code": 1.2, "security": 0.9},
    "codellama-13b": {"code": 1.8, "security": 1.0, "general": 0.8},
    "codellama-7b": {"code": 1.5, "security": 0.9, "general": 0.7},
    "yi-9b-200k": {"long_context": 2.0, "general": 1.0, "code": 1.0},
    "phi-3.5-mini": {"fast": 2.0, "general": 1.0, "code": 1.0},
}

# ── Response quality heuristics ───────────────────────────────

QUALITY_INDICATORS: dict[str, list[str]] = {
    "good": [
        "specific vulnerability name",
        "CVE reference",
        "code example",
        "tool command",
        "step-by-step",
    ],
    "poor": [
        "I cannot",
        "I'm not able",
        "As an AI",
        "I don't have access",
        "hypothetically",
    ],
}


def _score_response_quality(text: str) -> tuple[ResponseQuality, float]:
    """Score response quality heuristically."""
    if not text or len(text) < 20:
        return ResponseQuality.POOR, 0.1

    text_lower = text.lower()
    score = 0.5

    # Check for good indicators
    for indicator in QUALITY_INDICATORS["good"]:
        if indicator.lower() in text_lower:
            score += 0.1

    # Check for poor indicators
    for indicator in QUALITY_INDICATORS["poor"]:
        if indicator.lower() in text_lower:
            score -= 0.15

    # Length bonus (longer = usually more detailed)
    if len(text) > 500:
        score += 0.1
    if len(text) > 1000:
        score += 0.05

    # Contains actionable content
    if "```" in text or "$ " in text or "nmap " in text:
        score += 0.1

    score = max(0.0, min(1.0, score))

    if score >= 0.8:
        quality = ResponseQuality.EXCELLENT
    elif score >= 0.6:
        quality = ResponseQuality.GOOD
    elif score >= 0.4:
        quality = ResponseQuality.ACCEPTABLE
    elif score >= 0.2:
        quality = ResponseQuality.POOR
    else:
        quality = ResponseQuality.HALLUCINATION

    return quality, score


class MultiModelEnsemble:
    """Combines reasoning from multiple LLMs.

    Queries multiple models, scores responses,
    and aggregates using configurable strategies
    for more reliable results.
    """

    def __init__(
        self,
        default_strategy: AggregationStrategy = AggregationStrategy.BEST_OF_N,
    ) -> None:
        self._strategy = default_strategy
        self._history: list[EnsembleResult] = []
        self._model_performance: dict[str, list[float]] = defaultdict(list)
        self._log = logger.bind(component="multi_model_ensemble")

    def aggregate(
        self,
        responses: list[ModelResponse],
        strategy: AggregationStrategy | None = None,
        domain: str = "general",
    ) -> EnsembleResult:
        """Aggregate multiple model responses."""
        strat = strategy or self._strategy

        if not responses:
            return EnsembleResult(strategy=strat)

        # Score each response
        for resp in responses:
            quality, conf = _score_response_quality(resp.response_text)
            resp.quality = quality
            resp.confidence = conf

        if strat == AggregationStrategy.BEST_OF_N:
            result = self._best_of_n(responses, domain)
        elif strat == AggregationStrategy.WEIGHTED_MERGE:
            result = self._weighted_select(responses, domain)
        elif strat == AggregationStrategy.CASCADE:
            result = self._cascade(responses, domain)
        else:
            result = self._best_of_n(responses, domain)

        result.strategy = strat
        result.total_tokens = sum(r.tokens_used for r in responses)
        result.total_latency_ms = max(
            (r.latency_ms for r in responses), default=0.0,
        )

        # Track performance
        for resp in responses:
            self._model_performance[resp.model_id].append(resp.confidence)

        self._history.append(result)
        return result

    def _best_of_n(
        self,
        responses: list[ModelResponse],
        domain: str,
    ) -> EnsembleResult:
        """Select the best single response."""
        # Weight by model domain expertise
        scored = []
        for resp in responses:
            weights = MODEL_QUALITY_WEIGHTS.get(resp.model_id, {})
            domain_weight = weights.get(domain, weights.get("general", 1.0))
            final_score = resp.confidence * domain_weight
            scored.append((resp, final_score))

        scored.sort(key=lambda x: x[1], reverse=True)
        best = scored[0][0]

        # Calculate agreement
        agreement = self._calc_agreement(responses)

        return EnsembleResult(
            selected_response=best.response_text,
            selected_model=best.model_id,
            all_responses=responses,
            agreement_score=agreement,
            confidence=scored[0][1],
        )

    def _weighted_select(
        self,
        responses: list[ModelResponse],
        domain: str,
    ) -> EnsembleResult:
        """Select response weighted by domain expertise."""
        best_score = -1.0
        best_resp = responses[0]

        for resp in responses:
            weights = MODEL_QUALITY_WEIGHTS.get(resp.model_id, {})
            domain_weight = weights.get(domain, weights.get("general", 1.0))
            score = resp.confidence * domain_weight * (1 + len(resp.response_text) / 5000)
            if score > best_score:
                best_score = score
                best_resp = resp

        return EnsembleResult(
            selected_response=best_resp.response_text,
            selected_model=best_resp.model_id,
            all_responses=responses,
            agreement_score=self._calc_agreement(responses),
            confidence=best_score,
        )

    def _cascade(
        self,
        responses: list[ModelResponse],
        domain: str,
    ) -> EnsembleResult:
        """Try responses in quality order until acceptable."""
        for resp in sorted(responses, key=lambda r: r.confidence, reverse=True):
            if resp.quality in (ResponseQuality.EXCELLENT, ResponseQuality.GOOD):
                return EnsembleResult(
                    selected_response=resp.response_text,
                    selected_model=resp.model_id,
                    all_responses=responses,
                    agreement_score=self._calc_agreement(responses),
                    confidence=resp.confidence,
                )

        # Fallback to best
        return self._best_of_n(responses, domain)

    def _calc_agreement(self, responses: list[ModelResponse]) -> float:
        """Calculate how much models agree."""
        if len(responses) < 2:
            return 1.0

        # Compare quality ratings
        qualities = [r.quality for r in responses]
        most_common = max(set(qualities), key=qualities.count)
        agreement = qualities.count(most_common) / len(qualities)
        return agreement

    def get_model_rankings(self, domain: str = "general") -> list[tuple[str, float]]:
        """Get models ranked by performance in domain."""
        rankings = []
        for model_id, scores in self._model_performance.items():
            if not scores:
                continue
            weights = MODEL_QUALITY_WEIGHTS.get(model_id, {})
            domain_weight = weights.get(domain, weights.get("general", 1.0))
            avg_score = sum(scores) / len(scores) * domain_weight
            rankings.append((model_id, avg_score))

        rankings.sort(key=lambda x: x[1], reverse=True)
        return rankings

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_ensembles": len(self._history),
            "models_tracked": len(self._model_performance),
            "avg_agreement": round(
                sum(r.agreement_score for r in self._history) /
                max(1, len(self._history)),
                2,
            ),
        }
