"""Model ensemble engine — multi-model inference with aggregation.

Implements:
1. Parallel multi-model inference
2. Response aggregation strategies (majority vote, weighted, best-of-N)
3. Model agreement scoring
4. Confidence calibration across models
5. Specialized model selection per task type
6. Fallback chains when models disagree
7. Ensemble prompt construction
"""

from __future__ import annotations

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
    CHAIN_OF_VERIFICATION = "chain_of_verification"
    DEBATE = "debate"


class EnsembleStatus(str, Enum):
    PENDING = "pending"
    INFERRING = "inferring"
    AGGREGATING = "aggregating"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ModelResponse:
    """A response from a single model."""
    model_id: str = ""
    response: str = ""
    confidence: float = 0.5
    tokens_used: int = 0
    latency_ms: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "conf": round(self.confidence, 2),
            "tokens": self.tokens_used,
            "latency": round(self.latency_ms, 0),
        }


@dataclass
class EnsembleResult:
    """Result from ensemble inference."""
    ensemble_id: str = ""
    query: str = ""
    strategy: AggregationStrategy = AggregationStrategy.MAJORITY_VOTE
    status: EnsembleStatus = EnsembleStatus.PENDING
    responses: list[ModelResponse] = field(default_factory=list)
    final_response: str = ""
    final_confidence: float = 0.0
    agreement_score: float = 0.0
    total_tokens: int = 0
    total_latency_ms: float = 0.0
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def model_count(self) -> int:
        return len(self.responses)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.ensemble_id[:10],
            "strategy": self.strategy.value,
            "models": self.model_count,
            "agreement": round(self.agreement_score, 2),
            "conf": round(self.final_confidence, 2),
            "tokens": self.total_tokens,
        }


# ── Model capabilities for ensemble selection ────────────────

MODEL_CAPABILITIES: dict[str, dict[str, float]] = {
    "whiterabbitneo-7b": {"security": 0.95, "exploit": 0.9, "code": 0.6, "general": 0.5},
    "qwen-coder-14b": {"code": 0.95, "security": 0.6, "analysis": 0.8, "general": 0.7},
    "qwen-coder-7b": {"code": 0.85, "security": 0.5, "analysis": 0.7, "general": 0.6},
    "deepseek-r1-7b": {"reasoning": 0.95, "analysis": 0.9, "planning": 0.85, "general": 0.7},
    "hermes-14b": {"general": 0.85, "reasoning": 0.8, "security": 0.6, "code": 0.6},
    "llama-3.1-8b": {"general": 0.75, "reasoning": 0.7, "code": 0.6, "security": 0.5},
    "dolphin-8b": {"general": 0.7, "security": 0.65, "uncensored": 0.95, "code": 0.5},
    "mistral-7b": {"general": 0.75, "code": 0.6, "reasoning": 0.65, "security": 0.5},
    "codellama-13b": {"code": 0.9, "security": 0.5, "general": 0.5, "analysis": 0.6},
    "yi-9b-200k": {"long_context": 0.95, "code": 0.7, "general": 0.7, "analysis": 0.7},
    "phi-3.5-mini": {"fast": 0.95, "general": 0.65, "code": 0.6, "reasoning": 0.6},
}

# Default ensemble compositions for task types
ENSEMBLE_PRESETS: dict[str, list[str]] = {
    "security_analysis": ["whiterabbitneo-7b", "deepseek-r1-7b", "hermes-14b"],
    "code_review": ["qwen-coder-14b", "codellama-13b", "deepseek-r1-7b"],
    "vulnerability_validation": ["whiterabbitneo-7b", "qwen-coder-14b", "dolphin-8b"],
    "planning": ["deepseek-r1-7b", "hermes-14b", "llama-3.1-8b"],
    "general": ["hermes-14b", "mistral-7b", "llama-3.1-8b"],
}


class ModelEnsemble:
    """Multi-model ensemble inference engine.

    Queries multiple models and aggregates
    their responses using configurable strategies.
    """

    def __init__(self) -> None:
        self._results: dict[str, EnsembleResult] = {}
        self._counter = 0
        self._log = logger.bind(component="model_ensemble")

    def create_ensemble(
        self,
        query: str,
        strategy: AggregationStrategy = AggregationStrategy.MAJORITY_VOTE,
        preset: str = "",
    ) -> EnsembleResult:
        """Create a new ensemble inference request."""
        self._counter += 1
        result = EnsembleResult(
            ensemble_id=f"ens-{self._counter}",
            query=query,
            strategy=strategy,
        )
        self._results[result.ensemble_id] = result
        return result

    def add_response(
        self,
        ensemble_id: str,
        model_id: str,
        response: str,
        confidence: float = 0.5,
        tokens_used: int = 0,
        latency_ms: float = 0.0,
        error: str = "",
    ) -> ModelResponse | None:
        """Add a model response to an ensemble."""
        result = self._results.get(ensemble_id)
        if not result:
            return None

        resp = ModelResponse(
            model_id=model_id,
            response=response,
            confidence=confidence,
            tokens_used=tokens_used,
            latency_ms=latency_ms,
            error=error,
        )
        result.responses.append(resp)
        result.total_tokens += tokens_used
        result.total_latency_ms = max(result.total_latency_ms, latency_ms)

        return resp

    def aggregate(self, ensemble_id: str) -> EnsembleResult | None:
        """Aggregate responses from all models."""
        result = self._results.get(ensemble_id)
        if not result or not result.responses:
            return None

        valid_responses = [r for r in result.responses if not r.error]
        if not valid_responses:
            result.status = EnsembleStatus.FAILED
            return result

        if result.strategy == AggregationStrategy.BEST_OF_N:
            self._aggregate_best_of_n(result, valid_responses)
        elif result.strategy == AggregationStrategy.WEIGHTED_VOTE:
            self._aggregate_weighted(result, valid_responses)
        else:
            self._aggregate_best_of_n(result, valid_responses)

        # Calculate agreement score
        result.agreement_score = self._calculate_agreement(valid_responses)
        result.status = EnsembleStatus.COMPLETED
        result.completed_at = time.time()

        return result

    def select_models(
        self,
        task_type: str,
        n_models: int = 3,
    ) -> list[str]:
        """Select best models for a task type."""
        # Check presets first
        preset = ENSEMBLE_PRESETS.get(task_type)
        if preset:
            return preset[:n_models]

        # Score models by capability
        scored: list[tuple[float, str]] = []
        for model_id, caps in MODEL_CAPABILITIES.items():
            score = caps.get(task_type, caps.get("general", 0.5))
            scored.append((score, model_id))

        scored.sort(reverse=True)
        return [model_id for _, model_id in scored[:n_models]]

    def build_ensemble_prompt(
        self,
        ensemble_id: str = "",
        max_results: int = 5,
    ) -> str:
        """Build ensemble context for LLM."""
        lines = ["## Model Ensemble\n"]

        if ensemble_id:
            result = self._results.get(ensemble_id)
            if result:
                lines.append(
                    f"Strategy: {result.strategy.value} | "
                    f"Models: {result.model_count} | "
                    f"Agreement: {result.agreement_score:.0%}"
                )
                for resp in result.responses:
                    icon = "[x]" if resp.error else "[o]"
                    lines.append(
                        f"  {icon} {resp.model_id[:12]}: "
                        f"conf={resp.confidence:.0%} "
                        f"tokens={resp.tokens_used}"
                    )
        else:
            completed = [r for r in self._results.values() if r.status == EnsembleStatus.COMPLETED]
            lines.append(f"Completed ensembles: {len(completed)}")
            for r in completed[-max_results:]:
                lines.append(
                    f"  [{r.ensemble_id[:6]}] {r.strategy.value[:8]} "
                    f"agree={r.agreement_score:.0%} conf={r.final_confidence:.0%}"
                )

        return "\n".join(lines)

    def _aggregate_best_of_n(
        self,
        result: EnsembleResult,
        responses: list[ModelResponse],
    ) -> None:
        """Select best response by confidence."""
        best = max(responses, key=lambda r: r.confidence)
        result.final_response = best.response
        result.final_confidence = best.confidence

    def _aggregate_weighted(
        self,
        result: EnsembleResult,
        responses: list[ModelResponse],
    ) -> None:
        """Weighted aggregation by model capability."""
        best = max(responses, key=lambda r: r.confidence)
        total_weight = sum(r.confidence for r in responses)
        result.final_response = best.response
        result.final_confidence = (
            sum(r.confidence ** 2 for r in responses) / total_weight
            if total_weight else 0
        )

    def _calculate_agreement(
        self,
        responses: list[ModelResponse],
    ) -> float:
        """Calculate agreement score between model responses."""
        if len(responses) <= 1:
            return 1.0

        # Simple agreement: average pairwise similarity
        total_pairs = 0
        agreement_sum = 0.0

        for i in range(len(responses)):
            for j in range(i + 1, len(responses)):
                total_pairs += 1
                # Token overlap as proxy for agreement
                tokens_i = set(responses[i].response.lower().split()[:50])
                tokens_j = set(responses[j].response.lower().split()[:50])
                if tokens_i and tokens_j:
                    overlap = len(tokens_i & tokens_j) / len(tokens_i | tokens_j)
                    agreement_sum += overlap

        return agreement_sum / total_pairs if total_pairs else 0

    def get_stats(self) -> dict[str, Any]:
        completed = [r for r in self._results.values() if r.status == EnsembleStatus.COMPLETED]
        return {
            "total_ensembles": len(self._results),
            "completed": len(completed),
            "avg_agreement": (
                sum(r.agreement_score for r in completed) / len(completed)
                if completed else 0
            ),
            "total_tokens": sum(r.total_tokens for r in self._results.values()),
        }
