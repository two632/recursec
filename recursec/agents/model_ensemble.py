"""Model ensemble coordinator — multi-model inference.

Coordinates multiple LLMs for higher-quality decisions:
1. Parallel inference across models
2. Response aggregation strategies
3. Confidence-weighted merging
4. Disagreement detection
5. Fallback chains
6. Ensemble prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AggregationStrategy(str, Enum):
    BEST_OF_N = "best_of_n"         # Take highest-confidence response
    MAJORITY_VOTE = "majority_vote"   # Most common answer wins
    WEIGHTED_MERGE = "weighted_merge"  # Confidence-weighted combination
    CHAIN = "chain"                   # Sequential refinement
    DEBATE = "debate"                 # Adversarial discussion
    SPECIALIST = "specialist"         # Route to domain expert


class ModelRole(str, Enum):
    PRIMARY = "primary"
    SECONDARY = "secondary"
    VALIDATOR = "validator"
    SPECIALIST = "specialist"
    FAST = "fast"
    DEEP = "deep"


@dataclass
class ModelResponse:
    """A response from a single model."""
    model_name: str = ""
    role: ModelRole = ModelRole.PRIMARY
    content: str = ""
    confidence: float = 0.5
    latency_s: float = 0.0
    token_count: int = 0
    error: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_name[:12],
            "conf": f"{self.confidence:.2f}",
            "tokens": self.token_count,
        }


@dataclass
class EnsembleResult:
    """Aggregated result from ensemble."""
    strategy: AggregationStrategy = AggregationStrategy.BEST_OF_N
    responses: list[ModelResponse] = field(default_factory=list)
    final_content: str = ""
    final_confidence: float = 0.0
    agreement_score: float = 0.0
    selected_model: str = ""
    reasoning: str = ""
    total_latency_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy.value[:10],
            "models": len(self.responses),
            "confidence": f"{self.final_confidence:.2f}",
            "agreement": f"{self.agreement_score:.2f}",
        }


# Model capability profiles for routing
MODEL_PROFILES: dict[str, dict[str, Any]] = {
    "WhiteRabbitNeo": {
        "role": ModelRole.SPECIALIST,
        "strengths": ["security", "exploit", "pentest"],
        "speed": "medium",
        "quality": 0.85,
        "weight": 2.0,
    },
    "Qwen2.5-Coder-14B": {
        "role": ModelRole.SPECIALIST,
        "strengths": ["code", "audit", "analysis"],
        "speed": "slow",
        "quality": 0.9,
        "weight": 1.8,
    },
    "Qwen2.5-Coder-7B": {
        "role": ModelRole.SECONDARY,
        "strengths": ["code", "quick_audit"],
        "speed": "medium",
        "quality": 0.75,
        "weight": 1.2,
    },
    "DeepSeek-R1": {
        "role": ModelRole.DEEP,
        "strengths": ["reasoning", "planning", "analysis"],
        "speed": "slow",
        "quality": 0.88,
        "weight": 1.7,
    },
    "Yi-9B-200K": {
        "role": ModelRole.SPECIALIST,
        "strengths": ["long_context", "large_code"],
        "speed": "slow",
        "quality": 0.78,
        "weight": 1.3,
    },
    "Phi-3.5-mini": {
        "role": ModelRole.FAST,
        "strengths": ["quick", "triage", "classification"],
        "speed": "fast",
        "quality": 0.65,
        "weight": 0.8,
    },
    "Mistral-7B": {
        "role": ModelRole.PRIMARY,
        "strengths": ["general", "instruction"],
        "speed": "medium",
        "quality": 0.75,
        "weight": 1.0,
    },
    "CodeLlama-13B": {
        "role": ModelRole.SECONDARY,
        "strengths": ["code", "completion"],
        "speed": "medium",
        "quality": 0.8,
        "weight": 1.3,
    },
    "Hermes-4-14B": {
        "role": ModelRole.PRIMARY,
        "strengths": ["instruction", "planning", "general"],
        "speed": "slow",
        "quality": 0.82,
        "weight": 1.5,
    },
    "Dolphin-2.9": {
        "role": ModelRole.SECONDARY,
        "strengths": ["uncensored", "creative", "security"],
        "speed": "medium",
        "quality": 0.73,
        "weight": 1.2,
    },
    "DeepSeek-Math": {
        "role": ModelRole.SPECIALIST,
        "strengths": ["math", "crypto", "numerical"],
        "speed": "medium",
        "quality": 0.82,
        "weight": 1.4,
    },
    "Llama-3.1-8B": {
        "role": ModelRole.PRIMARY,
        "strengths": ["general", "instruction"],
        "speed": "medium",
        "quality": 0.76,
        "weight": 1.0,
    },
}


class ModelEnsembleCoordinator:
    """Coordinates multi-model inference.

    Selects models, aggregates responses,
    detects disagreements, and produces
    high-confidence ensemble results.
    """

    def __init__(self) -> None:
        self._results: list[EnsembleResult] = []
        self._model_stats: dict[str, dict[str, float]] = {}
        self._log = logger.bind(component="ensemble")

    def select_models(
        self,
        task_type: str = "",
        strategy: AggregationStrategy = AggregationStrategy.BEST_OF_N,
        max_models: int = 3,
    ) -> list[str]:
        """Select models for a task."""
        scores: list[tuple[str, float]] = []

        for name, profile in MODEL_PROFILES.items():
            score = profile["quality"] * profile["weight"]

            # Bonus for matching strengths
            for strength in profile["strengths"]:
                if strength in task_type.lower():
                    score *= 1.5
                    break

            # For debate/vote, prefer diverse models
            if strategy in (AggregationStrategy.DEBATE, AggregationStrategy.MAJORITY_VOTE):
                score *= 1.0

            scores.append((name, score))

        scores.sort(key=lambda x: x[1], reverse=True)
        return [s[0] for s in scores[:max_models]]

    def aggregate(
        self,
        responses: list[ModelResponse],
        strategy: AggregationStrategy = AggregationStrategy.BEST_OF_N,
    ) -> EnsembleResult:
        """Aggregate multiple model responses."""
        result = EnsembleResult(
            strategy=strategy,
            responses=responses,
        )

        if not responses:
            return result

        valid = [r for r in responses if not r.error]
        if not valid:
            result.reasoning = "All models errored"
            return result

        if strategy == AggregationStrategy.BEST_OF_N:
            result = self._best_of_n(result, valid)
        elif strategy == AggregationStrategy.WEIGHTED_MERGE:
            result = self._weighted_merge(result, valid)
        elif strategy == AggregationStrategy.MAJORITY_VOTE:
            result = self._majority_vote(result, valid)
        elif strategy == AggregationStrategy.CHAIN:
            result = self._chain(result, valid)
        elif strategy == AggregationStrategy.SPECIALIST:
            result = self._specialist(result, valid)
        else:
            result = self._best_of_n(result, valid)

        # Calculate agreement
        result.agreement_score = self._calculate_agreement(valid)

        # Total latency
        result.total_latency_s = sum(r.latency_s for r in valid)

        # Update stats
        for r in valid:
            self._update_model_stats(r)

        self._results.append(result)
        return result

    def _best_of_n(
        self,
        result: EnsembleResult,
        responses: list[ModelResponse],
    ) -> EnsembleResult:
        """Select highest-confidence response."""
        best = max(responses, key=lambda r: r.confidence)
        result.final_content = best.content
        result.final_confidence = best.confidence
        result.selected_model = best.model_name
        result.reasoning = f"Selected {best.model_name} (conf={best.confidence:.2f})"
        return result

    def _weighted_merge(
        self,
        result: EnsembleResult,
        responses: list[ModelResponse],
    ) -> EnsembleResult:
        """Confidence-weighted combination."""
        total_weight = sum(r.confidence for r in responses)
        if total_weight == 0:
            return self._best_of_n(result, responses)

        # Use highest-confidence response as base
        best = max(responses, key=lambda r: r.confidence)
        result.final_content = best.content
        result.final_confidence = total_weight / len(responses)
        result.selected_model = best.model_name
        result.reasoning = f"Weighted merge ({len(responses)} models, avg_conf={result.final_confidence:.2f})"
        return result

    def _majority_vote(
        self,
        result: EnsembleResult,
        responses: list[ModelResponse],
    ) -> EnsembleResult:
        """Most common answer wins (simplified)."""
        # For security findings, compare key conclusions
        # Simplified: use confidence-weighted selection
        confidences = {r.model_name: r.confidence for r in responses}
        best_name = max(confidences, key=lambda k: confidences[k])
        best = next(r for r in responses if r.model_name == best_name)

        result.final_content = best.content
        result.final_confidence = best.confidence
        result.selected_model = best.model_name
        result.reasoning = f"Majority vote (selected {best_name})"
        return result

    def _chain(
        self,
        result: EnsembleResult,
        responses: list[ModelResponse],
    ) -> EnsembleResult:
        """Sequential refinement — last response is final."""
        last = responses[-1]
        result.final_content = last.content
        result.final_confidence = last.confidence
        result.selected_model = last.model_name
        result.reasoning = f"Chain ({len(responses)} steps, final={last.model_name})"
        return result

    def _specialist(
        self,
        result: EnsembleResult,
        responses: list[ModelResponse],
    ) -> EnsembleResult:
        """Route to domain specialist."""
        specialists = [r for r in responses if r.role == ModelRole.SPECIALIST]
        if specialists:
            best = max(specialists, key=lambda r: r.confidence)
        else:
            best = max(responses, key=lambda r: r.confidence)

        result.final_content = best.content
        result.final_confidence = best.confidence
        result.selected_model = best.model_name
        result.reasoning = f"Specialist ({best.model_name})"
        return result

    def _calculate_agreement(self, responses: list[ModelResponse]) -> float:
        """Calculate agreement score between models."""
        if len(responses) < 2:
            return 1.0

        confidences = [r.confidence for r in responses]
        avg = sum(confidences) / len(confidences)
        variance = sum((c - avg) ** 2 for c in confidences) / len(confidences)

        # Low variance = high agreement
        return max(0.0, 1.0 - variance * 4)

    def _update_model_stats(self, response: ModelResponse) -> None:
        """Update model performance stats."""
        name = response.model_name
        if name not in self._model_stats:
            self._model_stats[name] = {
                "uses": 0,
                "total_conf": 0.0,
                "total_latency": 0.0,
                "errors": 0,
            }

        stats = self._model_stats[name]
        stats["uses"] += 1
        stats["total_conf"] += response.confidence
        stats["total_latency"] += response.latency_s
        if response.error:
            stats["errors"] += 1

    def build_ensemble_prompt(self) -> str:
        """Build ensemble context for LLM."""
        lines = ["## Model Ensemble\n"]
        lines.append(f"Models: {len(MODEL_PROFILES)}")
        lines.append(f"Ensembles run: {len(self._results)}")

        # Model stats
        if self._model_stats:
            lines.append("\nModel performance:")
            for name, stats in sorted(
                self._model_stats.items(),
                key=lambda x: x[1]["uses"],
                reverse=True,
            )[:5]:
                uses = stats["uses"]
                avg_conf = stats["total_conf"] / uses if uses > 0 else 0
                lines.append(
                    f"  {name[:12]}: uses={uses}, avg_conf={avg_conf:.2f}"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "models_available": len(MODEL_PROFILES),
            "ensembles_run": len(self._results),
            "model_stats": {
                n: {"uses": s["uses"], "avg_conf": s["total_conf"] / max(1, s["uses"])}
                for n, s in self._model_stats.items()
            },
        }
