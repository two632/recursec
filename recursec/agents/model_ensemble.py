"""Model ensemble — multi-model voting and consensus for high-confidence decisions.

Implements:
1. Multi-model voting (send same query to N models)
2. Weighted consensus (weight by model quality for task type)
3. Disagreement detection (flag when models disagree)
4. Confidence calibration
5. Model debate (models critique each other's answers)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ModelVote:
    """A vote from a single model."""
    model_id: str = ""
    response: str = ""
    confidence: float = 0.5
    quality_score: float = 0.5
    weight: float = 1.0
    tokens_used: int = 0
    latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:12],
            "confidence": f"{self.confidence:.2f}",
            "quality": f"{self.quality_score:.2f}",
            "weight": f"{self.weight:.1f}",
        }


@dataclass
class EnsembleResult:
    """Result from multi-model ensemble."""
    votes: list[ModelVote] = field(default_factory=list)
    consensus_response: str = ""
    consensus_confidence: float = 0.0
    agreement_level: float = 0.0
    total_tokens: int = 0
    winning_model: str = ""
    dissenting_models: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "models": len(self.votes),
            "confidence": f"{self.consensus_confidence:.2f}",
            "agreement": f"{self.agreement_level:.2f}",
            "winner": self.winning_model[:12],
            "dissenters": len(self.dissenting_models),
        }


# Model weights for different task types
MODEL_TASK_WEIGHTS: dict[str, dict[str, float]] = {
    "vulnerability_assessment": {"whiterabbit": 2.0, "qwen-coder-14b": 1.5, "deepseek-r1": 1.3, "hermes-4-14b": 1.0, "dolphin": 1.0, "mistral-7b": 0.8, "phi-3.5-mini": 0.6},
    "code_review": {"qwen-coder-14b": 2.0, "qwen-coder-7b": 1.5, "codellama-13b": 1.3, "deepseek-r1": 1.0, "whiterabbit": 0.8},
    "reasoning": {"deepseek-r1": 2.0, "hermes-4-14b": 1.5, "deepseek-math": 1.3, "qwen-coder-14b": 1.0},
    "tool_selection": {"functiongemma": 2.0, "phi-3.5-mini": 1.5, "mistral-7b": 1.0},
    "finding_validation": {"deepseek-r1": 2.0, "whiterabbit": 1.5, "qwen-coder-14b": 1.3},
}


class ModelEnsemble:
    """Multi-model ensemble for high-confidence decisions."""

    def __init__(self, min_votes: int = 2, agreement_threshold: float = 0.6) -> None:
        self._min_votes = min_votes
        self._agreement_threshold = agreement_threshold
        self._ensemble_counter = 0
        self._results: list[EnsembleResult] = []
        self._log = logger.bind(component="model_ensemble")

    def get_models_for_task(self, task_type: str, max_models: int = 3) -> list[tuple[str, float]]:
        """Get recommended models and weights for a task type."""
        weights = MODEL_TASK_WEIGHTS.get(task_type, MODEL_TASK_WEIGHTS.get("reasoning", {}))
        sorted_models = sorted(weights.items(), key=lambda x: x[1], reverse=True)
        return sorted_models[:max_models]

    def compute_consensus(
        self,
        votes: list[ModelVote],
        task_type: str = "reasoning",
    ) -> EnsembleResult:
        """Compute consensus from model votes."""
        self._ensemble_counter += 1

        if not votes:
            return EnsembleResult()

        # Get task-specific weights
        task_weights = MODEL_TASK_WEIGHTS.get(task_type, {})

        # Apply task-specific weights
        for vote in votes:
            if vote.model_id in task_weights:
                vote.weight = task_weights[vote.model_id]

        # Weighted confidence
        total_weight = sum(v.weight for v in votes)
        weighted_confidence = sum(v.confidence * v.weight for v in votes) / total_weight if total_weight > 0 else 0.0

        # Find winning vote (highest weighted score)
        for vote in votes:
            vote.quality_score = vote.confidence * vote.weight
        winner = max(votes, key=lambda v: v.quality_score)

        # Calculate agreement level
        if len(votes) >= 2:
            agreement_scores = []
            for i, va in enumerate(votes):
                for vb in votes[i + 1:]:
                    # Simple similarity: both high confidence or both low
                    sim = 1.0 - abs(va.confidence - vb.confidence)
                    agreement_scores.append(sim)
            agreement = sum(agreement_scores) / len(agreement_scores) if agreement_scores else 0.0
        else:
            agreement = 1.0

        # Find dissenters (low confidence or far from consensus)
        dissenters = [
            v.model_id for v in votes
            if abs(v.confidence - weighted_confidence) > 0.3
        ]

        result = EnsembleResult(
            votes=votes,
            consensus_response=winner.response,
            consensus_confidence=weighted_confidence,
            agreement_level=agreement,
            total_tokens=sum(v.tokens_used for v in votes),
            winning_model=winner.model_id,
            dissenting_models=dissenters,
        )

        self._results.append(result)
        if len(self._results) > 100:
            self._results = self._results[-50:]
        return result

    def needs_debate(self, result: EnsembleResult) -> bool:
        """Determine if models need to debate (low agreement)."""
        return result.agreement_level < self._agreement_threshold

    def build_debate_prompt(
        self,
        result: EnsembleResult,
        model_id: str,
    ) -> str:
        """Build a debate prompt for a model to critique other responses."""
        lines = ["You are reviewing other models' security assessments.\n"]
        lines.append("Other models found:\n")

        for vote in result.votes:
            if vote.model_id != model_id:
                lines.append(f"Model {vote.model_id} (confidence {vote.confidence:.2f}):")
                lines.append(f"  {vote.response[:300]}\n")

        lines.append("Your task:")
        lines.append("1. Do you agree or disagree with these assessments?")
        lines.append("2. What did they miss?")
        lines.append("3. Are any of their findings likely false positives?")
        lines.append("4. What is YOUR confidence level (0-1)?")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        if not self._results:
            return {"ensembles": 0}
        return {
            "ensembles": len(self._results),
            "avg_confidence": sum(r.consensus_confidence for r in self._results) / len(self._results),
            "avg_agreement": sum(r.agreement_level for r in self._results) / len(self._results),
            "debates_needed": sum(1 for r in self._results if self.needs_debate(r)),
        }

    def build_ensemble_prompt(self) -> str:
        """Build LLM prompt with ensemble state."""
        stats = self.get_stats()
        lines = ["## Model Ensemble State"]
        lines.append(f"Ensembles: {stats.get('ensembles', 0)}")
        if stats.get('ensembles', 0) > 0:
            lines.append(f"Avg confidence: {stats.get('avg_confidence', 0):.2f}")
            lines.append(f"Avg agreement: {stats.get('avg_agreement', 0):.2f}")
        return "\n".join(lines)
