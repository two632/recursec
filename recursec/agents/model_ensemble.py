"""Model ensemble engine — multi-model voting and consensus.

Implements:
1. Majority voting across multiple models
2. Weighted voting by model quality
3. Confidence-weighted aggregation
4. Disagreement detection
5. Ensemble diversity measurement
6. Model specialization scoring
7. Result fusion strategies
8. Ensemble calibration
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class EnsembleStrategy(str, Enum):
    MAJORITY_VOTE = "majority_vote"       # Simple majority
    WEIGHTED_VOTE = "weighted_vote"       # Weighted by model quality
    CONFIDENCE_WEIGHTED = "confidence_weighted"  # Weighted by confidence
    BEST_OF = "best_of"                  # Take highest confidence
    UNANIMOUS = "unanimous"              # All must agree
    DEBATE = "debate"                    # Models debate, coordinator decides


class AggregationMethod(str, Enum):
    CONCAT = "concat"         # Concatenate all outputs
    UNION = "union"          # Union of all findings
    INTERSECTION = "intersection"  # Only findings all models agree on
    RANKED = "ranked"        # Rank by frequency across models


@dataclass
class ModelResponse:
    """Response from a single model in the ensemble."""
    model_id: str = ""
    model_name: str = ""
    content: str = ""
    confidence: float = 0.5
    findings: list[dict[str, Any]] = field(default_factory=list)
    classification: str = ""     # For classification tasks
    score: float = 0.0           # For scoring tasks
    latency_s: float = 0.0
    tokens_used: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "confidence": round(self.confidence, 2),
            "findings": len(self.findings),
            "classification": self.classification[:15],
            "score": round(self.score, 2),
        }


@dataclass
class EnsembleResult:
    """Aggregated result from the ensemble."""
    ensemble_id: str = ""
    strategy: EnsembleStrategy = EnsembleStrategy.MAJORITY_VOTE
    responses: list[ModelResponse] = field(default_factory=list)
    consensus_classification: str = ""
    consensus_confidence: float = 0.0
    consensus_findings: list[dict[str, Any]] = field(default_factory=list)
    agreement_ratio: float = 0.0
    disagreements: list[dict[str, Any]] = field(default_factory=list)
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.ensemble_id[:10],
            "strategy": self.strategy.value,
            "models": len(self.responses),
            "classification": self.consensus_classification[:15],
            "confidence": round(self.consensus_confidence, 2),
            "agreement": round(self.agreement_ratio, 2),
            "findings": len(self.consensus_findings),
        }


# ── Model weights for ensemble voting ────────────────────────

MODEL_QUALITY_WEIGHTS: dict[str, float] = {
    "whiterabbitneo": 0.85,
    "qwen-coder-14b": 0.90,
    "qwen-coder-7b": 0.75,
    "deepseek-r1": 0.88,
    "deepseek-math": 0.72,
    "hermes-14b": 0.82,
    "llama-3.1-8b": 0.78,
    "dolphin-2.9": 0.70,
    "mistral-7b": 0.76,
    "codellama-13b": 0.80,
    "codellama-7b": 0.68,
    "yi-9b-200k": 0.77,
    "phi-3.5-mini": 0.65,
}


class ModelEnsemble:
    """Multi-model voting and consensus engine.

    Queries multiple models and aggregates their responses
    using various strategies to improve accuracy and reduce
    hallucination.
    """

    def __init__(self) -> None:
        self._counter = 0
        self._history: list[EnsembleResult] = []
        self._model_agreement_matrix: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._model_accuracy: dict[str, list[float]] = defaultdict(list)
        self._log = logger.bind(component="model_ensemble")

    def aggregate(
        self,
        responses: list[ModelResponse],
        strategy: EnsembleStrategy = EnsembleStrategy.WEIGHTED_VOTE,
    ) -> EnsembleResult:
        """Aggregate responses from multiple models."""
        self._counter += 1
        start = time.time()

        if strategy == EnsembleStrategy.MAJORITY_VOTE:
            result = self._majority_vote(responses)
        elif strategy == EnsembleStrategy.WEIGHTED_VOTE:
            result = self._weighted_vote(responses)
        elif strategy == EnsembleStrategy.CONFIDENCE_WEIGHTED:
            result = self._confidence_weighted(responses)
        elif strategy == EnsembleStrategy.BEST_OF:
            result = self._best_of(responses)
        elif strategy == EnsembleStrategy.UNANIMOUS:
            result = self._unanimous(responses)
        else:
            result = self._weighted_vote(responses)

        result.ensemble_id = f"ens-{self._counter}"
        result.strategy = strategy
        result.responses = responses
        result.duration_s = time.time() - start

        # Compute agreement
        result.agreement_ratio = self._compute_agreement(responses)
        result.disagreements = self._find_disagreements(responses)

        # Update agreement matrix
        self._update_agreement_matrix(responses)

        self._history.append(result)
        return result

    def _majority_vote(self, responses: list[ModelResponse]) -> EnsembleResult:
        """Simple majority voting on classification."""
        result = EnsembleResult()

        if not responses:
            return result

        # Vote on classification
        votes = [r.classification for r in responses if r.classification]
        if votes:
            counter = Counter(votes)
            result.consensus_classification = counter.most_common(1)[0][0]
            result.consensus_confidence = counter.most_common(1)[0][1] / len(votes)

        # Union findings
        result.consensus_findings = self._union_findings(responses)

        return result

    def _weighted_vote(self, responses: list[ModelResponse]) -> EnsembleResult:
        """Weighted voting by model quality."""
        result = EnsembleResult()

        if not responses:
            return result

        # Weighted vote on classification
        class_weights: dict[str, float] = defaultdict(float)
        total_weight = 0.0

        for r in responses:
            if r.classification:
                weight = MODEL_QUALITY_WEIGHTS.get(r.model_id, 0.5)
                class_weights[r.classification] += weight
                total_weight += weight

        if class_weights:
            best_class = max(class_weights, key=lambda k: class_weights[k])
            result.consensus_classification = best_class
            if total_weight > 0:
                result.consensus_confidence = class_weights[best_class] / total_weight

        # Weighted confidence for findings
        result.consensus_findings = self._weighted_findings(responses)

        return result

    def _confidence_weighted(self, responses: list[ModelResponse]) -> EnsembleResult:
        """Weighted by each model's own confidence score."""
        result = EnsembleResult()

        if not responses:
            return result

        class_weights: dict[str, float] = defaultdict(float)
        total_weight = 0.0

        for r in responses:
            if r.classification:
                weight = r.confidence
                class_weights[r.classification] += weight
                total_weight += weight

        if class_weights:
            best_class = max(class_weights, key=lambda k: class_weights[k])
            result.consensus_classification = best_class
            if total_weight > 0:
                result.consensus_confidence = class_weights[best_class] / total_weight

        result.consensus_findings = self._weighted_findings(responses)

        return result

    def _best_of(self, responses: list[ModelResponse]) -> EnsembleResult:
        """Take the response with highest confidence."""
        result = EnsembleResult()

        if not responses:
            return result

        best = max(responses, key=lambda r: r.confidence)
        result.consensus_classification = best.classification
        result.consensus_confidence = best.confidence
        result.consensus_findings = list(best.findings)

        return result

    def _unanimous(self, responses: list[ModelResponse]) -> EnsembleResult:
        """Only accept if all models agree."""
        result = EnsembleResult()

        if not responses:
            return result

        classifications = set(r.classification for r in responses if r.classification)
        if len(classifications) == 1:
            result.consensus_classification = classifications.pop()
            result.consensus_confidence = sum(r.confidence for r in responses) / len(responses)
        else:
            result.consensus_classification = "no_consensus"
            result.consensus_confidence = 0.0

        # Intersection of findings
        result.consensus_findings = self._intersect_findings(responses)

        return result

    @staticmethod
    def _union_findings(responses: list[ModelResponse]) -> list[dict[str, Any]]:
        """Union all findings from responses."""
        all_findings = []
        seen_titles = set()
        for r in responses:
            for f in r.findings:
                title = f.get("title", "")
                if title and title not in seen_titles:
                    seen_titles.add(title)
                    all_findings.append(f)
        return all_findings

    @staticmethod
    def _weighted_findings(responses: list[ModelResponse]) -> list[dict[str, Any]]:
        """Combine findings with weighted confidence."""
        finding_map: dict[str, dict[str, Any]] = {}
        finding_weights: dict[str, float] = defaultdict(float)
        finding_count: dict[str, int] = defaultdict(int)

        for r in responses:
            weight = MODEL_QUALITY_WEIGHTS.get(r.model_id, 0.5)
            for f in r.findings:
                title = f.get("title", "")
                if title:
                    finding_map[title] = f
                    finding_weights[title] += weight * r.confidence
                    finding_count[title] += 1

        results = []
        for title, data in finding_map.items():
            data["ensemble_confidence"] = round(
                finding_weights[title] / max(1, finding_count[title]), 2
            )
            data["model_count"] = finding_count[title]
            results.append(data)

        results.sort(key=lambda f: f.get("ensemble_confidence", 0), reverse=True)
        return results

    @staticmethod
    def _intersect_findings(responses: list[ModelResponse]) -> list[dict[str, Any]]:
        """Only keep findings that all models agree on."""
        if not responses:
            return []

        title_sets = []
        for r in responses:
            titles = {f.get("title", "") for f in r.findings if f.get("title")}
            title_sets.append(titles)

        if not title_sets:
            return []

        common = title_sets[0]
        for ts in title_sets[1:]:
            common = common & ts

        all_findings = {}
        for r in responses:
            for f in r.findings:
                title = f.get("title", "")
                if title in common:
                    all_findings[title] = f

        return list(all_findings.values())

    @staticmethod
    def _compute_agreement(responses: list[ModelResponse]) -> float:
        """Compute agreement ratio among responses."""
        if len(responses) < 2:
            return 1.0

        classifications = [r.classification for r in responses if r.classification]
        if not classifications:
            return 1.0

        counter = Counter(classifications)
        most_common_count = counter.most_common(1)[0][1]
        return most_common_count / len(classifications)

    @staticmethod
    def _find_disagreements(responses: list[ModelResponse]) -> list[dict[str, Any]]:
        """Find where models disagree."""
        if len(responses) < 2:
            return []

        classifications = {}
        for r in responses:
            if r.classification:
                classifications[r.model_id] = r.classification

        if len(set(classifications.values())) <= 1:
            return []

        return [
            {"model": model, "classification": cls}
            for model, cls in classifications.items()
        ]

    def _update_agreement_matrix(self, responses: list[ModelResponse]) -> None:
        """Track which models tend to agree with each other."""
        for i, r1 in enumerate(responses):
            for r2 in responses[i + 1:]:
                if r1.classification and r2.classification:
                    if r1.classification == r2.classification:
                        self._model_agreement_matrix[r1.model_id][r2.model_id] += 1
                        self._model_agreement_matrix[r2.model_id][r1.model_id] += 1

    def get_agreement_matrix(self) -> dict[str, dict[str, int]]:
        """Get the inter-model agreement matrix."""
        return dict(self._model_agreement_matrix)

    def get_stats(self) -> dict[str, Any]:
        strategy_counts: dict[str, int] = defaultdict(int)
        for r in self._history:
            strategy_counts[r.strategy.value] += 1

        avg_agreement = 0.0
        if self._history:
            avg_agreement = sum(r.agreement_ratio for r in self._history) / len(self._history)

        return {
            "ensembles_run": len(self._history),
            "avg_agreement": round(avg_agreement, 2),
            "by_strategy": dict(strategy_counts),
        }
