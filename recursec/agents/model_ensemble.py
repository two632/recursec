"""Model ensemble — combines outputs from multiple LLMs for better results.

Implements:
1. Voting ensemble (majority vote)
2. Weighted ensemble (weighted by model quality)
3. Debate ensemble (models argue, judge decides)
4. Chain ensemble (model A feeds model B)
5. Mixture-of-experts (route sub-tasks to specialists)
6. Best-of-N sampling
7. Disagreement detection
8. Ensemble confidence scoring
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class EnsembleMethod(str, Enum):
    VOTING = "voting"
    WEIGHTED = "weighted"
    DEBATE = "debate"
    CHAIN = "chain"
    MIXTURE = "mixture"
    BEST_OF_N = "best_of_n"


@dataclass
class ModelOutput:
    """Output from a single model."""
    model_id: str = ""
    content: str = ""
    confidence: float = 0.5
    latency_s: float = 0.0
    tokens_used: int = 0
    quality_score: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:20],
            "confidence": round(self.confidence, 2),
            "quality": round(self.quality_score, 2),
            "tokens": self.tokens_used,
        }


@dataclass
class EnsembleResult:
    """Result from an ensemble operation."""
    method: EnsembleMethod = EnsembleMethod.VOTING
    final_output: str = ""
    confidence: float = 0.5
    agreement_score: float = 0.0
    model_outputs: list[ModelOutput] = field(default_factory=list)
    total_tokens: int = 0
    total_latency_s: float = 0.0
    disagreements: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method.value,
            "output": self.final_output[:60],
            "confidence": round(self.confidence, 2),
            "agreement": round(self.agreement_score, 2),
            "models": len(self.model_outputs),
            "tokens": self.total_tokens,
            "disagreements": len(self.disagreements),
        }


# ── Model Quality Weights ─────────────────────────────────────

MODEL_QUALITY_WEIGHTS: dict[str, float] = {
    "whiterabbitneo-7b": 0.9,     # Security specialist
    "qwen-coder-14b": 0.85,      # Best code model
    "hermes-14b": 0.85,          # Best general
    "deepseek-r1-7b": 0.8,       # Best reasoning
    "qwen-coder-7b": 0.75,
    "dolphin-8b": 0.75,
    "llama-8b": 0.7,
    "mistral-7b": 0.7,
    "codellama-13b": 0.7,
    "deepseek-math-7b": 0.7,
    "yi-9b-200k": 0.65,
    "phi-3.5-mini": 0.6,
    "codellama-7b": 0.6,
}


class ModelEnsemble:
    """Combines outputs from multiple LLMs for better results.

    Supports voting, weighted, debate, chain, mixture,
    and best-of-N ensemble methods.
    """

    def __init__(self) -> None:
        self._ensemble_counter = 0
        self._total_ensembles = 0
        self._method_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"uses": 0, "success": 0})
        self._log = logger.bind(component="model_ensemble")

    def vote(
        self,
        outputs: list[ModelOutput],
    ) -> EnsembleResult:
        """Majority voting ensemble."""
        self._ensemble_counter += 1
        result = EnsembleResult(
            method=EnsembleMethod.VOTING,
            model_outputs=outputs,
        )

        if not outputs:
            return result

        # Simple voting: extract key answers and vote
        # For security: extract severity/type and vote
        answers = []
        for out in outputs:
            # Extract first significant line as "answer"
            lines = [ln.strip() for ln in out.content.split("\n") if ln.strip()]
            answer = lines[0] if lines else ""
            answers.append(answer)

        if answers:
            counter = Counter(answers)
            winner, count = counter.most_common(1)[0]
            result.final_output = winner
            result.agreement_score = count / len(answers)
            result.confidence = result.agreement_score

        result.total_tokens = sum(o.tokens_used for o in outputs)
        result.total_latency_s = max((o.latency_s for o in outputs), default=0)

        self._method_stats["voting"]["uses"] += 1
        return result

    def weighted_vote(
        self,
        outputs: list[ModelOutput],
    ) -> EnsembleResult:
        """Weighted voting ensemble."""
        self._ensemble_counter += 1
        result = EnsembleResult(
            method=EnsembleMethod.WEIGHTED,
            model_outputs=outputs,
        )

        if not outputs:
            return result

        # Weight each output by model quality and confidence
        best_score = -1.0
        best_output = outputs[0]

        for out in outputs:
            weight = MODEL_QUALITY_WEIGHTS.get(out.model_id, 0.5)
            score = weight * out.confidence * out.quality_score
            if score > best_score:
                best_score = score
                best_output = out

        result.final_output = best_output.content
        result.confidence = best_output.confidence
        result.total_tokens = sum(o.tokens_used for o in outputs)
        result.total_latency_s = max((o.latency_s for o in outputs), default=0)

        # Calculate agreement
        result.agreement_score = self._calculate_agreement(outputs)
        result.disagreements = self._find_disagreements(outputs)

        self._method_stats["weighted"]["uses"] += 1
        return result

    def chain(
        self,
        outputs: list[ModelOutput],
    ) -> EnsembleResult:
        """Chain ensemble — each model builds on the previous."""
        self._ensemble_counter += 1
        result = EnsembleResult(
            method=EnsembleMethod.CHAIN,
            model_outputs=outputs,
        )

        if not outputs:
            return result

        # Final output is the last model's output (which had access to all previous)
        result.final_output = outputs[-1].content
        result.confidence = outputs[-1].confidence

        # Boost confidence if chain is consistent
        consistent = True
        for i in range(1, len(outputs)):
            if self._content_similarity(outputs[i - 1].content, outputs[i].content) < 0.2:
                consistent = False
                break

        if consistent:
            result.confidence = min(1.0, result.confidence * 1.2)

        result.total_tokens = sum(o.tokens_used for o in outputs)
        result.total_latency_s = sum(o.latency_s for o in outputs)

        self._method_stats["chain"]["uses"] += 1
        return result

    def best_of_n(
        self,
        outputs: list[ModelOutput],
    ) -> EnsembleResult:
        """Best-of-N sampling — pick the best output."""
        self._ensemble_counter += 1
        result = EnsembleResult(
            method=EnsembleMethod.BEST_OF_N,
            model_outputs=outputs,
        )

        if not outputs:
            return result

        # Score each output
        best = max(
            outputs,
            key=lambda o: o.quality_score * o.confidence,
        )

        result.final_output = best.content
        result.confidence = best.confidence
        result.total_tokens = sum(o.tokens_used for o in outputs)

        self._method_stats["best_of_n"]["uses"] += 1
        return result

    def mixture_of_experts(
        self,
        outputs: list[ModelOutput],
        task_type: str = "",
    ) -> EnsembleResult:
        """Mixture-of-experts — route to the best model for the task."""
        self._ensemble_counter += 1
        result = EnsembleResult(
            method=EnsembleMethod.MIXTURE,
            model_outputs=outputs,
        )

        if not outputs:
            return result

        # Select expert based on task type
        expert_map: dict[str, list[str]] = {
            "security": ["whiterabbitneo-7b", "dolphin-8b"],
            "code": ["qwen-coder-14b", "qwen-coder-7b", "codellama-13b"],
            "reasoning": ["deepseek-r1-7b", "hermes-14b"],
            "general": ["hermes-14b", "llama-8b", "mistral-7b"],
        }

        preferred = expert_map.get(task_type, [])

        # Find the expert in outputs
        expert_output = None
        for out in outputs:
            if out.model_id in preferred:
                if expert_output is None or out.quality_score > expert_output.quality_score:
                    expert_output = out

        if expert_output:
            result.final_output = expert_output.content
            result.confidence = expert_output.confidence * 1.1  # Expert boost
        else:
            # Fall back to best quality
            best = max(outputs, key=lambda o: o.quality_score)
            result.final_output = best.content
            result.confidence = best.confidence

        result.confidence = min(1.0, result.confidence)
        result.total_tokens = sum(o.tokens_used for o in outputs)

        self._method_stats["mixture"]["uses"] += 1
        return result

    def detect_disagreement(
        self,
        outputs: list[ModelOutput],
    ) -> list[str]:
        """Detect significant disagreements between model outputs."""
        return self._find_disagreements(outputs)

    def _calculate_agreement(self, outputs: list[ModelOutput]) -> float:
        """Calculate pairwise agreement between outputs."""
        if len(outputs) < 2:
            return 1.0

        total_similarity = 0.0
        pairs = 0

        for i in range(len(outputs)):
            for j in range(i + 1, len(outputs)):
                total_similarity += self._content_similarity(
                    outputs[i].content, outputs[j].content,
                )
                pairs += 1

        return total_similarity / max(1, pairs)

    def _find_disagreements(self, outputs: list[ModelOutput]) -> list[str]:
        """Find specific disagreements."""
        disagreements = []

        for i in range(len(outputs)):
            for j in range(i + 1, len(outputs)):
                sim = self._content_similarity(
                    outputs[i].content, outputs[j].content,
                )
                if sim < 0.3:
                    disagreements.append(
                        f"{outputs[i].model_id} vs {outputs[j].model_id}: "
                        f"similarity={sim:.2f}"
                    )

        return disagreements

    @staticmethod
    def _content_similarity(text1: str, text2: str) -> float:
        """Simple Jaccard similarity between two texts."""
        if not text1 or not text2:
            return 0.0

        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())

        if not words1 or not words2:
            return 0.0

        intersection = words1 & words2
        union = words1 | words2

        return len(intersection) / len(union)

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_ensembles": self._ensemble_counter,
            "method_stats": {k: dict(v) for k, v in self._method_stats.items()},
        }
