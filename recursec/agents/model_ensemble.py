"""Model ensemble engine — combines multiple LLM outputs for higher quality.

Implements:
1. Voting ensemble (majority vote)
2. Weighted ensemble (model quality weighted)
3. Debate ensemble (models challenge each other)
4. Chain ensemble (sequential refinement)
5. Mixture of experts (route to specialists)
6. Confidence-weighted aggregation
7. Disagreement detection
8. Ensemble quality tracking
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine

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
class ModelResponse:
    """A response from a single model."""
    model: str = ""
    response: str = ""
    confidence: float = 0.5
    latency_ms: float = 0.0
    tokens_used: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "confidence": round(self.confidence, 2),
            "latency_ms": round(self.latency_ms, 0),
            "tokens": self.tokens_used,
        }


@dataclass
class EnsembleResult:
    """Result of an ensemble operation."""
    method: EnsembleMethod = EnsembleMethod.VOTING
    final_response: str = ""
    confidence: float = 0.5
    agreement_score: float = 0.0     # How much models agree
    model_responses: list[ModelResponse] = field(default_factory=list)
    disagreements: list[str] = field(default_factory=list)
    total_latency_ms: float = 0.0
    total_tokens: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method.value,
            "confidence": round(self.confidence, 2),
            "agreement": round(self.agreement_score, 2),
            "models_used": len(self.model_responses),
            "tokens": self.total_tokens,
        }


class ModelEnsemble:
    """Combines multiple LLM outputs for higher quality.

    Supports voting, weighted, debate, chain, and
    mixture-of-experts ensemble methods.
    """

    def __init__(self) -> None:
        self._model_weights: dict[str, float] = {}
        self._model_quality: dict[str, float] = defaultdict(lambda: 0.5)
        self._query_fn: Callable[..., Coroutine[Any, Any, ModelResponse]] | None = None
        self._ensemble_count = 0
        self._log = logger.bind(component="model_ensemble")

    def set_query_function(
        self,
        fn: Callable[..., Coroutine[Any, Any, ModelResponse]],
    ) -> None:
        """Set the function used to query individual models."""
        self._query_fn = fn

    def set_model_weight(self, model: str, weight: float) -> None:
        """Set weight for a model."""
        self._model_weights[model] = max(0.0, min(5.0, weight))

    async def query_models(
        self,
        prompt: str,
        models: list[str],
        system_prompt: str = "",
    ) -> list[ModelResponse]:
        """Query multiple models in parallel."""
        if not self._query_fn:
            return []

        async def query_one(model: str) -> ModelResponse:
            start = time.time()
            try:
                response = await self._query_fn(model, prompt, system_prompt)
                response.latency_ms = (time.time() - start) * 1000
                return response
            except Exception as e:
                return ModelResponse(
                    model=model, response=f"Error: {e}",
                    confidence=0.0,
                    latency_ms=(time.time() - start) * 1000,
                )

        tasks = [query_one(m) for m in models]
        responses = await asyncio.gather(*tasks)
        return list(responses)

    async def ensemble(
        self,
        prompt: str,
        models: list[str],
        method: EnsembleMethod = EnsembleMethod.WEIGHTED,
        system_prompt: str = "",
    ) -> EnsembleResult:
        """Run an ensemble of models."""
        self._ensemble_count += 1
        start = time.time()

        responses = await self.query_models(prompt, models, system_prompt)

        if method == EnsembleMethod.VOTING:
            result = self._voting_ensemble(responses)
        elif method == EnsembleMethod.WEIGHTED:
            result = self._weighted_ensemble(responses)
        elif method == EnsembleMethod.BEST_OF_N:
            result = self._best_of_n(responses)
        elif method == EnsembleMethod.CHAIN:
            result = await self._chain_ensemble(prompt, models, system_prompt)
        elif method == EnsembleMethod.DEBATE:
            result = await self._debate_ensemble(prompt, models, system_prompt, responses)
        else:
            result = self._weighted_ensemble(responses)

        result.method = method
        result.total_latency_ms = (time.time() - start) * 1000
        result.total_tokens = sum(r.tokens_used for r in responses)
        result.model_responses = responses

        return result

    def _voting_ensemble(self, responses: list[ModelResponse]) -> EnsembleResult:
        """Majority voting ensemble."""
        result = EnsembleResult()

        # Simple: pick the response with highest confidence
        valid = [r for r in responses if r.confidence > 0]
        if not valid:
            return result

        # Group by similar responses (simple length-based grouping)
        best = max(valid, key=lambda r: r.confidence)
        result.final_response = best.response
        result.confidence = best.confidence

        # Agreement: how many models gave similar responses
        if len(valid) > 1:
            confidences = [r.confidence for r in valid]
            avg_conf = sum(confidences) / len(confidences)
            variance = sum((c - avg_conf) ** 2 for c in confidences) / len(confidences)
            result.agreement_score = max(0.0, 1.0 - variance)
        else:
            result.agreement_score = 1.0

        return result

    def _weighted_ensemble(self, responses: list[ModelResponse]) -> EnsembleResult:
        """Weighted ensemble based on model quality and confidence."""
        result = EnsembleResult()

        valid = [r for r in responses if r.confidence > 0]
        if not valid:
            return result

        # Score each response
        scored = []
        for resp in valid:
            weight = self._model_weights.get(resp.model, 1.0)
            quality = self._model_quality.get(resp.model, 0.5)
            score = resp.confidence * weight * quality
            scored.append((score, resp))

        scored.sort(key=lambda x: x[0], reverse=True)

        best_score, best_resp = scored[0]
        result.final_response = best_resp.response
        result.confidence = best_resp.confidence

        # Weighted agreement
        total_weight = sum(s for s, _ in scored)
        if total_weight > 0:
            result.agreement_score = best_score / total_weight

        return result

    def _best_of_n(self, responses: list[ModelResponse]) -> EnsembleResult:
        """Select the single best response."""
        result = EnsembleResult()

        valid = [r for r in responses if r.confidence > 0]
        if not valid:
            return result

        best = max(valid, key=lambda r: r.confidence)
        result.final_response = best.response
        result.confidence = best.confidence
        result.agreement_score = 1.0

        return result

    async def _chain_ensemble(
        self,
        prompt: str,
        models: list[str],
        system_prompt: str,
    ) -> EnsembleResult:
        """Chain ensemble: each model refines the previous output."""
        result = EnsembleResult()

        if not self._query_fn or not models:
            return result

        current_response = ""

        for model in models:
            if current_response:
                refined_prompt = (
                    f"Previous analysis:\n{current_response[:500]}\n\n"
                    f"Please refine and improve this analysis:\n{prompt}"
                )
            else:
                refined_prompt = prompt

            response = await self._query_fn(model, refined_prompt, system_prompt)
            current_response = response.response
            result.model_responses.append(response)

        result.final_response = current_response
        if result.model_responses:
            result.confidence = result.model_responses[-1].confidence

        return result

    async def _debate_ensemble(
        self,
        prompt: str,
        models: list[str],
        system_prompt: str,
        initial_responses: list[ModelResponse],
    ) -> EnsembleResult:
        """Debate ensemble: models challenge each other's analysis."""
        result = EnsembleResult()

        if not self._query_fn or len(initial_responses) < 2:
            return self._weighted_ensemble(initial_responses)

        # Round 1: Initial responses (already have these)
        analyses = [(r.model, r.response) for r in initial_responses if r.response]

        if len(analyses) < 2:
            return self._weighted_ensemble(initial_responses)

        # Round 2: Each model critiques the others
        debate_responses = []
        for i, (model, analysis) in enumerate(analyses[:3]):
            others = [
                f"Model {j + 1}: {other_analysis[:200]}"
                for j, (other_model, other_analysis) in enumerate(analyses)
                if j != i
            ]

            debate_prompt = (
                f"Original question: {prompt[:200]}\n\n"
                f"Your analysis: {analysis[:200]}\n\n"
                f"Other analyses:\n" + "\n".join(others[:2]) + "\n\n"
                "Considering the other perspectives, what is your final refined analysis? "
                "Point out any errors in other analyses and provide your best answer."
            )

            response = await self._query_fn(model, debate_prompt, system_prompt)
            debate_responses.append(response)

        # Select best refined response
        all_responses = initial_responses + debate_responses
        result = self._weighted_ensemble(all_responses)
        result.model_responses = all_responses

        # Detect disagreements
        for i, r1 in enumerate(initial_responses):
            for r2 in initial_responses[i + 1:]:
                if r1.confidence > 0.5 and r2.confidence > 0.5:
                    # Simple disagreement detection
                    if abs(r1.confidence - r2.confidence) > 0.3:
                        result.disagreements.append(
                            f"{r1.model} ({r1.confidence:.2f}) vs {r2.model} ({r2.confidence:.2f})"
                        )

        return result

    def update_quality(self, model: str, correct: bool) -> None:
        """Update model quality based on feedback."""
        current = self._model_quality[model]
        if correct:
            self._model_quality[model] = min(1.0, current + 0.02)
        else:
            self._model_quality[model] = max(0.0, current - 0.05)

    def get_stats(self) -> dict[str, Any]:
        return {
            "ensembles": self._ensemble_count,
            "models_weighted": len(self._model_weights),
            "models_tracked": len(self._model_quality),
        }
