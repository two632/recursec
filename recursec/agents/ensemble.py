"""Model ensemble engine — multi-model reasoning with weighted consensus.

Leverages all 16+ local LLMs simultaneously for:
- Parallel query of multiple models for the same question
- Weighted voting based on model expertise
- Confidence-calibrated merging of responses
- Disagreement detection and resolution
- Specialized routing based on query characteristics
- Ensemble diversity for robust decision-making

Model specializations:
- WhiteRabbitNeo: Security analysis, exploit development
- Qwen-Coder-14B/7B: Code analysis, vulnerability patterns
- DeepSeek-R1: Complex reasoning, chain-of-thought
- DeepSeek-Math: Cryptographic analysis, hash calculations
- Yi-9B-200K: Long context analysis, large code review
- Hermes-4-14B: General analysis, report generation
- Llama-3.1-8B: Fast general queries
- Dolphin-2.9: Uncensored analysis, no safety filters
- Mistral-7B: Fast, balanced general purpose
- Phi-3.5-mini: Ultra-fast classification, routing
- FunctionGemma: Tool call routing, function selection
- Llama-Guard: Safety classification
- Nomic-Embed: Semantic similarity, RAG retrieval
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class AggregationMethod(str, Enum):
    MAJORITY_VOTE = "majority_vote"
    WEIGHTED_AVERAGE = "weighted_average"
    BEST_OF_N = "best_of_n"
    MERGE_SYNTHESIS = "merge_synthesis"
    CONFIDENCE_WEIGHTED = "confidence_weighted"
    HIERARCHICAL = "hierarchical"


class QueryCategory(str, Enum):
    SECURITY_ANALYSIS = "security_analysis"
    CODE_REVIEW = "code_review"
    REASONING = "reasoning"
    TOOL_SELECTION = "tool_selection"
    CLASSIFICATION = "classification"
    LONG_CONTEXT = "long_context"
    EXPLOITATION = "exploitation"
    GENERAL = "general"


@dataclass
class ModelResponse:
    """Response from a single model in the ensemble."""
    model_name: str = ""
    task_type: str = ""
    response: str = ""
    confidence: float = 0.5
    latency_ms: float = 0.0
    tokens_used: int = 0
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EnsembleResult:
    """Aggregated result from the ensemble."""
    query: str = ""
    method: AggregationMethod = AggregationMethod.WEIGHTED_AVERAGE
    final_response: str = ""
    confidence: float = 0.0
    agreement_score: float = 0.0
    individual_responses: list[ModelResponse] = field(default_factory=list)
    dissenting_views: list[str] = field(default_factory=list)
    total_latency_ms: float = 0.0
    total_tokens: int = 0
    models_used: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method.value,
            "confidence": round(self.confidence, 3),
            "agreement": round(self.agreement_score, 3),
            "models_used": self.models_used,
            "latency_ms": round(self.total_latency_ms, 1),
            "tokens": self.total_tokens,
            "dissenting_count": len(self.dissenting_views),
        }


# Model expertise weights (model_type → query_category → weight)
MODEL_EXPERTISE: dict[str, dict[str, float]] = {
    "security": {
        "security_analysis": 2.0, "exploitation": 2.0,
        "code_review": 1.2, "general": 0.8,
    },
    "code": {
        "code_review": 2.0, "security_analysis": 1.3,
        "tool_selection": 1.0, "general": 1.0,
    },
    "reasoning": {
        "reasoning": 2.0, "security_analysis": 1.5,
        "classification": 1.2, "general": 1.3,
    },
    "general": {
        "general": 1.5, "classification": 1.2,
        "security_analysis": 1.0, "code_review": 0.8,
    },
    "long_context": {
        "long_context": 2.0, "code_review": 1.5,
        "general": 1.0,
    },
    "uncensored": {
        "exploitation": 1.8, "security_analysis": 1.5,
        "general": 1.2,
    },
    "fast": {
        "classification": 1.5, "tool_selection": 1.3,
        "general": 1.0,
    },
    "function_call": {
        "tool_selection": 2.0, "classification": 1.5,
        "general": 0.5,
    },
}

# Minimum models needed per aggregation method
MIN_MODELS: dict[AggregationMethod, int] = {
    AggregationMethod.MAJORITY_VOTE: 3,
    AggregationMethod.WEIGHTED_AVERAGE: 2,
    AggregationMethod.BEST_OF_N: 2,
    AggregationMethod.MERGE_SYNTHESIS: 2,
    AggregationMethod.CONFIDENCE_WEIGHTED: 2,
    AggregationMethod.HIERARCHICAL: 2,
}


CONFIDENCE_EXTRACT_PROMPT = """Rate your confidence in the following analysis on a scale of 0.0 to 1.0.

Analysis: {response}

Respond with ONLY a JSON object: {{"confidence": 0.X, "reasoning": "brief explanation"}}"""

SYNTHESIS_PROMPT = """Multiple expert models have analyzed the same security question. Synthesize the best answer.

Question: {question}

Responses:
{responses}

Create a synthesized answer that:
1. Incorporates the strongest arguments from each response
2. Notes any disagreements between models
3. Provides a final confidence score

Respond as JSON:
{{
  "synthesis": "the best combined answer",
  "confidence": 0.X,
  "agreements": ["points all models agree on"],
  "disagreements": ["points where models disagree"],
  "strongest_model": "which model had the best response"
}}"""

JUDGE_PROMPT = """You are judging multiple model responses to a security question.

Question: {question}

{responses}

Rate each response 0.0-1.0 on: accuracy, completeness, specificity, and actionability.
Select the best overall response.

Respond as JSON:
{{
  "rankings": [
    {{"model": "name", "score": 0.X, "strengths": "...", "weaknesses": "..."}}
  ],
  "best": "model_name",
  "reasoning": "why this is best"
}}"""


class ModelEnsemble:
    """Multi-model ensemble for robust security analysis.

    Queries multiple models and aggregates their responses using
    various strategies to produce more reliable results.
    """

    def __init__(self, model_router: ModelRouter) -> None:
        self._router = model_router
        self._stats: dict[str, Any] = defaultdict(int)
        self._model_performance: dict[str, list[float]] = defaultdict(list)

    async def query(
        self,
        question: str,
        category: QueryCategory = QueryCategory.GENERAL,
        method: AggregationMethod = AggregationMethod.WEIGHTED_AVERAGE,
        model_types: list[str] | None = None,
        min_models: int = 2,
        max_models: int = 5,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> EnsembleResult:
        """Query the ensemble and aggregate results."""
        start = time.time()
        self._stats["total_queries"] += 1

        # Select models to use
        selected_types = model_types or self._select_models(category, min_models, max_models)

        # Query all models in parallel
        tasks = []
        for model_type in selected_types:
            tasks.append(self._query_model(
                question, model_type, category.value, temperature, max_tokens,
            ))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter successful responses
        valid_responses: list[ModelResponse] = []
        for resp in responses:
            if isinstance(resp, ModelResponse) and not resp.error:
                valid_responses.append(resp)

        if not valid_responses:
            return EnsembleResult(
                query=question, method=method,
                final_response="No models responded successfully",
                confidence=0.0,
            )

        # Aggregate
        result = await self._aggregate(question, valid_responses, method, category)
        result.total_latency_ms = (time.time() - start) * 1000
        result.total_tokens = sum(r.tokens_used for r in valid_responses)
        result.models_used = [r.model_name for r in valid_responses]

        return result

    async def _query_model(
        self,
        question: str,
        model_type: str,
        task_type: str,
        temperature: float,
        max_tokens: int,
    ) -> ModelResponse:
        """Query a single model."""
        start = time.time()
        try:
            response = await self._router.generate(
                messages=[{"role": "user", "content": question}],
                task_type=model_type,
                temperature=temperature,
                max_tokens=max_tokens,
            )

            latency = (time.time() - start) * 1000

            # Estimate confidence from response
            confidence = self._estimate_confidence(response)

            return ModelResponse(
                model_name=model_type,
                task_type=task_type,
                response=response,
                confidence=confidence,
                latency_ms=latency,
                tokens_used=len(response) // 4,
            )
        except Exception as e:
            return ModelResponse(
                model_name=model_type,
                error=str(e),
                latency_ms=(time.time() - start) * 1000,
            )

    async def _aggregate(
        self,
        question: str,
        responses: list[ModelResponse],
        method: AggregationMethod,
        category: QueryCategory,
    ) -> EnsembleResult:
        """Aggregate multiple model responses."""
        if method == AggregationMethod.BEST_OF_N:
            return await self._best_of_n(question, responses, category)
        if method == AggregationMethod.MERGE_SYNTHESIS:
            return await self._merge_synthesis(question, responses)
        if method == AggregationMethod.CONFIDENCE_WEIGHTED:
            return self._confidence_weighted(question, responses)
        if method == AggregationMethod.HIERARCHICAL:
            return await self._hierarchical(question, responses, category)
        # Default: weighted average by expertise
        return self._weighted_consensus(question, responses, category)

    def _weighted_consensus(
        self,
        question: str,
        responses: list[ModelResponse],
        category: QueryCategory,
    ) -> EnsembleResult:
        """Weight responses by model expertise for the query category."""
        result = EnsembleResult(
            query=question,
            method=AggregationMethod.WEIGHTED_AVERAGE,
            individual_responses=responses,
        )

        # Calculate weights
        weights: list[float] = []
        for resp in responses:
            expertise = MODEL_EXPERTISE.get(resp.model_name, {})
            weight = expertise.get(category.value, 1.0) * resp.confidence
            weights.append(weight)

        total_weight = sum(weights) or 1.0

        # Select response with highest weight
        best_idx = weights.index(max(weights))
        result.final_response = responses[best_idx].response
        result.confidence = sum(
            w * r.confidence for w, r in zip(weights, responses)
        ) / total_weight

        # Calculate agreement
        result.agreement_score = self._calculate_agreement(responses)

        # Identify dissenting views
        if len(responses) >= 3:
            for idx, resp in enumerate(responses):
                if idx != best_idx and weights[idx] / total_weight < 0.15:
                    result.dissenting_views.append(
                        f"{resp.model_name}: {resp.response[:200]}"
                    )

        return result

    def _confidence_weighted(
        self,
        question: str,
        responses: list[ModelResponse],
    ) -> EnsembleResult:
        """Weight purely by self-reported confidence."""
        result = EnsembleResult(
            query=question,
            method=AggregationMethod.CONFIDENCE_WEIGHTED,
            individual_responses=responses,
        )

        best = max(responses, key=lambda r: r.confidence)
        result.final_response = best.response
        result.confidence = best.confidence
        result.agreement_score = self._calculate_agreement(responses)

        return result

    async def _best_of_n(
        self,
        question: str,
        responses: list[ModelResponse],
        category: QueryCategory,
    ) -> EnsembleResult:
        """Use a judge model to select the best response."""
        result = EnsembleResult(
            query=question,
            method=AggregationMethod.BEST_OF_N,
            individual_responses=responses,
        )

        responses_text = "\n\n".join(
            f"Response from {r.model_name} (confidence: {r.confidence:.2f}):\n{r.response[:1000]}"
            for r in responses
        )

        judge_prompt = JUDGE_PROMPT.format(
            question=question[:500],
            responses=responses_text,
        )

        try:
            judge_response = await self._router.generate(
                messages=[{"role": "user", "content": judge_prompt}],
                task_type="reasoning",
                temperature=0.1,
                max_tokens=1024,
            )

            data = self._parse_json(judge_response)
            best_model = data.get("best", "")

            for resp in responses:
                if resp.model_name == best_model:
                    result.final_response = resp.response
                    break

            if not result.final_response:
                result.final_response = responses[0].response

            result.confidence = max(r.confidence for r in responses)
            result.agreement_score = self._calculate_agreement(responses)

        except Exception:
            # Fallback: highest confidence
            best = max(responses, key=lambda r: r.confidence)
            result.final_response = best.response
            result.confidence = best.confidence

        return result

    async def _merge_synthesis(
        self,
        question: str,
        responses: list[ModelResponse],
    ) -> EnsembleResult:
        """Synthesize all responses into a combined answer."""
        result = EnsembleResult(
            query=question,
            method=AggregationMethod.MERGE_SYNTHESIS,
            individual_responses=responses,
        )

        responses_text = "\n\n".join(
            f"Model '{r.model_name}' (confidence {r.confidence:.2f}):\n{r.response[:800]}"
            for r in responses
        )

        prompt = SYNTHESIS_PROMPT.format(
            question=question[:500],
            responses=responses_text,
        )

        try:
            synthesis = await self._router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type="reasoning",
                temperature=0.2,
                max_tokens=4096,
            )

            data = self._parse_json(synthesis)
            result.final_response = data.get("synthesis", synthesis)
            result.confidence = data.get("confidence", 0.5)
            result.dissenting_views = data.get("disagreements", [])
            result.agreement_score = self._calculate_agreement(responses)

        except Exception:
            best = max(responses, key=lambda r: r.confidence)
            result.final_response = best.response
            result.confidence = best.confidence

        return result

    async def _hierarchical(
        self,
        question: str,
        responses: list[ModelResponse],
        category: QueryCategory,
    ) -> EnsembleResult:
        """Hierarchical aggregation: fast models filter, then expert models analyze."""
        result = EnsembleResult(
            query=question,
            method=AggregationMethod.HIERARCHICAL,
            individual_responses=responses,
        )

        # Sort by expertise weight
        expertise_order = sorted(
            responses,
            key=lambda r: MODEL_EXPERTISE.get(r.model_name, {}).get(category.value, 0.0),
            reverse=True,
        )

        # Take the top expert's response as primary
        if expertise_order:
            result.final_response = expertise_order[0].response
            result.confidence = expertise_order[0].confidence

        result.agreement_score = self._calculate_agreement(responses)
        return result

    def _select_models(
        self,
        category: QueryCategory,
        min_models: int,
        max_models: int,
    ) -> list[str]:
        """Select which model types to query based on category."""
        # Rank model types by expertise for this category
        scored: list[tuple[str, float]] = []
        for model_type, expertise in MODEL_EXPERTISE.items():
            score = expertise.get(category.value, 0.5)
            scored.append((model_type, score))

        scored.sort(key=lambda x: -x[1])
        selected = [model_type for model_type, _ in scored[:max_models]]

        # Ensure minimum
        while len(selected) < min_models and len(selected) < len(scored):
            next_type = scored[len(selected)][0]
            if next_type not in selected:
                selected.append(next_type)

        return selected

    def _estimate_confidence(self, response: str) -> float:
        """Estimate confidence from response characteristics."""
        confidence = 0.5

        # Higher confidence for specific, detailed responses
        if len(response) > 500:
            confidence += 0.1
        if any(kw in response.lower() for kw in ["evidence", "confirmed", "verified", "proof"]):
            confidence += 0.15
        if any(kw in response.lower() for kw in ["uncertain", "might", "possibly", "unclear"]):
            confidence -= 0.15
        if any(kw in response.lower() for kw in ["critical", "high severity", "exploitable"]):
            confidence += 0.1

        return max(0.1, min(0.95, confidence))

    def _calculate_agreement(self, responses: list[ModelResponse]) -> float:
        """Calculate agreement score between responses."""
        if len(responses) < 2:
            return 1.0

        # Simple word-overlap based agreement
        word_sets = []
        for resp in responses:
            words = set(resp.response.lower().split())
            word_sets.append(words)

        total_overlap = 0.0
        pairs = 0
        for i in range(len(word_sets)):
            for j in range(i + 1, len(word_sets)):
                intersection = word_sets[i] & word_sets[j]
                union = word_sets[i] | word_sets[j]
                if union:
                    total_overlap += len(intersection) / len(union)
                pairs += 1

        return total_overlap / pairs if pairs > 0 else 0.0

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}

    def get_stats(self) -> dict[str, Any]:
        return dict(self._stats)
