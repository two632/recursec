"""Model ensemble — combines reasoning from multiple LLMs for better decisions.

Implements:
1. Multi-model query with result aggregation
2. Voting-based consensus (majority, weighted, unanimous)
3. Confidence-weighted merging
4. Model disagreement detection and resolution
5. Diversity-based model selection
6. Ensemble-specific prompt formatting
7. Cost-aware model allocation
8. Cascading inference (fast model first, escalate if uncertain)
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ConsensusMethod(str, Enum):
    MAJORITY_VOTE = "majority_vote"
    WEIGHTED_VOTE = "weighted_vote"
    UNANIMOUS = "unanimous"
    BEST_CONFIDENCE = "best_confidence"
    MERGE_ALL = "merge_all"


class ModelTier(str, Enum):
    FAST = "fast"          # Phi-3.5, FunctionGemma — quick screening
    STANDARD = "standard"  # Mistral, Llama-3.1, Dolphin — general tasks
    SPECIALIST = "specialist"  # WhiteRabbitNeo, CodeLlama — domain-specific
    REASONING = "reasoning"    # DeepSeek-R1, Hermes — deep analysis
    LONG_CONTEXT = "long_context"  # Yi-9B-200K — large inputs


@dataclass
class ModelResponse:
    """Response from a single model in the ensemble."""
    response_id: str = ""
    model_id: str = ""
    model_tier: ModelTier = ModelTier.STANDARD
    content: str = ""
    confidence: float = 0.5
    tokens_used: int = 0
    latency_ms: int = 0
    parsed_findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.response_id,
            "model": self.model_id[:20],
            "tier": self.model_tier.value,
            "confidence": round(self.confidence, 2),
            "tokens": self.tokens_used,
            "latency_ms": self.latency_ms,
            "findings": len(self.parsed_findings),
        }


@dataclass
class EnsembleResult:
    """Combined result from multiple models."""
    result_id: str = ""
    query: str = ""
    consensus_method: ConsensusMethod = ConsensusMethod.MAJORITY_VOTE
    responses: list[ModelResponse] = field(default_factory=list)
    consensus_content: str = ""
    consensus_confidence: float = 0.0
    merged_findings: list[dict[str, Any]] = field(default_factory=list)
    disagreements: list[dict[str, Any]] = field(default_factory=list)
    total_tokens: int = 0
    total_latency_ms: int = 0

    @property
    def agreement_ratio(self) -> float:
        if len(self.responses) <= 1:
            return 1.0
        if not self.merged_findings:
            return 0.0
        # Agreement = 1 - (disagreements / total findings)
        total = len(self.merged_findings) + len(self.disagreements)
        if total == 0:
            return 1.0
        return len(self.merged_findings) / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.result_id,
            "method": self.consensus_method.value,
            "models": len(self.responses),
            "confidence": round(self.consensus_confidence, 2),
            "findings": len(self.merged_findings),
            "disagreements": len(self.disagreements),
            "agreement": round(self.agreement_ratio, 2),
            "tokens": self.total_tokens,
        }


# ── Model Profiles ────────────────────────────────────────────

MODEL_PROFILES: dict[str, dict[str, Any]] = {
    "whiterabbitneo-7b": {
        "tier": "specialist", "weight": 2.0,
        "strengths": ["security", "exploitation", "vuln_analysis"],
        "cost_factor": 1.0, "context_length": 8192,
    },
    "qwen2.5-coder-14b": {
        "tier": "specialist", "weight": 1.8,
        "strengths": ["code_analysis", "code_audit", "exploit_dev"],
        "cost_factor": 1.5, "context_length": 32768,
    },
    "qwen2.5-coder-7b": {
        "tier": "standard", "weight": 1.2,
        "strengths": ["code_analysis", "quick_code_review"],
        "cost_factor": 0.8, "context_length": 32768,
    },
    "deepseek-r1-7b": {
        "tier": "reasoning", "weight": 1.7,
        "strengths": ["reasoning", "planning", "chain_of_thought"],
        "cost_factor": 1.0, "context_length": 32768,
    },
    "deepseek-math-7b": {
        "tier": "specialist", "weight": 1.3,
        "strengths": ["crypto", "math", "formal_analysis"],
        "cost_factor": 1.0, "context_length": 4096,
    },
    "hermes-4-14b": {
        "tier": "reasoning", "weight": 1.6,
        "strengths": ["general_reasoning", "planning", "coordination"],
        "cost_factor": 1.5, "context_length": 16384,
    },
    "llama-3.1-8b": {
        "tier": "standard", "weight": 1.0,
        "strengths": ["general", "instruction_following"],
        "cost_factor": 0.8, "context_length": 8192,
    },
    "dolphin-2.9": {
        "tier": "standard", "weight": 1.1,
        "strengths": ["uncensored", "security", "general"],
        "cost_factor": 0.8, "context_length": 8192,
    },
    "mistral-7b": {
        "tier": "standard", "weight": 1.0,
        "strengths": ["general", "fast", "instruction_following"],
        "cost_factor": 0.7, "context_length": 8192,
    },
    "codellama-13b": {
        "tier": "specialist", "weight": 1.4,
        "strengths": ["code_analysis", "code_generation"],
        "cost_factor": 1.3, "context_length": 16384,
    },
    "codellama-7b": {
        "tier": "standard", "weight": 1.0,
        "strengths": ["code_analysis", "quick_code_review"],
        "cost_factor": 0.7, "context_length": 16384,
    },
    "yi-9b-200k": {
        "tier": "long_context", "weight": 1.5,
        "strengths": ["long_context", "large_code_analysis", "report_synthesis"],
        "cost_factor": 1.2, "context_length": 200000,
    },
    "phi-3.5-mini": {
        "tier": "fast", "weight": 0.7,
        "strengths": ["fast_screening", "simple_tasks"],
        "cost_factor": 0.3, "context_length": 4096,
    },
}


class ModelEnsemble:
    """Combines reasoning from multiple LLMs for better decisions.

    Queries multiple models, aggregates their responses via
    voting or confidence-weighting, and detects disagreements
    that may indicate uncertainty.
    """

    def __init__(self) -> None:
        self._results: list[EnsembleResult] = []
        self._result_counter = 0
        self._response_counter = 0
        self._model_performance: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"queries": 0, "avg_confidence": 0.0, "avg_latency": 0.0}
        )
        self._log = logger.bind(component="model_ensemble")

    def select_models(
        self,
        task_type: str,
        num_models: int = 3,
        budget_tokens: int = 0,
    ) -> list[str]:
        """Select the best models for a task type."""
        scored: list[tuple[float, str]] = []

        for model_id, profile in MODEL_PROFILES.items():
            strength_match = 1.0
            if task_type in profile["strengths"]:
                strength_match = 2.0
            elif any(s in task_type for s in profile["strengths"]):
                strength_match = 1.5

            score = profile["weight"] * strength_match

            # Budget-aware: prefer cheaper models if budget is tight
            if budget_tokens > 0:
                cost = profile["cost_factor"]
                score /= max(0.1, cost)

            scored.append((score, model_id))

        scored.sort(key=lambda x: x[0], reverse=True)

        # Ensure diversity: pick from different tiers
        selected = []
        tiers_used: set[str] = set()

        for score, model_id in scored:
            tier = MODEL_PROFILES[model_id]["tier"]
            if len(selected) < num_models:
                if tier not in tiers_used or len(selected) >= num_models - 1:
                    selected.append(model_id)
                    tiers_used.add(tier)

        return selected[:num_models]

    def add_response(
        self,
        model_id: str,
        content: str,
        confidence: float = 0.5,
        tokens_used: int = 0,
        latency_ms: int = 0,
        parsed_findings: list[dict[str, Any]] | None = None,
    ) -> ModelResponse:
        """Add a response from a model."""
        self._response_counter += 1
        profile = MODEL_PROFILES.get(model_id, {})

        response = ModelResponse(
            response_id=f"mr-{self._response_counter}",
            model_id=model_id,
            model_tier=ModelTier(profile.get("tier", "standard")),
            content=content,
            confidence=confidence,
            tokens_used=tokens_used,
            latency_ms=latency_ms,
            parsed_findings=parsed_findings or [],
        )

        # Update model performance tracking
        perf = self._model_performance[model_id]
        old_count = perf["queries"]
        perf["queries"] = old_count + 1
        perf["avg_confidence"] = (
            (perf["avg_confidence"] * old_count + confidence) / (old_count + 1)
        )
        perf["avg_latency"] = (
            (perf["avg_latency"] * old_count + latency_ms) / (old_count + 1)
        )

        return response

    def build_consensus(
        self,
        query: str,
        responses: list[ModelResponse],
        method: ConsensusMethod = ConsensusMethod.WEIGHTED_VOTE,
    ) -> EnsembleResult:
        """Build consensus from multiple model responses."""
        self._result_counter += 1

        result = EnsembleResult(
            result_id=f"er-{self._result_counter}",
            query=query[:100],
            consensus_method=method,
            responses=responses,
            total_tokens=sum(r.tokens_used for r in responses),
            total_latency_ms=sum(r.latency_ms for r in responses),
        )

        if method == ConsensusMethod.MAJORITY_VOTE:
            self._majority_vote(result)
        elif method == ConsensusMethod.WEIGHTED_VOTE:
            self._weighted_vote(result)
        elif method == ConsensusMethod.BEST_CONFIDENCE:
            self._best_confidence(result)
        elif method == ConsensusMethod.MERGE_ALL:
            self._merge_all(result)
        elif method == ConsensusMethod.UNANIMOUS:
            self._unanimous(result)

        self._results.append(result)
        return result

    def cascade_inference(
        self,
        responses_by_tier: dict[str, ModelResponse],
        confidence_threshold: float = 0.8,
    ) -> ModelResponse:
        """Cascading inference: use fast model, escalate if uncertain."""
        tier_order = [
            ModelTier.FAST,
            ModelTier.STANDARD,
            ModelTier.SPECIALIST,
            ModelTier.REASONING,
        ]

        for tier in tier_order:
            response = responses_by_tier.get(tier.value)
            if response and response.confidence >= confidence_threshold:
                return response

        # Return the highest-confidence response if none met threshold
        all_responses = list(responses_by_tier.values())
        if all_responses:
            return max(all_responses, key=lambda r: r.confidence)

        # Fallback
        return ModelResponse()

    def _majority_vote(self, result: EnsembleResult) -> None:
        """Simple majority vote on findings."""
        all_findings: list[dict[str, Any]] = []
        for response in result.responses:
            all_findings.extend(response.parsed_findings)

        # Group similar findings by title
        title_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for finding in all_findings:
            title = finding.get("title", "unknown")
            title_groups[title].append(finding)

        threshold = len(result.responses) / 2

        for title, findings in title_groups.items():
            if len(findings) >= threshold:
                result.merged_findings.append(findings[0])
            else:
                result.disagreements.append({
                    "title": title,
                    "agreed_by": len(findings),
                    "total_models": len(result.responses),
                })

        result.consensus_confidence = result.agreement_ratio

    def _weighted_vote(self, result: EnsembleResult) -> None:
        """Weighted vote based on model weights and confidence."""
        finding_scores: dict[str, float] = defaultdict(float)
        finding_data: dict[str, dict[str, Any]] = {}

        for response in result.responses:
            profile = MODEL_PROFILES.get(response.model_id, {})
            model_weight = profile.get("weight", 1.0)

            for finding in response.parsed_findings:
                title = finding.get("title", "unknown")
                score = model_weight * response.confidence
                finding_scores[title] += score
                if title not in finding_data:
                    finding_data[title] = finding

        # Normalize scores
        max_possible = sum(
            MODEL_PROFILES.get(r.model_id, {}).get("weight", 1.0) * r.confidence
            for r in result.responses
        )

        for title, score in finding_scores.items():
            normalized = score / max(0.001, max_possible)
            if normalized >= 0.3:
                data = finding_data[title]
                data["ensemble_score"] = round(normalized, 2)
                result.merged_findings.append(data)
            else:
                result.disagreements.append({
                    "title": title,
                    "score": round(normalized, 2),
                })

        if finding_scores:
            result.consensus_confidence = (
                sum(finding_scores.values()) / max(1, len(finding_scores)) /
                max(0.001, max_possible)
            )

    def _best_confidence(self, result: EnsembleResult) -> None:
        """Use findings from the most confident model."""
        if not result.responses:
            return

        best = max(result.responses, key=lambda r: r.confidence)
        result.merged_findings = list(best.parsed_findings)
        result.consensus_confidence = best.confidence
        result.consensus_content = best.content

    def _merge_all(self, result: EnsembleResult) -> None:
        """Merge all findings (union)."""
        seen_titles: set[str] = set()

        for response in result.responses:
            for finding in response.parsed_findings:
                title = finding.get("title", "unknown")
                if title not in seen_titles:
                    result.merged_findings.append(finding)
                    seen_titles.add(title)

        if result.responses:
            result.consensus_confidence = (
                sum(r.confidence for r in result.responses) /
                len(result.responses)
            )

    def _unanimous(self, result: EnsembleResult) -> None:
        """Only include findings all models agree on."""
        if not result.responses:
            return

        # Count occurrences of each finding title
        title_counts: Counter[str] = Counter()
        finding_data: dict[str, dict[str, Any]] = {}

        for response in result.responses:
            for finding in response.parsed_findings:
                title = finding.get("title", "unknown")
                title_counts[title] += 1
                if title not in finding_data:
                    finding_data[title] = finding

        num_models = len(result.responses)

        for title, count in title_counts.items():
            if count == num_models:
                result.merged_findings.append(finding_data[title])
            else:
                result.disagreements.append({
                    "title": title,
                    "agreed_by": count,
                    "total_models": num_models,
                })

        result.consensus_confidence = (
            len(result.merged_findings) /
            max(1, len(result.merged_findings) + len(result.disagreements))
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "ensemble_queries": len(self._results),
            "model_stats": {
                mid: {
                    "queries": perf["queries"],
                    "avg_confidence": round(perf["avg_confidence"], 2),
                    "avg_latency_ms": round(perf["avg_latency"]),
                }
                for mid, perf in self._model_performance.items()
                if perf["queries"] > 0
            },
        }
