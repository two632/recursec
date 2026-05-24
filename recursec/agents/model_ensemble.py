"""Model ensemble — multi-model voting and consensus.

Uses multiple LLMs to produce higher-quality results:
1. Parallel inference across models
2. Majority voting on classifications
3. Best-of-N sampling for reasoning
4. Weighted consensus for decisions
5. Disagreement detection and escalation
6. Ensemble strategies per task type
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class EnsembleStrategy(str, Enum):
    MAJORITY_VOTE = "majority_vote"       # Most common answer wins
    WEIGHTED_VOTE = "weighted_vote"       # Weighted by model quality
    BEST_OF_N = "best_of_n"              # Score all, pick best
    DEBATE = "debate"                     # Models debate, judge decides
    CONSENSUS = "consensus"              # All must agree
    CASCADE = "cascade"                  # Try models in order
    SPECIALIZE = "specialize"            # Route by expertise
    MIXTURE = "mixture"                  # Mixture of experts


class VoteResult(str, Enum):
    UNANIMOUS = "unanimous"
    MAJORITY = "majority"
    SPLIT = "split"
    DISAGREE = "disagree"


@dataclass
class ModelResponse:
    """A response from one model."""
    model: str = ""
    response: str = ""
    confidence: float = 0.0
    tokens_used: int = 0
    latency_ms: float = 0.0
    quality_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model[:12],
            "conf": f"{self.confidence:.2f}",
            "tokens": self.tokens_used,
            "quality": f"{self.quality_score:.2f}",
        }


@dataclass
class EnsembleResult:
    """Result of an ensemble query."""
    ensemble_id: str = ""
    strategy: EnsembleStrategy = EnsembleStrategy.MAJORITY_VOTE
    responses: list[ModelResponse] = field(default_factory=list)
    final_response: str = ""
    final_confidence: float = 0.0
    vote_result: VoteResult = VoteResult.UNANIMOUS
    agreement_ratio: float = 0.0
    total_tokens: int = 0
    total_latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.ensemble_id[:8],
            "strategy": self.strategy.value[:10],
            "models": len(self.responses),
            "vote": self.vote_result.value[:8],
            "conf": f"{self.final_confidence:.2f}",
            "agree": f"{self.agreement_ratio:.0%}",
        }


# Model weights based on capabilities
MODEL_WEIGHTS: dict[str, dict[str, float]] = {
    "WhiteRabbitNeo-7B": {
        "security": 2.0, "exploit": 2.0, "vuln_analysis": 1.8,
        "general": 0.8, "code": 1.0, "reasoning": 0.9,
    },
    "Qwen2.5-Coder-14B": {
        "code": 2.0, "code_audit": 2.0, "exploit_dev": 1.5,
        "general": 1.2, "security": 1.0, "reasoning": 1.3,
    },
    "Qwen2.5-Coder-7B": {
        "code": 1.6, "code_audit": 1.5, "exploit_dev": 1.2,
        "general": 1.0, "security": 0.8, "reasoning": 1.0,
    },
    "DeepSeek-R1": {
        "reasoning": 2.0, "planning": 2.0, "analysis": 1.8,
        "general": 1.2, "security": 1.0, "code": 1.0,
    },
    "Yi-9B-200K": {
        "long_context": 2.0, "analysis": 1.5, "code_review": 1.5,
        "general": 1.0, "security": 0.8, "reasoning": 1.0,
    },
    "Hermes-4-14B": {
        "instruction": 1.8, "planning": 1.5, "general": 1.5,
        "security": 1.0, "code": 1.0, "reasoning": 1.2,
    },
    "Mistral-7B": {
        "general": 1.5, "instruction": 1.3, "reasoning": 1.2,
        "security": 0.8, "code": 0.8, "fast": 1.5,
    },
    "CodeLlama-13B": {
        "code": 1.5, "code_audit": 1.3, "general": 0.8,
        "security": 0.6, "reasoning": 0.7,
    },
    "CodeLlama-7B": {
        "code": 1.2, "code_audit": 1.0, "general": 0.7,
        "security": 0.5, "reasoning": 0.6,
    },
    "Dolphin-2.9": {
        "uncensored": 2.0, "security": 1.3, "exploit": 1.5,
        "general": 1.2, "code": 0.9, "reasoning": 1.0,
    },
    "Llama-3.1-8B": {
        "general": 1.3, "instruction": 1.2, "reasoning": 1.0,
        "security": 0.7, "code": 0.8,
    },
    "Phi-3.5-mini": {
        "fast": 2.0, "general": 1.0, "reasoning": 0.8,
        "security": 0.5, "code": 0.7,
    },
    "DeepSeek-Math-7B": {
        "math": 2.0, "crypto": 1.8, "reasoning": 1.5,
        "general": 0.7, "security": 0.5,
    },
}

# Task type → ensemble configuration
ENSEMBLE_CONFIGS: dict[str, dict[str, Any]] = {
    "vuln_classification": {
        "strategy": "majority_vote",
        "models": ["WhiteRabbitNeo-7B", "Dolphin-2.9", "Qwen2.5-Coder-14B"],
        "min_agreement": 0.67,
        "weight_key": "security",
    },
    "exploit_validation": {
        "strategy": "consensus",
        "models": ["WhiteRabbitNeo-7B", "Qwen2.5-Coder-14B", "DeepSeek-R1"],
        "min_agreement": 1.0,
        "weight_key": "exploit",
    },
    "code_review": {
        "strategy": "weighted_vote",
        "models": ["Qwen2.5-Coder-14B", "CodeLlama-13B", "Qwen2.5-Coder-7B"],
        "min_agreement": 0.5,
        "weight_key": "code_audit",
    },
    "reasoning": {
        "strategy": "best_of_n",
        "models": ["DeepSeek-R1", "Hermes-4-14B", "Mistral-7B"],
        "min_agreement": 0.5,
        "weight_key": "reasoning",
    },
    "planning": {
        "strategy": "debate",
        "models": ["DeepSeek-R1", "Hermes-4-14B", "WhiteRabbitNeo-7B"],
        "min_agreement": 0.67,
        "weight_key": "planning",
    },
    "fast_triage": {
        "strategy": "cascade",
        "models": ["Phi-3.5-mini", "Mistral-7B", "WhiteRabbitNeo-7B"],
        "min_agreement": 0.0,
        "weight_key": "fast",
    },
    "crypto_analysis": {
        "strategy": "specialize",
        "models": ["DeepSeek-Math-7B", "DeepSeek-R1", "Qwen2.5-Coder-14B"],
        "min_agreement": 0.67,
        "weight_key": "crypto",
    },
    "uncensored_analysis": {
        "strategy": "best_of_n",
        "models": ["Dolphin-2.9", "WhiteRabbitNeo-7B"],
        "min_agreement": 0.5,
        "weight_key": "uncensored",
    },
}


class ModelEnsemble:
    """Multi-model ensemble engine.

    Produces higher-quality outputs by combining
    multiple LLM responses through voting,
    consensus, debate, and selection.
    """

    def __init__(self) -> None:
        self._results: list[EnsembleResult] = []
        self._log = logger.bind(component="ensemble")

    def get_config(self, task_type: str) -> dict[str, Any]:
        """Get ensemble config for a task type."""
        return ENSEMBLE_CONFIGS.get(
            task_type,
            ENSEMBLE_CONFIGS.get("reasoning", {}),
        )

    def get_model_weight(self, model: str, domain: str) -> float:
        """Get model weight for a domain."""
        weights = MODEL_WEIGHTS.get(model, {})
        return weights.get(domain, 0.5)

    def select_models(
        self,
        task_type: str,
        count: int = 3,
    ) -> list[str]:
        """Select best models for task type."""
        config = self.get_config(task_type)
        models = config.get("models", [])
        return models[:count]

    def compute_majority_vote(
        self,
        responses: list[ModelResponse],
        weight_key: str = "general",
    ) -> tuple[str, float, VoteResult]:
        """Compute majority vote across responses."""
        if not responses:
            return "", 0.0, VoteResult.DISAGREE

        # Group by response similarity (simplified)
        votes: dict[str, float] = {}
        for resp in responses:
            key = resp.response[:100]
            weight = self.get_model_weight(resp.model, weight_key)
            votes[key] = votes.get(key, 0.0) + weight

        if not votes:
            return "", 0.0, VoteResult.DISAGREE

        best_key = max(votes, key=votes.get)  # type: ignore[arg-type]
        total_weight = sum(votes.values())
        agreement = votes[best_key] / total_weight if total_weight else 0

        # Find full response for winning key
        winner = ""
        for resp in responses:
            if resp.response[:100] == best_key:
                winner = resp.response
                break

        vote_result = VoteResult.DISAGREE
        if agreement >= 1.0:
            vote_result = VoteResult.UNANIMOUS
        elif agreement >= 0.67:
            vote_result = VoteResult.MAJORITY
        elif agreement >= 0.5:
            vote_result = VoteResult.SPLIT

        return winner, agreement, vote_result

    def compute_best_of_n(
        self,
        responses: list[ModelResponse],
    ) -> tuple[str, float]:
        """Pick the best response by quality score."""
        if not responses:
            return "", 0.0

        best = max(responses, key=lambda r: r.quality_score)
        return best.response, best.quality_score

    def compute_cascade(
        self,
        responses: list[ModelResponse],
        min_confidence: float = 0.7,
    ) -> tuple[str, float]:
        """Try models in order, return first confident one."""
        for resp in responses:
            if resp.confidence >= min_confidence:
                return resp.response, resp.confidence

        # Fallback to last model
        if responses:
            return responses[-1].response, responses[-1].confidence
        return "", 0.0

    def run_ensemble(
        self,
        task_type: str,
        responses: list[ModelResponse],
    ) -> EnsembleResult:
        """Run ensemble on model responses."""
        config = self.get_config(task_type)
        strategy = EnsembleStrategy(
            config.get("strategy", "majority_vote"),
        )
        weight_key = config.get("weight_key", "general")

        result = EnsembleResult(
            ensemble_id=f"ens-{len(self._results) + 1}",
            strategy=strategy,
            responses=responses,
            total_tokens=sum(r.tokens_used for r in responses),
            total_latency_ms=max(
                (r.latency_ms for r in responses), default=0,
            ),
        )

        if strategy == EnsembleStrategy.MAJORITY_VOTE:
            text, agreement, vote = self.compute_majority_vote(
                responses, weight_key,
            )
            result.final_response = text
            result.agreement_ratio = agreement
            result.vote_result = vote
            result.final_confidence = agreement

        elif strategy == EnsembleStrategy.WEIGHTED_VOTE:
            text, agreement, vote = self.compute_majority_vote(
                responses, weight_key,
            )
            result.final_response = text
            result.agreement_ratio = agreement
            result.vote_result = vote
            result.final_confidence = agreement

        elif strategy == EnsembleStrategy.BEST_OF_N:
            text, score = self.compute_best_of_n(responses)
            result.final_response = text
            result.final_confidence = score
            result.vote_result = VoteResult.MAJORITY

        elif strategy == EnsembleStrategy.CASCADE:
            text, conf = self.compute_cascade(responses)
            result.final_response = text
            result.final_confidence = conf
            result.vote_result = VoteResult.MAJORITY

        elif strategy == EnsembleStrategy.CONSENSUS:
            text, agreement, vote = self.compute_majority_vote(
                responses, weight_key,
            )
            result.final_response = text
            result.agreement_ratio = agreement
            result.vote_result = vote
            result.final_confidence = agreement

        else:
            if responses:
                result.final_response = responses[0].response
                result.final_confidence = responses[0].confidence

        self._results.append(result)
        return result

    def build_ensemble_prompt(self) -> str:
        """Build ensemble state for LLM."""
        lines = ["## Ensemble\n"]
        lines.append(f"Runs: {len(self._results)}")
        lines.append(f"Configs: {len(ENSEMBLE_CONFIGS)}")
        lines.append(f"Models: {len(MODEL_WEIGHTS)}")

        if self._results:
            last = self._results[-1]
            lines.append(f"\nLast: {last.strategy.value}")
            lines.append(f"  Vote: {last.vote_result.value}")
            lines.append(f"  Agreement: {last.agreement_ratio:.0%}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        strategy_counts: dict[str, int] = {}
        for r in self._results:
            strategy_counts[r.strategy.value] = (
                strategy_counts.get(r.strategy.value, 0) + 1
            )

        avg_agreement = 0.0
        if self._results:
            avg_agreement = (
                sum(r.agreement_ratio for r in self._results)
                / len(self._results)
            )

        return {
            "total_runs": len(self._results),
            "by_strategy": strategy_counts,
            "avg_agreement": f"{avg_agreement:.0%}",
        }
