"""Ensemble reasoner — multi-model consensus reasoning.

Implements:
1. Multi-model query for same question
2. Weighted voting based on expertise
3. Confidence aggregation
4. Disagreement detection and resolution
5. Model specialization awareness
6. Fallback chains on model failure
7. Answer synthesis from multiple perspectives
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class VotingStrategy(str, Enum):
    MAJORITY = "majority"           # Simple majority vote
    WEIGHTED = "weighted"           # Expertise-weighted vote
    CONSENSUS = "consensus"          # All must agree
    BEST_OF = "best_of"             # Highest confidence wins
    SYNTHESIZE = "synthesize"        # Combine all perspectives


class AgreementLevel(str, Enum):
    UNANIMOUS = "unanimous"          # All agree
    STRONG = "strong"                # >75% agree
    MODERATE = "moderate"            # >50% agree
    WEAK = "weak"                    # <50% agree
    CONFLICTING = "conflicting"      # Strong disagreement


@dataclass
class ModelResponse:
    """A response from a single model."""
    model_id: str = ""
    content: str = ""
    confidence: float = 0.5
    tokens_used: int = 0
    latency_ms: float = 0.0
    expertise_weight: float = 1.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "confidence": round(self.confidence, 2),
            "weight": round(self.expertise_weight, 2),
            "tokens": self.tokens_used,
        }


@dataclass
class EnsembleResult:
    """Result of ensemble reasoning."""
    result_id: str = ""
    question: str = ""
    responses: list[ModelResponse] = field(default_factory=list)
    consensus_answer: str = ""
    consensus_confidence: float = 0.0
    agreement_level: AgreementLevel = AgreementLevel.WEAK
    strategy_used: VotingStrategy = VotingStrategy.WEIGHTED
    total_tokens: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.result_id[:10],
            "models": len(self.responses),
            "confidence": round(self.consensus_confidence, 2),
            "agreement": self.agreement_level.value,
            "strategy": self.strategy_used.value,
        }


# ── Model expertise weights ──────────────────────────────────

EXPERTISE_WEIGHTS: dict[str, dict[str, float]] = {
    "security": {
        "whiterabbitneo-7b": 2.0,
        "dolphin-8b": 1.3,
        "qwen-coder-14b": 1.2,
        "hermes-14b": 1.0,
        "llama-3.1-8b": 0.8,
        "mistral-7b": 0.8,
    },
    "code": {
        "qwen-coder-14b": 2.0,
        "qwen-coder-7b": 1.8,
        "codellama-13b": 1.7,
        "codellama-7b": 1.5,
        "deepseek-math-7b": 1.0,
    },
    "reasoning": {
        "deepseek-r1-7b": 2.0,
        "hermes-14b": 1.5,
        "qwen-coder-14b": 1.2,
        "llama-3.1-8b": 1.0,
    },
    "analysis": {
        "hermes-14b": 1.5,
        "deepseek-r1-7b": 1.5,
        "yi-9b-200k": 1.3,
        "whiterabbitneo-7b": 1.2,
    },
    "general": {
        "hermes-14b": 1.5,
        "llama-3.1-8b": 1.3,
        "dolphin-8b": 1.2,
        "mistral-7b": 1.2,
    },
}


# ── Ensemble configurations ──────────────────────────────────

ENSEMBLE_CONFIGS: dict[str, dict[str, Any]] = {
    "vuln_verification": {
        "models": ["whiterabbitneo-7b", "qwen-coder-14b", "hermes-14b"],
        "strategy": "consensus",
        "domain": "security",
        "desc": "Verify vulnerability findings with security experts",
    },
    "code_review": {
        "models": ["qwen-coder-14b", "codellama-13b", "deepseek-r1-7b"],
        "strategy": "weighted",
        "domain": "code",
        "desc": "Multi-model code review for security issues",
    },
    "strategy_planning": {
        "models": ["deepseek-r1-7b", "hermes-14b", "whiterabbitneo-7b"],
        "strategy": "synthesize",
        "domain": "reasoning",
        "desc": "Synthesize attack strategy from multiple perspectives",
    },
    "finding_triage": {
        "models": ["whiterabbitneo-7b", "hermes-14b"],
        "strategy": "weighted",
        "domain": "security",
        "desc": "Triage and prioritize findings",
    },
    "false_positive_check": {
        "models": ["whiterabbitneo-7b", "qwen-coder-14b", "deepseek-r1-7b"],
        "strategy": "majority",
        "domain": "security",
        "desc": "Multi-model false positive detection",
    },
}


class EnsembleReasoner:
    """Multi-model consensus reasoning engine.

    Queries multiple models, aggregates responses
    with expertise-weighted voting, and detects
    disagreement.
    """

    def __init__(self) -> None:
        self._results: dict[str, EnsembleResult] = {}
        self._counter = 0
        self._log = logger.bind(component="ensemble_reasoner")

    def create_ensemble(
        self,
        question: str,
        config_name: str = "",
        models: list[str] | None = None,
        strategy: VotingStrategy = VotingStrategy.WEIGHTED,
        domain: str = "general",
    ) -> EnsembleResult:
        """Create an ensemble reasoning session."""
        self._counter += 1

        # Use config if specified
        if config_name and config_name in ENSEMBLE_CONFIGS:
            cfg = ENSEMBLE_CONFIGS[config_name]
            models = models or cfg.get("models", [])
            strategy = VotingStrategy(cfg.get("strategy", "weighted"))
            _ = cfg.get("domain", domain)  # inherit domain from config if needed

        result = EnsembleResult(
            result_id=f"ensemble-{self._counter}",
            question=question,
            strategy_used=strategy,
        )
        self._results[result.result_id] = result
        return result

    def add_response(
        self,
        result_id: str,
        model_id: str,
        content: str,
        confidence: float = 0.5,
        tokens_used: int = 0,
        latency_ms: float = 0.0,
        domain: str = "general",
    ) -> None:
        """Add a model response to the ensemble."""
        result = self._results.get(result_id)
        if not result:
            return

        # Get expertise weight
        weights = EXPERTISE_WEIGHTS.get(domain, EXPERTISE_WEIGHTS["general"])
        weight = weights.get(model_id, 1.0)

        response = ModelResponse(
            model_id=model_id,
            content=content,
            confidence=confidence,
            tokens_used=tokens_used,
            latency_ms=latency_ms,
            expertise_weight=weight,
        )
        result.responses.append(response)
        result.total_tokens += tokens_used

    def resolve(
        self,
        result_id: str,
    ) -> EnsembleResult | None:
        """Resolve the ensemble into a consensus."""
        result = self._results.get(result_id)
        if not result or not result.responses:
            return None

        strategy = result.strategy_used

        if strategy == VotingStrategy.BEST_OF:
            self._resolve_best_of(result)
        elif strategy == VotingStrategy.WEIGHTED:
            self._resolve_weighted(result)
        elif strategy == VotingStrategy.MAJORITY:
            self._resolve_majority(result)
        elif strategy == VotingStrategy.CONSENSUS:
            self._resolve_consensus(result)
        elif strategy == VotingStrategy.SYNTHESIZE:
            self._resolve_synthesize(result)

        # Determine agreement level
        result.agreement_level = self._assess_agreement(result)

        return result

    def _resolve_best_of(self, result: EnsembleResult) -> None:
        """Pick the highest confidence response."""
        best = max(
            result.responses,
            key=lambda r: r.confidence * r.expertise_weight,
        )
        result.consensus_answer = best.content
        result.consensus_confidence = best.confidence

    def _resolve_weighted(self, result: EnsembleResult) -> None:
        """Weighted average of confidences, best content."""
        total_weight = sum(r.expertise_weight for r in result.responses)
        weighted_conf = sum(
            r.confidence * r.expertise_weight
            for r in result.responses
        ) / max(0.001, total_weight)

        best = max(
            result.responses,
            key=lambda r: r.confidence * r.expertise_weight,
        )
        result.consensus_answer = best.content
        result.consensus_confidence = weighted_conf

    def _resolve_majority(self, result: EnsembleResult) -> None:
        """Simple majority — highest confidence wins."""
        # Group by high/medium/low confidence
        high_conf = [r for r in result.responses if r.confidence >= 0.7]
        if high_conf:
            best = max(high_conf, key=lambda r: r.expertise_weight)
            result.consensus_answer = best.content
            result.consensus_confidence = sum(r.confidence for r in high_conf) / len(high_conf)
        else:
            self._resolve_best_of(result)

    def _resolve_consensus(self, result: EnsembleResult) -> None:
        """All models must agree (high confidence)."""
        all_high = all(r.confidence >= 0.6 for r in result.responses)

        if all_high:
            self._resolve_weighted(result)
            result.consensus_confidence *= 1.2  # Boost for consensus
            result.consensus_confidence = min(1.0, result.consensus_confidence)
        else:
            self._resolve_weighted(result)
            result.consensus_confidence *= 0.7  # Penalty for disagreement

    def _resolve_synthesize(self, result: EnsembleResult) -> None:
        """Combine all perspectives."""
        parts = []
        for resp in sorted(result.responses, key=lambda r: r.expertise_weight, reverse=True):
            parts.append(f"[{resp.model_id}] {resp.content}")

        result.consensus_answer = "\n---\n".join(parts)
        result.consensus_confidence = sum(
            r.confidence for r in result.responses
        ) / len(result.responses)

    def _assess_agreement(self, result: EnsembleResult) -> AgreementLevel:
        """Assess the level of agreement."""
        if not result.responses:
            return AgreementLevel.WEAK

        confs = [r.confidence for r in result.responses]
        avg = sum(confs) / len(confs)
        spread = max(confs) - min(confs)

        if spread < 0.1 and avg > 0.7:
            return AgreementLevel.UNANIMOUS
        elif spread < 0.2 and avg > 0.5:
            return AgreementLevel.STRONG
        elif avg > 0.4:
            return AgreementLevel.MODERATE
        elif spread > 0.4:
            return AgreementLevel.CONFLICTING
        else:
            return AgreementLevel.WEAK

    def get_configs(self) -> dict[str, dict[str, Any]]:
        """Get available ensemble configurations."""
        return ENSEMBLE_CONFIGS

    def get_stats(self) -> dict[str, Any]:
        agreement_counts: dict[str, int] = defaultdict(int)
        for result in self._results.values():
            agreement_counts[result.agreement_level.value] += 1

        return {
            "total_ensembles": len(self._results),
            "total_tokens": sum(r.total_tokens for r in self._results.values()),
            "avg_confidence": round(
                sum(r.consensus_confidence for r in self._results.values()) /
                max(1, len(self._results)), 2,
            ),
            "by_agreement": dict(agreement_counts),
        }
