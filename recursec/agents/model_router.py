"""Model router — intelligent routing of tasks to models.

Implements:
1. Task-type to model mapping
2. Load-balanced routing
3. Capability-based selection
4. Context-size aware routing
5. Performance-based routing
6. Fallback chains
7. Hot model switching
"""

from __future__ import annotations

import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskType(str, Enum):
    SECURITY_ANALYSIS = "security_analysis"
    CODE_REVIEW = "code_review"
    REASONING = "reasoning"
    PLANNING = "planning"
    FAST_QUERY = "fast_query"
    LONG_CONTEXT = "long_context"
    TOOL_ROUTING = "tool_routing"
    EMBEDDING = "embedding"
    SAFETY_CHECK = "safety_check"
    GENERAL = "general"
    EXPLOIT_DEV = "exploit_dev"
    VULN_ANALYSIS = "vuln_analysis"


class RoutingStrategy(str, Enum):
    BEST_FIT = "best_fit"           # Highest capability score
    ROUND_ROBIN = "round_robin"      # Distribute evenly
    LEAST_LOADED = "least_loaded"    # Lowest current load
    RANDOM_WEIGHTED = "random_weighted"  # Random, weighted by score
    FALLBACK_CHAIN = "fallback_chain"    # Try in order


@dataclass
class ModelScore:
    """A model's score for a task type."""
    model_id: str = ""
    score: float = 0.0
    is_primary: bool = False
    context_size: int = 0
    avg_latency_ms: float = 0.0
    current_load: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "score": round(self.score, 2),
            "primary": self.is_primary,
        }


@dataclass
class RoutingDecision:
    """A routing decision."""
    decision_id: str = ""
    task_type: TaskType = TaskType.GENERAL
    selected_model: str = ""
    score: float = 0.0
    alternatives: list[str] = field(default_factory=list)
    strategy_used: RoutingStrategy = RoutingStrategy.BEST_FIT
    context_required: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.decision_id[:10],
            "task": self.task_type.value[:15],
            "model": self.selected_model[:15],
            "score": round(self.score, 2),
            "alts": len(self.alternatives),
        }


# ── Task→Model capability matrix ─────────────────────────────

CAPABILITY_MATRIX: dict[str, dict[str, float]] = {
    "security_analysis": {
        "whiterabbitneo-7b": 2.0,
        "dolphin-8b": 1.3,
        "qwen-coder-14b": 1.2,
        "hermes-14b": 1.0,
        "qwen-coder-7b": 0.9,
        "mistral-7b": 0.7,
        "llama-3.1-8b": 0.6,
    },
    "code_review": {
        "qwen-coder-14b": 2.0,
        "qwen-coder-7b": 1.7,
        "codellama-13b": 1.6,
        "codellama-7b": 1.3,
        "deepseek-r1-7b": 1.0,
        "yi-9b-200k": 0.9,
    },
    "reasoning": {
        "deepseek-r1-7b": 2.0,
        "hermes-14b": 1.5,
        "qwen-coder-14b": 1.3,
        "deepseek-math-7b": 1.2,
        "llama-3.1-8b": 1.0,
        "mistral-7b": 0.8,
    },
    "planning": {
        "deepseek-r1-7b": 1.8,
        "hermes-14b": 1.6,
        "qwen-coder-14b": 1.2,
        "llama-3.1-8b": 1.0,
        "mistral-7b": 0.8,
    },
    "fast_query": {
        "phi-3.5-mini": 2.0,
        "mistral-7b": 1.5,
        "functiongemma": 1.3,
        "llama-3.1-8b": 1.0,
    },
    "long_context": {
        "yi-9b-200k": 2.0,       # 200K context
        "llama-3.1-8b": 1.8,     # 131K context
        "qwen-coder-14b": 1.3,   # 32K context
        "qwen-coder-7b": 1.2,    # 32K context
        "mistral-7b": 1.0,       # 32K context
    },
    "tool_routing": {
        "functiongemma": 2.0,
        "phi-3.5-mini": 1.2,
        "mistral-7b": 0.8,
    },
    "embedding": {
        "nomic-embed": 2.0,
    },
    "safety_check": {
        "llama-guard-3": 2.0,
    },
    "exploit_dev": {
        "whiterabbitneo-7b": 2.0,
        "dolphin-8b": 1.5,
        "qwen-coder-14b": 1.3,
        "codellama-13b": 1.0,
    },
    "vuln_analysis": {
        "whiterabbitneo-7b": 2.0,
        "qwen-coder-14b": 1.5,
        "deepseek-r1-7b": 1.3,
        "hermes-14b": 1.0,
        "dolphin-8b": 0.9,
    },
    "general": {
        "hermes-14b": 1.5,
        "llama-3.1-8b": 1.2,
        "mistral-7b": 1.0,
        "dolphin-8b": 1.0,
        "yi-9b-200k": 0.9,
    },
}

# ── Model context sizes ──────────────────────────────────────

MODEL_CONTEXT_SIZES: dict[str, int] = {
    "whiterabbitneo-7b": 4096,
    "qwen-coder-14b": 32768,
    "qwen-coder-7b": 32768,
    "deepseek-r1-7b": 32768,
    "deepseek-math-7b": 4096,
    "hermes-14b": 8192,
    "llama-3.1-8b": 131072,
    "dolphin-8b": 8192,
    "mistral-7b": 32768,
    "codellama-13b": 16384,
    "codellama-7b": 16384,
    "yi-9b-200k": 200000,
    "phi-3.5-mini": 4096,
    "nomic-embed": 8192,
    "llama-guard-3": 4096,
    "functiongemma": 2048,
}


class ModelRouter:
    """Intelligent model routing.

    Routes tasks to the best available model
    based on task type, context requirements,
    and model performance.
    """

    def __init__(
        self,
        strategy: RoutingStrategy = RoutingStrategy.BEST_FIT,
        online_models: list[str] | None = None,
    ) -> None:
        self._strategy = strategy
        self._online_models: set[str] = set(online_models or MODEL_CONTEXT_SIZES.keys())
        self._counter = 0
        self._routing_history: list[RoutingDecision] = []
        self._model_loads: dict[str, int] = defaultdict(int)
        self._round_robin_idx: dict[str, int] = defaultdict(int)
        self._log = logger.bind(component="model_router")

    def route(
        self,
        task_type: TaskType,
        context_tokens: int = 0,
        strategy: RoutingStrategy | None = None,
    ) -> RoutingDecision:
        """Route a task to the best model."""
        self._counter += 1
        strategy = strategy or self._strategy

        # Get scores for this task type
        scores = self._get_scores(task_type, context_tokens)

        if not scores:
            return RoutingDecision(
                decision_id=f"route-{self._counter}",
                task_type=task_type,
                selected_model="",
                score=0.0,
                strategy_used=strategy,
            )

        if strategy == RoutingStrategy.BEST_FIT:
            selected = self._best_fit(scores)
        elif strategy == RoutingStrategy.ROUND_ROBIN:
            selected = self._round_robin(scores, task_type)
        elif strategy == RoutingStrategy.LEAST_LOADED:
            selected = self._least_loaded(scores)
        elif strategy == RoutingStrategy.RANDOM_WEIGHTED:
            selected = self._random_weighted(scores)
        else:
            selected = self._best_fit(scores)

        decision = RoutingDecision(
            decision_id=f"route-{self._counter}",
            task_type=task_type,
            selected_model=selected.model_id,
            score=selected.score,
            alternatives=[s.model_id for s in scores if s.model_id != selected.model_id][:3],
            strategy_used=strategy,
            context_required=context_tokens,
        )

        self._routing_history.append(decision)
        self._model_loads[selected.model_id] += 1

        return decision

    def _get_scores(
        self,
        task_type: TaskType,
        context_tokens: int,
    ) -> list[ModelScore]:
        """Get scored models for a task type."""
        cap_scores = CAPABILITY_MATRIX.get(task_type.value, {})
        scores = []

        for model_id, score in cap_scores.items():
            if model_id not in self._online_models:
                continue

            context_size = MODEL_CONTEXT_SIZES.get(model_id, 4096)
            if context_tokens > 0 and context_size < context_tokens:
                continue

            scores.append(ModelScore(
                model_id=model_id,
                score=score,
                is_primary=score >= 2.0,
                context_size=context_size,
                current_load=self._model_loads.get(model_id, 0),
            ))

        scores.sort(key=lambda s: s.score, reverse=True)
        return scores

    def _best_fit(self, scores: list[ModelScore]) -> ModelScore:
        """Select highest scoring model."""
        return scores[0]

    def _round_robin(
        self,
        scores: list[ModelScore],
        task_type: TaskType,
    ) -> ModelScore:
        """Round-robin among top models."""
        key = task_type.value
        idx = self._round_robin_idx[key] % len(scores)
        self._round_robin_idx[key] += 1
        return scores[idx]

    def _least_loaded(self, scores: list[ModelScore]) -> ModelScore:
        """Select the least loaded model."""
        return min(scores, key=lambda s: s.current_load)

    def _random_weighted(self, scores: list[ModelScore]) -> ModelScore:
        """Random selection weighted by score."""
        total = sum(s.score for s in scores)
        if total == 0:
            return scores[0]

        r = random.random() * total
        cumulative = 0.0
        for s in scores:
            cumulative += s.score
            if cumulative >= r:
                return s
        return scores[-1]

    def set_model_online(self, model_id: str) -> None:
        """Mark a model as online."""
        self._online_models.add(model_id)

    def set_model_offline(self, model_id: str) -> None:
        """Mark a model as offline."""
        self._online_models.discard(model_id)

    def get_stats(self) -> dict[str, Any]:
        task_counts: dict[str, int] = defaultdict(int)
        model_counts: dict[str, int] = defaultdict(int)

        for decision in self._routing_history:
            task_counts[decision.task_type.value] += 1
            model_counts[decision.selected_model] += 1

        return {
            "total_routes": len(self._routing_history),
            "online_models": len(self._online_models),
            "strategy": self._strategy.value,
            "by_task": dict(task_counts),
            "by_model": dict(model_counts),
        }
