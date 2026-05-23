"""Model router intelligence — task-aware LLM routing.

Routes queries to the optimal model based on:
1. Task type classification
2. Model capability matching
3. Context window requirements
4. Load balancing
5. Latency requirements
6. Cost optimization
7. Fallback chains
8. Historical performance
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskType(str, Enum):
    SECURITY_ANALYSIS = "security_analysis"
    CODE_REVIEW = "code_review"
    EXPLOITATION = "exploitation"
    REASONING = "reasoning"
    PLANNING = "planning"
    SUMMARIZATION = "summarization"
    TOOL_CALL = "tool_call"
    EMBEDDING = "embedding"
    SAFETY_CHECK = "safety_check"
    LONG_CONTEXT = "long_context"
    FAST_QUERY = "fast_query"
    GENERAL = "general"


class RoutingStrategy(str, Enum):
    BEST_FIT = "best_fit"         # Best model for the task
    ROUND_ROBIN = "round_robin"   # Distribute evenly
    LEAST_LOADED = "least_loaded"  # Route to least busy
    LOWEST_LATENCY = "lowest_latency"
    HIGHEST_QUALITY = "highest_quality"
    FALLBACK = "fallback"         # Try in order until one works


@dataclass
class ModelProfile:
    """Profile of a configured model."""
    model_id: str = ""
    name: str = ""
    port: int = 0
    context_window: int = 4096
    strengths: list[str] = field(default_factory=list)
    weight: float = 1.0
    max_concurrent: int = 4
    current_load: int = 0
    avg_latency_ms: float = 500.0
    error_count: int = 0
    total_requests: int = 0
    total_tokens: int = 0
    available: bool = True

    @property
    def utilization(self) -> float:
        return self.current_load / max(1, self.max_concurrent)

    @property
    def error_rate(self) -> float:
        return self.error_count / max(1, self.total_requests)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.model_id[:15],
            "port": self.port,
            "ctx": self.context_window,
            "weight": self.weight,
            "load": f"{self.current_load}/{self.max_concurrent}",
            "latency": round(self.avg_latency_ms, 0),
            "available": self.available,
        }


@dataclass
class RoutingDecision:
    """A routing decision with reasoning."""
    model_id: str = ""
    strategy: RoutingStrategy = RoutingStrategy.BEST_FIT
    score: float = 0.0
    reason: str = ""
    fallback_models: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "strategy": self.strategy.value,
            "score": round(self.score, 2),
            "reason": self.reason[:30],
            "fallbacks": len(self.fallback_models),
        }


# ── Default model configurations ─────────────────────────────

DEFAULT_MODELS: list[dict[str, Any]] = [
    {
        "id": "whiterabbitneo-7b", "name": "WhiteRabbitNeo-7B",
        "port": 8100, "ctx": 4096, "weight": 2.0, "max_concurrent": 4,
        "strengths": ["security_analysis", "exploitation", "reasoning"],
    },
    {
        "id": "qwen-coder-14b", "name": "Qwen2.5-Coder-14B",
        "port": 8101, "ctx": 8192, "weight": 1.8, "max_concurrent": 2,
        "strengths": ["code_review", "exploitation", "reasoning"],
    },
    {
        "id": "qwen-coder-7b", "name": "Qwen2.5-Coder-7B",
        "port": 8102, "ctx": 8192, "weight": 1.2, "max_concurrent": 4,
        "strengths": ["code_review", "fast_query"],
    },
    {
        "id": "deepseek-r1-7b", "name": "DeepSeek-R1-Distill-Qwen-7B",
        "port": 8103, "ctx": 8192, "weight": 1.6, "max_concurrent": 4,
        "strengths": ["reasoning", "planning"],
    },
    {
        "id": "deepseek-math-7b", "name": "DeepSeek-Math-7B",
        "port": 8104, "ctx": 4096, "weight": 1.0, "max_concurrent": 4,
        "strengths": ["reasoning"],
    },
    {
        "id": "hermes-14b", "name": "Hermes-4-14B",
        "port": 8105, "ctx": 8192, "weight": 1.5, "max_concurrent": 2,
        "strengths": ["general", "reasoning", "planning", "summarization"],
    },
    {
        "id": "llama-3.1-8b", "name": "Llama-3.1-8B",
        "port": 8106, "ctx": 131072, "weight": 1.2, "max_concurrent": 4,
        "strengths": ["general", "long_context", "summarization"],
    },
    {
        "id": "dolphin-8b", "name": "Dolphin-2.9-Llama3-8B",
        "port": 8107, "ctx": 8192, "weight": 1.2, "max_concurrent": 4,
        "strengths": ["general", "security_analysis", "exploitation"],
    },
    {
        "id": "mistral-7b", "name": "Mistral-7B",
        "port": 8108, "ctx": 8192, "weight": 1.0, "max_concurrent": 8,
        "strengths": ["fast_query", "general", "summarization"],
    },
    {
        "id": "codellama-13b", "name": "CodeLlama-13B",
        "port": 8109, "ctx": 16384, "weight": 1.4, "max_concurrent": 2,
        "strengths": ["code_review", "exploitation"],
    },
    {
        "id": "codellama-7b", "name": "CodeLlama-7B",
        "port": 8110, "ctx": 16384, "weight": 1.0, "max_concurrent": 4,
        "strengths": ["code_review", "fast_query"],
    },
    {
        "id": "yi-9b-200k", "name": "Yi-9B-200K",
        "port": 8111, "ctx": 200000, "weight": 1.3, "max_concurrent": 2,
        "strengths": ["long_context", "code_review", "summarization"],
    },
    {
        "id": "phi-3.5-mini", "name": "Phi-3.5-mini",
        "port": 8112, "ctx": 4096, "weight": 0.8, "max_concurrent": 16,
        "strengths": ["fast_query", "tool_call"],
    },
    {
        "id": "nomic-embed", "name": "Nomic-Embed-Text",
        "port": 8113, "ctx": 8192, "weight": 1.0, "max_concurrent": 8,
        "strengths": ["embedding"],
    },
    {
        "id": "llama-guard-3", "name": "Llama-Guard-3",
        "port": 8114, "ctx": 4096, "weight": 1.0, "max_concurrent": 8,
        "strengths": ["safety_check"],
    },
    {
        "id": "functiongemma", "name": "FunctionGemma-270m",
        "port": 8115, "ctx": 2048, "weight": 0.5, "max_concurrent": 16,
        "strengths": ["tool_call", "fast_query"],
    },
]


# ── Task→Model preference matrix ─────────────────────────────

TASK_MODEL_PREFERENCES: dict[str, list[str]] = {
    "security_analysis": ["whiterabbitneo-7b", "dolphin-8b", "hermes-14b", "qwen-coder-14b"],
    "code_review": ["qwen-coder-14b", "codellama-13b", "yi-9b-200k", "qwen-coder-7b"],
    "exploitation": ["whiterabbitneo-7b", "dolphin-8b", "qwen-coder-14b"],
    "reasoning": ["deepseek-r1-7b", "hermes-14b", "qwen-coder-14b", "whiterabbitneo-7b"],
    "planning": ["hermes-14b", "deepseek-r1-7b", "llama-3.1-8b"],
    "summarization": ["hermes-14b", "mistral-7b", "llama-3.1-8b"],
    "tool_call": ["functiongemma", "phi-3.5-mini", "mistral-7b"],
    "embedding": ["nomic-embed"],
    "safety_check": ["llama-guard-3"],
    "long_context": ["yi-9b-200k", "llama-3.1-8b"],
    "fast_query": ["phi-3.5-mini", "mistral-7b", "functiongemma", "qwen-coder-7b"],
    "general": ["hermes-14b", "llama-3.1-8b", "mistral-7b", "dolphin-8b"],
}


class ModelRouter:
    """Intelligent model routing for multi-LLM orchestration.

    Routes each query to the optimal model based on task type,
    current load, latency requirements, and historical performance.
    """

    def __init__(self) -> None:
        self._models: dict[str, ModelProfile] = {}
        self._decisions: list[RoutingDecision] = []
        self._log = logger.bind(component="model_router")
        self._load_default_models()

    def _load_default_models(self) -> None:
        """Load default model configurations."""
        for data in DEFAULT_MODELS:
            profile = ModelProfile(
                model_id=data["id"],
                name=data["name"],
                port=data["port"],
                context_window=data["ctx"],
                weight=data["weight"],
                max_concurrent=data["max_concurrent"],
                strengths=data.get("strengths", []),
            )
            self._models[profile.model_id] = profile

    def route(
        self,
        task_type: TaskType,
        context_tokens: int = 0,
        strategy: RoutingStrategy = RoutingStrategy.BEST_FIT,
        exclude_models: list[str] | None = None,
    ) -> RoutingDecision:
        """Route a task to the best model."""
        exclude = set(exclude_models or [])

        candidates = [
            m for m in self._models.values()
            if m.available and m.model_id not in exclude
        ]

        if not candidates:
            return RoutingDecision(
                model_id="",
                reason="No available models",
            )

        # Filter by context window
        if context_tokens > 0:
            candidates = [m for m in candidates if m.context_window >= context_tokens]
            if not candidates:
                return RoutingDecision(
                    model_id="",
                    reason=f"No model with context >= {context_tokens}",
                )

        if strategy == RoutingStrategy.BEST_FIT:
            decision = self._route_best_fit(candidates, task_type)
        elif strategy == RoutingStrategy.ROUND_ROBIN:
            decision = self._route_round_robin(candidates, task_type)
        elif strategy == RoutingStrategy.LEAST_LOADED:
            decision = self._route_least_loaded(candidates, task_type)
        elif strategy == RoutingStrategy.LOWEST_LATENCY:
            decision = self._route_lowest_latency(candidates, task_type)
        elif strategy == RoutingStrategy.HIGHEST_QUALITY:
            decision = self._route_highest_quality(candidates, task_type)
        else:
            decision = self._route_best_fit(candidates, task_type)

        # Add fallbacks
        fallback_ids = [
            m.model_id for m in candidates
            if m.model_id != decision.model_id
        ][:3]
        decision.fallback_models = fallback_ids

        self._decisions.append(decision)
        return decision

    def _route_best_fit(
        self,
        candidates: list[ModelProfile],
        task_type: TaskType,
    ) -> RoutingDecision:
        """Route to the best model for the task type."""
        preferences = TASK_MODEL_PREFERENCES.get(task_type.value, [])

        best = None
        best_score = -1.0

        for model in candidates:
            score = model.weight

            # Preference bonus
            if model.model_id in preferences:
                rank = preferences.index(model.model_id)
                score += (len(preferences) - rank) * 0.5

            # Strength match bonus
            if task_type.value in model.strengths:
                score += 1.0

            # Load penalty
            score -= model.utilization * 0.5

            # Error penalty
            score -= model.error_rate * 2.0

            if score > best_score:
                best_score = score
                best = model

        if best:
            return RoutingDecision(
                model_id=best.model_id,
                strategy=RoutingStrategy.BEST_FIT,
                score=best_score,
                reason=f"Best fit for {task_type.value}",
            )

        return RoutingDecision(reason="No suitable model found")

    def _route_round_robin(
        self,
        candidates: list[ModelProfile],
        task_type: TaskType,
    ) -> RoutingDecision:
        """Route round-robin among candidates."""
        # Pick the model with fewest total requests
        best = min(candidates, key=lambda m: m.total_requests)
        return RoutingDecision(
            model_id=best.model_id,
            strategy=RoutingStrategy.ROUND_ROBIN,
            score=1.0,
            reason="Round-robin selection",
        )

    def _route_least_loaded(
        self,
        candidates: list[ModelProfile],
        task_type: TaskType,
    ) -> RoutingDecision:
        """Route to the least loaded model."""
        best = min(candidates, key=lambda m: m.utilization)
        return RoutingDecision(
            model_id=best.model_id,
            strategy=RoutingStrategy.LEAST_LOADED,
            score=1.0 - best.utilization,
            reason=f"Least loaded ({best.utilization:.0%})",
        )

    def _route_lowest_latency(
        self,
        candidates: list[ModelProfile],
        task_type: TaskType,
    ) -> RoutingDecision:
        """Route to the lowest latency model."""
        best = min(candidates, key=lambda m: m.avg_latency_ms)
        return RoutingDecision(
            model_id=best.model_id,
            strategy=RoutingStrategy.LOWEST_LATENCY,
            score=1000.0 / max(1, best.avg_latency_ms),
            reason=f"Lowest latency ({best.avg_latency_ms:.0f}ms)",
        )

    def _route_highest_quality(
        self,
        candidates: list[ModelProfile],
        task_type: TaskType,
    ) -> RoutingDecision:
        """Route to the highest quality model."""
        best = max(candidates, key=lambda m: m.weight)
        return RoutingDecision(
            model_id=best.model_id,
            strategy=RoutingStrategy.HIGHEST_QUALITY,
            score=best.weight,
            reason=f"Highest quality (weight {best.weight})",
        )

    def acquire(self, model_id: str) -> bool:
        """Acquire a model slot (increment load)."""
        model = self._models.get(model_id)
        if not model or not model.available:
            return False
        if model.current_load >= model.max_concurrent:
            return False
        model.current_load += 1
        return True

    def release(
        self,
        model_id: str,
        latency_ms: float = 0.0,
        tokens: int = 0,
        success: bool = True,
    ) -> None:
        """Release a model slot (decrement load)."""
        model = self._models.get(model_id)
        if not model:
            return
        model.current_load = max(0, model.current_load - 1)
        model.total_requests += 1
        model.total_tokens += tokens

        # EMA update for latency
        if latency_ms > 0:
            model.avg_latency_ms = 0.9 * model.avg_latency_ms + 0.1 * latency_ms

        if not success:
            model.error_count += 1

    def mark_unavailable(self, model_id: str) -> None:
        """Mark a model as unavailable."""
        if model_id in self._models:
            self._models[model_id].available = False

    def mark_available(self, model_id: str) -> None:
        """Mark a model as available."""
        if model_id in self._models:
            self._models[model_id].available = True

    def get_model(self, model_id: str) -> ModelProfile | None:
        """Get a model profile."""
        return self._models.get(model_id)

    def get_stats(self) -> dict[str, Any]:
        available = sum(1 for m in self._models.values() if m.available)
        total_load = sum(m.current_load for m in self._models.values())
        total_capacity = sum(m.max_concurrent for m in self._models.values())

        return {
            "models": len(self._models),
            "available": available,
            "total_load": total_load,
            "total_capacity": total_capacity,
            "utilization": round(total_load / max(1, total_capacity), 2),
            "decisions": len(self._decisions),
            "model_details": {k: v.to_dict() for k, v in self._models.items()},
        }
