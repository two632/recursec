"""Model router — intelligent routing of tasks to optimal LLMs.

Implements:
1. Task-based routing (code→coder, reasoning→reasoner)
2. Load balancing across models
3. Fallback chains (if primary fails, try secondary)
4. Cost-aware routing (use cheaper models when possible)
5. Latency-aware routing (use faster models for time-sensitive tasks)
6. Quality-aware routing (use best models for critical decisions)
7. Capacity tracking per model
8. Dynamic routing table updates based on performance
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


class TaskCategory(str, Enum):
    CODE_ANALYSIS = "code_analysis"
    VULNERABILITY_SCAN = "vulnerability_scan"
    REASONING = "reasoning"
    PLANNING = "planning"
    TOOL_CALLING = "tool_calling"
    LONG_CONTEXT = "long_context"
    SECURITY_ANALYSIS = "security_analysis"
    MATH_CRYPTO = "math_crypto"
    GENERAL = "general"
    EMBEDDING = "embedding"
    SAFETY_CHECK = "safety_check"
    FAST_QUERY = "fast_query"
    UNCENSORED = "uncensored"


class RoutingStrategy(str, Enum):
    BEST_FIT = "best_fit"          # Use the model best suited for the task
    ROUND_ROBIN = "round_robin"     # Distribute evenly
    WEIGHTED = "weighted"           # Route by weight
    LEAST_LOADED = "least_loaded"   # Route to least busy model
    LATENCY_AWARE = "latency_aware"  # Route to fastest available
    CASCADE = "cascade"             # Try best, fallback to next


@dataclass
class ModelSpec:
    """Specification of an available model."""
    model_id: str = ""
    name: str = ""
    port: int = 0
    context_length: int = 4096
    weight: float = 1.0
    strengths: list[TaskCategory] = field(default_factory=list)
    cost_per_token: float = 0.0    # Relative cost
    avg_latency_ms: float = 100.0
    max_concurrent: int = 4
    current_load: int = 0
    total_requests: int = 0
    total_errors: int = 0
    avg_quality: float = 0.7       # Running average of output quality

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_errors / self.total_requests

    @property
    def is_available(self) -> bool:
        return self.current_load < self.max_concurrent

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.model_id,
            "name": self.name[:20],
            "port": self.port,
            "ctx": self.context_length,
            "weight": round(self.weight, 1),
            "load": f"{self.current_load}/{self.max_concurrent}",
            "quality": round(self.avg_quality, 2),
        }


@dataclass
class RoutingDecision:
    """Result of a routing decision."""
    model_id: str = ""
    model_name: str = ""
    port: int = 0
    reason: str = ""
    fallbacks: list[str] = field(default_factory=list)
    estimated_latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_name[:20],
            "port": self.port,
            "reason": self.reason[:30],
            "fallbacks": len(self.fallbacks),
        }


# ── Default Model Routing Table (user's 16 models) ───────────

DEFAULT_MODELS: list[dict[str, Any]] = [
    {
        "id": "whiterabbitneo", "name": "WhiteRabbitNeo-7B", "port": 8100,
        "ctx": 8192, "weight": 2.0,
        "strengths": ["security_analysis", "vulnerability_scan", "uncensored"],
        "cost": 0.3, "latency": 80, "concurrent": 4, "quality": 0.85,
    },
    {
        "id": "qwen-coder-14b", "name": "Qwen2.5-Coder-14B", "port": 8101,
        "ctx": 32768, "weight": 1.8,
        "strengths": ["code_analysis", "security_analysis", "reasoning"],
        "cost": 0.5, "latency": 120, "concurrent": 2, "quality": 0.9,
    },
    {
        "id": "qwen-coder-7b", "name": "Qwen2.5-Coder-7B", "port": 8102,
        "ctx": 32768, "weight": 1.2,
        "strengths": ["code_analysis", "fast_query"],
        "cost": 0.2, "latency": 60, "concurrent": 4, "quality": 0.75,
    },
    {
        "id": "deepseek-r1", "name": "DeepSeek-R1-Distill-Qwen-7B", "port": 8103,
        "ctx": 32768, "weight": 1.7,
        "strengths": ["reasoning", "planning", "math_crypto"],
        "cost": 0.3, "latency": 100, "concurrent": 4, "quality": 0.88,
    },
    {
        "id": "deepseek-math", "name": "DeepSeek-Math-7B", "port": 8104,
        "ctx": 4096, "weight": 1.3,
        "strengths": ["math_crypto", "reasoning"],
        "cost": 0.2, "latency": 70, "concurrent": 4, "quality": 0.82,
    },
    {
        "id": "hermes-14b", "name": "Hermes-4-14B", "port": 8105,
        "ctx": 32768, "weight": 1.6,
        "strengths": ["reasoning", "planning", "general"],
        "cost": 0.4, "latency": 110, "concurrent": 2, "quality": 0.87,
    },
    {
        "id": "llama-3.1-8b", "name": "Llama-3.1-8B", "port": 8106,
        "ctx": 131072, "weight": 1.0,
        "strengths": ["general", "long_context"],
        "cost": 0.3, "latency": 80, "concurrent": 4, "quality": 0.78,
    },
    {
        "id": "dolphin-2.9", "name": "Dolphin-2.9-Llama3-8B", "port": 8107,
        "ctx": 8192, "weight": 1.1,
        "strengths": ["uncensored", "general", "security_analysis"],
        "cost": 0.3, "latency": 80, "concurrent": 4, "quality": 0.76,
    },
    {
        "id": "mistral-7b", "name": "Mistral-7B-Instruct", "port": 8108,
        "ctx": 32768, "weight": 1.0,
        "strengths": ["fast_query", "general"],
        "cost": 0.2, "latency": 50, "concurrent": 8, "quality": 0.75,
    },
    {
        "id": "codellama-13b", "name": "CodeLlama-13B", "port": 8109,
        "ctx": 16384, "weight": 1.4,
        "strengths": ["code_analysis", "security_analysis"],
        "cost": 0.4, "latency": 100, "concurrent": 2, "quality": 0.83,
    },
    {
        "id": "codellama-7b", "name": "CodeLlama-7B", "port": 8110,
        "ctx": 16384, "weight": 1.0,
        "strengths": ["code_analysis", "fast_query"],
        "cost": 0.2, "latency": 50, "concurrent": 4, "quality": 0.72,
    },
    {
        "id": "yi-9b-200k", "name": "Yi-9B-200K", "port": 8111,
        "ctx": 200000, "weight": 1.5,
        "strengths": ["long_context", "code_analysis", "general"],
        "cost": 0.4, "latency": 150, "concurrent": 2, "quality": 0.8,
    },
    {
        "id": "phi-3.5-mini", "name": "Phi-3.5-mini", "port": 8112,
        "ctx": 131072, "weight": 0.7,
        "strengths": ["fast_query", "general"],
        "cost": 0.1, "latency": 30, "concurrent": 8, "quality": 0.7,
    },
    {
        "id": "nomic-embed", "name": "Nomic-Embed-Text", "port": 8113,
        "ctx": 8192, "weight": 0.5,
        "strengths": ["embedding"],
        "cost": 0.05, "latency": 20, "concurrent": 16, "quality": 0.9,
    },
    {
        "id": "llama-guard", "name": "Llama-Guard-3", "port": 8114,
        "ctx": 8192, "weight": 0.5,
        "strengths": ["safety_check"],
        "cost": 0.05, "latency": 30, "concurrent": 8, "quality": 0.9,
    },
    {
        "id": "functiongemma", "name": "FunctionGemma-270m", "port": 8115,
        "ctx": 8192, "weight": 0.3,
        "strengths": ["tool_calling", "fast_query"],
        "cost": 0.02, "latency": 15, "concurrent": 16, "quality": 0.65,
    },
]


class ModelRouter:
    """Routes tasks to the optimal model.

    Considers task type, model strengths, load, latency, quality,
    and cost to pick the best model for each request.
    """

    def __init__(self) -> None:
        self._models: dict[str, ModelSpec] = {}
        self._round_robin_idx: dict[str, int] = defaultdict(int)
        self._routing_history: list[dict[str, Any]] = []
        self._log = logger.bind(component="model_router")

        self._load_default_models()

    def _load_default_models(self) -> None:
        """Load default model routing table."""
        for data in DEFAULT_MODELS:
            spec = ModelSpec(
                model_id=data["id"],
                name=data["name"],
                port=data["port"],
                context_length=data["ctx"],
                weight=data["weight"],
                strengths=[TaskCategory(s) for s in data["strengths"]],
                cost_per_token=data.get("cost", 0.1),
                avg_latency_ms=data.get("latency", 100),
                max_concurrent=data.get("concurrent", 4),
                avg_quality=data.get("quality", 0.7),
            )
            self._models[spec.model_id] = spec

    def route(
        self,
        task_category: TaskCategory,
        strategy: RoutingStrategy = RoutingStrategy.BEST_FIT,
        min_context: int = 0,
        prefer_fast: bool = False,
        prefer_quality: bool = False,
    ) -> RoutingDecision:
        """Route a task to the best model."""
        candidates = self._get_candidates(task_category, min_context)

        if not candidates:
            # Fallback to any available model
            candidates = [
                m for m in self._models.values() if m.is_available
            ]

        if not candidates:
            return RoutingDecision(reason="no models available")

        if strategy == RoutingStrategy.BEST_FIT:
            selected = self._best_fit(candidates, task_category, prefer_fast, prefer_quality)
        elif strategy == RoutingStrategy.ROUND_ROBIN:
            selected = self._round_robin(candidates, task_category)
        elif strategy == RoutingStrategy.WEIGHTED:
            selected = self._weighted_random(candidates)
        elif strategy == RoutingStrategy.LEAST_LOADED:
            selected = self._least_loaded(candidates)
        elif strategy == RoutingStrategy.LATENCY_AWARE:
            selected = self._latency_aware(candidates)
        elif strategy == RoutingStrategy.CASCADE:
            selected = self._cascade(candidates, task_category)
        else:
            selected = candidates[0]

        # Build fallback chain
        fallbacks = [
            m.model_id for m in candidates
            if m.model_id != selected.model_id
        ][:3]

        decision = RoutingDecision(
            model_id=selected.model_id,
            model_name=selected.name,
            port=selected.port,
            reason=f"{strategy.value}: {task_category.value}",
            fallbacks=fallbacks,
            estimated_latency_ms=selected.avg_latency_ms,
        )

        # Record
        self._routing_history.append({
            "task": task_category.value,
            "model": selected.model_id,
            "strategy": strategy.value,
            "time": time.time(),
        })

        return decision

    def record_result(
        self,
        model_id: str,
        success: bool,
        quality: float = 0.7,
        latency_ms: float = 0.0,
    ) -> None:
        """Record the result of a model interaction."""
        model = self._models.get(model_id)
        if not model:
            return

        model.total_requests += 1
        if not success:
            model.total_errors += 1

        # Update running quality average
        alpha = 0.1
        model.avg_quality = (1 - alpha) * model.avg_quality + alpha * quality

        # Update latency estimate
        if latency_ms > 0:
            model.avg_latency_ms = (
                (1 - alpha) * model.avg_latency_ms + alpha * latency_ms
            )

    def acquire(self, model_id: str) -> bool:
        """Acquire a slot on a model (increment load)."""
        model = self._models.get(model_id)
        if not model or not model.is_available:
            return False
        model.current_load += 1
        return True

    def release(self, model_id: str) -> None:
        """Release a slot on a model."""
        model = self._models.get(model_id)
        if model and model.current_load > 0:
            model.current_load -= 1

    def _get_candidates(
        self,
        task_category: TaskCategory,
        min_context: int = 0,
    ) -> list[ModelSpec]:
        """Get candidate models for a task."""
        candidates = []
        for model in self._models.values():
            if not model.is_available:
                continue
            if min_context > 0 and model.context_length < min_context:
                continue
            if task_category in model.strengths:
                candidates.append(model)
        return candidates

    @staticmethod
    def _best_fit(
        candidates: list[ModelSpec],
        task_category: TaskCategory,
        prefer_fast: bool,
        prefer_quality: bool,
    ) -> ModelSpec:
        """Select the best-fit model."""
        def score(m: ModelSpec) -> float:
            s = m.weight * m.avg_quality
            if task_category in m.strengths:
                s *= 1.5
            if prefer_fast:
                s *= (1000 / max(1, m.avg_latency_ms))
            if prefer_quality:
                s *= m.avg_quality
            # Penalize error rate
            s *= (1 - m.error_rate)
            # Penalize load
            load_ratio = m.current_load / max(1, m.max_concurrent)
            s *= (1 - load_ratio * 0.5)
            return s

        return max(candidates, key=score)

    def _round_robin(
        self,
        candidates: list[ModelSpec],
        task_category: TaskCategory,
    ) -> ModelSpec:
        """Round-robin selection."""
        key = task_category.value
        idx = self._round_robin_idx[key] % len(candidates)
        self._round_robin_idx[key] = idx + 1
        return candidates[idx]

    @staticmethod
    def _weighted_random(candidates: list[ModelSpec]) -> ModelSpec:
        """Weighted random selection."""
        weights = [m.weight for m in candidates]
        total = sum(weights)
        if total == 0:
            return candidates[0]

        r = random.random() * total
        cumulative = 0.0
        for i, w in enumerate(weights):
            cumulative += w
            if r <= cumulative:
                return candidates[i]
        return candidates[-1]

    @staticmethod
    def _least_loaded(candidates: list[ModelSpec]) -> ModelSpec:
        """Select least loaded model."""
        return min(
            candidates,
            key=lambda m: m.current_load / max(1, m.max_concurrent),
        )

    @staticmethod
    def _latency_aware(candidates: list[ModelSpec]) -> ModelSpec:
        """Select lowest latency model."""
        return min(candidates, key=lambda m: m.avg_latency_ms)

    @staticmethod
    def _cascade(
        candidates: list[ModelSpec],
        task_category: TaskCategory,
    ) -> ModelSpec:
        """Cascade: try best quality first."""
        task_matches = [m for m in candidates if task_category in m.strengths]
        if task_matches:
            return max(task_matches, key=lambda m: m.avg_quality)
        return max(candidates, key=lambda m: m.avg_quality)

    def add_model(self, spec: ModelSpec) -> None:
        """Add a model to the routing table."""
        self._models[spec.model_id] = spec

    def remove_model(self, model_id: str) -> bool:
        """Remove a model from the routing table."""
        if model_id in self._models:
            del self._models[model_id]
            return True
        return False

    def get_model(self, model_id: str) -> ModelSpec | None:
        return self._models.get(model_id)

    def get_stats(self) -> dict[str, Any]:
        total_capacity = sum(m.max_concurrent for m in self._models.values())
        total_load = sum(m.current_load for m in self._models.values())
        return {
            "models": len(self._models),
            "total_capacity": total_capacity,
            "total_load": total_load,
            "utilization": round(total_load / max(1, total_capacity), 2),
            "routing_decisions": len(self._routing_history),
            "by_model": {
                m.model_id: m.to_dict() for m in self._models.values()
            },
        }
