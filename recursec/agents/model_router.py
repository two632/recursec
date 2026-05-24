"""Model router — intelligent routing of tasks to optimal models.

Implements:
1. Task-type → model mapping with capability scores
2. Load-aware routing (avoid overloaded models)
3. Fallback chains (if primary model unavailable)
4. Performance-based routing (route to historically best model)
5. Token budget consideration
6. Multi-model consultation for critical tasks
7. Router prompt for LLM context
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class RoutingStrategy(str, Enum):
    BEST_FIT = "best_fit"
    ROUND_ROBIN = "round_robin"
    FASTEST = "fastest"
    CHEAPEST = "cheapest"
    ENSEMBLE = "ensemble"


class TaskCategory(str, Enum):
    SECURITY_ANALYSIS = "security_analysis"
    CODE_REVIEW = "code_review"
    PLANNING = "planning"
    EXPLOITATION = "exploitation"
    GENERAL = "general"


class TaskType(str, Enum):
    SECURITY_ANALYSIS = "security_analysis"
    CODE_REVIEW = "code_review"
    REASONING = "reasoning"
    PLANNING = "planning"
    EXPLOIT_DEV = "exploit_dev"
    RECON = "recon"
    GENERAL = "general"
    EMBEDDING = "embedding"
    SAFETY_CHECK = "safety_check"
    TOOL_ROUTING = "tool_routing"
    LONG_CONTEXT = "long_context"
    MATH = "math"
    SUMMARIZE = "summarize"


class ModelStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    OVERLOADED = "overloaded"
    STARTING = "starting"


@dataclass
class ModelInfo:
    """Information about a configured model."""
    model_id: str = ""
    port: int = 0
    context_length: int = 4096
    capabilities: dict[str, float] = field(default_factory=dict)
    weight: float = 1.0
    status: ModelStatus = ModelStatus.OFFLINE
    current_load: int = 0            # Active requests
    max_concurrent: int = 4
    total_requests: int = 0
    total_tokens: int = 0
    avg_latency_ms: float = 0.0
    last_used: float = 0.0

    @property
    def load_ratio(self) -> float:
        if self.max_concurrent == 0:
            return 1.0
        return self.current_load / self.max_concurrent

    @property
    def is_available(self) -> bool:
        return (
            self.status == ModelStatus.ONLINE
            and self.current_load < self.max_concurrent
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.model_id[:15],
            "port": self.port,
            "status": self.status.value[:6],
            "load": f"{self.load_ratio:.0%}",
            "requests": self.total_requests,
        }


# ── Default model configurations ────────────────────────────

DEFAULT_MODELS: list[dict[str, Any]] = [
    {
        "id": "WhiteRabbitNeo-7B", "port": 8100,
        "context": 8192, "weight": 2.0, "concurrent": 4,
        "caps": {
            "security_analysis": 0.95, "exploit_dev": 0.90,
            "recon": 0.80, "general": 0.60,
        },
    },
    {
        "id": "Qwen2.5-Coder-14B", "port": 8101,
        "context": 32768, "weight": 2.0, "concurrent": 2,
        "caps": {
            "code_review": 0.95, "exploit_dev": 0.85,
            "security_analysis": 0.75, "general": 0.70,
        },
    },
    {
        "id": "Qwen2.5-Coder-7B", "port": 8102,
        "context": 32768, "weight": 1.5, "concurrent": 4,
        "caps": {
            "code_review": 0.85, "exploit_dev": 0.75,
            "general": 0.65,
        },
    },
    {
        "id": "DeepSeek-R1-Distill-Qwen-7B", "port": 8103,
        "context": 32768, "weight": 2.0, "concurrent": 4,
        "caps": {
            "reasoning": 0.95, "planning": 0.90,
            "security_analysis": 0.75, "math": 0.85,
        },
    },
    {
        "id": "Yi-9B-200K", "port": 8104,
        "context": 200000, "weight": 1.5, "concurrent": 2,
        "caps": {
            "long_context": 0.95, "code_review": 0.70,
            "summarize": 0.80, "general": 0.65,
        },
    },
    {
        "id": "Phi-3.5-mini", "port": 8105,
        "context": 4096, "weight": 1.0, "concurrent": 8,
        "caps": {
            "general": 0.70, "summarize": 0.65,
            "tool_routing": 0.60,
        },
    },
    {
        "id": "Mistral-7B", "port": 8106,
        "context": 8192, "weight": 1.0, "concurrent": 4,
        "caps": {
            "general": 0.80, "recon": 0.70,
            "summarize": 0.75, "planning": 0.65,
        },
    },
    {
        "id": "CodeLlama-13B", "port": 8107,
        "context": 16384, "weight": 1.5, "concurrent": 2,
        "caps": {
            "code_review": 0.90, "exploit_dev": 0.80,
            "security_analysis": 0.65,
        },
    },
    {
        "id": "CodeLlama-7B", "port": 8108,
        "context": 16384, "weight": 1.0, "concurrent": 4,
        "caps": {
            "code_review": 0.80, "exploit_dev": 0.70,
        },
    },
    {
        "id": "Hermes-4-14B", "port": 8109,
        "context": 16384, "weight": 1.5, "concurrent": 2,
        "caps": {
            "general": 0.85, "reasoning": 0.80,
            "planning": 0.80, "security_analysis": 0.70,
        },
    },
    {
        "id": "Llama-3.1-8B", "port": 8110,
        "context": 8192, "weight": 1.0, "concurrent": 4,
        "caps": {
            "general": 0.75, "recon": 0.65,
            "summarize": 0.70,
        },
    },
    {
        "id": "Dolphin-2.9", "port": 8111,
        "context": 8192, "weight": 1.3, "concurrent": 4,
        "caps": {
            "security_analysis": 0.75, "exploit_dev": 0.80,
            "general": 0.75,
        },
    },
    {
        "id": "DeepSeek-Math-7B", "port": 8112,
        "context": 4096, "weight": 1.0, "concurrent": 4,
        "caps": {
            "math": 0.90, "reasoning": 0.75,
        },
    },
    {
        "id": "Nomic-Embed-Text", "port": 8113,
        "context": 8192, "weight": 1.0, "concurrent": 16,
        "caps": {
            "embedding": 1.0,
        },
    },
    {
        "id": "Llama-Guard-3", "port": 8114,
        "context": 2048, "weight": 1.0, "concurrent": 8,
        "caps": {
            "safety_check": 1.0,
        },
    },
    {
        "id": "FunctionGemma-270m", "port": 8115,
        "context": 2048, "weight": 1.0, "concurrent": 16,
        "caps": {
            "tool_routing": 0.95,
        },
    },
]


class ModelRouter:
    """Routes tasks to optimal models based on capability and load.

    Considers task type, model capability scores,
    current load, historical performance, and token budget.
    """

    def __init__(self) -> None:
        self._models: dict[str, ModelInfo] = {}
        self._log = logger.bind(component="model_router")
        self._load_defaults()

    def _load_defaults(self) -> None:
        """Load default model configurations."""
        for spec in DEFAULT_MODELS:
            model = ModelInfo(
                model_id=spec["id"],
                port=spec["port"],
                context_length=spec.get("context", 4096),
                capabilities=spec.get("caps", {}),
                weight=spec.get("weight", 1.0),
                max_concurrent=spec.get("concurrent", 4),
            )
            self._models[model.model_id] = model

    def route(
        self,
        task_type: TaskType,
        required_context: int = 0,
        prefer_fast: bool = False,
    ) -> ModelInfo | None:
        """Route a task to the best available model."""
        candidates: list[tuple[float, ModelInfo]] = []

        for model in self._models.values():
            if not model.is_available:
                continue

            # Check context length requirement
            if required_context > model.context_length:
                continue

            # Capability score for this task
            cap_score = model.capabilities.get(task_type.value, 0.0)
            if cap_score == 0:
                continue

            # Load penalty
            load_penalty = model.load_ratio * 0.3

            # Weight bonus
            weight_bonus = (model.weight - 1.0) * 0.2

            # Speed bonus if prefer_fast
            speed_bonus = 0.0
            if prefer_fast and model.avg_latency_ms > 0:
                speed_bonus = max(0, (1000 - model.avg_latency_ms) / 1000) * 0.2

            score = cap_score - load_penalty + weight_bonus + speed_bonus
            candidates.append((score, model))

        if not candidates:
            # Fallback: any online model
            for model in self._models.values():
                if model.is_available:
                    return model
            return None

        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1]

    def route_multi(
        self,
        task_type: TaskType,
        count: int = 3,
    ) -> list[ModelInfo]:
        """Route to multiple models (for ensemble/consensus)."""
        candidates: list[tuple[float, ModelInfo]] = []

        for model in self._models.values():
            if not model.is_available:
                continue
            cap_score = model.capabilities.get(task_type.value, 0.0)
            if cap_score > 0:
                candidates.append((cap_score, model))

        candidates.sort(key=lambda x: x[0], reverse=True)
        return [m for _, m in candidates[:count]]

    def mark_online(self, model_id: str) -> bool:
        """Mark model as online."""
        model = self._models.get(model_id)
        if not model:
            return False
        model.status = ModelStatus.ONLINE
        return True

    def mark_offline(self, model_id: str) -> bool:
        """Mark model as offline."""
        model = self._models.get(model_id)
        if not model:
            return False
        model.status = ModelStatus.OFFLINE
        return True

    def acquire(self, model_id: str) -> bool:
        """Acquire a slot on a model (increment load)."""
        model = self._models.get(model_id)
        if not model or not model.is_available:
            return False
        model.current_load += 1
        model.total_requests += 1
        model.last_used = time.time()
        return True

    def release(self, model_id: str, tokens_used: int = 0, latency_ms: float = 0) -> None:
        """Release a slot on a model (decrement load)."""
        model = self._models.get(model_id)
        if not model:
            return
        model.current_load = max(0, model.current_load - 1)
        model.total_tokens += tokens_used
        if latency_ms > 0:
            model.avg_latency_ms = (
                (model.avg_latency_ms * (model.total_requests - 1) + latency_ms)
                / model.total_requests
            )

    def build_router_prompt(self) -> str:
        """Build router context for LLM."""
        lines = ["## Model Router\n"]

        online = [m for m in self._models.values() if m.status == ModelStatus.ONLINE]
        offline = [m for m in self._models.values() if m.status == ModelStatus.OFFLINE]
        lines.append(f"Models: {len(online)} online, {len(offline)} offline")

        if online:
            lines.append("\nAvailable models:")
            for m in online:
                top_caps = sorted(
                    m.capabilities.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )[:2]
                caps_str = ", ".join(f"{k}={v:.0%}" for k, v in top_caps)
                lines.append(
                    f"  {m.model_id[:15]}: load={m.load_ratio:.0%} "
                    f"ctx={m.context_length} [{caps_str}]"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_models": len(self._models),
            "online": sum(1 for m in self._models.values() if m.status == ModelStatus.ONLINE),
            "total_requests": sum(m.total_requests for m in self._models.values()),
            "total_tokens": sum(m.total_tokens for m in self._models.values()),
        }
