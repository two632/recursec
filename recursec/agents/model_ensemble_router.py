"""Model ensemble router — intelligent multi-model routing.

Implements:
1. Task-type → model routing
2. Expertise-weighted model selection
3. Load balancing across models
4. Fallback chains when models are unavailable
5. Multi-model voting for high-stakes decisions
6. Model performance tracking
7. Router prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskType(str, Enum):
    SECURITY = "security"
    CODE_AUDIT = "code_audit"
    REASONING = "reasoning"
    PLANNING = "planning"
    EXPLOITATION = "exploitation"
    RECON = "recon"
    REPORT = "report"
    GENERAL = "general"
    LONG_CONTEXT = "long_context"
    TOOL_ROUTING = "tool_routing"
    MATH = "math"
    UNCENSORED = "uncensored"
    EMBEDDING = "embedding"
    SAFETY = "safety"


class ModelStatus(str, Enum):
    AVAILABLE = "available"
    BUSY = "busy"
    UNAVAILABLE = "unavailable"
    DEGRADED = "degraded"


@dataclass
class ModelProfile:
    """Profile for a local LLM model."""
    model_id: str = ""
    name: str = ""
    port: int = 0
    status: ModelStatus = ModelStatus.AVAILABLE
    max_context: int = 4096
    expertise: dict[str, float] = field(default_factory=dict)
    weight: float = 1.0
    concurrent_slots: int = 1
    active_requests: int = 0
    total_requests: int = 0
    total_tokens: int = 0
    avg_latency_ms: float = 0.0
    error_count: int = 0
    last_used: float = 0.0

    @property
    def utilization(self) -> float:
        if self.concurrent_slots == 0:
            return 1.0
        return self.active_requests / self.concurrent_slots

    @property
    def is_available(self) -> bool:
        return (
            self.status in (ModelStatus.AVAILABLE, ModelStatus.DEGRADED)
            and self.active_requests < self.concurrent_slots
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.model_id[:12],
            "name": self.name[:15],
            "port": self.port,
            "status": self.status.value[:6],
            "util": f"{self.utilization:.0%}",
            "reqs": self.total_requests,
        }


# ── Default model registry (user's 16 GGUF models) ──────────

DEFAULT_MODELS: list[dict[str, Any]] = [
    {
        "id": "whiterabbitneo", "name": "WhiteRabbitNeo-7B",
        "port": 8100, "max_ctx": 4096, "slots": 2, "weight": 2.0,
        "expertise": {"security": 2.0, "exploitation": 2.0, "web": 1.8, "network": 1.8, "recon": 1.5},
    },
    {
        "id": "qwen-coder-14b", "name": "Qwen2.5-Coder-14B",
        "port": 8101, "max_ctx": 8192, "slots": 1, "weight": 2.0,
        "expertise": {"code_audit": 2.0, "reasoning": 1.5, "exploitation": 1.3, "general": 1.2},
    },
    {
        "id": "qwen-coder-7b", "name": "Qwen2.5-Coder-7B",
        "port": 8102, "max_ctx": 8192, "slots": 2, "weight": 1.5,
        "expertise": {"code_audit": 1.8, "general": 1.3, "reasoning": 1.2},
    },
    {
        "id": "deepseek-r1", "name": "DeepSeek-R1-Distill",
        "port": 8103, "max_ctx": 4096, "slots": 1, "weight": 2.0,
        "expertise": {"reasoning": 2.0, "planning": 2.0, "math": 1.5, "general": 1.3},
    },
    {
        "id": "yi-9b-200k", "name": "Yi-9B-200K",
        "port": 8104, "max_ctx": 200000, "slots": 1, "weight": 1.5,
        "expertise": {"long_context": 2.0, "code_audit": 1.5, "general": 1.3},
    },
    {
        "id": "phi-35-mini", "name": "Phi-3.5-mini",
        "port": 8105, "max_ctx": 4096, "slots": 4, "weight": 1.0,
        "expertise": {"general": 1.5, "report": 1.5, "recon": 1.2},
    },
    {
        "id": "mistral-7b", "name": "Mistral-7B",
        "port": 8106, "max_ctx": 4096, "slots": 2, "weight": 1.3,
        "expertise": {"general": 1.5, "recon": 1.5, "report": 1.3, "reasoning": 1.2},
    },
    {
        "id": "codellama-13b", "name": "CodeLlama-13B",
        "port": 8107, "max_ctx": 4096, "slots": 1, "weight": 1.5,
        "expertise": {"code_audit": 1.8, "exploitation": 1.3, "general": 1.0},
    },
    {
        "id": "codellama-7b", "name": "CodeLlama-7B",
        "port": 8108, "max_ctx": 4096, "slots": 2, "weight": 1.2,
        "expertise": {"code_audit": 1.5, "general": 1.0},
    },
    {
        "id": "hermes-4", "name": "Hermes-4-14B",
        "port": 8109, "max_ctx": 8192, "slots": 1, "weight": 1.5,
        "expertise": {"general": 1.8, "reasoning": 1.5, "planning": 1.3, "report": 1.3},
    },
    {
        "id": "llama-31-8b", "name": "Llama-3.1-8B",
        "port": 8110, "max_ctx": 8192, "slots": 2, "weight": 1.3,
        "expertise": {"general": 1.5, "recon": 1.3, "report": 1.2},
    },
    {
        "id": "dolphin-29", "name": "Dolphin-2.9",
        "port": 8111, "max_ctx": 4096, "slots": 2, "weight": 1.3,
        "expertise": {"uncensored": 2.0, "security": 1.5, "general": 1.3, "exploitation": 1.2},
    },
    {
        "id": "deepseek-math", "name": "DeepSeek-Math-7B",
        "port": 8112, "max_ctx": 4096, "slots": 2, "weight": 1.0,
        "expertise": {"math": 2.0, "reasoning": 1.5},
    },
    {
        "id": "nomic-embed", "name": "Nomic-Embed-Text",
        "port": 8113, "max_ctx": 8192, "slots": 8, "weight": 1.0,
        "expertise": {"embedding": 2.0},
    },
    {
        "id": "llama-guard", "name": "Llama-Guard-3",
        "port": 8114, "max_ctx": 4096, "slots": 4, "weight": 1.0,
        "expertise": {"safety": 2.0},
    },
    {
        "id": "functiongemma", "name": "FunctionGemma-270m",
        "port": 8115, "max_ctx": 2048, "slots": 16, "weight": 1.0,
        "expertise": {"tool_routing": 2.0},
    },
]


class ModelEnsembleRouter:
    """Intelligent multi-model routing with expertise weighting.

    Routes tasks to the best available model based on
    task type, model expertise, load, and performance history.
    """

    def __init__(self) -> None:
        self._models: dict[str, ModelProfile] = {}
        self._log = logger.bind(component="model_router")
        self._load_defaults()

    def _load_defaults(self) -> None:
        """Load default model profiles."""
        for spec in DEFAULT_MODELS:
            profile = ModelProfile(
                model_id=spec["id"],
                name=spec["name"],
                port=spec["port"],
                max_context=spec.get("max_ctx", 4096),
                concurrent_slots=spec.get("slots", 1),
                weight=spec.get("weight", 1.0),
                expertise=spec.get("expertise", {}),
            )
            self._models[profile.model_id] = profile

    def route(
        self,
        task_type: TaskType | str,
        context_length: int = 0,
        require_uncensored: bool = False,
    ) -> ModelProfile | None:
        """Route a task to the best available model."""
        tt = task_type.value if isinstance(task_type, TaskType) else task_type
        candidates: list[tuple[float, ModelProfile]] = []

        for model in self._models.values():
            if not model.is_available:
                continue

            # Context length filter
            if context_length > 0 and context_length > model.max_context:
                continue

            # Uncensored filter
            if require_uncensored and model.expertise.get("uncensored", 0) < 1.5:
                continue

            # Score = expertise * weight * (1 - utilization)
            expertise_score = model.expertise.get(tt, 0.5)
            util_penalty = 1.0 - (model.utilization * 0.5)
            score = expertise_score * model.weight * util_penalty

            candidates.append((score, model))

        if not candidates:
            return None

        # Sort by score descending
        candidates.sort(key=lambda x: x[0], reverse=True)
        best = candidates[0][1]

        best.active_requests += 1
        best.total_requests += 1
        best.last_used = time.time()

        return best

    def release(self, model_id: str, tokens_used: int = 0, latency_ms: float = 0) -> None:
        """Release a model after use."""
        model = self._models.get(model_id)
        if not model:
            return

        model.active_requests = max(0, model.active_requests - 1)
        model.total_tokens += tokens_used

        if latency_ms > 0:
            # Exponential moving average
            alpha = 0.3
            if model.avg_latency_ms == 0:
                model.avg_latency_ms = latency_ms
            else:
                model.avg_latency_ms = alpha * latency_ms + (1 - alpha) * model.avg_latency_ms

    def mark_error(self, model_id: str) -> None:
        """Mark a model as having an error."""
        model = self._models.get(model_id)
        if not model:
            return

        model.error_count += 1
        model.active_requests = max(0, model.active_requests - 1)

        if model.error_count >= 5:
            model.status = ModelStatus.UNAVAILABLE
        elif model.error_count >= 3:
            model.status = ModelStatus.DEGRADED

    def get_models_for_voting(
        self,
        task_type: TaskType | str,
        count: int = 3,
    ) -> list[ModelProfile]:
        """Get multiple models for voting (high-stakes decisions)."""
        tt = task_type.value if isinstance(task_type, TaskType) else task_type
        available = [
            m for m in self._models.values()
            if m.is_available and m.expertise.get(tt, 0) > 0
        ]

        available.sort(
            key=lambda m: m.expertise.get(tt, 0) * m.weight,
            reverse=True,
        )

        return available[:count]

    def add_model(
        self,
        model_id: str,
        name: str,
        port: int,
        max_context: int = 4096,
        slots: int = 1,
        weight: float = 1.0,
        expertise: dict[str, float] | None = None,
    ) -> ModelProfile:
        """Add a new model at runtime."""
        profile = ModelProfile(
            model_id=model_id,
            name=name,
            port=port,
            max_context=max_context,
            concurrent_slots=slots,
            weight=weight,
            expertise=expertise or {},
        )
        self._models[model_id] = profile
        return profile

    def remove_model(self, model_id: str) -> None:
        """Remove a model."""
        self._models.pop(model_id, None)

    def build_router_prompt(self) -> str:
        """Build router context for LLM."""
        lines = ["## Model Router\n"]

        available = [m for m in self._models.values() if m.is_available]
        busy = [m for m in self._models.values() if m.status == ModelStatus.BUSY]
        down = [m for m in self._models.values() if m.status == ModelStatus.UNAVAILABLE]

        lines.append(
            f"Models: {len(self._models)} total — "
            f"{len(available)} available, "
            f"{len(busy)} busy, "
            f"{len(down)} down"
        )

        total_reqs = sum(m.total_requests for m in self._models.values())
        total_tokens = sum(m.total_tokens for m in self._models.values())
        lines.append(f"Total requests: {total_reqs} | Tokens: {total_tokens}")

        # Top models by usage
        by_usage = sorted(self._models.values(), key=lambda m: m.total_requests, reverse=True)
        top = by_usage[:5]
        if top:
            lines.append("\nTop models:")
            for m in top:
                lines.append(
                    f"  {m.name[:15]} (:{m.port}) — "
                    f"reqs={m.total_requests} "
                    f"util={m.utilization:.0%}"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for m in self._models.values():
            s = m.status.value
            status_counts[s] = status_counts.get(s, 0) + 1

        return {
            "total_models": len(self._models),
            "by_status": status_counts,
            "total_requests": sum(m.total_requests for m in self._models.values()),
            "total_tokens": sum(m.total_tokens for m in self._models.values()),
            "total_errors": sum(m.error_count for m in self._models.values()),
        }
