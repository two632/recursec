"""Model router — intelligent task-to-model routing.

Implements:
1. Task-type classification
2. Domain-aware model selection
3. Context-length-aware routing
4. Load balancing across models
5. Fallback chains
6. Performance tracking per model
7. Dynamic weight adjustment
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskDomain(str, Enum):
    SECURITY = "security"
    CODE_ANALYSIS = "code_analysis"
    REASONING = "reasoning"
    PLANNING = "planning"
    EXPLOITATION = "exploitation"
    RECON = "recon"
    GENERAL = "general"
    LONG_CONTEXT = "long_context"
    EMBEDDING = "embedding"
    SAFETY = "safety"
    FUNCTION_CALL = "function_call"
    MATH = "math"
    UNCENSORED = "uncensored"


@dataclass
class ModelProfile:
    """Profile for a registered LLM model."""
    model_id: str = ""
    name: str = ""
    port: int = 8100
    context_size: int = 4096
    max_batch: int = 4
    domains: dict[str, float] = field(default_factory=dict)  # domain → weight
    active_requests: int = 0
    total_requests: int = 0
    total_tokens: int = 0
    avg_latency_ms: float = 0.0
    error_count: int = 0
    available: bool = True

    @property
    def load_factor(self) -> float:
        """Current load as fraction of capacity."""
        if self.max_batch == 0:
            return 1.0
        return self.active_requests / self.max_batch

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.error_count / self.total_requests

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.model_id[:12],
            "name": self.name[:20],
            "port": self.port,
            "ctx": self.context_size,
            "load": round(self.load_factor, 2),
            "reqs": self.total_requests,
        }


@dataclass
class RoutingDecision:
    """A model routing decision."""
    model_id: str = ""
    model_name: str = ""
    port: int = 8100
    score: float = 0.0
    reason: str = ""
    fallbacks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_name[:20],
            "port": self.port,
            "score": round(self.score, 3),
            "reason": self.reason[:30],
        }


# ── Default model profiles (user's 16 models) ───────────────

DEFAULT_MODELS: list[dict[str, Any]] = [
    {
        "id": "whiterabbitneo-7b", "name": "WhiteRabbitNeo-7B",
        "port": 8100, "ctx": 8192, "batch": 4,
        "domains": {"security": 2.0, "exploitation": 2.0, "recon": 1.5, "general": 0.8},
    },
    {
        "id": "qwen-coder-14b", "name": "Qwen2.5-Coder-14B",
        "port": 8101, "ctx": 32768, "batch": 2,
        "domains": {"code_analysis": 2.0, "security": 1.2, "reasoning": 1.3},
    },
    {
        "id": "qwen-coder-7b", "name": "Qwen2.5-Coder-7B",
        "port": 8102, "ctx": 32768, "batch": 4,
        "domains": {"code_analysis": 1.8, "function_call": 1.3, "general": 1.0},
    },
    {
        "id": "deepseek-r1-7b", "name": "DeepSeek-R1-Distill-Qwen-7B",
        "port": 8103, "ctx": 32768, "batch": 4,
        "domains": {"reasoning": 2.0, "planning": 1.8, "math": 1.5, "code_analysis": 1.2},
    },
    {
        "id": "deepseek-math-7b", "name": "DeepSeek-Math-7B",
        "port": 8104, "ctx": 4096, "batch": 8,
        "domains": {"math": 2.0, "reasoning": 1.3},
    },
    {
        "id": "hermes-14b", "name": "Hermes-4-14B",
        "port": 8105, "ctx": 32768, "batch": 2,
        "domains": {"general": 1.5, "reasoning": 1.4, "planning": 1.3, "function_call": 1.5},
    },
    {
        "id": "llama-3.1-8b", "name": "Meta-Llama-3.1-8B",
        "port": 8106, "ctx": 131072, "batch": 4,
        "domains": {"general": 1.3, "long_context": 1.8, "reasoning": 1.0},
    },
    {
        "id": "dolphin-8b", "name": "Dolphin-2.9-Llama3-8B",
        "port": 8107, "ctx": 8192, "batch": 4,
        "domains": {"uncensored": 2.0, "security": 1.3, "exploitation": 1.5, "general": 1.0},
    },
    {
        "id": "mistral-7b", "name": "Mistral-7B-Instruct",
        "port": 8108, "ctx": 32768, "batch": 4,
        "domains": {"general": 1.2, "reasoning": 1.0, "function_call": 1.2},
    },
    {
        "id": "codellama-13b", "name": "CodeLlama-13B",
        "port": 8109, "ctx": 16384, "batch": 2,
        "domains": {"code_analysis": 1.7, "exploitation": 1.0},
    },
    {
        "id": "codellama-7b", "name": "CodeLlama-7B",
        "port": 8110, "ctx": 16384, "batch": 8,
        "domains": {"code_analysis": 1.4, "function_call": 1.0},
    },
    {
        "id": "yi-9b-200k", "name": "Yi-9B-200K",
        "port": 8111, "ctx": 200000, "batch": 2,
        "domains": {"long_context": 2.0, "code_analysis": 1.2, "general": 1.0},
    },
    {
        "id": "phi-3.5-mini", "name": "Phi-3.5-mini",
        "port": 8112, "ctx": 131072, "batch": 8,
        "domains": {"general": 1.0, "math": 1.2, "long_context": 1.5, "reasoning": 1.0},
    },
    {
        "id": "nomic-embed", "name": "Nomic-Embed-Text",
        "port": 8113, "ctx": 8192, "batch": 16,
        "domains": {"embedding": 2.0},
    },
    {
        "id": "llama-guard-3", "name": "Llama-Guard-3",
        "port": 8114, "ctx": 8192, "batch": 8,
        "domains": {"safety": 2.0},
    },
    {
        "id": "functiongemma", "name": "FunctionGemma-270M",
        "port": 8115, "ctx": 2048, "batch": 16,
        "domains": {"function_call": 2.0},
    },
]


class ModelRouter:
    """Routes tasks to optimal LLM models.

    Selects models based on task domain,
    context requirements, model load, and
    historical performance.
    """

    def __init__(self) -> None:
        self._models: dict[str, ModelProfile] = {}
        self._log = logger.bind(component="model_router")
        self._load_defaults()

    def _load_defaults(self) -> None:
        """Load default model profiles."""
        for data in DEFAULT_MODELS:
            profile = ModelProfile(
                model_id=data["id"],
                name=data["name"],
                port=data["port"],
                context_size=data["ctx"],
                max_batch=data["batch"],
                domains=data.get("domains", {}),
            )
            self._models[profile.model_id] = profile

    def add_model(
        self,
        model_id: str,
        name: str,
        port: int,
        context_size: int = 4096,
        max_batch: int = 4,
        domains: dict[str, float] | None = None,
    ) -> ModelProfile:
        """Register a new model."""
        profile = ModelProfile(
            model_id=model_id,
            name=name,
            port=port,
            context_size=context_size,
            max_batch=max_batch,
            domains=domains or {},
        )
        self._models[model_id] = profile
        return profile

    def route(
        self,
        domain: TaskDomain,
        required_context: int = 0,
        prefer_fast: bool = False,
    ) -> RoutingDecision:
        """Route a task to the best model."""
        candidates: list[tuple[float, ModelProfile]] = []

        for model in self._models.values():
            if not model.available:
                continue

            # Filter by context requirement
            if required_context > 0 and model.context_size < required_context:
                continue

            # Calculate score
            score = self._score_model(model, domain, required_context, prefer_fast)
            if score > 0:
                candidates.append((score, model))

        if not candidates:
            # Fallback to any available model
            for model in self._models.values():
                if model.available and model.context_size >= required_context:
                    return RoutingDecision(
                        model_id=model.model_id,
                        model_name=model.name,
                        port=model.port,
                        score=0.1,
                        reason="fallback (no domain match)",
                    )
            return RoutingDecision(reason="no models available")

        candidates.sort(key=lambda x: x[0], reverse=True)

        best_score, best_model = candidates[0]
        fallbacks = [m.model_id for _, m in candidates[1:3]]

        return RoutingDecision(
            model_id=best_model.model_id,
            model_name=best_model.name,
            port=best_model.port,
            score=best_score,
            reason=f"domain={domain.value}",
            fallbacks=fallbacks,
        )

    def record_request(
        self,
        model_id: str,
        tokens: int = 0,
        latency_ms: float = 0.0,
        error: bool = False,
    ) -> None:
        """Record a request result for a model."""
        model = self._models.get(model_id)
        if not model:
            return

        model.total_requests += 1
        model.total_tokens += tokens
        if error:
            model.error_count += 1

        # Running average latency
        if latency_ms > 0:
            if model.avg_latency_ms == 0:
                model.avg_latency_ms = latency_ms
            else:
                model.avg_latency_ms = model.avg_latency_ms * 0.9 + latency_ms * 0.1

    def _score_model(
        self,
        model: ModelProfile,
        domain: TaskDomain,
        required_context: int,
        prefer_fast: bool,
    ) -> float:
        """Score a model for a task."""
        # Domain weight
        domain_weight = model.domains.get(domain.value, 0.0)
        if domain_weight == 0:
            return 0.0

        # Load penalty
        load_penalty = 1.0 - (model.load_factor * 0.5)

        # Error penalty
        error_penalty = 1.0 - (model.error_rate * 2.0)
        error_penalty = max(0.1, error_penalty)

        # Speed bonus
        speed_bonus = 1.0
        if prefer_fast:
            if model.max_batch >= 8:
                speed_bonus = 1.3
            elif model.avg_latency_ms > 0 and model.avg_latency_ms < 500:
                speed_bonus = 1.2

        # Context fit bonus
        ctx_bonus = 1.0
        if required_context > 0:
            ratio = model.context_size / max(required_context, 1)
            if 1.0 <= ratio <= 2.0:
                ctx_bonus = 1.2  # Good fit
            elif ratio > 10:
                ctx_bonus = 0.8  # Wasteful

        return domain_weight * load_penalty * error_penalty * speed_bonus * ctx_bonus

    def build_routing_prompt(self) -> str:
        """Build routing context for LLM."""
        lines = ["## Model Router\n"]
        lines.append("Available models:")

        for model in sorted(self._models.values(), key=lambda m: m.port):
            if not model.available:
                continue
            domains = ", ".join(
                f"{d}:{w:.1f}" for d, w in
                sorted(model.domains.items(), key=lambda x: x[1], reverse=True)[:3]
            )
            lines.append(
                f"  [{model.port}] {model.name[:20]} "
                f"(ctx={model.context_size}, {domains})"
            )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_models": len(self._models),
            "available": sum(1 for m in self._models.values() if m.available),
            "total_requests": sum(m.total_requests for m in self._models.values()),
            "total_tokens": sum(m.total_tokens for m in self._models.values()),
        }
