"""Multi-model orchestrator — intelligent model routing and management.

Orchestrates the user's local LLM fleet:
1. Model capability profiling
2. Task-to-model routing
3. Load balancing across models
4. Model specialization scoring
5. Ensemble coordination
6. Fallback chains
7. Token budget allocation per model
8. Performance benchmarking
9. Dynamic model selection based on task complexity

Model fleet (user's 16 GGUF models):
- WhiteRabbitNeo-7B: Security specialist
- Qwen2.5-Coder-14B/7B: Code analysis
- CodeLlama-13B/7B: Code generation
- DeepSeek-R1-Distill-Qwen-7B: Reasoning/chain-of-thought
- DeepSeek-Math-7B: Mathematical/logical reasoning
- Hermes-4-14B: General purpose
- Llama-3.1-8B: General purpose
- Dolphin-2.9: Uncensored general
- Mistral-7B: Fast general
- Yi-9B-200K: Long context
- Llama-Guard-3-1b: Safety filter
- Nomic-Embed-Text: Embeddings
- FunctionGemma-270m: Tool routing
- Phi-3.5-mini: Fast small tasks
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ModelCapability(str, Enum):
    SECURITY = "security"
    CODE_ANALYSIS = "code_analysis"
    CODE_GENERATION = "code_generation"
    REASONING = "reasoning"
    PLANNING = "planning"
    GENERAL = "general"
    LONG_CONTEXT = "long_context"
    SAFETY = "safety"
    EMBEDDINGS = "embeddings"
    TOOL_ROUTING = "tool_routing"
    FAST = "fast"
    UNCENSORED = "uncensored"
    MATH = "math"


class ModelSize(str, Enum):
    TINY = "tiny"     # < 1B params
    SMALL = "small"   # 1-3B
    MEDIUM = "medium"  # 7B
    LARGE = "large"    # 13-14B


@dataclass
class ModelProfile:
    """Profile of a local LLM model."""
    model_id: str = ""
    name: str = ""
    port: int = 0
    size: ModelSize = ModelSize.MEDIUM
    context_length: int = 4096
    capabilities: list[ModelCapability] = field(default_factory=list)
    specialty_scores: dict[str, float] = field(default_factory=dict)
    max_concurrent: int = 4
    current_load: int = 0
    avg_latency_ms: float = 0.0
    avg_tokens_per_sec: float = 0.0
    total_requests: int = 0
    total_failures: int = 0
    is_online: bool = False
    weight: float = 1.0  # Higher = preferred

    @property
    def available(self) -> bool:
        return self.is_online and self.current_load < self.max_concurrent

    @property
    def utilization(self) -> float:
        return self.current_load / max(1, self.max_concurrent)

    @property
    def success_rate(self) -> float:
        total = self.total_requests
        return (total - self.total_failures) / max(1, total)

    def get_score(self, task_type: str) -> float:
        """Get score for a specific task type."""
        base = self.specialty_scores.get(task_type, 0.3)
        # Adjust for load
        load_factor = 1.0 - (self.utilization * 0.3)
        # Adjust for reliability
        reliability_factor = self.success_rate
        return base * load_factor * reliability_factor * self.weight

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.model_id, "name": self.name,
            "port": self.port, "size": self.size.value,
            "capabilities": [c.value for c in self.capabilities],
            "load": f"{self.current_load}/{self.max_concurrent}",
            "online": self.is_online,
            "avg_latency_ms": round(self.avg_latency_ms, 0),
        }


@dataclass
class RoutingDecision:
    """A model routing decision."""
    task_type: str = ""
    selected_model: str = ""
    score: float = 0.0
    alternatives: list[str] = field(default_factory=list)
    reasoning: str = ""
    is_ensemble: bool = False
    ensemble_models: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task_type,
            "model": self.selected_model,
            "score": round(self.score, 3),
            "alternatives": self.alternatives[:3],
            "ensemble": self.is_ensemble,
        }


# ── Default Model Configuration ─────────────────────────────

DEFAULT_MODEL_CONFIGS: list[dict[str, Any]] = [
    {
        "model_id": "whiterabbit", "name": "WhiteRabbitNeo-7B",
        "port": 8100, "size": "medium", "context": 4096,
        "capabilities": ["security", "general"],
        "scores": {"security": 0.95, "exploit": 0.9, "vuln_analysis": 0.9,
                   "planning": 0.6, "general": 0.5},
        "weight": 2.0,
    },
    {
        "model_id": "qwen-coder-14b", "name": "Qwen2.5-Coder-14B",
        "port": 8101, "size": "large", "context": 8192,
        "capabilities": ["code_analysis", "code_generation"],
        "scores": {"code_analysis": 0.95, "code_generation": 0.9,
                   "exploit_dev": 0.7, "general": 0.6},
        "weight": 1.5,
    },
    {
        "model_id": "qwen-coder-7b", "name": "Qwen2.5-Coder-7B",
        "port": 8102, "size": "medium", "context": 8192,
        "capabilities": ["code_analysis", "code_generation"],
        "scores": {"code_analysis": 0.85, "code_generation": 0.8,
                   "general": 0.5},
        "weight": 1.0,
    },
    {
        "model_id": "deepseek-r1", "name": "DeepSeek-R1-Distill-Qwen-7B",
        "port": 8103, "size": "medium", "context": 4096,
        "capabilities": ["reasoning", "planning"],
        "scores": {"reasoning": 0.95, "planning": 0.9, "math": 0.8,
                   "general": 0.6},
        "weight": 1.5,
    },
    {
        "model_id": "deepseek-math", "name": "DeepSeek-Math-7B",
        "port": 8104, "size": "medium", "context": 4096,
        "capabilities": ["math", "reasoning"],
        "scores": {"math": 0.95, "reasoning": 0.8, "crypto": 0.7,
                   "general": 0.4},
        "weight": 1.0,
    },
    {
        "model_id": "hermes", "name": "Hermes-4-14B",
        "port": 8105, "size": "large", "context": 8192,
        "capabilities": ["general", "reasoning"],
        "scores": {"general": 0.85, "reasoning": 0.8, "planning": 0.8,
                   "security": 0.5},
        "weight": 1.2,
    },
    {
        "model_id": "llama3", "name": "Llama-3.1-8B",
        "port": 8106, "size": "medium", "context": 8192,
        "capabilities": ["general"],
        "scores": {"general": 0.8, "reasoning": 0.7, "planning": 0.7},
        "weight": 1.0,
    },
    {
        "model_id": "dolphin", "name": "Dolphin-2.9",
        "port": 8107, "size": "medium", "context": 8192,
        "capabilities": ["general", "uncensored"],
        "scores": {"general": 0.75, "uncensored": 1.0, "security": 0.6,
                   "exploit": 0.6},
        "weight": 1.2,
    },
    {
        "model_id": "mistral", "name": "Mistral-7B",
        "port": 8108, "size": "medium", "context": 8192,
        "capabilities": ["general", "fast"],
        "scores": {"general": 0.8, "fast": 0.9, "reasoning": 0.7},
        "weight": 1.0,
    },
    {
        "model_id": "codellama-13b", "name": "CodeLlama-13B",
        "port": 8109, "size": "large", "context": 16384,
        "capabilities": ["code_analysis", "code_generation"],
        "scores": {"code_analysis": 0.85, "code_generation": 0.85,
                   "general": 0.4},
        "weight": 1.0,
    },
    {
        "model_id": "codellama-7b", "name": "CodeLlama-7B",
        "port": 8110, "size": "medium", "context": 16384,
        "capabilities": ["code_analysis", "code_generation"],
        "scores": {"code_analysis": 0.75, "code_generation": 0.75},
        "weight": 0.8,
    },
    {
        "model_id": "yi-200k", "name": "Yi-9B-200K",
        "port": 8111, "size": "medium", "context": 200000,
        "capabilities": ["long_context", "general"],
        "scores": {"long_context": 1.0, "code_analysis": 0.7,
                   "general": 0.7},
        "weight": 1.0,
    },
    {
        "model_id": "phi35", "name": "Phi-3.5-mini",
        "port": 8112, "size": "small", "context": 4096,
        "capabilities": ["fast", "general"],
        "scores": {"fast": 0.95, "general": 0.6, "reasoning": 0.5},
        "weight": 0.7,
    },
    {
        "model_id": "llamaguard", "name": "Llama-Guard-3-1B",
        "port": 8113, "size": "tiny", "context": 4096,
        "capabilities": ["safety"],
        "scores": {"safety": 0.95},
        "weight": 1.0, "max_concurrent": 16,
    },
    {
        "model_id": "nomic-embed", "name": "Nomic-Embed-Text-v1.5",
        "port": 8114, "size": "small", "context": 8192,
        "capabilities": ["embeddings"],
        "scores": {"embeddings": 1.0},
        "weight": 1.0, "max_concurrent": 16,
    },
    {
        "model_id": "funcgemma", "name": "FunctionGemma-270m",
        "port": 8115, "size": "tiny", "context": 2048,
        "capabilities": ["tool_routing", "fast"],
        "scores": {"tool_routing": 0.9, "fast": 1.0},
        "weight": 1.0, "max_concurrent": 32,
    },
]


class ModelOrchestrator:
    """Orchestrates routing across multiple local LLMs.

    Profiles models, routes tasks to the best model,
    manages load balancing, and tracks performance.
    """

    def __init__(self) -> None:
        self._models: dict[str, ModelProfile] = {}
        self._routing_history: list[RoutingDecision] = []
        self._task_type_map: dict[str, list[str]] = defaultdict(list)
        self._log = logger.bind(component="model_orchestrator")

        self._load_defaults()

    def _load_defaults(self) -> None:
        """Load default model configurations."""
        for cfg in DEFAULT_MODEL_CONFIGS:
            try:
                size = ModelSize(cfg.get("size", "medium"))
            except ValueError:
                size = ModelSize.MEDIUM

            capabilities = []
            for cap_str in cfg.get("capabilities", []):
                try:
                    capabilities.append(ModelCapability(cap_str))
                except ValueError:
                    pass

            profile = ModelProfile(
                model_id=cfg["model_id"],
                name=cfg["name"],
                port=cfg["port"],
                size=size,
                context_length=cfg.get("context", 4096),
                capabilities=capabilities,
                specialty_scores=cfg.get("scores", {}),
                weight=cfg.get("weight", 1.0),
                max_concurrent=cfg.get("max_concurrent", 4),
            )
            self._models[profile.model_id] = profile

    def route(
        self,
        task_type: str,
        context_length: int = 0,
        prefer_speed: bool = False,
        require_uncensored: bool = False,
    ) -> RoutingDecision:
        """Route a task to the best model."""
        candidates = list(self._models.values())

        # Filter by availability
        candidates = [m for m in candidates if m.available]

        # Filter by context length requirement
        if context_length > 0:
            candidates = [m for m in candidates if m.context_length >= context_length]

        # Filter by uncensored requirement
        if require_uncensored:
            candidates = [m for m in candidates if ModelCapability.UNCENSORED in m.capabilities]

        if not candidates:
            # Fallback to any available model
            candidates = [m for m in self._models.values() if m.is_online]

        if not candidates:
            return RoutingDecision(
                task_type=task_type,
                reasoning="No models available",
            )

        # Score each candidate
        scored = [(m, m.get_score(task_type)) for m in candidates]

        # Speed preference
        if prefer_speed:
            scored = [
                (m, score * (1.5 if m.size in (ModelSize.TINY, ModelSize.SMALL) else 1.0))
                for m, score in scored
            ]

        scored.sort(key=lambda x: -x[1])
        best = scored[0]

        decision = RoutingDecision(
            task_type=task_type,
            selected_model=best[0].model_id,
            score=best[1],
            alternatives=[m.model_id for m, _ in scored[1:4]],
            reasoning=f"Best score for {task_type}: {best[0].name}",
        )

        self._routing_history.append(decision)
        return decision

    def route_ensemble(
        self,
        task_type: str,
        num_models: int = 3,
    ) -> RoutingDecision:
        """Route to multiple models for ensemble."""
        candidates = [m for m in self._models.values() if m.available]
        scored = [(m, m.get_score(task_type)) for m in candidates]
        scored.sort(key=lambda x: -x[1])

        selected = scored[:num_models]

        decision = RoutingDecision(
            task_type=task_type,
            selected_model=selected[0][0].model_id if selected else "",
            score=selected[0][1] if selected else 0.0,
            is_ensemble=True,
            ensemble_models=[m.model_id for m, _ in selected],
            reasoning=f"Ensemble of {num_models} models for {task_type}",
        )

        self._routing_history.append(decision)
        return decision

    def get_safety_model(self) -> str:
        """Get the safety filter model."""
        guard = self._models.get("llamaguard")
        if guard and guard.is_online:
            return "llamaguard"
        return ""

    def get_embedding_model(self) -> str:
        """Get the embedding model."""
        embed = self._models.get("nomic-embed")
        if embed and embed.is_online:
            return "nomic-embed"
        return ""

    def get_tool_router_model(self) -> str:
        """Get the fast tool routing model."""
        func = self._models.get("funcgemma")
        if func and func.is_online:
            return "funcgemma"
        return ""

    def record_request(self, model_id: str, latency_ms: float, success: bool) -> None:
        """Record a request to a model."""
        model = self._models.get(model_id)
        if not model:
            return

        model.total_requests += 1
        if not success:
            model.total_failures += 1

        n = model.total_requests
        model.avg_latency_ms = (model.avg_latency_ms * (n - 1) + latency_ms) / n

    def set_model_online(self, model_id: str, online: bool = True) -> None:
        model = self._models.get(model_id)
        if model:
            model.is_online = online

    def set_all_online(self) -> None:
        for model in self._models.values():
            model.is_online = True

    def add_model(self, profile: ModelProfile) -> None:
        self._models[profile.model_id] = profile

    def remove_model(self, model_id: str) -> None:
        self._models.pop(model_id, None)

    def get_model(self, model_id: str) -> ModelProfile | None:
        return self._models.get(model_id)

    def get_all_models(self) -> list[dict[str, Any]]:
        return [m.to_dict() for m in self._models.values()]

    def get_stats(self) -> dict[str, Any]:
        online = sum(1 for m in self._models.values() if m.is_online)
        total_requests = sum(m.total_requests for m in self._models.values())
        return {
            "total_models": len(self._models),
            "online": online,
            "total_requests": total_requests,
            "routing_decisions": len(self._routing_history),
        }
