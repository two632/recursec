"""Model router — intelligent task-to-model routing.

Implements:
1. Task classification for model selection
2. Expertise-weighted model scoring
3. Load-aware routing with backpressure
4. Fallback chains for unavailable models
5. Context-size-aware routing
6. Cost/speed tradeoff optimization
7. Per-model performance tracking
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
    GENERAL = "general"
    MATH_LOGIC = "math_logic"
    LONG_CONTEXT = "long_context"
    FAST_QUERY = "fast_query"
    TOOL_CALLING = "tool_calling"
    SAFETY_CHECK = "safety_check"
    EMBEDDING = "embedding"
    EXPLOITATION = "exploitation"
    UNCENSORED = "uncensored"


class RoutingStrategy(str, Enum):
    BEST_FIT = "best_fit"       # Highest expertise score
    FASTEST = "fastest"         # Lowest latency
    LOAD_BALANCED = "load_balanced"  # Least loaded
    ROUND_ROBIN = "round_robin"
    FALLBACK = "fallback"       # Try primary, then fallbacks


@dataclass
class ModelProfile:
    """Profile of a model's capabilities."""
    model_id: str = ""
    port: int = 0
    context_size: int = 4096
    expertise: dict[str, float] = field(default_factory=dict)
    speed_score: float = 0.5     # 0-1, higher = faster
    quality_score: float = 0.5   # 0-1, higher = better
    current_load: int = 0        # Active requests
    max_concurrent: int = 4
    available: bool = False
    total_queries: int = 0
    avg_latency_ms: float = 0.0
    success_rate: float = 1.0

    @property
    def load_ratio(self) -> float:
        if self.max_concurrent == 0:
            return 1.0
        return self.current_load / self.max_concurrent

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "port": self.port,
            "available": self.available,
            "load": f"{self.current_load}/{self.max_concurrent}",
            "queries": self.total_queries,
        }


@dataclass
class RoutingDecision:
    """A routing decision."""
    model_id: str = ""
    score: float = 0.0
    reason: str = ""
    fallbacks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "score": round(self.score, 2),
            "reason": self.reason[:30],
        }


# ── Model expertise profiles ─────────────────────────────────

MODEL_PROFILES: list[dict[str, Any]] = [
    {
        "id": "whiterabbitneo-7b", "port": 8100, "ctx": 8192,
        "speed": 0.7, "quality": 0.8,
        "expertise": {
            "security": 2.0, "exploitation": 1.8,
            "code_analysis": 1.2, "uncensored": 1.5,
        },
    },
    {
        "id": "qwen-coder-14b", "port": 8101, "ctx": 32768,
        "speed": 0.4, "quality": 0.9,
        "expertise": {
            "code_analysis": 2.0, "security": 1.3,
            "reasoning": 1.4, "general": 1.2,
        },
    },
    {
        "id": "qwen-coder-7b", "port": 8102, "ctx": 32768,
        "speed": 0.6, "quality": 0.7,
        "expertise": {
            "code_analysis": 1.8, "security": 1.1,
            "fast_query": 1.3, "tool_calling": 1.1,
        },
    },
    {
        "id": "deepseek-r1-7b", "port": 8103, "ctx": 32768,
        "speed": 0.5, "quality": 0.85,
        "expertise": {
            "reasoning": 2.0, "planning": 1.8,
            "math_logic": 1.5, "general": 1.3,
        },
    },
    {
        "id": "deepseek-math-7b", "port": 8104, "ctx": 4096,
        "speed": 0.6, "quality": 0.7,
        "expertise": {
            "math_logic": 2.0, "reasoning": 1.3,
        },
    },
    {
        "id": "hermes-14b", "port": 8105, "ctx": 8192,
        "speed": 0.4, "quality": 0.85,
        "expertise": {
            "general": 1.8, "planning": 1.5,
            "reasoning": 1.4, "security": 1.2,
        },
    },
    {
        "id": "llama-3.1-8b", "port": 8106, "ctx": 131072,
        "speed": 0.6, "quality": 0.75,
        "expertise": {
            "long_context": 2.0, "general": 1.5,
            "reasoning": 1.2,
        },
    },
    {
        "id": "dolphin-8b", "port": 8107, "ctx": 8192,
        "speed": 0.6, "quality": 0.7,
        "expertise": {
            "uncensored": 2.0, "security": 1.3,
            "general": 1.4, "exploitation": 1.2,
        },
    },
    {
        "id": "mistral-7b", "port": 8108, "ctx": 32768,
        "speed": 0.8, "quality": 0.7,
        "expertise": {
            "fast_query": 1.8, "general": 1.5,
            "code_analysis": 1.1,
        },
    },
    {
        "id": "codellama-13b", "port": 8109, "ctx": 16384,
        "speed": 0.4, "quality": 0.8,
        "expertise": {
            "code_analysis": 1.9, "security": 1.1,
        },
    },
    {
        "id": "codellama-7b", "port": 8110, "ctx": 16384,
        "speed": 0.6, "quality": 0.65,
        "expertise": {
            "code_analysis": 1.6, "fast_query": 1.2,
        },
    },
    {
        "id": "yi-9b-200k", "port": 8111, "ctx": 200000,
        "speed": 0.5, "quality": 0.75,
        "expertise": {
            "long_context": 2.0, "code_analysis": 1.3,
            "general": 1.2,
        },
    },
    {
        "id": "phi-3.5-mini", "port": 8112, "ctx": 128000,
        "speed": 0.9, "quality": 0.6,
        "expertise": {
            "fast_query": 2.0, "long_context": 1.5,
            "general": 1.0,
        },
    },
    {
        "id": "nomic-embed", "port": 8113, "ctx": 8192,
        "speed": 0.95, "quality": 0.8,
        "expertise": {"embedding": 2.0},
    },
    {
        "id": "llama-guard-3", "port": 8114, "ctx": 8192,
        "speed": 0.9, "quality": 0.85,
        "expertise": {"safety_check": 2.0},
    },
    {
        "id": "functiongemma", "port": 8115, "ctx": 8192,
        "speed": 0.95, "quality": 0.7,
        "expertise": {"tool_calling": 2.0, "fast_query": 1.5},
    },
]


class ModelRouter:
    """Intelligent model routing engine.

    Routes tasks to the best available model
    based on expertise, load, context requirements,
    and performance history.
    """

    def __init__(self) -> None:
        self._profiles: dict[str, ModelProfile] = {}
        self._query_count = 0
        self._log = logger.bind(component="model_router")
        self._load_profiles()

    def _load_profiles(self) -> None:
        """Load model profiles."""
        for cfg in MODEL_PROFILES:
            profile = ModelProfile(
                model_id=cfg["id"],
                port=cfg["port"],
                context_size=cfg.get("ctx", 4096),
                speed_score=cfg.get("speed", 0.5),
                quality_score=cfg.get("quality", 0.5),
                expertise=cfg.get("expertise", {}),
            )
            self._profiles[profile.model_id] = profile

    def route(
        self,
        domain: TaskDomain,
        context_tokens: int = 0,
        strategy: RoutingStrategy = RoutingStrategy.BEST_FIT,
        exclude: list[str] | None = None,
    ) -> RoutingDecision:
        """Route a task to the best model."""
        candidates = [
            p for p in self._profiles.values()
            if (not exclude or p.model_id not in exclude)
            and (context_tokens == 0 or p.context_size >= context_tokens)
        ]

        if not candidates:
            return RoutingDecision(reason="No available models")

        if strategy == RoutingStrategy.FASTEST:
            return self._route_fastest(candidates, domain)
        elif strategy == RoutingStrategy.LOAD_BALANCED:
            return self._route_load_balanced(candidates, domain)
        else:
            return self._route_best_fit(candidates, domain)

    def _route_best_fit(
        self,
        candidates: list[ModelProfile],
        domain: TaskDomain,
    ) -> RoutingDecision:
        """Route to model with highest expertise."""
        scored = []
        for profile in candidates:
            expertise = profile.expertise.get(domain.value, 0.5)
            quality = profile.quality_score
            load_penalty = profile.load_ratio * 0.3

            score = expertise * 0.5 + quality * 0.3 - load_penalty
            scored.append((profile, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        best = scored[0]
        fallbacks = [s[0].model_id for s in scored[1:3]]

        return RoutingDecision(
            model_id=best[0].model_id,
            score=best[1],
            reason=f"Best fit for {domain.value}",
            fallbacks=fallbacks,
        )

    def _route_fastest(
        self,
        candidates: list[ModelProfile],
        domain: TaskDomain,
    ) -> RoutingDecision:
        """Route to fastest available model."""
        scored = []
        for profile in candidates:
            expertise = profile.expertise.get(domain.value, 0.5)
            speed = profile.speed_score
            score = speed * 0.6 + expertise * 0.3 + (1 - profile.load_ratio) * 0.1
            scored.append((profile, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        best = scored[0]

        return RoutingDecision(
            model_id=best[0].model_id,
            score=best[1],
            reason=f"Fastest for {domain.value}",
            fallbacks=[s[0].model_id for s in scored[1:3]],
        )

    def _route_load_balanced(
        self,
        candidates: list[ModelProfile],
        domain: TaskDomain,
    ) -> RoutingDecision:
        """Route to least loaded model with adequate expertise."""
        min_expertise = 0.8
        adequate = [
            p for p in candidates
            if p.expertise.get(domain.value, 0.5) >= min_expertise
        ]

        if not adequate:
            adequate = candidates

        adequate.sort(key=lambda p: p.load_ratio)
        best = adequate[0]

        return RoutingDecision(
            model_id=best.model_id,
            score=1.0 - best.load_ratio,
            reason=f"Load balanced for {domain.value}",
            fallbacks=[p.model_id for p in adequate[1:3]],
        )

    def record_query(
        self,
        model_id: str,
        latency_ms: float = 0.0,
        success: bool = True,
    ) -> None:
        """Record query results for routing optimization."""
        profile = self._profiles.get(model_id)
        if not profile:
            return

        profile.total_queries += 1
        self._query_count += 1

        if latency_ms > 0:
            profile.avg_latency_ms = (
                profile.avg_latency_ms * (profile.total_queries - 1)
                + latency_ms
            ) / profile.total_queries

        if not success:
            profile.success_rate = (
                profile.success_rate * (profile.total_queries - 1)
            ) / profile.total_queries

    def acquire_slot(self, model_id: str) -> bool:
        """Acquire a concurrency slot."""
        profile = self._profiles.get(model_id)
        if not profile or profile.current_load >= profile.max_concurrent:
            return False
        profile.current_load += 1
        return True

    def release_slot(self, model_id: str) -> None:
        """Release a concurrency slot."""
        profile = self._profiles.get(model_id)
        if profile and profile.current_load > 0:
            profile.current_load -= 1

    def set_available(self, model_id: str, available: bool) -> None:
        """Set model availability."""
        profile = self._profiles.get(model_id)
        if profile:
            profile.available = available

    def build_router_prompt(self) -> str:
        """Build router context for LLM."""
        lines = ["## Model Router Status\n"]

        for profile in self._profiles.values():
            top_domain = ""
            top_score = 0.0
            for domain, score in profile.expertise.items():
                if score > top_score:
                    top_score = score
                    top_domain = domain

            lines.append(
                f"- {profile.model_id}: "
                f"ctx={profile.context_size}, "
                f"best={top_domain}({top_score:.1f}), "
                f"load={profile.current_load}/{profile.max_concurrent}"
            )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        available = sum(1 for p in self._profiles.values() if p.available)
        total_load = sum(p.current_load for p in self._profiles.values())

        domain_best: dict[str, str] = {}
        for domain in TaskDomain:
            decision = self.route(domain)
            if decision.model_id:
                domain_best[domain.value] = decision.model_id

        return {
            "models": len(self._profiles),
            "available": available,
            "total_load": total_load,
            "total_queries": self._query_count,
            "domain_routing": domain_best,
        }
