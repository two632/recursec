"""Model routing optimizer — intelligent LLM selection and load balancing.

This module decides which of the 16 models handles each request:
1. Task-type routing (security → WhiteRabbit, code → Qwen/CodeLlama)
2. Quality-based routing (historical accuracy per task type)
3. Latency-aware selection (prefer faster models for simple tasks)
4. Token budget optimization (route to smaller models when possible)
5. Cascade routing (try small model first, escalate if needed)
6. Ensemble routing (multi-model consensus for critical decisions)
7. Context-length routing (long docs → Yi-9B-200K)
8. Specialization scoring (per-model per-task effectiveness)
"""

from __future__ import annotations

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
    EXPLOIT_DEVELOPMENT = "exploit_development"
    REASONING = "reasoning"
    PLANNING = "planning"
    TOOL_SELECTION = "tool_selection"
    OUTPUT_PARSING = "output_parsing"
    REPORT_WRITING = "report_writing"
    LONG_CONTEXT = "long_context"
    FUNCTION_CALL = "function_call"
    SAFETY_CHECK = "safety_check"
    EMBEDDING = "embedding"
    GENERAL = "general"
    FAST_QUERY = "fast_query"
    UNCENSORED = "uncensored"


class RoutingStrategy(str, Enum):
    BEST_FIT = "best_fit"
    CASCADE = "cascade"
    ENSEMBLE = "ensemble"
    ROUND_ROBIN = "round_robin"
    LEAST_LOADED = "least_loaded"
    RANDOM = "random"


@dataclass
class ModelProfile:
    """Profile for a single model's capabilities."""
    model_id: str = ""
    display_name: str = ""
    context_window: int = 4096
    avg_latency_ms: float = 500.0
    tokens_per_second: float = 30.0
    specializations: list[TaskType] = field(default_factory=list)
    quality_scores: dict[str, float] = field(default_factory=dict)
    total_requests: int = 0
    total_errors: int = 0
    is_available: bool = True
    current_load: int = 0
    max_concurrent: int = 4

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_errors / self.total_requests

    @property
    def utilization(self) -> float:
        return self.current_load / max(self.max_concurrent, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "ctx": self.context_window,
            "latency": f"{self.avg_latency_ms:.0f}ms",
            "tps": f"{self.tokens_per_second:.0f}",
            "load": f"{self.current_load}/{self.max_concurrent}",
            "err": f"{self.error_rate:.0%}",
            "specs": len(self.specializations),
        }


@dataclass
class RoutingDecision:
    """Result of a routing decision."""
    model_id: str = ""
    strategy_used: RoutingStrategy = RoutingStrategy.BEST_FIT
    score: float = 0.0
    reason: str = ""
    alternatives: list[str] = field(default_factory=list)
    cascade_fallbacks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "strategy": self.strategy_used.value[:10],
            "score": f"{self.score:.2f}",
            "alts": len(self.alternatives),
        }


@dataclass
class RoutingFeedback:
    """Feedback from a completed request."""
    model_id: str = ""
    task_type: TaskType = TaskType.GENERAL
    quality: float = 0.5
    latency_ms: float = 0.0
    tokens_used: int = 0
    success: bool = True
    timestamp: float = field(default_factory=time.time)


# Pre-configured model profiles for user's 16 GGUF models
DEFAULT_PROFILES: list[ModelProfile] = [
    ModelProfile(model_id="whiterabbit", display_name="WhiteRabbitNeo-7B", context_window=4096, avg_latency_ms=400, tokens_per_second=35, specializations=[TaskType.SECURITY_ANALYSIS, TaskType.EXPLOIT_DEVELOPMENT, TaskType.UNCENSORED]),
    ModelProfile(model_id="qwen-coder-14b", display_name="Qwen2.5-Coder-14B", context_window=8192, avg_latency_ms=600, tokens_per_second=20, specializations=[TaskType.CODE_REVIEW, TaskType.EXPLOIT_DEVELOPMENT, TaskType.REASONING]),
    ModelProfile(model_id="qwen-coder-7b", display_name="Qwen2.5-Coder-7B", context_window=8192, avg_latency_ms=350, tokens_per_second=40, specializations=[TaskType.CODE_REVIEW, TaskType.FAST_QUERY]),
    ModelProfile(model_id="codellama-13b", display_name="CodeLlama-13B", context_window=4096, avg_latency_ms=550, tokens_per_second=22, specializations=[TaskType.CODE_REVIEW, TaskType.EXPLOIT_DEVELOPMENT]),
    ModelProfile(model_id="codellama-7b", display_name="CodeLlama-7B", context_window=4096, avg_latency_ms=300, tokens_per_second=45, specializations=[TaskType.CODE_REVIEW, TaskType.FAST_QUERY]),
    ModelProfile(model_id="deepseek-r1", display_name="DeepSeek-R1-Distill-7B", context_window=8192, avg_latency_ms=450, tokens_per_second=30, specializations=[TaskType.REASONING, TaskType.PLANNING, TaskType.SECURITY_ANALYSIS]),
    ModelProfile(model_id="deepseek-math", display_name="DeepSeek-Math-7B", context_window=4096, avg_latency_ms=380, tokens_per_second=35, specializations=[TaskType.REASONING]),
    ModelProfile(model_id="hermes-4-14b", display_name="Hermes-4-14B", context_window=8192, avg_latency_ms=650, tokens_per_second=18, specializations=[TaskType.GENERAL, TaskType.REASONING, TaskType.PLANNING]),
    ModelProfile(model_id="llama-3.1-8b", display_name="Llama-3.1-8B", context_window=8192, avg_latency_ms=400, tokens_per_second=35, specializations=[TaskType.GENERAL, TaskType.REPORT_WRITING]),
    ModelProfile(model_id="dolphin-2.9", display_name="Dolphin-2.9-Llama3-8B", context_window=8192, avg_latency_ms=380, tokens_per_second=35, specializations=[TaskType.UNCENSORED, TaskType.SECURITY_ANALYSIS, TaskType.GENERAL]),
    ModelProfile(model_id="mistral-7b", display_name="Mistral-7B-v0.3", context_window=8192, avg_latency_ms=350, tokens_per_second=40, specializations=[TaskType.GENERAL, TaskType.FAST_QUERY, TaskType.TOOL_SELECTION]),
    ModelProfile(model_id="yi-9b-200k", display_name="Yi-9B-200K", context_window=200000, avg_latency_ms=500, tokens_per_second=25, specializations=[TaskType.LONG_CONTEXT, TaskType.CODE_REVIEW]),
    ModelProfile(model_id="llama-guard", display_name="Llama-Guard-3-1B", context_window=4096, avg_latency_ms=100, tokens_per_second=100, specializations=[TaskType.SAFETY_CHECK]),
    ModelProfile(model_id="nomic-embed", display_name="Nomic-Embed-v1.5", context_window=2048, avg_latency_ms=50, tokens_per_second=200, specializations=[TaskType.EMBEDDING]),
    ModelProfile(model_id="functiongemma", display_name="FunctionGemma-270m", context_window=2048, avg_latency_ms=30, tokens_per_second=300, specializations=[TaskType.FUNCTION_CALL, TaskType.TOOL_SELECTION]),
    ModelProfile(model_id="phi-3.5-mini", display_name="Phi-3.5-mini", context_window=4096, avg_latency_ms=150, tokens_per_second=80, specializations=[TaskType.FAST_QUERY, TaskType.OUTPUT_PARSING]),
]


class ModelRoutingOptimizer:
    """Intelligent LLM routing and load balancing."""

    def __init__(self) -> None:
        self._profiles: dict[str, ModelProfile] = {}
        for p in DEFAULT_PROFILES:
            self._profiles[p.model_id] = p
        self._feedback_history: list[RoutingFeedback] = []
        self._task_quality: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
        self._routing_count = 0
        self._log = logger.bind(component="model_router")

    def route(
        self,
        task_type: TaskType,
        context_length: int = 0,
        strategy: RoutingStrategy = RoutingStrategy.BEST_FIT,
        require_uncensored: bool = False,
    ) -> RoutingDecision:
        """Route a request to the best model."""
        self._routing_count += 1

        if strategy == RoutingStrategy.BEST_FIT:
            return self._route_best_fit(task_type, context_length, require_uncensored)
        elif strategy == RoutingStrategy.CASCADE:
            return self._route_cascade(task_type, context_length)
        elif strategy == RoutingStrategy.ENSEMBLE:
            return self._route_ensemble(task_type)
        elif strategy == RoutingStrategy.LEAST_LOADED:
            return self._route_least_loaded(task_type)
        else:
            return self._route_best_fit(task_type, context_length, require_uncensored)

    def _route_best_fit(
        self,
        task_type: TaskType,
        context_length: int,
        require_uncensored: bool,
    ) -> RoutingDecision:
        """Route to the best-fit model for this task."""
        candidates: list[tuple[str, float]] = []

        for model_id, profile in self._profiles.items():
            if not profile.is_available:
                continue
            if profile.utilization >= 1.0:
                continue
            if context_length > profile.context_window:
                continue
            if require_uncensored and TaskType.UNCENSORED not in profile.specializations:
                continue

            score = self._score_model(profile, task_type)
            candidates.append((model_id, score))

        if not candidates:
            # Fallback to any available
            for model_id, profile in self._profiles.items():
                if profile.is_available:
                    candidates.append((model_id, 0.1))
            if not candidates:
                return RoutingDecision(model_id="", reason="No models available")

        candidates.sort(key=lambda x: x[1], reverse=True)
        best_id, best_score = candidates[0]

        return RoutingDecision(
            model_id=best_id,
            strategy_used=RoutingStrategy.BEST_FIT,
            score=best_score,
            reason=f"Best fit for {task_type.value}",
            alternatives=[c[0] for c in candidates[1:3]],
        )

    def _route_cascade(self, task_type: TaskType, context_length: int) -> RoutingDecision:
        """Route with cascade: try small/fast model first, escalate if quality too low."""
        # Order by speed (tokens/sec descending)
        fast_models = sorted(
            [(k, v) for k, v in self._profiles.items() if v.is_available and context_length <= v.context_window],
            key=lambda x: x[1].tokens_per_second,
            reverse=True,
        )

        fallbacks = []
        for model_id, profile in fast_models:
            if task_type in profile.specializations:
                fallbacks.append(model_id)

        if not fallbacks:
            fallbacks = [m[0] for m in fast_models[:3]]

        primary = fallbacks[0] if fallbacks else ""
        return RoutingDecision(
            model_id=primary,
            strategy_used=RoutingStrategy.CASCADE,
            score=0.7,
            reason="Cascade routing, start with fastest",
            cascade_fallbacks=fallbacks[1:3],
        )

    def _route_ensemble(self, task_type: TaskType) -> RoutingDecision:
        """Route to multiple models for ensemble consensus."""
        specialists = []
        for model_id, profile in self._profiles.items():
            if profile.is_available and task_type in profile.specializations:
                specialists.append(model_id)

        if len(specialists) < 2:
            return self._route_best_fit(task_type, 0, False)

        return RoutingDecision(
            model_id=specialists[0],
            strategy_used=RoutingStrategy.ENSEMBLE,
            score=0.9,
            reason=f"Ensemble with {len(specialists)} models",
            alternatives=specialists[1:],
        )

    def _route_least_loaded(self, task_type: TaskType) -> RoutingDecision:
        """Route to the model with lowest utilization."""
        available = [
            (k, v) for k, v in self._profiles.items()
            if v.is_available
        ]
        if not available:
            return RoutingDecision(model_id="", reason="No models available")

        available.sort(key=lambda x: x[1].utilization)
        best_id = available[0][0]

        return RoutingDecision(
            model_id=best_id,
            strategy_used=RoutingStrategy.LEAST_LOADED,
            score=0.6,
            reason="Least loaded model",
            alternatives=[a[0] for a in available[1:3]],
        )

    def _score_model(self, profile: ModelProfile, task_type: TaskType) -> float:
        """Score a model for a task type."""
        score = 0.0

        # Specialization match (most important)
        if task_type in profile.specializations:
            score += 0.5

        # Historical quality
        quality_history = self._task_quality.get(task_type.value, {}).get(profile.model_id, [])
        if quality_history:
            recent = quality_history[-10:]
            avg_quality = sum(recent) / len(recent)
            score += avg_quality * 0.3

        # Latency (prefer faster)
        if profile.avg_latency_ms < 200:
            score += 0.1
        elif profile.avg_latency_ms < 500:
            score += 0.05

        # Error rate (penalize unreliable)
        if profile.error_rate > 0.1:
            score -= 0.2

        # Load (prefer less loaded)
        score -= profile.utilization * 0.1

        return max(0.0, score)

    def record_feedback(self, feedback: RoutingFeedback) -> None:
        """Record feedback from a completed request."""
        self._feedback_history.append(feedback)
        self._task_quality[feedback.task_type.value][feedback.model_id].append(feedback.quality)

        # Keep only recent history
        history = self._task_quality[feedback.task_type.value][feedback.model_id]
        if len(history) > 100:
            self._task_quality[feedback.task_type.value][feedback.model_id] = history[-100:]

        # Update profile stats
        profile = self._profiles.get(feedback.model_id)
        if profile:
            profile.total_requests += 1
            if not feedback.success:
                profile.total_errors += 1
            # Update latency (exponential moving average)
            alpha = 0.1
            profile.avg_latency_ms = alpha * feedback.latency_ms + (1 - alpha) * profile.avg_latency_ms

    def get_model_rankings(self, task_type: TaskType | None = None) -> list[dict[str, Any]]:
        """Get models ranked by effectiveness."""
        rankings = []
        for model_id, profile in self._profiles.items():
            entry = profile.to_dict()
            if task_type:
                quality_history = self._task_quality.get(task_type.value, {}).get(model_id, [])
                if quality_history:
                    entry["avg_quality"] = f"{sum(quality_history) / len(quality_history):.2f}"
                entry["is_specialist"] = task_type in profile.specializations
            rankings.append(entry)
        return rankings

    def build_routing_prompt(self) -> str:
        """Build LLM prompt with routing info."""
        lines = ["## Model Routing Status"]
        lines.append(f"Total models: {len(self._profiles)}")
        available = sum(1 for p in self._profiles.values() if p.is_available)
        lines.append(f"Available: {available}")
        lines.append(f"Total routings: {self._routing_count}")

        lines.append("\nModel specializations:")
        for model_id, profile in self._profiles.items():
            specs = [s.value[:12] for s in profile.specializations]
            lines.append(f"  {model_id[:15]}: {', '.join(specs)}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "models": len(self._profiles),
            "available": sum(1 for p in self._profiles.values() if p.is_available),
            "total_routings": self._routing_count,
            "feedback_count": len(self._feedback_history),
        }
