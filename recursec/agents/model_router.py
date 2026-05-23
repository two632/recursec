"""Model router — intelligent routing of requests to optimal LLM models.

Implements:
1. Capability-based routing (security, code, reasoning, etc.)
2. Load balancing across available models
3. Latency-aware routing
4. Quality-weighted selection
5. Fallback chains for model failures
6. Context-length-aware routing
7. Cost optimization (prefer smaller models for simple tasks)
8. Health monitoring and circuit breaking
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ModelEndpoint:
    """Configuration for a model endpoint."""
    name: str = ""
    host: str = "127.0.0.1"
    port: int = 8080
    capabilities: list[str] = field(default_factory=list)
    weight: float = 1.0
    context_length: int = 4096
    enabled: bool = True
    healthy: bool = True
    # Performance tracking
    total_requests: int = 0
    total_errors: int = 0
    avg_latency_ms: float = 0.0
    last_error_at: float = 0.0
    last_success_at: float = 0.0
    consecutive_errors: int = 0
    # Circuit breaker
    circuit_open: bool = False
    circuit_open_until: float = 0.0

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_errors / self.total_requests

    @property
    def is_available(self) -> bool:
        if not self.enabled or not self.healthy:
            return False
        if self.circuit_open and time.time() < self.circuit_open_until:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "port": self.port,
            "caps": self.capabilities[:4],
            "weight": self.weight,
            "available": self.is_available,
            "requests": self.total_requests,
            "error_rate": round(self.error_rate, 2),
            "latency_ms": round(self.avg_latency_ms, 0),
        }


@dataclass
class RoutingDecision:
    """A routing decision."""
    model: str = ""
    reason: str = ""
    score: float = 0.0
    alternatives: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model, "reason": self.reason[:40],
            "score": round(self.score, 2),
            "alternatives": self.alternatives[:3],
        }


# ── Default Model Mappings ────────────────────────────────────

CAPABILITY_MAP: dict[str, list[str]] = {
    "security": ["whiterabbit", "dolphin", "hermes-14b"],
    "code": ["qwen-coder-14b", "qwen-coder-7b", "codellama-13b", "codellama-7b"],
    "code_audit": ["qwen-coder-14b", "codellama-13b", "yi-9b-200k"],
    "reasoning": ["deepseek-r1", "hermes-14b", "llama-8b"],
    "planning": ["deepseek-r1", "hermes-14b", "mistral-7b"],
    "exploit": ["whiterabbit", "dolphin"],
    "math": ["deepseek-math"],
    "long_context": ["yi-9b-200k"],
    "fast": ["phi-3.5-mini", "functiongemma", "codellama-7b"],
    "general": ["hermes-14b", "llama-8b", "mistral-7b", "dolphin"],
    "embedding": ["nomic-embed"],
    "safety": ["llama-guard"],
    "function_call": ["functiongemma"],
    "tool_routing": ["functiongemma"],
    "uncensored": ["dolphin"],
}


class ModelRouter:
    """Intelligent routing of requests to optimal LLM models.

    Routes based on capability, load, latency, quality,
    and model health with circuit breaking.
    """

    def __init__(self) -> None:
        self._models: dict[str, ModelEndpoint] = {}
        self._routing_count = 0
        self._fallback_count = 0
        self._circuit_break_threshold = 5  # Consecutive errors
        self._circuit_break_duration_s = 60.0
        self._log = logger.bind(component="model_router")

    def register_model(self, endpoint: ModelEndpoint) -> None:
        """Register a model endpoint."""
        self._models[endpoint.name] = endpoint

    def register_defaults(self) -> None:
        """Register default models from config."""
        defaults = [
            ("whiterabbit", 8100, ["security", "exploit"], 2.0, 4096),
            ("qwen-coder-14b", 8101, ["code", "code_audit"], 1.5, 8192),
            ("qwen-coder-7b", 8102, ["code", "code_audit"], 1.0, 8192),
            ("deepseek-r1", 8103, ["reasoning", "planning"], 1.5, 8192),
            ("deepseek-math", 8104, ["math", "reasoning"], 0.8, 4096),
            ("hermes-14b", 8105, ["general", "reasoning", "planning"], 1.2, 4096),
            ("llama-8b", 8106, ["general", "reasoning"], 1.0, 4096),
            ("dolphin", 8107, ["general", "security", "uncensored"], 1.2, 4096),
            ("mistral-7b", 8108, ["general", "fast", "reasoning"], 1.0, 4096),
            ("codellama-13b", 8109, ["code", "code_audit"], 1.3, 4096),
            ("codellama-7b", 8110, ["code", "fast"], 0.8, 4096),
            ("yi-9b-200k", 8111, ["long_context", "code_audit"], 1.0, 200000),
            ("phi-3.5-mini", 8112, ["fast", "general"], 0.6, 4096),
            ("llama-guard", 8113, ["safety"], 0.5, 4096),
            ("nomic-embed", 8114, ["embedding"], 1.0, 2048),
            ("functiongemma", 8115, ["function_call", "tool_routing"], 0.5, 2048),
        ]

        for name, port, caps, weight, ctx in defaults:
            self.register_model(ModelEndpoint(
                name=name, port=port,
                capabilities=caps, weight=weight,
                context_length=ctx,
            ))

    def route(
        self,
        capability: str = "general",
        context_needed: int = 0,
        prefer_fast: bool = False,
        prefer_quality: bool = False,
    ) -> RoutingDecision:
        """Route a request to the best model."""
        self._routing_count += 1

        candidates = self._get_candidates(capability, context_needed)

        if not candidates:
            # Fallback to any available model
            candidates = [m for m in self._models.values() if m.is_available]
            self._fallback_count += 1

        if not candidates:
            return RoutingDecision(reason="no_models_available")

        # Score candidates
        scored = []
        for model in candidates:
            score = self._score_model(model, capability, prefer_fast, prefer_quality)
            scored.append((score, model))

        scored.sort(key=lambda x: x[0], reverse=True)

        best_score, best_model = scored[0]
        alternatives = [m.name for _, m in scored[1:4]]

        return RoutingDecision(
            model=best_model.name,
            reason=f"capability={capability}",
            score=best_score,
            alternatives=alternatives,
        )

    def _get_candidates(
        self,
        capability: str,
        context_needed: int,
    ) -> list[ModelEndpoint]:
        """Get candidate models for a capability."""
        # First try capability map
        preferred = CAPABILITY_MAP.get(capability, [])
        candidates = []

        for name in preferred:
            model = self._models.get(name)
            if model and model.is_available:
                if context_needed <= 0 or model.context_length >= context_needed:
                    candidates.append(model)

        # If no preferred models, try all capable
        if not candidates:
            for model in self._models.values():
                if model.is_available and capability in model.capabilities:
                    if context_needed <= 0 or model.context_length >= context_needed:
                        candidates.append(model)

        return candidates

    def _score_model(
        self,
        model: ModelEndpoint,
        capability: str,
        prefer_fast: bool,
        prefer_quality: bool,
    ) -> float:
        """Score a model for routing."""
        score = model.weight

        # Capability match bonus
        if capability in model.capabilities:
            score += 2.0

        # Error rate penalty
        score -= model.error_rate * 3.0

        # Latency factor
        if prefer_fast:
            if model.avg_latency_ms > 0:
                score -= model.avg_latency_ms / 5000.0
            if "fast" in model.capabilities:
                score += 1.0

        # Quality factor
        if prefer_quality:
            if model.weight >= 1.5:
                score += 1.0
            if model.context_length >= 8192:
                score += 0.5

        # Load balancing (prefer less-used models)
        if model.total_requests > 0:
            max_requests = max(m.total_requests for m in self._models.values() if m.total_requests > 0)
            if max_requests > 0:
                load_factor = model.total_requests / max_requests
                score -= load_factor * 0.5

        # Small random factor for load distribution
        score += random.random() * 0.1

        return score

    def record_success(self, model_name: str, latency_ms: float) -> None:
        """Record a successful request."""
        model = self._models.get(model_name)
        if not model:
            return

        model.total_requests += 1
        model.consecutive_errors = 0
        model.last_success_at = time.time()

        # Running average latency
        if model.avg_latency_ms == 0:
            model.avg_latency_ms = latency_ms
        else:
            model.avg_latency_ms = model.avg_latency_ms * 0.9 + latency_ms * 0.1

        # Reset circuit breaker
        if model.circuit_open:
            model.circuit_open = False

    def record_error(self, model_name: str) -> None:
        """Record a request error."""
        model = self._models.get(model_name)
        if not model:
            return

        model.total_requests += 1
        model.total_errors += 1
        model.consecutive_errors += 1
        model.last_error_at = time.time()

        # Circuit breaker
        if model.consecutive_errors >= self._circuit_break_threshold:
            model.circuit_open = True
            model.circuit_open_until = time.time() + self._circuit_break_duration_s

    def get_model_status(self) -> list[dict[str, Any]]:
        return [m.to_dict() for m in self._models.values()]

    def get_stats(self) -> dict[str, Any]:
        available = sum(1 for m in self._models.values() if m.is_available)
        return {
            "models": len(self._models),
            "available": available,
            "routing_count": self._routing_count,
            "fallback_count": self._fallback_count,
        }
