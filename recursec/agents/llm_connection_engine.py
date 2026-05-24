"""LLM connection engine — optimal multi-model orchestration.

How the agent connects to and uses LLMs effectively:
1. Model health monitoring and failover
2. Context window optimization per model
3. Prompt routing based on task type + model strengths
4. Multi-turn conversation state management
5. Token budget tracking and adaptive allocation
6. Response quality scoring and model selection feedback
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ModelHealth(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNRESPONSIVE = "unresponsive"
    OVERLOADED = "overloaded"
    STARTING = "starting"


class TaskDomain(str, Enum):
    SECURITY = "security"
    CODE = "code"
    REASONING = "reasoning"
    FAST = "fast"
    LONG_CONTEXT = "long_context"
    EMBEDDING = "embedding"
    SAFETY = "safety"
    FUNCTION_CALL = "function_call"
    GENERAL = "general"
    UNCENSORED = "uncensored"
    MATH = "math"


@dataclass
class ModelEndpoint:
    """An LLM server endpoint."""
    model_id: str = ""
    model_name: str = ""
    endpoint_url: str = ""
    port: int = 0
    context_size: int = 4096
    domains: list[TaskDomain] = field(default_factory=list)
    domain_weights: dict[str, float] = field(default_factory=dict)
    health: ModelHealth = ModelHealth.STARTING
    avg_latency_ms: float = 0.0
    total_requests: int = 0
    total_tokens: int = 0
    error_count: int = 0
    last_health_check: float = 0.0
    max_concurrent: int = 4

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.error_count / self.total_requests

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.model_id[:12],
            "name": self.model_name[:20],
            "health": self.health.value[:8],
            "latency": f"{self.avg_latency_ms:.0f}ms",
            "requests": self.total_requests,
            "errors": f"{self.error_rate:.1%}",
        }


@dataclass
class RoutingDecision:
    """A model routing decision."""
    selected_model: str = ""
    reason: str = ""
    fallback_model: str = ""
    token_budget: int = 4096
    expected_latency_ms: float = 0.0
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.selected_model[:15],
            "reason": self.reason[:20],
            "budget": self.token_budget,
        }


@dataclass
class ConversationState:
    """Multi-turn conversation state for an agent."""
    conversation_id: str = ""
    model_id: str = ""
    messages: list[dict[str, str]] = field(default_factory=list)
    total_tokens: int = 0
    max_tokens: int = 4096
    started_at: float = field(default_factory=time.time)

    @property
    def remaining_tokens(self) -> int:
        return max(0, self.max_tokens - self.total_tokens)

    @property
    def is_near_limit(self) -> bool:
        return self.remaining_tokens < self.max_tokens * 0.1

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.conversation_id[:8],
            "model": self.model_id[:12],
            "msgs": len(self.messages),
            "tokens": f"{self.total_tokens}/{self.max_tokens}",
        }


# Default model configurations for user's 16 GGUF models
DEFAULT_MODEL_CONFIGS: list[dict[str, Any]] = [
    {"id": "whiterabbit", "name": "WhiteRabbitNeo-7B", "port": 8100, "ctx": 4096,
     "domains": [TaskDomain.SECURITY, TaskDomain.UNCENSORED],
     "weights": {"security": 2.0, "uncensored": 1.5, "general": 0.8}},
    {"id": "qwen-coder-14b", "name": "Qwen2.5-Coder-14B", "port": 8101, "ctx": 8192,
     "domains": [TaskDomain.CODE, TaskDomain.SECURITY],
     "weights": {"code": 2.0, "security": 1.2, "general": 1.0}},
    {"id": "qwen-coder-7b", "name": "Qwen2.5-Coder-7B", "port": 8102, "ctx": 8192,
     "domains": [TaskDomain.CODE],
     "weights": {"code": 1.5, "general": 0.8}},
    {"id": "deepseek-r1", "name": "DeepSeek-R1-Distill-Qwen-7B", "port": 8103, "ctx": 8192,
     "domains": [TaskDomain.REASONING],
     "weights": {"reasoning": 2.0, "general": 1.0}},
    {"id": "yi-9b-200k", "name": "Yi-9B-200K", "port": 8104, "ctx": 200000,
     "domains": [TaskDomain.LONG_CONTEXT, TaskDomain.CODE],
     "weights": {"long_context": 3.0, "code": 1.0}},
    {"id": "phi-3.5-mini", "name": "Phi-3.5-mini", "port": 8105, "ctx": 4096,
     "domains": [TaskDomain.FAST, TaskDomain.GENERAL],
     "weights": {"fast": 2.0, "general": 1.0}},
    {"id": "mistral-7b", "name": "Mistral-7B", "port": 8106, "ctx": 8192,
     "domains": [TaskDomain.GENERAL],
     "weights": {"general": 1.5}},
    {"id": "codellama-13b", "name": "CodeLlama-13B", "port": 8107, "ctx": 16384,
     "domains": [TaskDomain.CODE],
     "weights": {"code": 1.8, "general": 0.7}},
    {"id": "codellama-7b", "name": "CodeLlama-7B", "port": 8108, "ctx": 16384,
     "domains": [TaskDomain.CODE, TaskDomain.FAST],
     "weights": {"code": 1.3, "fast": 1.0}},
    {"id": "hermes-4-14b", "name": "Hermes-4-14B", "port": 8109, "ctx": 8192,
     "domains": [TaskDomain.GENERAL, TaskDomain.REASONING],
     "weights": {"general": 1.5, "reasoning": 1.2}},
    {"id": "llama-3.1-8b", "name": "Llama-3.1-8B", "port": 8110, "ctx": 8192,
     "domains": [TaskDomain.GENERAL],
     "weights": {"general": 1.2}},
    {"id": "dolphin-2.9", "name": "Dolphin-2.9", "port": 8111, "ctx": 8192,
     "domains": [TaskDomain.UNCENSORED, TaskDomain.GENERAL],
     "weights": {"uncensored": 2.0, "general": 1.0, "security": 1.2}},
    {"id": "deepseek-math", "name": "DeepSeek-Math-7B", "port": 8112, "ctx": 4096,
     "domains": [TaskDomain.MATH, TaskDomain.REASONING],
     "weights": {"math": 2.0, "reasoning": 1.5}},
    {"id": "nomic-embed", "name": "Nomic-Embed-Text", "port": 8113, "ctx": 8192,
     "domains": [TaskDomain.EMBEDDING],
     "weights": {"embedding": 3.0}},
    {"id": "llama-guard", "name": "Llama-Guard-3", "port": 8114, "ctx": 4096,
     "domains": [TaskDomain.SAFETY],
     "weights": {"safety": 3.0}},
    {"id": "functiongemma", "name": "FunctionGemma-270m", "port": 8115, "ctx": 2048,
     "domains": [TaskDomain.FUNCTION_CALL, TaskDomain.FAST],
     "weights": {"function_call": 3.0, "fast": 2.0}},
]

# Task type → preferred domain mapping
TASK_DOMAIN_MAP: dict[str, TaskDomain] = {
    "vuln_scan": TaskDomain.SECURITY,
    "code_audit": TaskDomain.CODE,
    "code_review": TaskDomain.CODE,
    "planning": TaskDomain.REASONING,
    "analysis": TaskDomain.REASONING,
    "exploit_dev": TaskDomain.SECURITY,
    "recon": TaskDomain.GENERAL,
    "fast_triage": TaskDomain.FAST,
    "tool_routing": TaskDomain.FUNCTION_CALL,
    "long_analysis": TaskDomain.LONG_CONTEXT,
    "embedding": TaskDomain.EMBEDDING,
    "safety_check": TaskDomain.SAFETY,
    "crypto_analysis": TaskDomain.MATH,
    "uncensored": TaskDomain.UNCENSORED,
}


class LLMConnectionEngine:
    """Manages connections to all LLM endpoints."""

    def __init__(self) -> None:
        self._models: dict[str, ModelEndpoint] = {}
        self._conversations: dict[str, ConversationState] = {}
        self._routing_history: list[RoutingDecision] = []
        self._conv_counter = 0
        self._log = logger.bind(component="llm_engine")
        self._initialize_models()

    def _initialize_models(self) -> None:
        for cfg in DEFAULT_MODEL_CONFIGS:
            model = ModelEndpoint(
                model_id=cfg["id"],
                model_name=cfg["name"],
                endpoint_url=f"http://localhost:{cfg['port']}/v1",
                port=cfg["port"],
                context_size=cfg["ctx"],
                domains=cfg["domains"],
                domain_weights=cfg["weights"],
                health=ModelHealth.STARTING,
            )
            self._models[cfg["id"]] = model

    def route_request(
        self,
        task_type: str,
        required_context: int = 4096,
        prefer_fast: bool = False,
    ) -> RoutingDecision:
        """Route a request to the optimal model."""
        domain = TASK_DOMAIN_MAP.get(task_type, TaskDomain.GENERAL)

        candidates: list[tuple[float, ModelEndpoint]] = []
        for model in self._models.values():
            if model.health in (ModelHealth.UNRESPONSIVE, ModelHealth.OVERLOADED):
                continue
            if required_context > model.context_size:
                continue

            score = model.domain_weights.get(domain.value, 0.5)
            if prefer_fast and TaskDomain.FAST in model.domains:
                score *= 1.5
            if model.error_rate > 0.3:
                score *= 0.5
            candidates.append((score, model))

        if not candidates:
            return RoutingDecision(
                selected_model="phi-3.5-mini",
                reason="fallback (no candidates)",
                token_budget=min(required_context, 4096),
            )

        candidates.sort(key=lambda x: x[0], reverse=True)
        best_score, best_model = candidates[0]
        fallback = candidates[1][1].model_id if len(candidates) > 1 else ""

        decision = RoutingDecision(
            selected_model=best_model.model_id,
            reason=f"best for {domain.value} (score={best_score:.2f})",
            fallback_model=fallback,
            token_budget=min(required_context, best_model.context_size),
            expected_latency_ms=best_model.avg_latency_ms,
            confidence=min(best_score / 2.0, 1.0),
        )

        self._routing_history.append(decision)
        if len(self._routing_history) > 1000:
            self._routing_history = self._routing_history[-500:]

        return decision

    def create_conversation(
        self,
        model_id: str,
        system_prompt: str = "",
    ) -> ConversationState:
        """Create a new multi-turn conversation."""
        self._conv_counter += 1
        model = self._models.get(model_id)
        max_tokens = model.context_size if model else 4096

        conv = ConversationState(
            conversation_id=f"conv-{self._conv_counter}",
            model_id=model_id,
            max_tokens=max_tokens,
        )
        if system_prompt:
            conv.messages.append({"role": "system", "content": system_prompt})
            conv.total_tokens += len(system_prompt) // 4  # rough estimate

        self._conversations[conv.conversation_id] = conv
        return conv

    def add_message(
        self,
        conversation_id: str,
        role: str,
        content: str,
    ) -> bool:
        """Add a message to a conversation."""
        conv = self._conversations.get(conversation_id)
        if not conv:
            return False

        est_tokens = len(content) // 4
        if conv.total_tokens + est_tokens > conv.max_tokens:
            # Compress: remove oldest non-system messages
            while conv.messages and conv.total_tokens + est_tokens > conv.max_tokens * 0.8:
                if conv.messages[0]["role"] == "system":
                    if len(conv.messages) > 1:
                        removed = conv.messages.pop(1)
                        conv.total_tokens -= len(removed["content"]) // 4
                    else:
                        break
                else:
                    removed = conv.messages.pop(0)
                    conv.total_tokens -= len(removed["content"]) // 4

        conv.messages.append({"role": role, "content": content})
        conv.total_tokens += est_tokens
        return True

    def update_model_health(
        self,
        model_id: str,
        health: ModelHealth,
        latency_ms: float = 0.0,
    ) -> None:
        """Update model health status."""
        model = self._models.get(model_id)
        if not model:
            return
        model.health = health
        model.last_health_check = time.time()
        if latency_ms > 0:
            # Exponential moving average
            alpha = 0.3
            model.avg_latency_ms = (
                alpha * latency_ms + (1 - alpha) * model.avg_latency_ms
            )

    def record_request(
        self,
        model_id: str,
        tokens_used: int,
        success: bool,
    ) -> None:
        """Record a completed request."""
        model = self._models.get(model_id)
        if not model:
            return
        model.total_requests += 1
        model.total_tokens += tokens_used
        if not success:
            model.error_count += 1

    def get_healthy_models(self) -> list[ModelEndpoint]:
        """Get all healthy model endpoints."""
        return [
            m for m in self._models.values()
            if m.health in (ModelHealth.HEALTHY, ModelHealth.STARTING)
        ]

    def get_model_for_domain(self, domain: TaskDomain) -> ModelEndpoint | None:
        """Get the best model for a specific domain."""
        best: ModelEndpoint | None = None
        best_weight = 0.0
        for model in self._models.values():
            if model.health == ModelHealth.UNRESPONSIVE:
                continue
            weight = model.domain_weights.get(domain.value, 0.0)
            if weight > best_weight:
                best_weight = weight
                best = model
        return best

    def build_connection_prompt(self) -> str:
        """Build LLM prompt with model connection status."""
        lines = ["## LLM Connection Status\n"]
        for model in self._models.values():
            lines.append(
                f"  {model.model_name}: {model.health.value} "
                f"(ctx={model.context_size}, "
                f"reqs={model.total_requests})"
            )
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        health_counts: dict[str, int] = {}
        for m in self._models.values():
            key = m.health.value
            health_counts[key] = health_counts.get(key, 0) + 1
        return {
            "total_models": len(self._models),
            "healthy": health_counts.get("healthy", 0),
            "conversations": len(self._conversations),
            "routing_decisions": len(self._routing_history),
            "total_requests": sum(m.total_requests for m in self._models.values()),
            "total_tokens": sum(m.total_tokens for m in self._models.values()),
        }
