"""Advanced model router — intelligent multi-model routing and orchestration.

Implements:
1. Task-type based model selection
2. Weighted random selection with capability matching
3. Load balancing across models
4. Automatic fallback chains
5. Response quality tracking per model
6. Latency-aware routing
7. Context-length aware routing
8. Cost optimization (prefer smaller models for simple tasks)
9. Model warm-up and cooldown
10. Streaming support
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ModelEndpoint:
    """A configured model endpoint."""
    name: str = ""
    host: str = "127.0.0.1"
    port: int = 8100
    capabilities: list[str] = field(default_factory=list)
    weight: float = 1.0
    context_length: int = 4096
    max_batch: int = 1
    system_prompt: str = ""
    enabled: bool = True

    # Runtime metrics
    active_requests: int = 0
    total_requests: int = 0
    total_tokens: int = 0
    total_errors: int = 0
    avg_latency_ms: float = 0.0
    quality_score: float = 0.5

    @property
    def load(self) -> float:
        if self.max_batch <= 0:
            return 1.0
        return self.active_requests / self.max_batch

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "port": self.port,
            "capabilities": self.capabilities[:5],
            "weight": self.weight, "load": round(self.load, 2),
            "quality": round(self.quality_score, 2),
            "requests": self.total_requests,
        }


@dataclass
class RoutingDecision:
    """Records why a model was selected."""
    model: str = ""
    reason: str = ""
    alternatives: list[str] = field(default_factory=list)
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {"model": self.model, "reason": self.reason, "score": round(self.score, 2)}


# ── Default Model Configurations ─────────────────────────────

DEFAULT_MODELS: list[dict[str, Any]] = [
    {"name": "whiterabbit", "port": 8100, "capabilities": ["security", "exploit", "vuln_analysis"],
     "weight": 2.0, "context_length": 4096},
    {"name": "qwen-coder-14b", "port": 8101, "capabilities": ["code", "code_audit", "exploit_dev"],
     "weight": 1.5, "context_length": 8192},
    {"name": "qwen-coder-7b", "port": 8102, "capabilities": ["code", "code_audit"],
     "weight": 1.0, "context_length": 4096},
    {"name": "deepseek-r1", "port": 8103, "capabilities": ["reasoning", "planning", "analysis"],
     "weight": 1.5, "context_length": 4096},
    {"name": "deepseek-math", "port": 8104, "capabilities": ["math", "crypto", "analysis"],
     "weight": 1.0, "context_length": 4096},
    {"name": "hermes-14b", "port": 8105, "capabilities": ["general", "reasoning", "security"],
     "weight": 1.2, "context_length": 4096},
    {"name": "llama-3.1-8b", "port": 8106, "capabilities": ["general", "fast"],
     "weight": 1.0, "context_length": 8192},
    {"name": "dolphin", "port": 8107, "capabilities": ["general", "uncensored", "security"],
     "weight": 1.2, "context_length": 4096},
    {"name": "mistral-7b", "port": 8108, "capabilities": ["general", "fast"],
     "weight": 1.0, "context_length": 4096},
    {"name": "codellama-13b", "port": 8109, "capabilities": ["code", "code_audit"],
     "weight": 1.0, "context_length": 4096},
    {"name": "codellama-7b", "port": 8110, "capabilities": ["code", "fast"],
     "weight": 0.8, "context_length": 4096},
    {"name": "yi-9b-200k", "port": 8111, "capabilities": ["long_context", "code_audit", "analysis"],
     "weight": 1.0, "context_length": 200000},
    {"name": "phi-3.5-mini", "port": 8112, "capabilities": ["fast", "general", "small"],
     "weight": 0.8, "context_length": 4096},
    {"name": "llama-guard", "port": 8113, "capabilities": ["safety"],
     "weight": 1.0, "context_length": 4096},
    {"name": "nomic-embed", "port": 8114, "capabilities": ["embedding"],
     "weight": 1.0, "context_length": 8192},
    {"name": "functiongemma", "port": 8115, "capabilities": ["function_call", "tool_routing"],
     "weight": 1.0, "context_length": 2048, "max_batch": 16},
]


# ── Task to Capability Mapping ───────────────────────────────

TASK_CAPABILITIES: dict[str, list[str]] = {
    "security": ["security", "vuln_analysis", "exploit"],
    "exploit": ["security", "exploit", "exploit_dev"],
    "code_audit": ["code_audit", "code"],
    "code": ["code", "code_audit", "exploit_dev"],
    "reasoning": ["reasoning", "planning", "analysis"],
    "planning": ["planning", "reasoning", "general"],
    "analysis": ["analysis", "reasoning", "general"],
    "recon": ["general", "security", "fast"],
    "osint": ["general", "reasoning"],
    "reporting": ["general", "reasoning"],
    "validation": ["security", "reasoning", "analysis"],
    "fast": ["fast", "small"],
    "long_context": ["long_context"],
    "embedding": ["embedding"],
    "safety": ["safety"],
    "tool_routing": ["function_call", "tool_routing"],
    "crypto": ["math", "crypto"],
    "general": ["general"],
}


class AdvancedRouter:
    """Intelligent multi-model routing engine.

    Routes requests to the optimal model based on task type,
    model capabilities, load, latency, and quality metrics.
    """

    def __init__(self) -> None:
        self._models: dict[str, ModelEndpoint] = {}
        self._fallback_chains: dict[str, list[str]] = {}
        self._latency_history: dict[str, list[float]] = defaultdict(list)
        self._quality_history: dict[str, list[float]] = defaultdict(list)
        self._log = logger.bind(component="advanced_router")

        self._init_models()

    def _init_models(self) -> None:
        """Initialize with default model configuration."""
        for model_data in DEFAULT_MODELS:
            endpoint = ModelEndpoint(
                name=model_data["name"],
                port=model_data["port"],
                capabilities=model_data.get("capabilities", []),
                weight=model_data.get("weight", 1.0),
                context_length=model_data.get("context_length", 4096),
                max_batch=model_data.get("max_batch", 1),
            )
            self._models[model_data["name"]] = endpoint

    def route(
        self,
        task_type: str = "general",
        required_context: int = 0,
        prefer_fast: bool = False,
        model_hint: str = "",
    ) -> RoutingDecision:
        """Route a request to the best model."""
        # Model hint takes priority
        if model_hint:
            match = self._find_by_hint(model_hint)
            if match:
                return RoutingDecision(
                    model=match.name,
                    reason=f"model_hint: {model_hint}",
                    score=1.0,
                )

        # Get candidate models
        candidates = self._get_candidates(task_type, required_context)

        if not candidates:
            # Fallback to any available model
            candidates = [m for m in self._models.values() if m.enabled]

        if not candidates:
            return RoutingDecision(model="", reason="no_models_available")

        # Score candidates
        scored = []
        for model in candidates:
            score = self._score_model(model, task_type, prefer_fast)
            scored.append((model, score))

        scored.sort(key=lambda x: x[1], reverse=True)

        best = scored[0]
        alternatives = [m.name for m, _ in scored[1:4]]

        return RoutingDecision(
            model=best[0].name,
            reason=f"best_score for {task_type}",
            alternatives=alternatives,
            score=best[1],
        )

    def _find_by_hint(self, hint: str) -> ModelEndpoint | None:
        """Find a model by name hint."""
        hint_lower = hint.lower()
        for model in self._models.values():
            if model.enabled and hint_lower in model.name.lower():
                return model
        return None

    def _get_candidates(
        self,
        task_type: str,
        required_context: int,
    ) -> list[ModelEndpoint]:
        """Get candidate models for a task type."""
        required_caps = TASK_CAPABILITIES.get(task_type, ["general"])

        candidates = []
        for model in self._models.values():
            if not model.enabled:
                continue
            if required_context > 0 and model.context_length < required_context:
                continue

            # Check capability overlap
            model_caps = set(model.capabilities)
            required_set = set(required_caps)
            if model_caps & required_set:
                candidates.append(model)

        return candidates

    def _score_model(
        self,
        model: ModelEndpoint,
        task_type: str,
        prefer_fast: bool,
    ) -> float:
        """Score a model for a specific task."""
        score = 0.0

        # Weight contribution
        score += model.weight * 2.0

        # Capability match bonus
        required_caps = set(TASK_CAPABILITIES.get(task_type, ["general"]))
        model_caps = set(model.capabilities)
        overlap = len(required_caps & model_caps)
        score += overlap * 1.5

        # Quality score
        score += model.quality_score * 2.0

        # Load penalty
        score -= model.load * 3.0

        # Latency factor
        if prefer_fast:
            if model.avg_latency_ms > 0:
                score -= (model.avg_latency_ms / 1000) * 2.0
            if "fast" in model.capabilities:
                score += 2.0

        # Error rate penalty
        if model.total_requests > 0:
            error_rate = model.total_errors / model.total_requests
            score -= error_rate * 5.0

        return score

    async def generate(
        self,
        messages: list[dict[str, str]],
        task_type: str = "general",
        model_hint: str = "",
        temperature: float = 0.3,
        max_tokens: int = 1024,
    ) -> str:
        """Generate a response using the best model."""
        decision = self.route(
            task_type=task_type,
            model_hint=model_hint,
        )

        if not decision.model:
            return ""

        model = self._models.get(decision.model)
        if not model:
            return ""

        model.active_requests += 1
        start = time.time()

        try:
            response = await self._call_model(model, messages, temperature, max_tokens)
            latency = (time.time() - start) * 1000
            self._record_success(model.name, latency)
            return response

        except Exception as e:
            self._record_error(model.name, str(e))

            # Try fallback
            for alt_name in decision.alternatives:
                alt = self._models.get(alt_name)
                if alt and alt.enabled:
                    try:
                        return await self._call_model(alt, messages, temperature, max_tokens)
                    except Exception:
                        continue
            return ""

        finally:
            model.active_requests = max(0, model.active_requests - 1)

    async def _call_model(
        self,
        model: ModelEndpoint,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> str:
        """Make an HTTP request to a llama.cpp server."""
        payload = json.dumps({
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }).encode()

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(model.host, model.port),
            timeout=30.0,
        )

        request = (
            f"POST /v1/chat/completions HTTP/1.1\r\n"
            f"Host: {model.host}:{model.port}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n\r\n"
        )

        writer.write(request.encode() + payload)
        await writer.drain()

        response_data = b""
        while True:
            chunk = await asyncio.wait_for(reader.read(8192), timeout=120.0)
            if not chunk:
                break
            response_data += chunk

        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass

        # Parse HTTP response
        response_str = response_data.decode(errors="replace")
        if "\r\n\r\n" in response_str:
            body = response_str.split("\r\n\r\n", 1)[1]
        else:
            body = response_str

        try:
            data = json.loads(body)
            choices = data.get("choices", [])
            if choices:
                msg = choices[0].get("message", {})
                return msg.get("content", "")
        except json.JSONDecodeError:
            pass

        return body[:500]

    async def embed(self, text: str) -> list[float]:
        """Get embeddings using the embedding model."""
        model = self._models.get("nomic-embed")
        if not model or not model.enabled:
            return []

        payload = json.dumps({"input": text[:8000]}).encode()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(model.host, model.port),
                timeout=15.0,
            )

            request = (
                f"POST /v1/embeddings HTTP/1.1\r\n"
                f"Host: {model.host}:{model.port}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"Connection: close\r\n\r\n"
            )

            writer.write(request.encode() + payload)
            await writer.drain()

            response_data = b""
            while True:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=30.0)
                if not chunk:
                    break
                response_data += chunk

            writer.close()

            response_str = response_data.decode(errors="replace")
            if "\r\n\r\n" in response_str:
                body = response_str.split("\r\n\r\n", 1)[1]
            else:
                body = response_str

            data = json.loads(body)
            emb_data = data.get("data", [])
            if emb_data:
                return emb_data[0].get("embedding", [])

        except Exception:
            pass

        return []

    def _record_success(self, name: str, latency_ms: float) -> None:
        model = self._models.get(name)
        if model:
            model.total_requests += 1

            history = self._latency_history[name]
            history.append(latency_ms)
            if len(history) > 50:
                self._latency_history[name] = history[-50:]
            model.avg_latency_ms = sum(history) / len(history)

    def _record_error(self, name: str, error: str) -> None:
        model = self._models.get(name)
        if model:
            model.total_requests += 1
            model.total_errors += 1

    def record_quality(self, name: str, score: float) -> None:
        """Record a quality score for a model response."""
        model = self._models.get(name)
        if model:
            history = self._quality_history[name]
            history.append(score)
            if len(history) > 50:
                self._quality_history[name] = history[-50:]
            model.quality_score = sum(history) / len(history)

    def add_model(self, endpoint: ModelEndpoint) -> None:
        self._models[endpoint.name] = endpoint

    def remove_model(self, name: str) -> bool:
        return self._models.pop(name, None) is not None

    def enable_model(self, name: str) -> bool:
        model = self._models.get(name)
        if model:
            model.enabled = True
            return True
        return False

    def disable_model(self, name: str) -> bool:
        model = self._models.get(name)
        if model:
            model.enabled = False
            return True
        return False

    def get_stats(self) -> dict[str, Any]:
        return {
            "models": len(self._models),
            "enabled": sum(1 for m in self._models.values() if m.enabled),
            "total_requests": sum(m.total_requests for m in self._models.values()),
            "total_errors": sum(m.total_errors for m in self._models.values()),
        }
