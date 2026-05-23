"""Intelligent model router — routes tasks to the best LLM based on task type, load, and capability."""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any

import structlog

from recursec.llm.backends import LLMBackend, create_backend

logger = structlog.get_logger()


class ModelConfig:
    """Configuration for a single model in the router."""

    def __init__(
        self,
        name: str,
        backend_type: str,
        model_id: str,
        base_url: str,
        api_key: str = "",
        task_types: list[str] | None = None,
        priority: int = 5,
        max_concurrent: int = 10,
        weight: float = 1.0,
        **kwargs: Any,
    ):
        self.name = name
        self.backend_type = backend_type
        self.model_id = model_id
        self.base_url = base_url
        self.api_key = api_key
        self.task_types = task_types or ["general"]
        self.priority = priority
        self.max_concurrent = max_concurrent
        self.weight = weight
        self.extra = kwargs
        self.backend: LLMBackend | None = None
        self._active_requests = 0
        self._total_requests = 0
        self._total_tokens = 0
        self._total_errors = 0
        self._avg_latency_ms = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "backend_type": self.backend_type,
            "model_id": self.model_id,
            "base_url": self.base_url,
            "task_types": self.task_types,
            "priority": self.priority,
            "active_requests": self._active_requests,
            "total_requests": self._total_requests,
            "total_errors": self._total_errors,
            "avg_latency_ms": round(self._avg_latency_ms, 1),
            "healthy": self.backend.is_healthy if self.backend else False,
        }


class ModelRouter:
    """Routes LLM requests to the best available model.

    Routing strategies:
    - task_type: Match model specialization to task type
    - load_balance: Spread requests across models with same capability
    - fallback: Try next model if primary fails
    - priority: Higher priority models preferred
    - weighted_random: Weighted random selection among eligible models
    """

    def __init__(self):
        self._models: dict[str, ModelConfig] = {}
        self._task_type_map: dict[str, list[str]] = {}  # task_type -> [model_names]
        self._fallback_chain: list[str] = []
        self._lock = asyncio.Lock()

    async def add_model(self, config: ModelConfig) -> None:
        """Add a model to the router. Can be called at runtime (hot-add)."""
        async with self._lock:
            backend = create_backend(
                backend_type=config.backend_type,
                model_id=config.model_id,
                base_url=config.base_url,
                api_key=config.api_key,
                **config.extra,
            )
            config.backend = backend
            self._models[config.name] = config

            # Update task type map
            for task_type in config.task_types:
                if task_type not in self._task_type_map:
                    self._task_type_map[task_type] = []
                if config.name not in self._task_type_map[task_type]:
                    self._task_type_map[task_type].append(config.name)

            # Add to fallback chain
            if config.name not in self._fallback_chain:
                self._fallback_chain.append(config.name)
                self._fallback_chain.sort(key=lambda n: self._models[n].priority)

            logger.info("model_added", name=config.name, model_id=config.model_id, task_types=config.task_types)

    async def remove_model(self, name: str) -> None:
        """Remove a model from the router (hot-remove)."""
        async with self._lock:
            config = self._models.pop(name, None)
            if config and config.backend:
                await config.backend.close()
            # Clean task type map
            for task_type, names in self._task_type_map.items():
                if name in names:
                    names.remove(name)
            if name in self._fallback_chain:
                self._fallback_chain.remove(name)
            logger.info("model_removed", name=name)

    def _select_model(self, task_type: str = "general", prefer_model: str | None = None) -> ModelConfig | None:
        """Select the best model for the given task type."""
        if prefer_model and prefer_model in self._models:
            config = self._models[prefer_model]
            if config.backend and config.backend.is_healthy and config._active_requests < config.max_concurrent:
                return config

        # Find models that match this task type
        candidates = []
        model_names = self._task_type_map.get(task_type, []) or self._task_type_map.get("general", [])

        for name in model_names:
            config = self._models.get(name)
            if not config or not config.backend or not config.backend.is_healthy:
                continue
            if config._active_requests >= config.max_concurrent:
                continue
            candidates.append(config)

        if not candidates:
            # Fallback: try any healthy model
            for name in self._fallback_chain:
                config = self._models.get(name)
                if config and config.backend and config.backend.is_healthy:
                    if config._active_requests < config.max_concurrent:
                        candidates.append(config)
                        break

        if not candidates:
            return None

        # Weighted selection among candidates
        total_weight = sum(c.weight for c in candidates)
        if total_weight <= 0:
            return candidates[0]

        r = random.uniform(0, total_weight)
        cumulative = 0.0
        for c in candidates:
            cumulative += c.weight
            if r <= cumulative:
                return c
        return candidates[-1]

    async def generate(
        self,
        messages: list[dict[str, str]],
        task_type: str = "general",
        prefer_model: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | None = None,
        response_format: dict[str, Any] | None = None,
        max_retries: int = 3,
    ) -> str:
        """Generate a response using the best available model.

        Returns the assistant message content as a string.
        """
        last_error = None

        for attempt in range(max_retries):
            config = self._select_model(task_type, prefer_model)
            if not config or not config.backend:
                if attempt < max_retries - 1:
                    await asyncio.sleep(1.0 * (attempt + 1))
                    continue
                raise RuntimeError(f"No healthy model available for task_type={task_type}")

            config._active_requests += 1
            start = time.monotonic()
            try:
                response = await config.backend.generate(
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=tools,
                    tool_choice=tool_choice,
                    response_format=response_format,
                )
                elapsed_ms = (time.monotonic() - start) * 1000
                config._total_requests += 1
                config._avg_latency_ms = (
                    config._avg_latency_ms * (config._total_requests - 1) + elapsed_ms
                ) / config._total_requests

                # Track token usage
                usage = response.get("usage", {})
                config._total_tokens += usage.get("total_tokens", 0)

                # Extract content
                choices = response.get("choices", [])
                if choices:
                    msg = choices[0].get("message", {})
                    content = msg.get("content", "")
                    return content

                return ""

            except Exception as e:
                config._total_errors += 1
                last_error = e
                logger.warning("model_error", model=config.name, attempt=attempt + 1, error=str(e))
                if attempt < max_retries - 1:
                    await asyncio.sleep(1.0 * (attempt + 1))
            finally:
                config._active_requests -= 1

        raise RuntimeError(f"All retries exhausted for task_type={task_type}: {last_error}")

    async def generate_with_tools(
        self,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]],
        task_type: str = "general",
        prefer_model: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> dict[str, Any]:
        """Generate with tool calling. Returns the full response for tool call parsing."""
        config = self._select_model(task_type, prefer_model)
        if not config or not config.backend:
            raise RuntimeError(f"No healthy model available for task_type={task_type}")

        config._active_requests += 1
        try:
            response = await config.backend.generate(
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                tools=tools,
                tool_choice="auto",
            )
            config._total_requests += 1
            return response
        finally:
            config._active_requests -= 1

    async def health_check_all(self) -> dict[str, bool]:
        """Run health checks on all models."""
        results = {}
        tasks = []
        for name, config in self._models.items():
            if config.backend:
                tasks.append((name, config.backend.health_check()))

        for name, coro in tasks:
            try:
                results[name] = await coro
            except Exception:
                results[name] = False

        return results

    def list_models(self) -> list[dict[str, Any]]:
        """List all configured models and their stats."""
        return [config.to_dict() for config in self._models.values()]

    async def close_all(self) -> None:
        """Close all backend connections."""
        for config in self._models.values():
            if config.backend:
                await config.backend.close()
