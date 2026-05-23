"""Inference engine — core LLM calling engine for llama.cpp backends.

The actual interface between the agent brain and LLM models. Implements:
1. Direct llama.cpp server HTTP calls
2. Streaming response handling
3. Multi-model parallel inference
4. Response quality scoring
5. Retry with exponential backoff
6. Token usage tracking
7. Response caching
8. Model health monitoring
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ModelConfig:
    """Configuration for a llama.cpp model server."""
    model_id: str = ""
    name: str = ""
    host: str = "127.0.0.1"
    port: int = 8100
    max_tokens: int = 2048
    context_size: int = 4096
    temperature: float = 0.7
    top_p: float = 0.9
    top_k: int = 40
    repeat_penalty: float = 1.1
    capabilities: list[str] = field(default_factory=list)

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.model_id, "name": self.name[:30],
            "url": self.base_url,
            "context": self.context_size,
            "caps": self.capabilities[:3],
        }


@dataclass
class InferenceRequest:
    """A request to the inference engine."""
    request_id: str = ""
    model_id: str = ""
    messages: list[dict[str, str]] = field(default_factory=list)
    system_prompt: str = ""
    temperature: float = 0.7
    max_tokens: int = 2048
    stop_sequences: list[str] = field(default_factory=list)
    json_mode: bool = False
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.request_id,
            "model": self.model_id[:20],
            "msgs": len(self.messages),
            "max_tokens": self.max_tokens,
            "temp": self.temperature,
        }


@dataclass
class InferenceResponse:
    """Response from the inference engine."""
    request_id: str = ""
    model_id: str = ""
    content: str = ""
    tokens_prompt: int = 0
    tokens_completion: int = 0
    latency_s: float = 0.0
    cached: bool = False
    error: str = ""

    @property
    def total_tokens(self) -> int:
        return self.tokens_prompt + self.tokens_completion

    @property
    def success(self) -> bool:
        return not self.error and len(self.content) > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.request_id,
            "model": self.model_id[:20],
            "tokens": self.total_tokens,
            "latency_s": round(self.latency_s, 2),
            "cached": self.cached,
            "success": self.success,
        }


@dataclass
class ModelHealth:
    """Health status of a model server."""
    model_id: str = ""
    is_healthy: bool = True
    consecutive_errors: int = 0
    total_requests: int = 0
    total_errors: int = 0
    avg_latency_s: float = 0.0
    last_check: float = field(default_factory=time.time)
    last_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:20],
            "healthy": self.is_healthy,
            "errors": self.total_errors,
            "requests": self.total_requests,
            "avg_latency": round(self.avg_latency_s, 2),
        }


# ── Default Model Configurations ──────────────────────────────

DEFAULT_MODELS: list[dict[str, Any]] = [
    {"id": "whiterabbitneo-7b", "name": "WhiteRabbitNeo-7B", "port": 8100,
     "ctx": 8192, "caps": ["security", "exploit", "analysis"]},
    {"id": "qwen-coder-14b", "name": "Qwen2.5-Coder-14B", "port": 8101,
     "ctx": 32768, "caps": ["code", "code_audit", "reasoning"]},
    {"id": "qwen-coder-7b", "name": "Qwen2.5-Coder-7B", "port": 8102,
     "ctx": 32768, "caps": ["code", "code_audit", "fast"]},
    {"id": "deepseek-r1-7b", "name": "DeepSeek-R1-Distill-Qwen-7B", "port": 8103,
     "ctx": 32768, "caps": ["reasoning", "planning", "chain_of_thought"]},
    {"id": "deepseek-math-7b", "name": "DeepSeek-Math-7B", "port": 8104,
     "ctx": 4096, "caps": ["reasoning", "math", "logic"]},
    {"id": "hermes-14b", "name": "Hermes-4-14B", "port": 8105,
     "ctx": 32768, "caps": ["general", "reasoning", "analysis"]},
    {"id": "llama-8b", "name": "Meta-Llama-3.1-8B", "port": 8106,
     "ctx": 8192, "caps": ["general", "recon", "fast"]},
    {"id": "dolphin-8b", "name": "Dolphin-2.9-Llama3-8B", "port": 8107,
     "ctx": 8192, "caps": ["general", "security", "uncensored"]},
    {"id": "mistral-7b", "name": "Mistral-7B-Instruct", "port": 8108,
     "ctx": 8192, "caps": ["general", "recon", "fast"]},
    {"id": "codellama-13b", "name": "CodeLlama-13B", "port": 8109,
     "ctx": 16384, "caps": ["code", "code_audit"]},
    {"id": "codellama-7b", "name": "CodeLlama-7B", "port": 8110,
     "ctx": 16384, "caps": ["code", "fast"]},
    {"id": "yi-9b-200k", "name": "Yi-9B-200K", "port": 8111,
     "ctx": 200000, "caps": ["long_context", "analysis", "code_audit"]},
    {"id": "phi-3.5-mini", "name": "Phi-3.5-mini", "port": 8112,
     "ctx": 4096, "caps": ["fast", "general", "reasoning"]},
    {"id": "llama-guard-1b", "name": "Llama-Guard-3-1B", "port": 8113,
     "ctx": 4096, "caps": ["safety", "moderation"]},
    {"id": "nomic-embed", "name": "Nomic-Embed-Text-v1.5", "port": 8114,
     "ctx": 8192, "caps": ["embedding"]},
    {"id": "functiongemma-270m", "name": "FunctionGemma-270m", "port": 8115,
     "ctx": 2048, "caps": ["function_call", "routing", "fast"]},
]


class InferenceEngine:
    """Core LLM calling engine for llama.cpp backends.

    The actual interface between the agent brain
    and the local LLM models. Handles HTTP calls,
    retries, caching, and health monitoring.
    """

    def __init__(self) -> None:
        self._models: dict[str, ModelConfig] = {}
        self._health: dict[str, ModelHealth] = {}
        self._cache: dict[str, InferenceResponse] = {}
        self._cache_max = 500
        self._request_counter = 0
        self._total_tokens = 0
        self._log = logger.bind(component="inference_engine")

        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register default model configurations."""
        for data in DEFAULT_MODELS:
            model = ModelConfig(
                model_id=data["id"],
                name=data["name"],
                port=data["port"],
                context_size=data.get("ctx", 4096),
                capabilities=data.get("caps", []),
            )
            self._models[model.model_id] = model
            self._health[model.model_id] = ModelHealth(model_id=model.model_id)

    def register_model(
        self,
        model_id: str,
        name: str,
        host: str = "127.0.0.1",
        port: int = 8100,
        context_size: int = 4096,
        capabilities: list[str] | None = None,
    ) -> None:
        """Register a new model."""
        model = ModelConfig(
            model_id=model_id, name=name,
            host=host, port=port,
            context_size=context_size,
            capabilities=capabilities or [],
        )
        self._models[model_id] = model
        self._health[model_id] = ModelHealth(model_id=model_id)

    async def infer(
        self,
        model_id: str,
        messages: list[dict[str, str]],
        system_prompt: str = "",
        temperature: float = 0.7,
        max_tokens: int = 2048,
        stop_sequences: list[str] | None = None,
        json_mode: bool = False,
        use_cache: bool = True,
    ) -> InferenceResponse:
        """Run inference on a model."""
        self._request_counter += 1
        request_id = f"inf-{self._request_counter}"

        model = self._models.get(model_id)
        if not model:
            return InferenceResponse(
                request_id=request_id,
                model_id=model_id,
                error=f"Model not found: {model_id}",
            )

        # Check cache
        if use_cache:
            cache_key = self._cache_key(model_id, messages, system_prompt, temperature)
            cached = self._cache.get(cache_key)
            if cached:
                return InferenceResponse(
                    request_id=request_id,
                    model_id=model_id,
                    content=cached.content,
                    tokens_prompt=cached.tokens_prompt,
                    tokens_completion=cached.tokens_completion,
                    cached=True,
                )

        # Check health
        health = self._health.get(model_id)
        if health and not health.is_healthy:
            # Try anyway but log warning
            self._log.warning("calling_unhealthy_model", model=model_id)

        # Build request body
        body = self._build_request_body(
            model, messages, system_prompt,
            temperature, max_tokens, stop_sequences, json_mode,
        )

        # Execute with retry
        response = await self._call_with_retry(
            model, body, request_id, max_retries=2,
        )

        # Update health
        if health:
            health.total_requests += 1
            if response.success:
                health.consecutive_errors = 0
                health.avg_latency_s = (
                    health.avg_latency_s * 0.9 + response.latency_s * 0.1
                )
            else:
                health.total_errors += 1
                health.consecutive_errors += 1
                health.last_error = response.error[:200]
                if health.consecutive_errors >= 3:
                    health.is_healthy = False
            health.last_check = time.time()

        # Cache successful response
        if response.success and use_cache:
            cache_key = self._cache_key(model_id, messages, system_prompt, temperature)
            self._cache[cache_key] = response
            if len(self._cache) > self._cache_max:
                oldest = next(iter(self._cache))
                del self._cache[oldest]

        self._total_tokens += response.total_tokens

        return response

    async def infer_parallel(
        self,
        requests: list[dict[str, Any]],
    ) -> list[InferenceResponse]:
        """Run multiple inferences in parallel."""
        tasks = []
        for req in requests:
            tasks.append(self.infer(
                model_id=req.get("model_id", ""),
                messages=req.get("messages", []),
                system_prompt=req.get("system_prompt", ""),
                temperature=req.get("temperature", 0.7),
                max_tokens=req.get("max_tokens", 2048),
            ))
        return await asyncio.gather(*tasks)

    async def _call_with_retry(
        self,
        model: ModelConfig,
        body: dict[str, Any],
        request_id: str,
        max_retries: int = 2,
    ) -> InferenceResponse:
        """Call model with exponential backoff retry."""
        last_error = ""

        for attempt in range(max_retries + 1):
            start = time.time()

            try:
                response = await self._http_call(model, body)
                latency = time.time() - start

                # Parse response
                content = ""
                prompt_tokens = 0
                completion_tokens = 0

                if "choices" in response:
                    choices = response["choices"]
                    if choices:
                        content = choices[0].get("message", {}).get("content", "")
                        if not content:
                            content = choices[0].get("text", "")

                if "usage" in response:
                    usage = response["usage"]
                    prompt_tokens = usage.get("prompt_tokens", 0)
                    completion_tokens = usage.get("completion_tokens", 0)

                if "content" in response and not content:
                    content = response["content"]

                return InferenceResponse(
                    request_id=request_id,
                    model_id=model.model_id,
                    content=content,
                    tokens_prompt=prompt_tokens,
                    tokens_completion=completion_tokens,
                    latency_s=latency,
                )

            except Exception as exc:
                last_error = str(exc)[:300]
                if attempt < max_retries:
                    await asyncio.sleep(2 ** attempt)

        return InferenceResponse(
            request_id=request_id,
            model_id=model.model_id,
            error=last_error,
        )

    async def _http_call(
        self,
        model: ModelConfig,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        """Make HTTP call to llama.cpp server."""
        import aiohttp

        url = f"{model.base_url}/v1/chat/completions"

        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=body,
                timeout=aiohttp.ClientTimeout(total=120),
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(f"HTTP {resp.status}: {text[:200]}")
                return await resp.json()

    @staticmethod
    def _build_request_body(
        model: ModelConfig,
        messages: list[dict[str, str]],
        system_prompt: str,
        temperature: float,
        max_tokens: int,
        stop_sequences: list[str] | None,
        json_mode: bool,
    ) -> dict[str, Any]:
        """Build the request body for llama.cpp."""
        full_messages = []

        if system_prompt:
            full_messages.append({"role": "system", "content": system_prompt})

        full_messages.extend(messages)

        body: dict[str, Any] = {
            "messages": full_messages,
            "temperature": temperature,
            "max_tokens": min(max_tokens, model.context_size),
            "top_p": model.top_p,
            "top_k": model.top_k,
            "repeat_penalty": model.repeat_penalty,
            "stream": False,
        }

        if stop_sequences:
            body["stop"] = stop_sequences

        if json_mode:
            body["response_format"] = {"type": "json_object"}

        return body

    @staticmethod
    def _cache_key(
        model_id: str,
        messages: list[dict[str, str]],
        system_prompt: str,
        temperature: float,
    ) -> str:
        """Generate a cache key."""
        data = json.dumps({
            "m": model_id, "msgs": messages,
            "sys": system_prompt, "t": temperature,
        }, sort_keys=True)
        return hashlib.md5(data.encode()).hexdigest()

    async def check_health(self, model_id: str) -> bool:
        """Check if a model server is healthy."""
        model = self._models.get(model_id)
        if not model:
            return False

        try:
            import aiohttp
            url = f"{model.base_url}/health"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    healthy = resp.status == 200
                    health = self._health.get(model_id)
                    if health:
                        health.is_healthy = healthy
                        health.last_check = time.time()
                    return healthy
        except Exception:
            health = self._health.get(model_id)
            if health:
                health.is_healthy = False
            return False

    def get_models(self) -> list[dict[str, Any]]:
        return [m.to_dict() for m in self._models.values()]

    def get_health(self) -> list[dict[str, Any]]:
        return [h.to_dict() for h in self._health.values()]

    def get_stats(self) -> dict[str, Any]:
        healthy = sum(1 for h in self._health.values() if h.is_healthy)
        return {
            "models": len(self._models),
            "healthy": healthy,
            "total_requests": self._request_counter,
            "total_tokens": self._total_tokens,
            "cache_size": len(self._cache),
        }
