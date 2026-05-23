"""LLM backend implementations — pluggable inference engines.

Supported:
- vLLM (highest throughput, PagedAttention)
- llama.cpp server (CPU/GPU, GGUF quantized, lightweight)
- SGLang (fastest latency, multi-turn optimized)
- LiteLLM (universal proxy — 100+ providers)
- Any OpenAI-compatible endpoint (custom)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


class LLMBackend(ABC):
    """Abstract base class for LLM inference backends."""

    def __init__(self, model_id: str, base_url: str, api_key: str = "", **kwargs: Any):
        self.model_id = model_id
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.extra_config = kwargs
        self._client: httpx.AsyncClient | None = None
        self._healthy = True

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=httpx.Timeout(300.0, connect=10.0),
            )
        return self._client

    @abstractmethod
    async def generate(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.3,
        max_tokens: int = 4096,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | None = None,
        response_format: dict[str, Any] | None = None,
        stop: list[str] | None = None,
    ) -> dict[str, Any]:
        """Generate a completion. Returns OpenAI-compatible response dict."""

    async def health_check(self) -> bool:
        """Check if this backend is healthy."""
        try:
            client = await self._get_client()
            resp = await client.get("/health", timeout=5.0)
            self._healthy = resp.status_code == 200
        except Exception:
            try:
                client = await self._get_client()
                resp = await client.get("/v1/models", timeout=5.0)
                self._healthy = resp.status_code == 200
            except Exception:
                self._healthy = False
        return self._healthy

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    @property
    def is_healthy(self) -> bool:
        return self._healthy


class OpenAICompatibleBackend(LLMBackend):
    """Works with any OpenAI-compatible API (vLLM, llama.cpp, SGLang, LiteLLM, etc.)."""

    async def generate(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.3,
        max_tokens: int = 4096,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | None = None,
        response_format: dict[str, Any] | None = None,
        stop: list[str] | None = None,
    ) -> dict[str, Any]:
        client = await self._get_client()
        payload: dict[str, Any] = {
            "model": self.model_id,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools
        if tool_choice:
            payload["tool_choice"] = tool_choice
        if response_format:
            payload["response_format"] = response_format
        if stop:
            payload["stop"] = stop

        # Merge any extra config (e.g. top_p, repetition_penalty)
        for k, v in self.extra_config.items():
            if k not in payload:
                payload[k] = v

        try:
            resp = await client.post("/v1/chat/completions", json=payload)
            resp.raise_for_status()
            data = resp.json()
            self._healthy = True
            return data
        except httpx.HTTPStatusError as e:
            self._healthy = False
            logger.error("llm_http_error", status=e.response.status_code, body=e.response.text[:500], model=self.model_id)
            raise
        except Exception as e:
            self._healthy = False
            logger.error("llm_error", error=str(e), model=self.model_id)
            raise


class VLLMBackend(OpenAICompatibleBackend):
    """vLLM-specific backend — highest throughput, PagedAttention."""

    def __init__(self, model_id: str, base_url: str = "http://localhost:8000", **kwargs: Any):
        super().__init__(model_id=model_id, base_url=base_url, **kwargs)


class LlamaCppBackend(OpenAICompatibleBackend):
    """llama.cpp server backend — lightweight, GGUF, CPU/GPU."""

    def __init__(self, model_id: str, base_url: str = "http://localhost:8080", **kwargs: Any):
        super().__init__(model_id=model_id, base_url=base_url, **kwargs)

    async def health_check(self) -> bool:
        try:
            client = await self._get_client()
            resp = await client.get("/health", timeout=5.0)
            self._healthy = resp.status_code == 200
        except Exception:
            self._healthy = False
        return self._healthy


class SGLangBackend(OpenAICompatibleBackend):
    """SGLang backend — fastest latency, RadixAttention, multi-turn optimized."""

    def __init__(self, model_id: str, base_url: str = "http://localhost:30000", **kwargs: Any):
        super().__init__(model_id=model_id, base_url=base_url, **kwargs)


class LiteLLMBackend(OpenAICompatibleBackend):
    """LiteLLM proxy backend — routes to 100+ providers."""

    def __init__(self, model_id: str, base_url: str = "http://localhost:4000", api_key: str = "", **kwargs: Any):
        super().__init__(model_id=model_id, base_url=base_url, api_key=api_key, **kwargs)


class OllamaBackend(OpenAICompatibleBackend):
    """Ollama backend — included for compatibility, but NOT recommended (slower)."""

    def __init__(self, model_id: str, base_url: str = "http://localhost:11434", **kwargs: Any):
        super().__init__(model_id=model_id, base_url=base_url, **kwargs)

    async def generate(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.3,
        max_tokens: int = 4096,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | None = None,
        response_format: dict[str, Any] | None = None,
        stop: list[str] | None = None,
    ) -> dict[str, Any]:
        # Ollama supports /v1/chat/completions (OpenAI-compat)
        return await super().generate(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            tools=tools,
            tool_choice=tool_choice,
            response_format=response_format,
            stop=stop,
        )


BACKEND_REGISTRY: dict[str, type[LLMBackend]] = {
    "vllm": VLLMBackend,
    "llama_cpp": LlamaCppBackend,
    "sglang": SGLangBackend,
    "litellm": LiteLLMBackend,
    "ollama": OllamaBackend,
    "openai_compatible": OpenAICompatibleBackend,
}


def create_backend(backend_type: str, **kwargs: Any) -> LLMBackend:
    """Factory function to create an LLM backend."""
    cls = BACKEND_REGISTRY.get(backend_type)
    if not cls:
        raise ValueError(f"Unknown backend type: {backend_type}. Available: {list(BACKEND_REGISTRY.keys())}")
    return cls(**kwargs)
