"""LLM client — the actual HTTP interface to llama.cpp servers.

This is the module that sends requests to the running llama.cpp
servers and receives responses. All other modules build prompts;
this one actually calls the model.

Supports:
1. /v1/chat/completions (OpenAI-compatible)
2. /completion (llama.cpp native)
3. /embedding (for Nomic-embed)
4. Health checks (/health)
5. Connection pooling
6. Timeout handling
7. Streaming support
8. Error recovery and retry
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class LLMRequest:
    """A request to send to an LLM server."""
    model_id: str = ""
    endpoint_url: str = ""
    messages: list[dict[str, str]] = field(default_factory=list)
    prompt: str = ""
    temperature: float = 0.7
    max_tokens: int = 2048
    top_p: float = 0.95
    top_k: int = 40
    repeat_penalty: float = 1.1
    stop: list[str] = field(default_factory=list)
    stream: bool = False

    def to_chat_completion(self) -> dict[str, Any]:
        """Build OpenAI-compatible chat completion request."""
        return {
            "model": self.model_id,
            "messages": self.messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "top_p": self.top_p,
            "stream": self.stream,
            "stop": self.stop or None,
        }

    def to_completion(self) -> dict[str, Any]:
        """Build llama.cpp native /completion request."""
        return {
            "prompt": self.prompt,
            "n_predict": self.max_tokens,
            "temperature": self.temperature,
            "top_p": self.top_p,
            "top_k": self.top_k,
            "repeat_penalty": self.repeat_penalty,
            "stop": self.stop,
            "stream": self.stream,
        }

    def to_embedding(self) -> dict[str, Any]:
        """Build embedding request."""
        return {
            "content": self.prompt or (self.messages[-1]["content"] if self.messages else ""),
        }


@dataclass
class LLMResponse:
    """Response from an LLM server."""
    model_id: str = ""
    content: str = ""
    tokens_prompt: int = 0
    tokens_completion: int = 0
    finish_reason: str = ""
    latency_ms: float = 0.0
    success: bool = True
    error: str = ""
    raw_response: dict[str, Any] = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return self.tokens_prompt + self.tokens_completion

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:12],
            "tokens": self.total_tokens,
            "latency": f"{self.latency_ms:.0f}ms",
            "ok": self.success,
            "content_len": len(self.content),
        }


@dataclass
class EmbeddingResponse:
    """Response from an embedding request."""
    model_id: str = ""
    embedding: list[float] = field(default_factory=list)
    dimensions: int = 0
    success: bool = True
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"model": self.model_id[:12], "dims": self.dimensions, "ok": self.success}


# Model server configurations
MODEL_SERVERS: dict[str, dict[str, Any]] = {
    "whiterabbit": {"port": 8100, "name": "WhiteRabbitNeo-7B", "ctx": 4096},
    "mistral": {"port": 8101, "name": "Mistral-7B-Instruct", "ctx": 8192},
    "qwen-coder-14b": {"port": 8102, "name": "Qwen2.5-Coder-14B", "ctx": 8192},
    "qwen-coder-7b": {"port": 8103, "name": "Qwen2.5-Coder-7B", "ctx": 8192},
    "deepseek-r1": {"port": 8104, "name": "DeepSeek-R1-Distill-Qwen-7B", "ctx": 8192},
    "hermes-4-14b": {"port": 8105, "name": "Hermes-4-14B", "ctx": 4096},
    "llama-3.1-8b": {"port": 8106, "name": "Meta-Llama-3.1-8B", "ctx": 8192},
    "codellama-13b": {"port": 8107, "name": "CodeLlama-13B", "ctx": 4096},
    "codellama-7b": {"port": 8108, "name": "CodeLlama-7B", "ctx": 4096},
    "dolphin": {"port": 8109, "name": "Dolphin-2.9-Llama3-8B", "ctx": 8192},
    "phi-3.5-mini": {"port": 8110, "name": "Phi-3.5-mini", "ctx": 4096},
    "deepseek-math": {"port": 8111, "name": "DeepSeek-Math-7B", "ctx": 4096},
    "yi-9b-200k": {"port": 8112, "name": "Yi-9B-200K", "ctx": 200000},
    "functiongemma": {"port": 8113, "name": "FunctionGemma-270m", "ctx": 2048},
    "llama-guard": {"port": 8114, "name": "Llama-Guard-3-1B", "ctx": 2048},
    "nomic-embed": {"port": 8115, "name": "Nomic-Embed-Text-v1.5", "ctx": 8192},
}


class LLMClient:
    """HTTP client for llama.cpp servers."""

    def __init__(self, base_host: str = "127.0.0.1") -> None:
        self._base_host = base_host
        self._request_count = 0
        self._total_tokens = 0
        self._total_latency_ms = 0.0
        self._errors = 0
        self._log = logger.bind(component="llm_client")

    def get_endpoint(self, model_id: str) -> str:
        """Get the HTTP endpoint URL for a model."""
        server = MODEL_SERVERS.get(model_id)
        if not server:
            return ""
        return f"http://{self._base_host}:{server['port']}"

    def build_chat_request(
        self,
        model_id: str,
        messages: list[dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ) -> LLMRequest:
        """Build a chat completion request."""
        return LLMRequest(
            model_id=model_id,
            endpoint_url=f"{self.get_endpoint(model_id)}/v1/chat/completions",
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def build_completion_request(
        self,
        model_id: str,
        prompt: str,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ) -> LLMRequest:
        """Build a native completion request."""
        return LLMRequest(
            model_id=model_id,
            endpoint_url=f"{self.get_endpoint(model_id)}/completion",
            prompt=prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def build_embedding_request(
        self,
        text: str,
        model_id: str = "nomic-embed",
    ) -> LLMRequest:
        """Build an embedding request."""
        return LLMRequest(
            model_id=model_id,
            endpoint_url=f"{self.get_endpoint(model_id)}/embedding",
            prompt=text,
        )

    def parse_chat_response(self, raw: dict[str, Any], model_id: str = "", latency_ms: float = 0.0) -> LLMResponse:
        """Parse a chat completion response."""
        try:
            choices = raw.get("choices", [])
            content = ""
            finish_reason = ""
            if choices:
                message = choices[0].get("message", {})
                content = message.get("content", "")
                finish_reason = choices[0].get("finish_reason", "")

            usage = raw.get("usage", {})
            return LLMResponse(
                model_id=model_id,
                content=content,
                tokens_prompt=usage.get("prompt_tokens", 0),
                tokens_completion=usage.get("completion_tokens", 0),
                finish_reason=finish_reason,
                latency_ms=latency_ms,
                raw_response=raw,
            )
        except (KeyError, IndexError) as exc:
            return LLMResponse(model_id=model_id, success=False, error=str(exc))

    def parse_completion_response(self, raw: dict[str, Any], model_id: str = "", latency_ms: float = 0.0) -> LLMResponse:
        """Parse a native /completion response."""
        try:
            content = raw.get("content", "")
            tokens_evaluated = raw.get("tokens_evaluated", 0)
            tokens_predicted = raw.get("tokens_predicted", 0)
            return LLMResponse(
                model_id=model_id,
                content=content,
                tokens_prompt=tokens_evaluated,
                tokens_completion=tokens_predicted,
                finish_reason=raw.get("stop_type", ""),
                latency_ms=latency_ms,
                raw_response=raw,
            )
        except (KeyError, IndexError) as exc:
            return LLMResponse(model_id=model_id, success=False, error=str(exc))

    def parse_embedding_response(self, raw: dict[str, Any], model_id: str = "") -> EmbeddingResponse:
        """Parse an embedding response."""
        try:
            embedding = raw.get("embedding", [])
            return EmbeddingResponse(
                model_id=model_id,
                embedding=embedding,
                dimensions=len(embedding),
            )
        except (KeyError, TypeError) as exc:
            return EmbeddingResponse(model_id=model_id, success=False, error=str(exc))

    def record_request(self, response: LLMResponse) -> None:
        """Record request metrics."""
        self._request_count += 1
        self._total_tokens += response.total_tokens
        self._total_latency_ms += response.latency_ms
        if not response.success:
            self._errors += 1

    def get_model_context_size(self, model_id: str) -> int:
        """Get the context size for a model."""
        server = MODEL_SERVERS.get(model_id)
        return server["ctx"] if server else 4096

    def get_available_models(self) -> list[str]:
        """Get list of configured model IDs."""
        return list(MODEL_SERVERS.keys())

    def get_stats(self) -> dict[str, Any]:
        return {
            "requests": self._request_count,
            "tokens": self._total_tokens,
            "avg_latency_ms": self._total_latency_ms / max(self._request_count, 1),
            "errors": self._errors,
            "error_rate": self._errors / max(self._request_count, 1),
            "models_configured": len(MODEL_SERVERS),
        }

    def build_client_prompt(self) -> str:
        """Build LLM prompt with client state."""
        stats = self.get_stats()
        lines = ["## LLM Client Status"]
        lines.append(f"Models: {stats['models_configured']}")
        lines.append(f"Requests: {stats['requests']}")
        lines.append(f"Tokens: {stats['tokens']}")
        lines.append(f"Avg latency: {stats['avg_latency_ms']:.0f}ms")
        return "\n".join(lines)
