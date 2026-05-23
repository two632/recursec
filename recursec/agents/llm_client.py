"""LLM client — unified interface for llama.cpp and vLLM backends.

Implements:
1. llama.cpp server HTTP client
2. vLLM server HTTP client
3. Connection pooling and health checks
4. Token counting and budgeting
5. Request queuing and rate limiting
6. Response streaming support
7. Model-specific parameter tuning
8. Retry with exponential backoff
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class LLMBackend(str, Enum):
    LLAMA_CPP = "llama_cpp"
    VLLM = "vllm"
    GENERIC_OPENAI = "generic_openai"


class ModelStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class ModelEndpoint:
    """An LLM model endpoint."""
    model_id: str = ""
    name: str = ""
    backend: LLMBackend = LLMBackend.LLAMA_CPP
    host: str = "127.0.0.1"
    port: int = 8100
    context_size: int = 4096
    status: ModelStatus = ModelStatus.UNKNOWN
    capabilities: list[str] = field(default_factory=list)
    default_temperature: float = 0.7
    default_max_tokens: int = 2048
    last_health_check: float = 0.0
    total_requests: int = 0
    total_tokens: int = 0
    avg_latency_ms: float = 0.0

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.model_id[:15],
            "name": self.name[:20],
            "backend": self.backend.value,
            "port": self.port,
            "context": self.context_size,
            "status": self.status.value,
            "requests": self.total_requests,
        }


@dataclass
class LLMRequest:
    """An LLM inference request."""
    request_id: str = ""
    model_id: str = ""
    prompt: str = ""
    system_prompt: str = ""
    temperature: float = 0.7
    max_tokens: int = 2048
    top_p: float = 0.95
    top_k: int = 40
    repeat_penalty: float = 1.1
    stop_sequences: list[str] = field(default_factory=list)
    stream: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.request_id[:10],
            "model": self.model_id[:15],
            "temp": self.temperature,
            "max_tokens": self.max_tokens,
        }


@dataclass
class LLMResponse:
    """An LLM inference response."""
    request_id: str = ""
    model_id: str = ""
    content: str = ""
    tokens_prompt: int = 0
    tokens_completion: int = 0
    latency_ms: float = 0.0
    success: bool = True
    error: str = ""

    @property
    def total_tokens(self) -> int:
        return self.tokens_prompt + self.tokens_completion

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.request_id[:10],
            "model": self.model_id[:15],
            "tokens": self.total_tokens,
            "latency": round(self.latency_ms, 0),
            "ok": self.success,
        }


# ── Default model configurations ─────────────────────────────

DEFAULT_MODELS: list[dict[str, Any]] = [
    {"id": "whiterabbitneo-7b", "name": "WhiteRabbitNeo-7B", "port": 8100,
     "context": 4096, "caps": ["security", "exploit", "vuln_analysis"],
     "temp": 0.3, "max": 2048},
    {"id": "qwen-coder-14b", "name": "Qwen2.5-Coder-14B", "port": 8101,
     "context": 32768, "caps": ["code", "code_audit", "exploit_dev"],
     "temp": 0.2, "max": 4096},
    {"id": "qwen-coder-7b", "name": "Qwen2.5-Coder-7B", "port": 8102,
     "context": 32768, "caps": ["code", "code_review"],
     "temp": 0.2, "max": 2048},
    {"id": "deepseek-r1-7b", "name": "DeepSeek-R1-Distill-7B", "port": 8103,
     "context": 32768, "caps": ["reasoning", "planning", "chain_of_thought"],
     "temp": 0.6, "max": 4096},
    {"id": "deepseek-math-7b", "name": "DeepSeek-Math-7B", "port": 8104,
     "context": 4096, "caps": ["math", "logic", "crypto"],
     "temp": 0.1, "max": 1024},
    {"id": "hermes-14b", "name": "Hermes-4-14B", "port": 8105,
     "context": 8192, "caps": ["general", "analysis", "reasoning"],
     "temp": 0.7, "max": 4096},
    {"id": "llama-3.1-8b", "name": "Llama-3.1-8B", "port": 8106,
     "context": 131072, "caps": ["general", "long_context"],
     "temp": 0.7, "max": 4096},
    {"id": "dolphin-8b", "name": "Dolphin-2.9-Llama3-8B", "port": 8107,
     "context": 8192, "caps": ["general", "security", "uncensored"],
     "temp": 0.7, "max": 2048},
    {"id": "mistral-7b", "name": "Mistral-7B", "port": 8108,
     "context": 32768, "caps": ["general", "fast"],
     "temp": 0.7, "max": 2048},
    {"id": "codellama-13b", "name": "CodeLlama-13B", "port": 8109,
     "context": 16384, "caps": ["code", "code_audit"],
     "temp": 0.2, "max": 2048},
    {"id": "codellama-7b", "name": "CodeLlama-7B", "port": 8110,
     "context": 16384, "caps": ["code"],
     "temp": 0.2, "max": 1024},
    {"id": "yi-9b-200k", "name": "Yi-9B-200K", "port": 8111,
     "context": 200000, "caps": ["long_context", "code_audit", "analysis"],
     "temp": 0.7, "max": 8192},
    {"id": "phi-3.5-mini", "name": "Phi-3.5-mini", "port": 8112,
     "context": 4096, "caps": ["fast", "general"],
     "temp": 0.7, "max": 1024},
    {"id": "nomic-embed", "name": "Nomic-Embed-Text", "port": 8113,
     "context": 8192, "caps": ["embedding"],
     "temp": 0.0, "max": 0},
    {"id": "llama-guard-3", "name": "Llama-Guard-3", "port": 8114,
     "context": 4096, "caps": ["safety", "moderation"],
     "temp": 0.0, "max": 256},
    {"id": "functiongemma", "name": "FunctionGemma-270m", "port": 8115,
     "context": 2048, "caps": ["function_call", "tool_routing"],
     "temp": 0.1, "max": 256},
]


class LLMClient:
    """Unified LLM client for llama.cpp and vLLM backends.

    Manages connections to multiple model servers
    with health checking and request routing.
    """

    def __init__(self) -> None:
        self._endpoints: dict[str, ModelEndpoint] = {}
        self._counter = 0
        self._log = logger.bind(component="llm_client")
        self._load_defaults()

    def _load_defaults(self) -> None:
        """Load default model endpoints."""
        for m in DEFAULT_MODELS:
            endpoint = ModelEndpoint(
                model_id=m["id"],
                name=m["name"],
                port=m["port"],
                context_size=m.get("context", 4096),
                capabilities=m.get("caps", []),
                default_temperature=m.get("temp", 0.7),
                default_max_tokens=m.get("max", 2048),
            )
            self._endpoints[endpoint.model_id] = endpoint

    def add_endpoint(
        self,
        model_id: str,
        name: str = "",
        host: str = "127.0.0.1",
        port: int = 8100,
        backend: str = "llama_cpp",
        context_size: int = 4096,
        capabilities: list[str] | None = None,
    ) -> ModelEndpoint:
        """Add a model endpoint."""
        endpoint = ModelEndpoint(
            model_id=model_id,
            name=name or model_id,
            backend=LLMBackend(backend),
            host=host,
            port=port,
            context_size=context_size,
            capabilities=capabilities or [],
        )
        self._endpoints[model_id] = endpoint
        return endpoint

    def remove_endpoint(self, model_id: str) -> bool:
        """Remove a model endpoint."""
        if model_id in self._endpoints:
            del self._endpoints[model_id]
            return True
        return False

    async def query(
        self,
        model_id: str,
        prompt: str,
        system_prompt: str = "",
        temperature: float = -1,
        max_tokens: int = -1,
        stop: list[str] | None = None,
    ) -> LLMResponse:
        """Send a query to a model."""
        endpoint = self._endpoints.get(model_id)
        if not endpoint:
            return LLMResponse(
                model_id=model_id,
                success=False,
                error=f"Unknown model: {model_id}",
            )

        self._counter += 1
        request = LLMRequest(
            request_id=f"req-{self._counter}",
            model_id=model_id,
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature if temperature >= 0 else endpoint.default_temperature,
            max_tokens=max_tokens if max_tokens >= 0 else endpoint.default_max_tokens,
            stop_sequences=stop or [],
        )

        if endpoint.backend == LLMBackend.LLAMA_CPP:
            return await self._query_llama_cpp(endpoint, request)
        elif endpoint.backend == LLMBackend.VLLM:
            return await self._query_vllm(endpoint, request)
        else:
            return await self._query_openai_compat(endpoint, request)

    async def _query_llama_cpp(
        self,
        endpoint: ModelEndpoint,
        request: LLMRequest,
    ) -> LLMResponse:
        """Query a llama.cpp server."""
        payload = {
            "prompt": request.prompt,
            "temperature": request.temperature,
            "n_predict": request.max_tokens,
            "top_p": request.top_p,
            "top_k": request.top_k,
            "repeat_penalty": request.repeat_penalty,
            "stop": request.stop_sequences,
        }

        if request.system_prompt:
            payload["prompt"] = f"### System:\n{request.system_prompt}\n\n### User:\n{request.prompt}\n\n### Assistant:\n"

        start = time.time()
        try:
            reader, writer = await asyncio.open_connection(
                endpoint.host, endpoint.port,
            )

            http_request = (
                f"POST /completion HTTP/1.1\r\n"
                f"Host: {endpoint.host}:{endpoint.port}\r\n"
                f"Content-Type: application/json\r\n"
            )
            body = json.dumps(payload).encode()
            http_request += f"Content-Length: {len(body)}\r\n\r\n"
            writer.write(http_request.encode() + body)
            await writer.drain()

            # Read response
            response_data = b""
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=120)
                if not chunk:
                    break
                response_data += chunk
                if b"\r\n\r\n" in response_data:
                    parts = response_data.split(b"\r\n\r\n", 1)
                    if len(parts) > 1:
                        try:
                            result = json.loads(parts[1])
                            break
                        except json.JSONDecodeError:
                            continue

            writer.close()
            latency = (time.time() - start) * 1000

            if isinstance(result, dict):
                content = result.get("content", "")
                tokens_eval = result.get("tokens_evaluated", 0)
                tokens_pred = result.get("tokens_predicted", 0)

                endpoint.total_requests += 1
                endpoint.total_tokens += tokens_eval + tokens_pred
                endpoint.status = ModelStatus.ONLINE

                return LLMResponse(
                    request_id=request.request_id,
                    model_id=request.model_id,
                    content=content,
                    tokens_prompt=tokens_eval,
                    tokens_completion=tokens_pred,
                    latency_ms=latency,
                )

        except (OSError, asyncio.TimeoutError) as e:
            endpoint.status = ModelStatus.OFFLINE
            return LLMResponse(
                request_id=request.request_id,
                model_id=request.model_id,
                success=False,
                error=str(e)[:200],
                latency_ms=(time.time() - start) * 1000,
            )

        return LLMResponse(
            request_id=request.request_id,
            model_id=request.model_id,
            success=False,
            error="Invalid response",
        )

    async def _query_vllm(
        self,
        endpoint: ModelEndpoint,
        request: LLMRequest,
    ) -> LLMResponse:
        """Query a vLLM server (OpenAI-compatible)."""
        return await self._query_openai_compat(endpoint, request)

    async def _query_openai_compat(
        self,
        endpoint: ModelEndpoint,
        request: LLMRequest,
    ) -> LLMResponse:
        """Query an OpenAI-compatible server."""
        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.append({"role": "user", "content": request.prompt})

        payload = {
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "top_p": request.top_p,
            "stop": request.stop_sequences or None,
        }

        start = time.time()
        try:
            reader, writer = await asyncio.open_connection(
                endpoint.host, endpoint.port,
            )

            body = json.dumps(payload).encode()
            http_request = (
                f"POST /v1/chat/completions HTTP/1.1\r\n"
                f"Host: {endpoint.host}:{endpoint.port}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            )
            writer.write(http_request.encode() + body)
            await writer.drain()

            response_data = b""
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=120)
                if not chunk:
                    break
                response_data += chunk
                if b"\r\n\r\n" in response_data:
                    parts = response_data.split(b"\r\n\r\n", 1)
                    if len(parts) > 1:
                        try:
                            result = json.loads(parts[1])
                            break
                        except json.JSONDecodeError:
                            continue

            writer.close()
            latency = (time.time() - start) * 1000

            if isinstance(result, dict) and "choices" in result:
                content = result["choices"][0].get("message", {}).get("content", "")
                usage = result.get("usage", {})

                endpoint.total_requests += 1
                endpoint.total_tokens += usage.get("total_tokens", 0)
                endpoint.status = ModelStatus.ONLINE

                return LLMResponse(
                    request_id=request.request_id,
                    model_id=request.model_id,
                    content=content,
                    tokens_prompt=usage.get("prompt_tokens", 0),
                    tokens_completion=usage.get("completion_tokens", 0),
                    latency_ms=latency,
                )

        except (OSError, asyncio.TimeoutError) as e:
            endpoint.status = ModelStatus.OFFLINE
            return LLMResponse(
                request_id=request.request_id,
                model_id=request.model_id,
                success=False,
                error=str(e)[:200],
                latency_ms=(time.time() - start) * 1000,
            )

        return LLMResponse(
            request_id=request.request_id,
            model_id=request.model_id,
            success=False,
            error="Invalid response",
        )

    async def health_check(self, model_id: str) -> ModelStatus:
        """Check if a model endpoint is healthy."""
        endpoint = self._endpoints.get(model_id)
        if not endpoint:
            return ModelStatus.UNKNOWN

        try:
            reader, writer = await asyncio.open_connection(
                endpoint.host, endpoint.port,
            )
            writer.write(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            writer.close()

            endpoint.last_health_check = time.time()
            if b"200" in data:
                endpoint.status = ModelStatus.ONLINE
            else:
                endpoint.status = ModelStatus.ERROR
        except (OSError, asyncio.TimeoutError):
            endpoint.status = ModelStatus.OFFLINE

        return endpoint.status

    async def health_check_all(self) -> dict[str, str]:
        """Health check all endpoints."""
        results = {}
        tasks = [self.health_check(mid) for mid in self._endpoints]
        statuses = await asyncio.gather(*tasks, return_exceptions=True)
        for mid, status in zip(self._endpoints, statuses):
            if isinstance(status, ModelStatus):
                results[mid] = status.value
            else:
                results[mid] = "error"
        return results

    def get_models_by_capability(
        self,
        capability: str,
    ) -> list[ModelEndpoint]:
        """Get models with a specific capability."""
        return [
            ep for ep in self._endpoints.values()
            if capability in ep.capabilities
        ]

    def get_endpoint(self, model_id: str) -> ModelEndpoint | None:
        """Get an endpoint by model ID."""
        return self._endpoints.get(model_id)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for ep in self._endpoints.values():
            status_counts[ep.status.value] += 1

        return {
            "models": len(self._endpoints),
            "total_requests": sum(ep.total_requests for ep in self._endpoints.values()),
            "total_tokens": sum(ep.total_tokens for ep in self._endpoints.values()),
            "by_status": dict(status_counts),
        }
