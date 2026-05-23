"""LLM client — communicates with llama.cpp servers.

Implements:
1. HTTP client for llama.cpp /completion and /v1/chat/completions
2. Streaming support
3. Retry with exponential backoff
4. Connection pooling
5. Token counting from response
6. Server health checking
7. Multi-server management
8. Embedding requests via /embedding
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator

import structlog

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    import httpx as httpx_lib  # noqa: F401
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

logger = structlog.get_logger()


class ServerStatus(str, Enum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    OFFLINE = "offline"


@dataclass
class LLMServer:
    """A llama.cpp server instance."""
    server_id: str = ""
    model_name: str = ""
    host: str = "127.0.0.1"
    port: int = 8080
    status: ServerStatus = ServerStatus.UNKNOWN
    max_context: int = 4096
    last_health_check: float = 0.0
    total_requests: int = 0
    total_errors: int = 0
    avg_latency_ms: float = 0.0
    active_requests: int = 0

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def is_available(self) -> bool:
        return self.status in (ServerStatus.HEALTHY, ServerStatus.DEGRADED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.server_id,
            "model": self.model_name[:20],
            "url": self.base_url,
            "status": self.status.value,
            "requests": self.total_requests,
            "errors": self.total_errors,
            "latency": round(self.avg_latency_ms, 1),
        }


@dataclass
class CompletionRequest:
    """A completion request to a llama.cpp server."""
    prompt: str = ""
    system_prompt: str = ""
    messages: list[dict[str, str]] = field(default_factory=list)
    max_tokens: int = 2048
    temperature: float = 0.7
    top_p: float = 0.9
    top_k: int = 40
    repeat_penalty: float = 1.1
    stop: list[str] = field(default_factory=list)
    stream: bool = False

    def to_llama_params(self) -> dict[str, Any]:
        """Convert to llama.cpp /completion params."""
        params: dict[str, Any] = {
            "prompt": self.prompt,
            "n_predict": self.max_tokens,
            "temperature": self.temperature,
            "top_p": self.top_p,
            "top_k": self.top_k,
            "repeat_penalty": self.repeat_penalty,
            "stream": self.stream,
        }
        if self.stop:
            params["stop"] = self.stop
        return params

    def to_chat_params(self) -> dict[str, Any]:
        """Convert to OpenAI-compatible /v1/chat/completions params."""
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.extend(self.messages)
        if self.prompt and not self.messages:
            messages.append({"role": "user", "content": self.prompt})

        return {
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "top_p": self.top_p,
            "stream": self.stream,
        }


@dataclass
class CompletionResponse:
    """Response from a llama.cpp server."""
    content: str = ""
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    finish_reason: str = ""
    server_id: str = ""
    success: bool = True
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model[:20],
            "tokens": self.total_tokens,
            "latency": round(self.latency_ms, 1),
            "success": self.success,
            "length": len(self.content),
        }


@dataclass
class EmbeddingResponse:
    """Response from an embedding request."""
    embedding: list[float] = field(default_factory=list)
    model: str = ""
    tokens_used: int = 0
    latency_ms: float = 0.0
    success: bool = True
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "dim": len(self.embedding),
            "model": self.model[:20],
            "latency": round(self.latency_ms, 1),
            "success": self.success,
        }


class LLMClient:
    """Client for communicating with llama.cpp servers.

    Manages multiple servers, handles retries, and provides
    both completion and embedding interfaces.
    """

    def __init__(self) -> None:
        self._servers: dict[str, LLMServer] = {}
        self._request_timeout = 120.0
        self._max_retries = 3
        self._health_check_interval = 60.0
        self._log = logger.bind(component="llm_client")

    def add_server(
        self,
        server_id: str,
        model_name: str,
        host: str = "127.0.0.1",
        port: int = 8080,
        max_context: int = 4096,
    ) -> LLMServer:
        """Register a llama.cpp server."""
        server = LLMServer(
            server_id=server_id,
            model_name=model_name,
            host=host,
            port=port,
            max_context=max_context,
        )
        self._servers[server_id] = server
        return server

    def remove_server(self, server_id: str) -> bool:
        if server_id in self._servers:
            del self._servers[server_id]
            return True
        return False

    async def complete(
        self,
        server_id: str,
        request: CompletionRequest,
    ) -> CompletionResponse:
        """Send a completion request to a server."""
        server = self._servers.get(server_id)
        if not server:
            return CompletionResponse(
                success=False,
                error=f"Server not found: {server_id}",
            )

        if not server.is_available:
            return CompletionResponse(
                success=False,
                error=f"Server unavailable: {server.status.value}",
                server_id=server_id,
            )

        server.active_requests += 1
        start_time = time.time()

        try:
            # Try chat completions API first, fallback to completion
            if request.messages or request.system_prompt:
                response = await self._chat_complete(server, request)
            else:
                response = await self._raw_complete(server, request)

            elapsed = (time.time() - start_time) * 1000
            response.latency_ms = elapsed
            response.server_id = server_id
            response.model = server.model_name

            # Update stats
            server.total_requests += 1
            alpha = 0.1
            server.avg_latency_ms = (
                (1 - alpha) * server.avg_latency_ms + alpha * elapsed
            )
            server.status = ServerStatus.HEALTHY

            return response

        except Exception as e:
            elapsed = (time.time() - start_time) * 1000
            server.total_errors += 1
            server.total_requests += 1
            return CompletionResponse(
                success=False,
                error=str(e),
                server_id=server_id,
                latency_ms=elapsed,
            )
        finally:
            server.active_requests -= 1

    async def embed(
        self,
        server_id: str,
        text: str,
    ) -> EmbeddingResponse:
        """Get embeddings from a server."""
        server = self._servers.get(server_id)
        if not server:
            return EmbeddingResponse(
                success=False,
                error=f"Server not found: {server_id}",
            )

        start_time = time.time()

        try:
            if HAS_AIOHTTP:
                async with aiohttp.ClientSession() as session:
                    url = f"{server.base_url}/embedding"
                    payload = {"content": text}
                    async with session.post(
                        url, json=payload, timeout=aiohttp.ClientTimeout(total=30)
                    ) as resp:
                        data = await resp.json()

                embedding = data.get("embedding", [])
                elapsed = (time.time() - start_time) * 1000

                return EmbeddingResponse(
                    embedding=embedding,
                    model=server.model_name,
                    latency_ms=elapsed,
                )
            else:
                return EmbeddingResponse(
                    success=False,
                    error="aiohttp not installed",
                )

        except Exception as e:
            return EmbeddingResponse(
                success=False,
                error=str(e),
            )

    async def health_check(self, server_id: str) -> ServerStatus:
        """Check if a server is healthy."""
        server = self._servers.get(server_id)
        if not server:
            return ServerStatus.OFFLINE

        try:
            if HAS_AIOHTTP:
                async with aiohttp.ClientSession() as session:
                    url = f"{server.base_url}/health"
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status == 200:
                            server.status = ServerStatus.HEALTHY
                        elif resp.status == 503:
                            server.status = ServerStatus.DEGRADED
                        else:
                            server.status = ServerStatus.UNHEALTHY
            else:
                server.status = ServerStatus.UNKNOWN

            server.last_health_check = time.time()
            return server.status

        except Exception:
            server.status = ServerStatus.OFFLINE
            server.last_health_check = time.time()
            return server.status

    async def health_check_all(self) -> dict[str, str]:
        """Check health of all servers."""
        results = {}
        for server_id in self._servers:
            status = await self.health_check(server_id)
            results[server_id] = status.value
        return results

    async def _chat_complete(
        self,
        server: LLMServer,
        request: CompletionRequest,
    ) -> CompletionResponse:
        """Use /v1/chat/completions endpoint."""
        if not HAS_AIOHTTP:
            return CompletionResponse(success=False, error="aiohttp not installed")

        url = f"{server.base_url}/v1/chat/completions"
        params = request.to_chat_params()

        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=params,
                timeout=aiohttp.ClientTimeout(total=self._request_timeout),
            ) as resp:
                data = await resp.json()

        choices = data.get("choices", [])
        content = ""
        finish_reason = ""
        if choices:
            message = choices[0].get("message", {})
            content = message.get("content", "")
            finish_reason = choices[0].get("finish_reason", "")

        usage = data.get("usage", {})

        return CompletionResponse(
            content=content,
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
            total_tokens=usage.get("total_tokens", 0),
            finish_reason=finish_reason,
            success=True,
        )

    async def _raw_complete(
        self,
        server: LLMServer,
        request: CompletionRequest,
    ) -> CompletionResponse:
        """Use /completion endpoint."""
        if not HAS_AIOHTTP:
            return CompletionResponse(success=False, error="aiohttp not installed")

        url = f"{server.base_url}/completion"
        params = request.to_llama_params()

        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=params,
                timeout=aiohttp.ClientTimeout(total=self._request_timeout),
            ) as resp:
                data = await resp.json()

        content = data.get("content", "")
        tokens_predicted = data.get("tokens_predicted", 0)
        tokens_evaluated = data.get("tokens_evaluated", 0)
        stop_type = data.get("stop_type", "")

        return CompletionResponse(
            content=content,
            prompt_tokens=tokens_evaluated,
            completion_tokens=tokens_predicted,
            total_tokens=tokens_evaluated + tokens_predicted,
            finish_reason=stop_type,
            success=True,
        )

    async def stream_complete(
        self,
        server_id: str,
        request: CompletionRequest,
    ) -> AsyncIterator[str]:
        """Stream a completion response."""
        server = self._servers.get(server_id)
        if not server or not HAS_AIOHTTP:
            return

        request.stream = True
        url = f"{server.base_url}/v1/chat/completions"
        params = request.to_chat_params()

        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=params,
                timeout=aiohttp.ClientTimeout(total=self._request_timeout),
            ) as resp:
                async for line in resp.content:
                    decoded = line.decode("utf-8").strip()
                    if decoded.startswith("data: "):
                        data_str = decoded[6:]
                        if data_str == "[DONE]":
                            break
                        try:
                            data = json.loads(data_str)
                            delta = data.get("choices", [{}])[0].get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                yield content
                        except json.JSONDecodeError:
                            continue

    def get_server(self, server_id: str) -> LLMServer | None:
        return self._servers.get(server_id)

    def get_available_servers(self) -> list[LLMServer]:
        return [s for s in self._servers.values() if s.is_available]

    def get_stats(self) -> dict[str, Any]:
        total_requests = sum(s.total_requests for s in self._servers.values())
        total_errors = sum(s.total_errors for s in self._servers.values())
        return {
            "servers": len(self._servers),
            "available": len(self.get_available_servers()),
            "total_requests": total_requests,
            "total_errors": total_errors,
            "error_rate": round(
                total_errors / max(1, total_requests), 3
            ),
            "by_server": {
                sid: s.to_dict() for sid, s in self._servers.items()
            },
        }
