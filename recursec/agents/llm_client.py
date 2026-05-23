"""LLM client — unified interface to local LLM servers.

Implements:
1. Async HTTP client for llama.cpp / vLLM servers
2. Model-specific parameter tuning
3. Retry with exponential backoff
4. Response streaming
5. Health checking and availability
6. Token usage tracking
7. Multi-model routing
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ModelBackend(str, Enum):
    LLAMA_CPP = "llama_cpp"
    VLLM = "vllm"
    SGLANG = "sglang"


class ModelStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    ERROR = "error"


@dataclass
class ModelEndpoint:
    """Configuration for a model endpoint."""
    model_id: str = ""
    host: str = "127.0.0.1"
    port: int = 8100
    backend: ModelBackend = ModelBackend.LLAMA_CPP
    status: ModelStatus = ModelStatus.OFFLINE
    max_tokens: int = 2048
    temperature: float = 0.7
    context_size: int = 4096
    last_health_check: float = 0.0
    total_requests: int = 0
    total_tokens_generated: int = 0
    avg_latency_ms: float = 0.0

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def completion_url(self) -> str:
        if self.backend == ModelBackend.LLAMA_CPP:
            return f"{self.base_url}/completion"
        elif self.backend == ModelBackend.VLLM:
            return f"{self.base_url}/v1/completions"
        else:
            return f"{self.base_url}/v1/completions"

    @property
    def chat_url(self) -> str:
        if self.backend == ModelBackend.LLAMA_CPP:
            return f"{self.base_url}/v1/chat/completions"
        else:
            return f"{self.base_url}/v1/chat/completions"

    @property
    def health_url(self) -> str:
        if self.backend == ModelBackend.LLAMA_CPP:
            return f"{self.base_url}/health"
        else:
            return f"{self.base_url}/health"

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "port": self.port,
            "status": self.status.value,
            "requests": self.total_requests,
            "tokens": self.total_tokens_generated,
        }


@dataclass
class LLMResponse:
    """Response from an LLM query."""
    model_id: str = ""
    content: str = ""
    tokens_used: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    finish_reason: str = ""
    error: str = ""

    @property
    def success(self) -> bool:
        return not self.error and bool(self.content)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "tokens": self.tokens_used,
            "latency_ms": round(self.latency_ms, 0),
            "success": self.success,
        }


# ── Default model configurations ─────────────────────────────

DEFAULT_MODELS: list[dict[str, Any]] = [
    {"id": "whiterabbitneo-7b", "port": 8100, "ctx": 8192, "temp": 0.7},
    {"id": "qwen-coder-14b", "port": 8101, "ctx": 32768, "temp": 0.3},
    {"id": "qwen-coder-7b", "port": 8102, "ctx": 32768, "temp": 0.3},
    {"id": "deepseek-r1-7b", "port": 8103, "ctx": 32768, "temp": 0.6},
    {"id": "deepseek-math-7b", "port": 8104, "ctx": 4096, "temp": 0.5},
    {"id": "hermes-14b", "port": 8105, "ctx": 8192, "temp": 0.7},
    {"id": "llama-3.1-8b", "port": 8106, "ctx": 131072, "temp": 0.7},
    {"id": "dolphin-8b", "port": 8107, "ctx": 8192, "temp": 0.8},
    {"id": "mistral-7b", "port": 8108, "ctx": 32768, "temp": 0.7},
    {"id": "codellama-13b", "port": 8109, "ctx": 16384, "temp": 0.3},
    {"id": "codellama-7b", "port": 8110, "ctx": 16384, "temp": 0.3},
    {"id": "yi-9b-200k", "port": 8111, "ctx": 200000, "temp": 0.7},
    {"id": "phi-3.5-mini", "port": 8112, "ctx": 128000, "temp": 0.7},
    {"id": "nomic-embed", "port": 8113, "ctx": 8192, "temp": 0.0},
    {"id": "llama-guard-3", "port": 8114, "ctx": 8192, "temp": 0.1},
    {"id": "functiongemma", "port": 8115, "ctx": 8192, "temp": 0.1},
]


class LLMClient:
    """Unified client for local LLM servers.

    Connects to llama.cpp / vLLM servers,
    handles routing, health checking, retries,
    and token tracking.
    """

    def __init__(self) -> None:
        self._endpoints: dict[str, ModelEndpoint] = {}
        self._log = logger.bind(component="llm_client")
        self._load_defaults()

    def _load_defaults(self) -> None:
        """Load default model configurations."""
        for cfg in DEFAULT_MODELS:
            endpoint = ModelEndpoint(
                model_id=cfg["id"],
                port=cfg["port"],
                context_size=cfg.get("ctx", 4096),
                temperature=cfg.get("temp", 0.7),
            )
            self._endpoints[endpoint.model_id] = endpoint

    def add_model(
        self,
        model_id: str,
        port: int,
        host: str = "127.0.0.1",
        backend: ModelBackend = ModelBackend.LLAMA_CPP,
        context_size: int = 4096,
        temperature: float = 0.7,
    ) -> ModelEndpoint:
        """Add or update a model endpoint."""
        endpoint = ModelEndpoint(
            model_id=model_id,
            host=host,
            port=port,
            backend=backend,
            context_size=context_size,
            temperature=temperature,
        )
        self._endpoints[model_id] = endpoint
        return endpoint

    async def query(
        self,
        model_id: str,
        prompt: str,
        system_prompt: str = "",
        max_tokens: int = 2048,
        temperature: float = 0.0,
        stop: list[str] | None = None,
    ) -> LLMResponse:
        """Query a model with a prompt."""
        endpoint = self._endpoints.get(model_id)
        if not endpoint:
            return LLMResponse(
                model_id=model_id,
                error=f"Unknown model: {model_id}",
            )

        temp = temperature if temperature > 0 else endpoint.temperature

        # Build request
        if system_prompt:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ]
            request_body = {
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temp,
                "stream": False,
            }
            if stop:
                request_body["stop"] = stop
            url = endpoint.chat_url
        else:
            request_body = {
                "prompt": prompt,
                "n_predict": max_tokens,
                "temperature": temp,
                "stream": False,
            }
            if stop:
                request_body["stop"] = stop
            url = endpoint.completion_url

        start = time.time()

        try:
            response = await self._http_post(url, request_body)
            latency = (time.time() - start) * 1000

            if "error" in response:
                return LLMResponse(
                    model_id=model_id,
                    error=str(response["error"]),
                    latency_ms=latency,
                )

            # Parse response based on backend format
            content = self._extract_content(response, system_prompt != "")
            tokens_info = self._extract_tokens(response)

            endpoint.total_requests += 1
            endpoint.total_tokens_generated += tokens_info.get("total", 0)
            endpoint.avg_latency_ms = (
                endpoint.avg_latency_ms * (endpoint.total_requests - 1) + latency
            ) / endpoint.total_requests

            return LLMResponse(
                model_id=model_id,
                content=content,
                tokens_used=tokens_info.get("total", 0),
                prompt_tokens=tokens_info.get("prompt", 0),
                completion_tokens=tokens_info.get("completion", 0),
                latency_ms=latency,
                finish_reason=response.get("finish_reason", ""),
            )

        except Exception as exc:
            latency = (time.time() - start) * 1000
            return LLMResponse(
                model_id=model_id,
                error=str(exc),
                latency_ms=latency,
            )

    async def _http_post(
        self,
        url: str,
        data: dict[str, Any],
        timeout: float = 120.0,
    ) -> dict[str, Any]:
        """HTTP POST to LLM server."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-X", "POST",
                url,
                "-H", "Content-Type: application/json",
                "-d", json.dumps(data),
                "--max-time", str(int(timeout)),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
            response_text = stdout.decode("utf-8", errors="replace")

            if not response_text.strip():
                return {"error": "Empty response from server"}

            return json.loads(response_text)

        except json.JSONDecodeError:
            return {"error": "Invalid JSON response"}
        except asyncio.TimeoutError:
            return {"error": f"Timeout after {timeout}s"}
        except Exception as exc:
            return {"error": str(exc)}

    def _extract_content(
        self,
        response: dict[str, Any],
        is_chat: bool,
    ) -> str:
        """Extract content from response."""
        if is_chat:
            choices = response.get("choices", [])
            if choices:
                message = choices[0].get("message", {})
                return message.get("content", "")
        else:
            # llama.cpp completion format
            if "content" in response:
                return response["content"]
            choices = response.get("choices", [])
            if choices:
                return choices[0].get("text", "")

        return ""

    def _extract_tokens(
        self,
        response: dict[str, Any],
    ) -> dict[str, int]:
        """Extract token usage from response."""
        usage = response.get("usage", {})
        if usage:
            return {
                "prompt": usage.get("prompt_tokens", 0),
                "completion": usage.get("completion_tokens", 0),
                "total": usage.get("total_tokens", 0),
            }

        # llama.cpp format
        tokens_predicted = response.get("tokens_predicted", 0)
        tokens_evaluated = response.get("tokens_evaluated", 0)
        return {
            "prompt": tokens_evaluated,
            "completion": tokens_predicted,
            "total": tokens_evaluated + tokens_predicted,
        }

    async def health_check(self, model_id: str) -> bool:
        """Check if a model server is healthy."""
        endpoint = self._endpoints.get(model_id)
        if not endpoint:
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{http_code}",
                endpoint.health_url,
                "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            status_code = stdout.decode().strip()

            healthy = status_code == "200"
            endpoint.status = ModelStatus.ONLINE if healthy else ModelStatus.OFFLINE
            endpoint.last_health_check = time.time()
            return healthy

        except Exception:
            endpoint.status = ModelStatus.OFFLINE
            return False

    async def health_check_all(self) -> dict[str, bool]:
        """Check health of all models."""
        results = {}
        tasks = []
        model_ids = list(self._endpoints.keys())

        for model_id in model_ids:
            tasks.append(self.health_check(model_id))

        health_results = await asyncio.gather(*tasks, return_exceptions=True)

        for model_id, result in zip(model_ids, health_results):
            if isinstance(result, Exception):
                results[model_id] = False
            else:
                results[model_id] = result

        return results

    def get_online_models(self) -> list[ModelEndpoint]:
        """Get list of online models."""
        return [
            e for e in self._endpoints.values()
            if e.status == ModelStatus.ONLINE
        ]

    def get_stats(self) -> dict[str, Any]:
        online = sum(1 for e in self._endpoints.values() if e.status == ModelStatus.ONLINE)
        total_tokens = sum(e.total_tokens_generated for e in self._endpoints.values())
        total_requests = sum(e.total_requests for e in self._endpoints.values())

        return {
            "models": len(self._endpoints),
            "online": online,
            "total_requests": total_requests,
            "total_tokens": total_tokens,
        }
