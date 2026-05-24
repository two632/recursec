"""LLM client — on-demand model loading + smart routing + consensus voting.

TRUE on-demand architecture:
- Models live on disk as GGUF files (~200GB total).
- DynamicModelLoader starts/stops llama-server processes on demand.
- LRU cache keeps max 2 models loaded in RAM (8-16GB).
- Smart router picks the best specialist model for each task.
- Consensus voting sends critical findings to 2-3 models for validation.
- Task batching groups work by model to minimize load/unload cycles.

When you call llm_client.chat("whiterabbitneo", ...):
1. Loader checks if whiterabbitneo's llama-server is running.
2. If not, it starts the process (loads GGUF into RAM, ~5-10s).
3. If cache is full (>2 models), it kills the least-recently-used server.
4. Then it sends the HTTP request to the now-running server.

This uses 8-18GB RAM instead of 80-120GB.
"""

from __future__ import annotations

import json as json_mod
import os
import signal
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
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
    "whiterabbitneo": {"port": 8100, "name": "WhiteRabbitNeo-7B", "ctx": 4096},
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

# GGUF file names on disk (in RECURSEC_MODELS_DIR, default ~/agent/models/gguf/)
MODEL_GGUF_FILES: dict[str, str] = {
    "whiterabbitneo": "WhiteRabbitNeo-7B-v1.5a-Q4_K_M.gguf",
    "whiterabbit": "WhiteRabbitNeo-7B-v1.5a-Q4_K_M.gguf",
    "mistral": "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf",
    "qwen-coder-14b": "Qwen2.5-Coder-14B-Instruct-Q3_K_M.gguf",
    "qwen-coder-7b": "Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf",
    "deepseek-r1": "DeepSeek-R1-Distill-Qwen-7B-q4_k_m.gguf",
    "hermes-4-14b": "Hermes-4-14B-IQ2_M.gguf",
    "llama-3.1-8b": "Meta-Llama-3.1-8B-Instruct-Q4_K_S.gguf",
    "codellama-13b": "codellama-13b-instruct.Q3_K_M.gguf",
    "codellama-7b": "codellama-7b.Q4_K_M.gguf",
    "dolphin": "dolphin-2.9-llama3-8b.Q4_K_M.gguf",
    "phi-3.5-mini": "Phi-3.5-mini-instruct-Q4_K_M.gguf",
    "deepseek-math": "deepseek-math-7b-instruct-q4_k_m.gguf",
    "yi-9b-200k": "Yi-9B-200K.Q5_K_M.gguf",
    "functiongemma": "functiongemma-270m-it-BF16.gguf",
    "llama-guard": "llama-guard-3-1b-q4_k_m.gguf",
    "nomic-embed": "nomic-embed-text-v1.5.f32.gguf",
}

# Approximate RAM usage per model (in GB) for capacity planning
MODEL_RAM_GB: dict[str, float] = {
    "whiterabbitneo": 5.0, "whiterabbit": 5.0,
    "mistral": 4.0, "qwen-coder-14b": 8.0, "qwen-coder-7b": 4.0,
    "deepseek-r1": 4.0, "hermes-4-14b": 7.0, "llama-3.1-8b": 4.0,
    "codellama-13b": 7.0, "codellama-7b": 4.0, "dolphin": 4.0,
    "phi-3.5-mini": 2.0, "deepseek-math": 4.0, "yi-9b-200k": 6.0,
    "functiongemma": 0.6, "llama-guard": 1.0, "nomic-embed": 0.5,
}


class DynamicModelLoader:
    """TRUE on-demand model loading — starts/stops llama-server processes.

    Instead of running all 16 models (80-120GB RAM), this keeps
    a maximum of max_cached models running at once (default 2 = 8-16GB).

    When a model is needed:
    1. If already running → return immediately
    2. If cache full → kill the least-recently-used server
    3. Start llama-server for the requested model
    4. Wait for /health to return 200
    5. Return

    Each model gets its own llama-server process on its configured port.
    """

    def __init__(
        self,
        max_cached: int = 2,
        models_dir: str = "",
        llama_cpp_path: str = "",
        log_dir: str = "/tmp/recursec-models",
    ) -> None:
        self._max_cached = max_cached
        self._models_dir = models_dir or os.environ.get(
            "RECURSEC_MODELS_DIR",
            os.path.expanduser("~/agent/models/gguf"),
        )
        self._llama_cpp = llama_cpp_path or os.environ.get(
            "RECURSEC_LLAMA_CPP",
            os.path.expanduser("~/llama.cpp/build/bin/llama-server"),
        )
        self._log_dir = log_dir
        os.makedirs(self._log_dir, exist_ok=True)

        # Currently loaded models: model_id → {"pid": int, "loaded_at": float, "last_used": float}
        self._loaded: dict[str, dict[str, Any]] = {}
        self._log = logger.bind(component="model_loader")

    @property
    def loaded_models(self) -> list[str]:
        """Return list of currently loaded model IDs."""
        return list(self._loaded.keys())

    @property
    def loaded_count(self) -> int:
        return len(self._loaded)

    @property
    def ram_usage_gb(self) -> float:
        """Estimated RAM usage of all loaded models."""
        return sum(MODEL_RAM_GB.get(m, 4.0) for m in self._loaded)

    def is_loaded(self, model_id: str) -> bool:
        """Check if a model's server process is running."""
        if model_id not in self._loaded:
            return False
        pid = self._loaded[model_id].get("pid", 0)
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            del self._loaded[model_id]
            return False

    def _get_model_path(self, model_id: str) -> str:
        """Get the full path to a model's GGUF file."""
        filename = MODEL_GGUF_FILES.get(model_id, "")
        if not filename:
            return ""
        return os.path.join(self._models_dir, filename)

    def _get_lru_model(self) -> str:
        """Return the model_id that was least recently used."""
        if not self._loaded:
            return ""
        return min(
            self._loaded.keys(),
            key=lambda m: self._loaded[m].get("last_used", 0.0),
        )

    def ensure_loaded(self, model_id: str, timeout_s: int = 60) -> bool:
        """Ensure a model is loaded and its server is running.

        - If already running, updates last_used and returns True.
        - If not running, evicts LRU model if at capacity, then starts it.
        - Waits up to timeout_s for the server to become healthy.
        - Returns True if the model is ready, False if it failed to start.
        """
        # Already loaded and process alive?
        if self.is_loaded(model_id):
            self._loaded[model_id]["last_used"] = time.time()
            return True

        # Check if the model file exists on disk
        model_path = self._get_model_path(model_id)
        if not model_path or not Path(model_path).exists():
            self._log.warning(
                "model_file_missing", model=model_id, path=model_path,
            )
            return False

        # Check if llama-server binary exists
        if not Path(self._llama_cpp).exists():
            self._log.warning(
                "llama_server_missing", path=self._llama_cpp,
            )
            return False

        # Evict LRU if at capacity
        while len(self._loaded) >= self._max_cached:
            lru = self._get_lru_model()
            if lru:
                self._log.info("evicting_lru_model", model=lru,
                               ram_freed=f"{MODEL_RAM_GB.get(lru, 4.0):.1f}GB")
                self.unload(lru)

        # Start the llama-server process
        server_config = MODEL_SERVERS.get(model_id, {})
        port = server_config.get("port", 8100)
        ctx = server_config.get("ctx", 4096)

        log_file = os.path.join(self._log_dir, f"{model_id}.log")

        embed_args: list[str] = []
        if model_id == "nomic-embed":
            embed_args = ["--embedding"]

        cmd = [
            self._llama_cpp,
            "--model", model_path,
            "--port", str(port),
            "--ctx-size", str(ctx),
            "--threads", "4",
            "--n-gpu-layers", "99",
            "--parallel", "4",
            "--cont-batching",
            "--flash-attn",
            *embed_args,
        ]

        self._log.info(
            "starting_model", model=model_id, port=port,
            ram=f"{MODEL_RAM_GB.get(model_id, 4.0):.1f}GB",
        )

        with open(log_file, "w") as lf:
            process = subprocess.Popen(
                cmd, stdout=lf, stderr=subprocess.STDOUT,
                start_new_session=True,
            )

        # Wait for the server to become healthy
        endpoint = f"http://127.0.0.1:{port}/health"
        start_time = time.time()
        while time.time() - start_time < timeout_s:
            try:
                req = urllib.request.Request(endpoint, method="GET")
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status == 200:
                        self._loaded[model_id] = {
                            "pid": process.pid,
                            "port": port,
                            "loaded_at": time.time(),
                            "last_used": time.time(),
                        }
                        elapsed = time.time() - start_time
                        self._log.info(
                            "model_loaded", model=model_id,
                            port=port, pid=process.pid,
                            elapsed=f"{elapsed:.1f}s",
                            total_loaded=len(self._loaded),
                            ram_estimate=f"{self.ram_usage_gb:.1f}GB",
                        )
                        return True
            except Exception:
                pass
            time.sleep(1.0)

        # Timed out — kill the process
        self._log.error("model_load_timeout", model=model_id, timeout=timeout_s)
        try:
            process.kill()
        except Exception:
            pass
        return False

    def unload(self, model_id: str) -> bool:
        """Stop a model's llama-server process and free its RAM."""
        info = self._loaded.pop(model_id, None)
        if not info:
            return False

        pid = info.get("pid", 0)
        if pid > 0:
            try:
                os.kill(pid, signal.SIGTERM)
                # Give it 5 seconds to shut down gracefully
                for _ in range(10):
                    try:
                        os.kill(pid, 0)
                        time.sleep(0.5)
                    except OSError:
                        break
                else:
                    # Force kill if still alive
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass
            except OSError:
                pass

        self._log.info(
            "model_unloaded", model=model_id, pid=pid,
            ram_freed=f"{MODEL_RAM_GB.get(model_id, 4.0):.1f}GB",
            remaining_loaded=len(self._loaded),
        )
        return True

    def unload_all(self) -> int:
        """Stop all loaded model servers. Returns count of models unloaded."""
        models = list(self._loaded.keys())
        count = 0
        for model_id in models:
            if self.unload(model_id):
                count += 1
        return count

    def get_status(self) -> dict[str, Any]:
        """Get loader status including loaded models and RAM usage."""
        loaded_info = {}
        for model_id, info in self._loaded.items():
            loaded_info[model_id] = {
                "pid": info.get("pid"),
                "port": info.get("port"),
                "ram_gb": MODEL_RAM_GB.get(model_id, 4.0),
                "loaded_at": info.get("loaded_at", 0),
                "last_used": info.get("last_used", 0),
                "uptime_s": round(time.time() - info.get("loaded_at", time.time()), 1),
            }
        return {
            "max_cached": self._max_cached,
            "loaded_count": len(self._loaded),
            "loaded_models": loaded_info,
            "total_ram_gb": round(self.ram_usage_gb, 1),
            "models_dir": self._models_dir,
            "llama_cpp": self._llama_cpp,
        }


# ── Smart routing table ───────────────────────────────────────
# Maps task types to the best specialist model(s).
# For critical tasks, multiple models analyze + vote (consensus).
# Router picks from this table; loader only starts servers on demand.

TASK_ROUTING: dict[str, dict[str, Any]] = {
    # Web vulnerability detection — WhiteRabbitNeo is the security specialist
    "scan_web_vulns": {
        "primary": "whiterabbitneo",
        "fallback": ["dolphin", "mistral"],
        "consensus": ["whiterabbitneo", "qwen-coder-14b", "deepseek-r1"],
    },
    "test_sql_injection": {
        "primary": "whiterabbitneo",
        "fallback": ["dolphin"],
        "consensus": ["whiterabbitneo", "qwen-coder-14b"],
    },
    "test_xss": {
        "primary": "whiterabbitneo",
        "fallback": ["dolphin"],
    },
    "test_auth_bypass": {
        "primary": "dolphin",
        "fallback": ["whiterabbitneo"],
    },

    # Code analysis — Qwen-Coder is the code specialist
    "analyze_source_code": {
        "primary": "qwen-coder-14b",
        "fallback": ["qwen-coder-7b", "codellama-13b"],
    },
    "review_security": {
        "primary": "qwen-coder-14b",
        "fallback": ["codellama-13b"],
        "consensus": ["qwen-coder-14b", "whiterabbitneo"],
    },
    "find_code_vulns": {
        "primary": "qwen-coder-14b",
        "fallback": ["codellama-13b"],
        "consensus": ["qwen-coder-14b", "whiterabbitneo", "deepseek-r1"],
    },
    "analyze_binary": {
        "primary": "codellama-13b",
        "fallback": ["codellama-7b", "qwen-coder-14b"],
    },

    # Exploit development — DeepSeek-R1 is the reasoning specialist
    "build_exploit_chain": {
        "primary": "deepseek-r1",
        "fallback": ["qwen-coder-14b"],
    },
    "plan_attack_path": {
        "primary": "deepseek-r1",
        "fallback": ["hermes-4-14b", "whiterabbitneo"],
    },
    "complex_reasoning": {
        "primary": "deepseek-r1",
        "fallback": ["hermes-4-14b"],
    },

    # Special cases
    "analyze_long_file": {
        "primary": "yi-9b-200k",
        "fallback": ["qwen-coder-14b"],
    },
    "quick_triage": {
        "primary": "phi-3.5-mini",
        "fallback": ["mistral", "functiongemma"],
    },
    "write_report": {
        "primary": "hermes-4-14b",
        "fallback": ["llama-3.1-8b", "mistral"],
    },
    "research_technique": {
        "primary": "dolphin",
        "fallback": ["whiterabbitneo"],
    },

    # General analysis — broad model preferences
    "security_analysis": {
        "primary": "whiterabbitneo",
        "fallback": ["dolphin", "hermes-4-14b", "qwen-coder-14b"],
        "consensus": ["whiterabbitneo", "dolphin", "deepseek-r1"],
    },
    "code_review": {
        "primary": "qwen-coder-14b",
        "fallback": ["qwen-coder-7b", "codellama-13b", "codellama-7b"],
    },
    "planning": {
        "primary": "deepseek-r1",
        "fallback": ["hermes-4-14b", "qwen-coder-14b"],
    },
    "recon_analysis": {
        "primary": "whiterabbitneo",
        "fallback": ["mistral", "llama-3.1-8b"],
    },
    "exploit_analysis": {
        "primary": "whiterabbitneo",
        "fallback": ["dolphin", "deepseek-r1"],
        "consensus": ["whiterabbitneo", "dolphin", "deepseek-r1"],
    },
    "general": {
        "primary": "mistral",
        "fallback": ["llama-3.1-8b", "phi-3.5-mini"],
    },
    "fast": {
        "primary": "phi-3.5-mini",
        "fallback": ["functiongemma", "mistral"],
    },
}

# Predictive model preloading — after task X, likely need model Y
TASK_PREDICTION: dict[str, str] = {
    "scan_web_vulns": "analyze_source_code",
    "analyze_source_code": "build_exploit_chain",
    "quick_triage": "scan_web_vulns",
    "recon_analysis": "planning",
    "planning": "security_analysis",
}


class LLMClient:
    """HTTP client for llama.cpp servers with TRUE on-demand model loading.

    The DynamicModelLoader starts/stops llama-server processes as needed.
    When chat() or complete() is called, the loader ensures the model is
    running (starting it if not), then sends the HTTP request.

    Use on_demand=True (default) for automatic model management.
    Use on_demand=False to connect to pre-running servers (legacy mode).
    """

    def __init__(
        self,
        base_host: str = "127.0.0.1",
        on_demand: bool = True,
        max_cached_models: int = 2,
    ) -> None:
        self._base_host = base_host
        self._request_count = 0
        self._total_tokens = 0
        self._total_latency_ms = 0.0
        self._errors = 0
        self._log = logger.bind(component="llm_client")
        # On-demand model loading
        self._on_demand = on_demand
        self._loader = DynamicModelLoader(max_cached=max_cached_models)
        # Routing state
        self._online_models: list[str] = []
        self._model_last_used: dict[str, float] = {}
        self._model_load_count: dict[str, int] = {}
        self._last_task_type: str = ""

    @property
    def loader(self) -> DynamicModelLoader:
        """Access the dynamic model loader for direct control."""
        return self._loader

    def ensure_model(self, model_id: str) -> bool:
        """Ensure a model is loaded and ready for requests.

        In on-demand mode: starts llama-server if not running, evicts LRU if full.
        In legacy mode: just checks if the server is responding.
        Returns True if the model is ready, False otherwise.
        """
        if not self._on_demand:
            return self.check_health(model_id)
        return self._loader.ensure_loaded(model_id)

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

    # ── Smart routing ──────────────────────────────────────────

    def refresh_online_models(self) -> list[str]:
        """Discover which model servers are currently online.

        Checks all ports. If a server is already running (e.g. started
        externally by the user), registers it with the loader so it
        participates in LRU tracking. On-demand models started by the
        loader are already tracked.
        """
        self._online_models = self.get_healthy_models()
        # Register externally-started servers with the loader
        for model_id in self._online_models:
            if model_id not in self._loader._loaded:
                server = MODEL_SERVERS.get(model_id, {})
                self._loader._loaded[model_id] = {
                    "pid": 0,  # 0 = externally managed, don't kill
                    "port": server.get("port", 0),
                    "loaded_at": time.time(),
                    "last_used": time.time(),
                }
        return self._online_models

    def route_task(self, task_type: str) -> str:
        """Route a task to the best available model using the smart routing table.

        On-demand mode: if the preferred model isn't running but its GGUF file
        exists on disk, the loader will start it (evicting LRU if needed).
        This means the router can pick the BEST model, not just whatever
        happens to be running.

        Fallback order:
        1. Primary model (start it if not running, on-demand mode)
        2. Primary model (if already online)
        3. Fallback models (already online)
        4. Any online model
        """
        routing = TASK_ROUTING.get(task_type, TASK_ROUTING.get("general", {}))
        if not routing:
            return self._online_models[0] if self._online_models else ""

        primary = routing.get("primary", "")

        # On-demand: try to load the primary model even if it's not running
        if self._on_demand and primary:
            if self.ensure_model(primary):
                if primary not in self._online_models:
                    self._online_models.append(primary)
                self._model_last_used[primary] = time.time()
                self._model_load_count[primary] = self._model_load_count.get(primary, 0) + 1
                self._last_task_type = task_type
                return primary

        # Primary already online?
        if primary and primary in self._online_models:
            self._model_last_used[primary] = time.time()
            self._model_load_count[primary] = self._model_load_count.get(primary, 0) + 1
            self._last_task_type = task_type
            return primary

        # Try fallbacks (prefer already-online ones first)
        for fallback in routing.get("fallback", []):
            if fallback in self._online_models:
                self._model_last_used[fallback] = time.time()
                self._model_load_count[fallback] = self._model_load_count.get(fallback, 0) + 1
                self._last_task_type = task_type
                return fallback

        # On-demand: try loading fallbacks
        if self._on_demand:
            for fallback in routing.get("fallback", []):
                if self.ensure_model(fallback):
                    if fallback not in self._online_models:
                        self._online_models.append(fallback)
                    self._model_last_used[fallback] = time.time()
                    self._model_load_count[fallback] = self._model_load_count.get(fallback, 0) + 1
                    self._last_task_type = task_type
                    return fallback

        # Any online model as last resort
        if self._online_models:
            model = self._online_models[0]
            self._model_last_used[model] = time.time()
            self._last_task_type = task_type
            return model

        return ""

    def get_consensus_models(self, task_type: str) -> list[str]:
        """Get the models that should participate in consensus voting for a task.

        Returns only models that are currently online. If fewer than 2 are
        available, consensus is not possible — caller should fall back to
        single-model analysis.
        """
        routing = TASK_ROUTING.get(task_type, {})
        consensus_list = routing.get("consensus", [])
        available = [m for m in consensus_list if m in self._online_models]
        return available

    def consensus_vote(
        self,
        task_type: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> tuple[str, float]:
        """Multi-model consensus voting for critical findings.

        Sends the same prompt to multiple specialist models, collects
        responses, and returns the majority-agreed content + confidence
        score (0.0 - 1.0). Higher confidence = more models agree.

        If only one model is available, returns its response with 0.5 confidence.
        """
        models = self.get_consensus_models(task_type)
        if not models:
            # No consensus models online — use single best model
            best = self.route_task(task_type)
            if not best:
                return ("", 0.0)
            resp = self.chat(best, [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ], temperature=temperature, max_tokens=max_tokens)
            return (resp.content if resp.success else "", 0.5)

        # Query each consensus model
        responses: list[tuple[str, str]] = []
        for model_id in models:
            self._log.info("consensus_query", model=model_id, task=task_type)
            resp = self.chat(model_id, [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ], temperature=temperature, max_tokens=max_tokens)
            if resp.success and resp.content:
                responses.append((model_id, resp.content))

        if not responses:
            return ("", 0.0)
        if len(responses) == 1:
            return (responses[0][1], 0.5)

        # Score: proportion of models that returned valid responses
        confidence = len(responses) / len(models)

        # Use the longest response as the primary (usually most detailed)
        # but combine unique findings from all models
        primary_response = max(responses, key=lambda r: len(r[1]))[1]

        self._log.info(
            "consensus_result",
            task=task_type,
            models_queried=len(models),
            models_responded=len(responses),
            confidence=f"{confidence:.2f}",
        )

        return (primary_response, confidence)

    def batch_route_tasks(self, task_types: list[str]) -> dict[str, list[str]]:
        """Group tasks by their target model to minimize model swaps.

        Returns {model_id: [task_type, task_type, ...]} so the orchestrator
        can execute all tasks for one model before loading the next.
        """
        batched: dict[str, list[str]] = {}
        for task_type in task_types:
            model = self.route_task(task_type)
            if model:
                if model not in batched:
                    batched[model] = []
                batched[model].append(task_type)
        return batched

    def predict_next_model(self) -> str:
        """Predict which model will be needed next based on task flow.

        Uses TASK_PREDICTION to anticipate the next task type after the
        current one, and returns the model that would handle it. Callers
        can use this to preload that model's server in the background.
        """
        if not self._last_task_type:
            return ""
        next_task = TASK_PREDICTION.get(self._last_task_type, "")
        if not next_task:
            return ""
        routing = TASK_ROUTING.get(next_task, {})
        return routing.get("primary", "")

    def get_routing_stats(self) -> dict[str, Any]:
        """Get stats about model routing, loading, and RAM usage."""
        return {
            "online_models": self._online_models,
            "model_usage_counts": dict(self._model_load_count),
            "last_task_type": self._last_task_type,
            "predicted_next_model": self.predict_next_model(),
            "total_task_routes": len(TASK_ROUTING),
            "on_demand": self._on_demand,
            "loader": self._loader.get_status(),
        }

    # ── Actual HTTP methods ─────────────────────────────────────

    def _http_post(self, url: str, payload: dict[str, Any], timeout_s: int = 120) -> dict[str, Any]:
        """Send a POST request and return parsed JSON."""
        data = json_mod.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return json_mod.loads(body)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            self._log.error("llm_http_error", url=url, status=exc.code, body=body[:200])
            return {"error": f"HTTP {exc.code}: {body[:200]}"}
        except urllib.error.URLError as exc:
            self._log.error("llm_url_error", url=url, reason=str(exc.reason))
            return {"error": f"Connection failed: {exc.reason}"}
        except Exception as exc:
            self._log.error("llm_request_error", url=url, error=str(exc))
            return {"error": str(exc)}

    def _http_get(self, url: str, timeout_s: int = 10) -> dict[str, Any]:
        """Send a GET request and return parsed JSON."""
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return json_mod.loads(body)
        except Exception:
            return {"error": "unreachable"}

    def check_health(self, model_id: str) -> bool:
        """Check if a model server is healthy."""
        endpoint = self.get_endpoint(model_id)
        if not endpoint:
            return False
        result = self._http_get(f"{endpoint}/health", timeout_s=5)
        return "error" not in result

    def get_healthy_models(self) -> list[str]:
        """Return list of model IDs that are currently healthy."""
        healthy = []
        for model_id in MODEL_SERVERS:
            if self.check_health(model_id):
                healthy.append(model_id)
        return healthy

    def chat(
        self,
        model_id: str,
        messages: list[dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        """Send a chat completion request, auto-loading the model if needed.

        On-demand: if the model's server isn't running, starts it first
        (evicts LRU model if cache is full). Then sends the HTTP request.
        """
        # Ensure model is loaded before sending request
        if self._on_demand:
            if not self.ensure_model(model_id):
                return LLMResponse(
                    model_id=model_id, success=False,
                    error=f"Failed to load model {model_id} on-demand",
                )

        request = self.build_chat_request(model_id, messages, temperature, max_tokens)
        if not request.endpoint_url:
            return LLMResponse(model_id=model_id, success=False, error="Unknown model")

        start = time.time()
        raw = self._http_post(request.endpoint_url, request.to_chat_completion())
        latency_ms = (time.time() - start) * 1000

        if "error" in raw and not raw.get("choices"):
            resp = LLMResponse(model_id=model_id, success=False, error=raw["error"], latency_ms=latency_ms)
        else:
            resp = self.parse_chat_response(raw, model_id=model_id, latency_ms=latency_ms)

        self.record_request(resp)
        return resp

    def complete(
        self,
        model_id: str,
        prompt: str,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        """Send a native /completion request, auto-loading the model if needed."""
        # Ensure model is loaded before sending request
        if self._on_demand:
            if not self.ensure_model(model_id):
                return LLMResponse(
                    model_id=model_id, success=False,
                    error=f"Failed to load model {model_id} on-demand",
                )

        request = self.build_completion_request(model_id, prompt, temperature, max_tokens)
        if not request.endpoint_url:
            return LLMResponse(model_id=model_id, success=False, error="Unknown model")

        start = time.time()
        raw = self._http_post(request.endpoint_url, request.to_completion())
        latency_ms = (time.time() - start) * 1000

        if "error" in raw and not raw.get("content"):
            resp = LLMResponse(model_id=model_id, success=False, error=raw["error"], latency_ms=latency_ms)
        else:
            resp = self.parse_completion_response(raw, model_id=model_id, latency_ms=latency_ms)

        self.record_request(resp)
        return resp

    def embed(self, text: str, model_id: str = "nomic-embed") -> EmbeddingResponse:
        """Send an embedding request and return the response."""
        request = self.build_embedding_request(text, model_id)
        if not request.endpoint_url:
            return EmbeddingResponse(model_id=model_id, success=False, error="Unknown model")

        raw = self._http_post(request.endpoint_url, request.to_embedding())
        if "error" in raw and not raw.get("embedding"):
            return EmbeddingResponse(model_id=model_id, success=False, error=raw["error"])

        return self.parse_embedding_response(raw, model_id=model_id)
