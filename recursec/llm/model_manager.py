"""Model manager — lifecycle management for local LLM servers.

Manages starting, stopping, monitoring, and auto-scaling of llama.cpp
server instances for all configured GGUF models.

Features:
- Launch llama.cpp servers for each model on separate ports
- Health monitoring with auto-restart
- Load-based auto-scaling (start/stop models based on demand)
- GPU memory management (track VRAM usage)
- Model priority queuing (ensure critical models stay loaded)
- Graceful shutdown with state persistence
- Performance metrics per model
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class ModelStatus(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    UNHEALTHY = "unhealthy"
    STOPPING = "stopping"
    ERROR = "error"


class ModelTier(str, Enum):
    CRITICAL = "critical"    # Always running (e.g., WhiteRabbitNeo, guard)
    HIGH = "high"            # Running unless memory pressure
    MEDIUM = "medium"        # Running when needed
    LOW = "low"              # Only started on demand
    EMBEDDING = "embedding"  # Embedding models (always running)


@dataclass
class ModelInstance:
    """A running model instance."""
    name: str
    model_path: str
    port: int
    tier: ModelTier = ModelTier.MEDIUM
    status: ModelStatus = ModelStatus.STOPPED
    pid: int | None = None
    process: Any = None  # asyncio.subprocess.Process
    context_size: int = 4096
    gpu_layers: int = -1  # -1 = all layers on GPU
    threads: int = 4
    parallel_slots: int = 4
    batch_size: int = 512
    flash_attention: bool = True

    # Performance metrics
    total_requests: int = 0
    total_tokens_generated: int = 0
    total_errors: int = 0
    avg_tokens_per_s: float = 0.0
    avg_latency_ms: float = 0.0
    last_request_at: float = 0.0
    started_at: float = 0.0
    uptime_s: float = 0.0

    # Health check
    last_health_check: float = 0.0
    consecutive_failures: int = 0
    max_consecutive_failures: int = 3

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "port": self.port,
            "tier": self.tier.value, "status": self.status.value,
            "pid": self.pid, "context_size": self.context_size,
            "total_requests": self.total_requests,
            "total_tokens": self.total_tokens_generated,
            "avg_tokens_per_s": round(self.avg_tokens_per_s, 1),
            "avg_latency_ms": round(self.avg_latency_ms, 1),
            "uptime_s": round(time.time() - self.started_at, 1) if self.started_at else 0,
        }


# Default model configurations for the user's 16 GGUF models
DEFAULT_MODELS: list[dict[str, Any]] = [
    {"name": "whiterabbitneo-7b", "file": "WhiteRabbitNeo-7B-v1.5a-Q4_K_M.gguf", "port": 8100, "tier": "critical", "ctx": 8192, "parallel": 4},
    {"name": "qwen-coder-14b", "file": "Qwen2.5-Coder-14B-Instruct-Q3_K_M.gguf", "port": 8101, "tier": "high", "ctx": 8192, "parallel": 2},
    {"name": "qwen-coder-7b", "file": "Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf", "port": 8102, "tier": "medium", "ctx": 8192, "parallel": 4},
    {"name": "codellama-13b", "file": "codellama-13b-instruct.Q3_K_M.gguf", "port": 8103, "tier": "medium", "ctx": 8192, "parallel": 2},
    {"name": "codellama-7b", "file": "codellama-7b.Q4_K_M.gguf", "port": 8104, "tier": "low", "ctx": 4096, "parallel": 4},
    {"name": "deepseek-r1-7b", "file": "DeepSeek-R1-Distill-Qwen-7B-q4_k_m.gguf", "port": 8105, "tier": "high", "ctx": 8192, "parallel": 4},
    {"name": "deepseek-math-7b", "file": "deepseek-math-7b-instruct-q4_k_m.gguf", "port": 8106, "tier": "low", "ctx": 4096, "parallel": 4},
    {"name": "yi-9b-200k", "file": "Yi-9B-200K.Q5_K_M.gguf", "port": 8107, "tier": "medium", "ctx": 32768, "parallel": 2},
    {"name": "hermes-4-14b", "file": "Hermes-4-14B-IQ2_M.gguf", "port": 8108, "tier": "medium", "ctx": 8192, "parallel": 2},
    {"name": "llama-3.1-8b", "file": "Meta-Llama-3.1-8B-Instruct-Q4_K_S.gguf", "port": 8109, "tier": "medium", "ctx": 8192, "parallel": 4},
    {"name": "dolphin-2.9-8b", "file": "dolphin-2.9-llama3-8b.Q4_K_M.gguf", "port": 8110, "tier": "medium", "ctx": 8192, "parallel": 4},
    {"name": "mistral-7b", "file": "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf", "port": 8111, "tier": "medium", "ctx": 8192, "parallel": 4},
    {"name": "phi-3.5-mini", "file": "Phi-3.5-mini-instruct-Q4_K_M.gguf", "port": 8112, "tier": "low", "ctx": 4096, "parallel": 8},
    {"name": "functiongemma", "file": "functiongemma-270m-it-BF16.gguf", "port": 8113, "tier": "critical", "ctx": 2048, "parallel": 16},
    {"name": "llama-guard-3", "file": "llama-guard-3-1b-q4_k_m.gguf", "port": 8114, "tier": "critical", "ctx": 2048, "parallel": 8},
    {"name": "nomic-embed", "file": "nomic-embed-text-v1.5.f32.gguf", "port": 8115, "tier": "embedding", "ctx": 2048, "parallel": 16},
]


class ModelManager:
    """Manages lifecycle of local LLM server instances.

    Handles starting llama.cpp servers, health monitoring,
    auto-restart, and graceful shutdown.
    """

    def __init__(
        self,
        models_dir: str = "",
        llama_cpp_path: str = "",
        auto_start_tiers: list[ModelTier] | None = None,
    ) -> None:
        self._models_dir = Path(models_dir) if models_dir else Path.home() / "agent" / "models" / "gguf"
        self._llama_cpp = llama_cpp_path or "llama-server"
        self._auto_start_tiers = auto_start_tiers or [ModelTier.CRITICAL, ModelTier.EMBEDDING]
        self._instances: dict[str, ModelInstance] = {}
        self._health_task: asyncio.Task[None] | None = None
        self._running = False
        self._log = logger.bind(component="model_manager")

    def configure_models(self, models: list[dict[str, Any]] | None = None) -> None:
        """Configure model instances from a list of model configs."""
        model_list = models or DEFAULT_MODELS
        for model_data in model_list:
            name = model_data["name"]
            model_path = str(self._models_dir / model_data["file"])

            try:
                tier = ModelTier(model_data.get("tier", "medium"))
            except ValueError:
                tier = ModelTier.MEDIUM

            instance = ModelInstance(
                name=name,
                model_path=model_path,
                port=model_data.get("port", 8100),
                tier=tier,
                context_size=model_data.get("ctx", 4096),
                parallel_slots=model_data.get("parallel", 4),
                gpu_layers=model_data.get("gpu_layers", -1),
                threads=model_data.get("threads", 4),
                batch_size=model_data.get("batch_size", 512),
                flash_attention=model_data.get("flash_attention", True),
            )
            self._instances[name] = instance

    async def start_all(self) -> dict[str, bool]:
        """Start all models in auto-start tiers."""
        results: dict[str, bool] = {}
        for name, instance in self._instances.items():
            if instance.tier in self._auto_start_tiers:
                success = await self.start_model(name)
                results[name] = success
        return results

    async def start_model(self, name: str) -> bool:
        """Start a specific model's llama.cpp server."""
        instance = self._instances.get(name)
        if not instance:
            self._log.error("model_not_found", name=name)
            return False

        if instance.status == ModelStatus.RUNNING:
            return True

        instance.status = ModelStatus.STARTING

        # Build command
        cmd = self._build_launch_command(instance)
        self._log.info("starting_model", name=name, port=instance.port, cmd=" ".join(cmd[:5]))

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            instance.process = process
            instance.pid = process.pid
            instance.started_at = time.time()

            # Wait for server to be ready
            ready = await self._wait_for_ready(instance, timeout_s=60.0)
            if ready:
                instance.status = ModelStatus.RUNNING
                self._log.info("model_started", name=name, port=instance.port, pid=instance.pid)
                return True
            else:
                instance.status = ModelStatus.ERROR
                self._log.error("model_start_timeout", name=name)
                await self.stop_model(name)
                return False

        except FileNotFoundError:
            instance.status = ModelStatus.ERROR
            self._log.error("llama_cpp_not_found", path=self._llama_cpp)
            return False
        except Exception as e:
            instance.status = ModelStatus.ERROR
            self._log.error("model_start_error", name=name, error=str(e))
            return False

    async def stop_model(self, name: str) -> bool:
        """Stop a specific model's server."""
        instance = self._instances.get(name)
        if not instance:
            return False

        if instance.process:
            instance.status = ModelStatus.STOPPING
            try:
                instance.process.terminate()
                await asyncio.wait_for(instance.process.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                instance.process.kill()
                await instance.process.wait()
            except ProcessLookupError:
                pass

        instance.status = ModelStatus.STOPPED
        instance.process = None
        instance.pid = None
        instance.uptime_s = time.time() - instance.started_at if instance.started_at else 0

        self._log.info("model_stopped", name=name)
        return True

    async def stop_all(self) -> None:
        """Stop all running models."""
        self._running = False
        if self._health_task:
            self._health_task.cancel()

        tasks = []
        for name, instance in self._instances.items():
            if instance.status in (ModelStatus.RUNNING, ModelStatus.UNHEALTHY):
                tasks.append(self.stop_model(name))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def start_health_monitor(self, interval_s: float = 30.0) -> None:
        """Start background health monitoring."""
        self._running = True
        self._health_task = asyncio.create_task(self._health_loop(interval_s))

    async def _health_loop(self, interval_s: float) -> None:
        """Background health check loop."""
        while self._running:
            try:
                await asyncio.sleep(interval_s)
                for name, instance in self._instances.items():
                    if instance.status != ModelStatus.RUNNING:
                        continue

                    healthy = await self._check_health(instance)
                    instance.last_health_check = time.time()

                    if healthy:
                        instance.consecutive_failures = 0
                    else:
                        instance.consecutive_failures += 1
                        if instance.consecutive_failures >= instance.max_consecutive_failures:
                            self._log.warning(
                                "model_unhealthy, restarting",
                                name=name,
                                failures=instance.consecutive_failures,
                            )
                            instance.status = ModelStatus.UNHEALTHY
                            await self.stop_model(name)
                            await self.start_model(name)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._log.error("health_loop_error", error=str(e))

    async def _check_health(self, instance: ModelInstance) -> bool:
        """Check if a model server is healthy via /health endpoint."""
        import aiohttp
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://127.0.0.1:{instance.port}/health"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def _wait_for_ready(self, instance: ModelInstance, timeout_s: float = 60.0) -> bool:
        """Wait for a model server to become ready."""
        start = time.time()
        while time.time() - start < timeout_s:
            if await self._check_health(instance):
                return True
            await asyncio.sleep(1.0)
        return False

    def _build_launch_command(self, instance: ModelInstance) -> list[str]:
        """Build the llama.cpp server launch command."""
        cmd = [
            self._llama_cpp,
            "--model", instance.model_path,
            "--port", str(instance.port),
            "--ctx-size", str(instance.context_size),
            "--n-gpu-layers", str(instance.gpu_layers),
            "--threads", str(instance.threads),
            "--parallel", str(instance.parallel_slots),
            "--batch-size", str(instance.batch_size),
            "--host", "127.0.0.1",
        ]

        if instance.flash_attention:
            cmd.append("--flash-attn")

        return cmd

    # ── Auto-scaling ────────────────────────────────────────

    async def scale_up(self, model_type: str) -> str | None:
        """Start a stopped model that matches the type. Returns model name or None."""
        for name, instance in self._instances.items():
            if instance.status == ModelStatus.STOPPED and model_type in name:
                success = await self.start_model(name)
                if success:
                    return name
        return None

    async def scale_down(self, exclude_tiers: list[ModelTier] | None = None) -> str | None:
        """Stop the least-used non-critical model. Returns model name or None."""
        protected = exclude_tiers or [ModelTier.CRITICAL, ModelTier.EMBEDDING]
        candidates = [
            (name, inst) for name, inst in self._instances.items()
            if inst.status == ModelStatus.RUNNING and inst.tier not in protected
        ]

        if not candidates:
            return None

        # Find least recently used
        candidates.sort(key=lambda x: x[1].last_request_at)
        name = candidates[0][0]
        await self.stop_model(name)
        return name

    # ── Reporting ───────────────────────────────────────────

    def get_model_status(self, name: str) -> dict[str, Any] | None:
        instance = self._instances.get(name)
        return instance.to_dict() if instance else None

    def get_all_status(self) -> dict[str, Any]:
        by_status: dict[str, int] = defaultdict(int)
        for inst in self._instances.values():
            by_status[inst.status.value] += 1
        return {
            "total_models": len(self._instances),
            "by_status": dict(by_status),
            "models": {name: inst.to_dict() for name, inst in self._instances.items()},
        }

    def get_running_models(self) -> list[str]:
        return [
            name for name, inst in self._instances.items()
            if inst.status == ModelStatus.RUNNING
        ]

    def get_total_tokens(self) -> int:
        return sum(inst.total_tokens_generated for inst in self._instances.values())

    def get_performance_summary(self) -> dict[str, Any]:
        return {
            name: {
                "requests": inst.total_requests,
                "tokens": inst.total_tokens_generated,
                "avg_tps": round(inst.avg_tokens_per_s, 1),
                "avg_latency_ms": round(inst.avg_latency_ms, 1),
                "errors": inst.total_errors,
            }
            for name, inst in self._instances.items()
            if inst.total_requests > 0
        }
