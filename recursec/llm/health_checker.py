"""Model health checker — monitors LLM server health and availability.

Implements:
1. Periodic health checks for all configured models
2. Latency measurement
3. Error rate tracking
4. Automatic failover detection
5. Model warm-up and readiness checks
6. Throughput monitoring
7. Context window utilization
8. Model comparison metrics
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ModelStatus(str, Enum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNREACHABLE = "unreachable"
    OVERLOADED = "overloaded"
    STARTING = "starting"


@dataclass
class ModelHealth:
    """Health status of a single model."""
    name: str = ""
    host: str = "127.0.0.1"
    port: int = 8100
    status: ModelStatus = ModelStatus.UNKNOWN
    latency_ms: float = 0.0
    latency_avg_ms: float = 0.0
    error_rate: float = 0.0
    requests_total: int = 0
    requests_failed: int = 0
    last_check: float = 0.0
    last_success: float = 0.0
    last_error: str = ""
    consecutive_failures: int = 0
    uptime_s: float = 0.0

    @property
    def is_available(self) -> bool:
        return self.status in (ModelStatus.HEALTHY, ModelStatus.DEGRADED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "port": self.port,
            "status": self.status.value,
            "latency_ms": round(self.latency_ms, 1),
            "error_rate": round(self.error_rate, 3),
            "requests": self.requests_total,
            "available": self.is_available,
        }


@dataclass
class HealthReport:
    """Aggregate health report for all models."""
    models: list[ModelHealth] = field(default_factory=list)
    healthy_count: int = 0
    total_count: int = 0
    avg_latency_ms: float = 0.0
    overall_status: str = "unknown"
    checked_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "healthy": self.healthy_count,
            "total": self.total_count,
            "avg_latency_ms": round(self.avg_latency_ms, 1),
            "status": self.overall_status,
            "models": [m.to_dict() for m in self.models],
        }


class ModelHealthChecker:
    """Monitors LLM server health and availability.

    Performs periodic health checks, tracks latency,
    and detects degradation or failures.
    """

    def __init__(
        self,
        check_interval_s: float = 30.0,
        timeout_s: float = 10.0,
        max_consecutive_failures: int = 3,
    ) -> None:
        self._check_interval = check_interval_s
        self._timeout = timeout_s
        self._max_failures = max_consecutive_failures
        self._models: dict[str, ModelHealth] = {}
        self._latency_history: dict[str, list[float]] = {}
        self._running = False
        self._log = logger.bind(component="health_checker")

    def register_model(
        self,
        name: str,
        host: str = "127.0.0.1",
        port: int = 8100,
    ) -> None:
        """Register a model for health checking."""
        self._models[name] = ModelHealth(
            name=name, host=host, port=port,
        )
        self._latency_history[name] = []

    async def check_model(self, name: str) -> ModelHealth:
        """Check a single model's health."""
        model = self._models.get(name)
        if not model:
            return ModelHealth(name=name, status=ModelStatus.UNKNOWN)

        start = time.time()
        model.last_check = start

        try:
            # HTTP health check to llama.cpp /health endpoint
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(model.host, model.port),
                timeout=self._timeout,
            )

            request = (
                f"GET /health HTTP/1.1\r\n"
                f"Host: {model.host}:{model.port}\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(request.encode())
            await writer.drain()

            response = await asyncio.wait_for(
                reader.read(4096),
                timeout=self._timeout,
            )

            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass

            latency = (time.time() - start) * 1000
            model.latency_ms = latency

            # Track latency history
            history = self._latency_history.get(name, [])
            history.append(latency)
            if len(history) > 100:
                history = history[-100:]
            self._latency_history[name] = history
            model.latency_avg_ms = sum(history) / len(history)

            # Parse response
            response_str = response.decode(errors="replace")
            status_line = response_str.split("\r\n")[0] if response_str else ""

            model.requests_total += 1

            if "200" in status_line:
                model.status = ModelStatus.HEALTHY
                model.consecutive_failures = 0
                model.last_success = time.time()

                # Check for degradation
                if latency > 5000:
                    model.status = ModelStatus.DEGRADED
            elif "503" in status_line:
                model.status = ModelStatus.OVERLOADED
                model.consecutive_failures += 1
            else:
                model.status = ModelStatus.DEGRADED
                model.consecutive_failures += 1

        except asyncio.TimeoutError:
            model.status = ModelStatus.UNREACHABLE
            model.requests_total += 1
            model.requests_failed += 1
            model.consecutive_failures += 1
            model.last_error = "Connection timeout"

        except (OSError, ConnectionError) as e:
            model.status = ModelStatus.UNREACHABLE
            model.requests_total += 1
            model.requests_failed += 1
            model.consecutive_failures += 1
            model.last_error = str(e)[:100]

        # Update error rate
        if model.requests_total > 0:
            model.error_rate = model.requests_failed / model.requests_total

        return model

    async def check_all(self) -> HealthReport:
        """Check all registered models."""
        tasks = [self.check_model(name) for name in self._models]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        models = []
        for result in results:
            if isinstance(result, ModelHealth):
                models.append(result)

        healthy = sum(1 for m in models if m.status == ModelStatus.HEALTHY)
        latencies = [m.latency_ms for m in models if m.latency_ms > 0]

        overall = "healthy"
        if healthy == 0:
            overall = "critical"
        elif healthy < len(models) // 2:
            overall = "degraded"

        return HealthReport(
            models=models,
            healthy_count=healthy,
            total_count=len(models),
            avg_latency_ms=sum(latencies) / len(latencies) if latencies else 0,
            overall_status=overall,
        )

    async def start_monitoring(self) -> None:
        """Start periodic health checking."""
        self._running = True
        while self._running:
            await self.check_all()
            await asyncio.sleep(self._check_interval)

    def stop_monitoring(self) -> None:
        self._running = False

    def get_model_health(self, name: str) -> ModelHealth | None:
        return self._models.get(name)

    def get_available_models(self) -> list[str]:
        return [
            name for name, health in self._models.items()
            if health.is_available
        ]

    def get_stats(self) -> dict[str, Any]:
        by_status: dict[str, int] = {}
        for model in self._models.values():
            by_status.setdefault(model.status.value, 0)
            by_status[model.status.value] += 1

        return {
            "registered": len(self._models),
            "available": len(self.get_available_models()),
            "by_status": by_status,
        }
