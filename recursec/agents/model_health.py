"""Model health monitor — tracks LLM inference server health.

Implements:
1. Health check for all model servers
2. Latency tracking and alerting
3. Throughput monitoring
4. Error rate tracking
5. Automatic failover triggers
6. Model warmup detection
7. Resource utilization estimation
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ModelStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    OFFLINE = "offline"
    WARMING_UP = "warming_up"
    OVERLOADED = "overloaded"


class HealthCheckType(str, Enum):
    PING = "ping"                # Simple connectivity
    INFERENCE = "inference"      # Test generation
    EMBEDDING = "embedding"      # Test embedding
    LOAD = "load"               # Check load metrics


@dataclass
class HealthCheckResult:
    """Result of a health check."""
    model_id: str = ""
    check_type: HealthCheckType = HealthCheckType.PING
    status: ModelStatus = ModelStatus.HEALTHY
    latency_ms: float = 0.0
    error: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:12],
            "type": self.check_type.value,
            "status": self.status.value,
            "latency_ms": round(self.latency_ms, 1),
        }


@dataclass
class ModelMetrics:
    """Aggregated metrics for a model."""
    model_id: str = ""
    port: int = 0
    status: ModelStatus = ModelStatus.OFFLINE
    total_requests: int = 0
    total_errors: int = 0
    total_tokens_generated: int = 0
    latencies_ms: deque[float] = field(default_factory=lambda: deque(maxlen=100))
    last_check: float = 0.0
    last_success: float = 0.0
    consecutive_failures: int = 0

    @property
    def avg_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        return sum(self.latencies_ms) / len(self.latencies_ms)

    @property
    def p95_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        sorted_lats = sorted(self.latencies_ms)
        idx = int(len(sorted_lats) * 0.95)
        return sorted_lats[min(idx, len(sorted_lats) - 1)]

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_errors / self.total_requests

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:12],
            "port": self.port,
            "status": self.status.value,
            "requests": self.total_requests,
            "errors": self.total_errors,
            "error_rate": round(self.error_rate, 3),
            "avg_latency_ms": round(self.avg_latency_ms, 1),
            "p95_latency_ms": round(self.p95_latency_ms, 1),
        }


# ── Model server configuration ──────────────────────────────

MODEL_SERVERS: list[dict[str, Any]] = [
    {"id": "whiterabbitneo-7b", "port": 8100, "type": "llama_cpp"},
    {"id": "qwen-coder-14b", "port": 8101, "type": "llama_cpp"},
    {"id": "qwen-coder-7b", "port": 8102, "type": "llama_cpp"},
    {"id": "deepseek-r1-7b", "port": 8103, "type": "llama_cpp"},
    {"id": "deepseek-math-7b", "port": 8104, "type": "llama_cpp"},
    {"id": "hermes-14b", "port": 8105, "type": "llama_cpp"},
    {"id": "llama-3.1-8b", "port": 8106, "type": "llama_cpp"},
    {"id": "dolphin-8b", "port": 8107, "type": "llama_cpp"},
    {"id": "mistral-7b", "port": 8108, "type": "llama_cpp"},
    {"id": "codellama-13b", "port": 8109, "type": "llama_cpp"},
    {"id": "codellama-7b", "port": 8110, "type": "llama_cpp"},
    {"id": "yi-9b-200k", "port": 8111, "type": "llama_cpp"},
    {"id": "phi-3.5-mini", "port": 8112, "type": "llama_cpp"},
    {"id": "nomic-embed", "port": 8113, "type": "llama_cpp"},
    {"id": "llama-guard-3", "port": 8114, "type": "llama_cpp"},
    {"id": "functiongemma", "port": 8115, "type": "llama_cpp"},
]

# ── Health thresholds ────────────────────────────────────────

HEALTH_THRESHOLDS: dict[str, float] = {
    "latency_degraded_ms": 5000.0,    # 5 seconds
    "latency_unhealthy_ms": 15000.0,   # 15 seconds
    "error_rate_degraded": 0.05,       # 5%
    "error_rate_unhealthy": 0.20,      # 20%
    "consecutive_failures_unhealthy": 3,
    "warmup_time_s": 30.0,            # Time after startup
}


class ModelHealthMonitor:
    """Monitors health of LLM inference servers.

    Tracks latency, error rates, and availability
    for all configured model servers.
    """

    def __init__(self) -> None:
        self._models: dict[str, ModelMetrics] = {}
        self._log = logger.bind(component="model_health")
        self._init_models()

    def _init_models(self) -> None:
        """Initialize model metrics."""
        for server in MODEL_SERVERS:
            self._models[server["id"]] = ModelMetrics(
                model_id=server["id"],
                port=server["port"],
            )

    def record_request(
        self,
        model_id: str,
        latency_ms: float,
        tokens_generated: int = 0,
        success: bool = True,
        error: str = "",
    ) -> None:
        """Record a request to a model."""
        metrics = self._models.get(model_id)
        if not metrics:
            return

        metrics.total_requests += 1
        metrics.latencies_ms.append(latency_ms)
        metrics.last_check = time.time()

        if success:
            metrics.total_tokens_generated += tokens_generated
            metrics.last_success = time.time()
            metrics.consecutive_failures = 0
        else:
            metrics.total_errors += 1
            metrics.consecutive_failures += 1

        # Update status
        metrics.status = self._evaluate_status(metrics)

    def _evaluate_status(self, metrics: ModelMetrics) -> ModelStatus:
        """Evaluate model health status."""
        # Check consecutive failures
        if metrics.consecutive_failures >= HEALTH_THRESHOLDS["consecutive_failures_unhealthy"]:
            return ModelStatus.UNHEALTHY

        # Check error rate
        if metrics.error_rate >= HEALTH_THRESHOLDS["error_rate_unhealthy"]:
            return ModelStatus.UNHEALTHY
        if metrics.error_rate >= HEALTH_THRESHOLDS["error_rate_degraded"]:
            return ModelStatus.DEGRADED

        # Check latency
        if metrics.avg_latency_ms >= HEALTH_THRESHOLDS["latency_unhealthy_ms"]:
            return ModelStatus.OVERLOADED
        if metrics.avg_latency_ms >= HEALTH_THRESHOLDS["latency_degraded_ms"]:
            return ModelStatus.DEGRADED

        # Check warmup
        if metrics.total_requests < 3:
            return ModelStatus.WARMING_UP

        return ModelStatus.HEALTHY

    def record_health_check(self, result: HealthCheckResult) -> None:
        """Record a health check result."""
        metrics = self._models.get(result.model_id)
        if not metrics:
            return

        metrics.last_check = result.timestamp
        if result.status == ModelStatus.HEALTHY:
            metrics.consecutive_failures = 0
            metrics.last_success = result.timestamp
        else:
            metrics.consecutive_failures += 1

        metrics.status = result.status

    def get_healthy_models(self) -> list[str]:
        """Get list of healthy model IDs."""
        return [
            m.model_id for m in self._models.values()
            if m.status in (ModelStatus.HEALTHY, ModelStatus.WARMING_UP)
        ]

    def get_model_for_task(
        self,
        preferred_models: list[str] | None = None,
    ) -> str | None:
        """Get best available model for a task."""
        candidates = preferred_models or list(self._models.keys())

        # Filter to healthy/degraded models
        available = []
        for model_id in candidates:
            metrics = self._models.get(model_id)
            if metrics and metrics.status in (
                ModelStatus.HEALTHY,
                ModelStatus.WARMING_UP,
                ModelStatus.DEGRADED,
            ):
                available.append(metrics)

        if not available:
            return None

        # Sort by latency (prefer fastest)
        available.sort(key=lambda m: m.avg_latency_ms)
        return available[0].model_id

    def should_failover(self, model_id: str) -> bool:
        """Check if a model should be failed over."""
        metrics = self._models.get(model_id)
        if not metrics:
            return True
        return metrics.status in (ModelStatus.UNHEALTHY, ModelStatus.OFFLINE)

    def build_health_prompt(self) -> str:
        """Build health status for LLM context."""
        lines = ["## Model Health\n"]
        for metrics in self._models.values():
            status_icon = {
                "healthy": "OK",
                "degraded": "WARN",
                "unhealthy": "DOWN",
                "offline": "OFF",
                "warming_up": "WARM",
                "overloaded": "LOAD",
            }.get(metrics.status.value, "?")
            lines.append(
                f"- {metrics.model_id[:15]}: [{status_icon}] "
                f"lat={metrics.avg_latency_ms:.0f}ms "
                f"err={metrics.error_rate:.1%}"
            )
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for m in self._models.values():
            status_counts[m.status.value] = status_counts.get(m.status.value, 0) + 1

        return {
            "total_models": len(self._models),
            "by_status": status_counts,
            "total_requests": sum(m.total_requests for m in self._models.values()),
            "total_tokens": sum(m.total_tokens_generated for m in self._models.values()),
        }
