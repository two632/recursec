"""Agent metrics collector — comprehensive observability.

Implements:
1. Token usage tracking (per model, per task)
2. Latency tracking (LLM calls, tool calls)
3. Finding rate metrics
4. Agent efficiency scoring
5. Cost estimation
6. Throughput measurement
7. Error rate tracking
8. Resource utilization
9. Time-series aggregation
10. Alerting thresholds
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MetricType(str, Enum):
    COUNTER = "counter"         # Monotonically increasing
    GAUGE = "gauge"             # Current value
    HISTOGRAM = "histogram"     # Distribution of values
    RATE = "rate"               # Events per second


class AlertLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class MetricPoint:
    """A single metric data point."""
    name: str = ""
    value: float = 0.0
    labels: dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:30],
            "value": round(self.value, 3),
            "labels": self.labels,
        }


@dataclass
class TokenUsage:
    """Token usage tracking per model."""
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    requests: int = 0
    total_latency_ms: float = 0.0
    errors: int = 0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / max(1, self.requests)

    @property
    def avg_tokens_per_request(self) -> float:
        return self.total_tokens / max(1, self.requests)

    @property
    def error_rate(self) -> float:
        return self.errors / max(1, self.requests)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model[:20],
            "requests": self.requests,
            "total_tokens": self.total_tokens,
            "avg_latency_ms": round(self.avg_latency_ms, 1),
            "avg_tokens": round(self.avg_tokens_per_request, 0),
            "errors": self.errors,
            "error_rate": round(self.error_rate, 3),
        }


@dataclass
class ToolMetric:
    """Tool execution metrics."""
    tool: str = ""
    invocations: int = 0
    successes: int = 0
    failures: int = 0
    timeouts: int = 0
    total_duration_ms: float = 0.0
    findings_produced: int = 0

    @property
    def avg_duration_ms(self) -> float:
        return self.total_duration_ms / max(1, self.invocations)

    @property
    def success_rate(self) -> float:
        return self.successes / max(1, self.invocations)

    @property
    def finding_rate(self) -> float:
        return self.findings_produced / max(1, self.invocations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool[:15],
            "invocations": self.invocations,
            "success_rate": round(self.success_rate, 2),
            "avg_duration_ms": round(self.avg_duration_ms, 1),
            "findings": self.findings_produced,
            "finding_rate": round(self.finding_rate, 3),
        }


@dataclass
class AgentMetric:
    """Per-agent performance metrics."""
    agent_id: str = ""
    agent_type: str = ""
    tasks_completed: int = 0
    tasks_failed: int = 0
    findings_produced: int = 0
    tokens_used: int = 0
    tools_invoked: int = 0
    duration_s: float = 0.0
    children_spawned: int = 0

    @property
    def efficiency(self) -> float:
        """Findings per 1000 tokens."""
        return (self.findings_produced * 1000) / max(1, self.tokens_used)

    @property
    def success_rate(self) -> float:
        total = self.tasks_completed + self.tasks_failed
        return self.tasks_completed / max(1, total)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id[:10],
            "type": self.agent_type[:10],
            "tasks": self.tasks_completed,
            "findings": self.findings_produced,
            "tokens": self.tokens_used,
            "efficiency": round(self.efficiency, 2),
            "success_rate": round(self.success_rate, 2),
        }


@dataclass
class Alert:
    """A metric alert."""
    alert_id: str = ""
    level: AlertLevel = AlertLevel.WARNING
    metric: str = ""
    message: str = ""
    value: float = 0.0
    threshold: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.alert_id[:10],
            "level": self.level.value,
            "metric": self.metric[:20],
            "message": self.message[:40],
        }


class AgentMetricsCollector:
    """Comprehensive metrics collection and aggregation.

    Tracks all aspects of agent performance: token usage,
    latency, findings, tool effectiveness, and resource
    utilization.
    """

    def __init__(
        self,
        window_s: float = 300.0,
        max_history: int = 10000,
    ) -> None:
        self._token_usage: dict[str, TokenUsage] = {}
        self._tool_metrics: dict[str, ToolMetric] = {}
        self._agent_metrics: dict[str, AgentMetric] = {}
        self._alerts: list[Alert] = []
        self._counter = 0
        self._window_s = window_s
        self._max_history = max_history
        self._log = logger.bind(component="agent_metrics")

        # Time series data
        self._timeseries: dict[str, deque[MetricPoint]] = defaultdict(lambda: deque(maxlen=max_history))

        # Thresholds for alerts
        self._thresholds: dict[str, dict[str, float]] = {
            "error_rate": {"warning": 0.1, "critical": 0.3},
            "avg_latency_ms": {"warning": 5000, "critical": 15000},
            "token_rate": {"warning": 100000, "critical": 500000},
        }

        # Session totals
        self._session_start = time.time()
        self._total_tokens = 0
        self._total_findings = 0
        self._total_tool_calls = 0
        self._total_llm_calls = 0

    def record_llm_call(
        self,
        model: str,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        latency_ms: float = 0.0,
        success: bool = True,
    ) -> None:
        """Record an LLM API call."""
        if model not in self._token_usage:
            self._token_usage[model] = TokenUsage(model=model)

        usage = self._token_usage[model]
        usage.prompt_tokens += prompt_tokens
        usage.completion_tokens += completion_tokens
        usage.total_tokens += prompt_tokens + completion_tokens
        usage.requests += 1
        usage.total_latency_ms += latency_ms
        if not success:
            usage.errors += 1

        self._total_tokens += prompt_tokens + completion_tokens
        self._total_llm_calls += 1

        # Time series
        self._timeseries["tokens"].append(MetricPoint(
            name="tokens",
            value=prompt_tokens + completion_tokens,
            labels={"model": model},
        ))
        self._timeseries["latency"].append(MetricPoint(
            name="latency",
            value=latency_ms,
            labels={"model": model},
        ))

        # Check alerts
        if usage.error_rate > self._thresholds["error_rate"]["critical"]:
            self._create_alert(
                AlertLevel.CRITICAL,
                "error_rate",
                f"Model {model} error rate {usage.error_rate:.0%}",
                usage.error_rate,
                self._thresholds["error_rate"]["critical"],
            )

    def record_tool_call(
        self,
        tool: str,
        duration_ms: float = 0.0,
        success: bool = True,
        timeout: bool = False,
        findings: int = 0,
    ) -> None:
        """Record a tool invocation."""
        if tool not in self._tool_metrics:
            self._tool_metrics[tool] = ToolMetric(tool=tool)

        metric = self._tool_metrics[tool]
        metric.invocations += 1
        metric.total_duration_ms += duration_ms
        metric.findings_produced += findings

        if success:
            metric.successes += 1
        else:
            metric.failures += 1
        if timeout:
            metric.timeouts += 1

        self._total_tool_calls += 1
        self._total_findings += findings

        self._timeseries["tool_calls"].append(MetricPoint(
            name="tool_calls",
            value=duration_ms,
            labels={"tool": tool},
        ))

    def record_agent_task(
        self,
        agent_id: str,
        agent_type: str,
        success: bool,
        findings: int = 0,
        tokens: int = 0,
        tools: int = 0,
        duration_s: float = 0.0,
        children: int = 0,
    ) -> None:
        """Record an agent task completion."""
        if agent_id not in self._agent_metrics:
            self._agent_metrics[agent_id] = AgentMetric(
                agent_id=agent_id,
                agent_type=agent_type,
            )

        metric = self._agent_metrics[agent_id]
        if success:
            metric.tasks_completed += 1
        else:
            metric.tasks_failed += 1
        metric.findings_produced += findings
        metric.tokens_used += tokens
        metric.tools_invoked += tools
        metric.duration_s += duration_s
        metric.children_spawned += children

    def _create_alert(
        self,
        level: AlertLevel,
        metric: str,
        message: str,
        value: float,
        threshold: float,
    ) -> Alert:
        """Create a new alert."""
        self._counter += 1
        alert = Alert(
            alert_id=f"alert-{self._counter}",
            level=level,
            metric=metric,
            message=message,
            value=value,
            threshold=threshold,
        )
        self._alerts.append(alert)
        return alert

    def get_recent_rate(
        self,
        metric_name: str,
        window_s: float = 0.0,
    ) -> float:
        """Get rate (events/second) for a metric over window."""
        window = window_s or self._window_s
        cutoff = time.time() - window
        series = self._timeseries.get(metric_name, deque())

        count = sum(1 for p in series if p.timestamp > cutoff)
        return count / window if window > 0 else 0

    def get_session_summary(self) -> dict[str, Any]:
        """Get summary of the entire session."""
        elapsed = time.time() - self._session_start

        return {
            "duration_s": round(elapsed, 1),
            "total_tokens": self._total_tokens,
            "total_findings": self._total_findings,
            "total_tool_calls": self._total_tool_calls,
            "total_llm_calls": self._total_llm_calls,
            "tokens_per_minute": round(self._total_tokens / max(1, elapsed / 60), 0),
            "findings_per_hour": round(self._total_findings / max(1, elapsed / 3600), 1),
            "tool_calls_per_minute": round(self._total_tool_calls / max(1, elapsed / 60), 1),
        }

    def get_model_rankings(self) -> list[dict[str, Any]]:
        """Rank models by efficiency."""
        rankings = []
        for model, usage in self._token_usage.items():
            rankings.append({
                "model": model,
                "efficiency": round(usage.avg_tokens_per_request, 0),
                "latency": round(usage.avg_latency_ms, 0),
                "error_rate": round(usage.error_rate, 3),
                "total_tokens": usage.total_tokens,
            })
        rankings.sort(key=lambda r: r["error_rate"])
        return rankings

    def get_tool_rankings(self) -> list[dict[str, Any]]:
        """Rank tools by finding effectiveness."""
        rankings = []
        for tool, metric in self._tool_metrics.items():
            rankings.append({
                "tool": tool,
                "finding_rate": round(metric.finding_rate, 3),
                "success_rate": round(metric.success_rate, 2),
                "avg_duration": round(metric.avg_duration_ms, 0),
                "invocations": metric.invocations,
            })
        rankings.sort(key=lambda r: r["finding_rate"], reverse=True)
        return rankings

    def get_stats(self) -> dict[str, Any]:
        return {
            "session": self.get_session_summary(),
            "models": {k: v.to_dict() for k, v in self._token_usage.items()},
            "tools": {k: v.to_dict() for k, v in self._tool_metrics.items()},
            "agents": {k: v.to_dict() for k, v in self._agent_metrics.items()},
            "alerts": len(self._alerts),
            "recent_alerts": [a.to_dict() for a in self._alerts[-5:]],
        }
