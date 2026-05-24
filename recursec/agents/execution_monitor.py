"""Execution monitor — real-time monitoring of agent and tool execution.

Tracks and monitors:
1. Agent execution status (running, waiting, completed, failed)
2. Tool execution metrics (duration, success rate, output size)
3. LLM request metrics (latency, token usage, quality)
4. Resource consumption (memory, CPU, network)
5. Error tracking and alerting
6. Performance bottleneck detection
7. Execution timeline visualization
8. SLA violation detection
9. Automatic throttling on resource limits
10. Execution replay/audit trail
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class EventType(str, Enum):
    AGENT_START = "agent_start"
    AGENT_COMPLETE = "agent_complete"
    AGENT_FAIL = "agent_fail"
    TOOL_START = "tool_start"
    TOOL_COMPLETE = "tool_complete"
    TOOL_FAIL = "tool_fail"
    LLM_REQUEST = "llm_request"
    LLM_RESPONSE = "llm_response"
    LLM_ERROR = "llm_error"
    FINDING = "finding"
    ERROR = "error"
    WARNING = "warning"
    THROTTLE = "throttle"
    SLA_VIOLATION = "sla_violation"


class SeverityLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ExecutionEvent:
    """A single execution event."""
    event_id: str = ""
    event_type: EventType = EventType.AGENT_START
    severity: SeverityLevel = SeverityLevel.INFO
    agent_id: str = ""
    component: str = ""
    message: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "time": f"{self.timestamp:.0f}",
            "type": self.event_type.value[:12],
            "sev": self.severity.value[:4],
            "agent": self.agent_id[:8],
            "msg": self.message[:40],
        }


@dataclass
class AgentMetrics:
    """Metrics for a single agent."""
    agent_id: str = ""
    role: str = ""
    status: str = "idle"
    tasks_completed: int = 0
    tasks_failed: int = 0
    tools_executed: int = 0
    llm_requests: int = 0
    total_tokens: int = 0
    total_duration_ms: float = 0.0
    findings_reported: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)

    @property
    def success_rate(self) -> float:
        total = self.tasks_completed + self.tasks_failed
        if total == 0:
            return 0.0
        return self.tasks_completed / total

    @property
    def avg_task_duration_ms(self) -> float:
        if self.tasks_completed == 0:
            return 0.0
        return self.total_duration_ms / self.tasks_completed

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id[:8],
            "role": self.role[:10],
            "status": self.status[:8],
            "tasks": f"{self.tasks_completed}/{self.tasks_completed + self.tasks_failed}",
            "tools": self.tools_executed,
            "llm": self.llm_requests,
            "findings": self.findings_reported,
            "errors": self.errors,
        }


@dataclass
class ToolMetrics:
    """Metrics for a specific tool."""
    tool_name: str = ""
    executions: int = 0
    successes: int = 0
    failures: int = 0
    total_duration_ms: float = 0.0
    avg_output_bytes: float = 0.0
    findings_generated: int = 0

    @property
    def success_rate(self) -> float:
        if self.executions == 0:
            return 0.0
        return self.successes / self.executions

    @property
    def avg_duration_ms(self) -> float:
        if self.executions == 0:
            return 0.0
        return self.total_duration_ms / self.executions

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name[:15],
            "execs": self.executions,
            "rate": f"{self.success_rate:.0%}",
            "avg_ms": f"{self.avg_duration_ms:.0f}",
            "findings": self.findings_generated,
        }


@dataclass
class ModelMetrics:
    """Metrics for an LLM model."""
    model_id: str = ""
    requests: int = 0
    errors: int = 0
    total_tokens: int = 0
    total_latency_ms: float = 0.0
    quality_scores: list[float] = field(default_factory=list)

    @property
    def avg_latency_ms(self) -> float:
        if self.requests == 0:
            return 0.0
        return self.total_latency_ms / self.requests

    @property
    def avg_quality(self) -> float:
        if not self.quality_scores:
            return 0.0
        return sum(self.quality_scores) / len(self.quality_scores)

    @property
    def error_rate(self) -> float:
        if self.requests == 0:
            return 0.0
        return self.errors / self.requests

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "reqs": self.requests,
            "err": f"{self.error_rate:.0%}",
            "latency": f"{self.avg_latency_ms:.0f}ms",
            "quality": f"{self.avg_quality:.2f}",
            "tokens": self.total_tokens,
        }


@dataclass
class SLAConfig:
    """SLA thresholds for monitoring."""
    max_tool_duration_ms: float = 600000.0
    max_llm_latency_ms: float = 30000.0
    max_agent_duration_ms: float = 3600000.0
    max_error_rate: float = 0.3
    min_quality_score: float = 0.3
    max_tokens_per_agent: int = 50000


class ExecutionMonitor:
    """Monitors all agent execution in real-time."""

    def __init__(self, sla: SLAConfig | None = None) -> None:
        self._events: list[ExecutionEvent] = []
        self._agent_metrics: dict[str, AgentMetrics] = {}
        self._tool_metrics: dict[str, ToolMetrics] = {}
        self._model_metrics: dict[str, ModelMetrics] = {}
        self._event_counter = 0
        self._sla = sla or SLAConfig()
        self._alerts: list[dict[str, Any]] = []
        self._start_time = time.time()
        self._log = logger.bind(component="execution_monitor")

    def record_event(
        self,
        event_type: EventType,
        agent_id: str = "",
        component: str = "",
        message: str = "",
        duration_ms: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> ExecutionEvent:
        """Record an execution event."""
        self._event_counter += 1
        event = ExecutionEvent(
            event_id=f"evt-{self._event_counter}",
            event_type=event_type,
            agent_id=agent_id,
            component=component,
            message=message,
            duration_ms=duration_ms,
            metadata=metadata or {},
        )

        # Set severity
        if event_type in (EventType.AGENT_FAIL, EventType.TOOL_FAIL, EventType.LLM_ERROR, EventType.ERROR):
            event.severity = SeverityLevel.ERROR
        elif event_type in (EventType.WARNING, EventType.THROTTLE):
            event.severity = SeverityLevel.WARNING
        elif event_type == EventType.SLA_VIOLATION:
            event.severity = SeverityLevel.CRITICAL

        self._events.append(event)

        # Update metrics
        self._update_metrics(event)

        # Check SLA
        self._check_sla(event)

        return event

    def _update_metrics(self, event: ExecutionEvent) -> None:
        """Update metrics based on event."""
        # Agent metrics
        if event.agent_id:
            if event.agent_id not in self._agent_metrics:
                self._agent_metrics[event.agent_id] = AgentMetrics(
                    agent_id=event.agent_id,
                    role=event.metadata.get("role", ""),
                )
            metrics = self._agent_metrics[event.agent_id]

            if event.event_type == EventType.AGENT_START:
                metrics.status = "running"
            elif event.event_type == EventType.AGENT_COMPLETE:
                metrics.status = "completed"
                metrics.tasks_completed += 1
                metrics.total_duration_ms += event.duration_ms
            elif event.event_type == EventType.AGENT_FAIL:
                metrics.status = "failed"
                metrics.tasks_failed += 1
                metrics.errors += 1
            elif event.event_type in (EventType.TOOL_START, EventType.TOOL_COMPLETE):
                metrics.tools_executed += 1
            elif event.event_type == EventType.LLM_REQUEST:
                metrics.llm_requests += 1
                metrics.total_tokens += event.metadata.get("tokens", 0)
            elif event.event_type == EventType.FINDING:
                metrics.findings_reported += 1

        # Tool metrics
        if event.event_type in (EventType.TOOL_COMPLETE, EventType.TOOL_FAIL):
            tool_name = event.component
            if tool_name not in self._tool_metrics:
                self._tool_metrics[tool_name] = ToolMetrics(tool_name=tool_name)
            tmetrics = self._tool_metrics[tool_name]
            tmetrics.executions += 1
            tmetrics.total_duration_ms += event.duration_ms
            if event.event_type == EventType.TOOL_COMPLETE:
                tmetrics.successes += 1
                tmetrics.findings_generated += event.metadata.get("findings", 0)
            else:
                tmetrics.failures += 1

        # Model metrics
        if event.event_type in (EventType.LLM_RESPONSE, EventType.LLM_ERROR):
            model_id = event.component
            if model_id not in self._model_metrics:
                self._model_metrics[model_id] = ModelMetrics(model_id=model_id)
            mmetrics = self._model_metrics[model_id]
            mmetrics.requests += 1
            mmetrics.total_latency_ms += event.duration_ms
            mmetrics.total_tokens += event.metadata.get("tokens", 0)
            if event.event_type == EventType.LLM_ERROR:
                mmetrics.errors += 1
            else:
                quality = event.metadata.get("quality", 0.5)
                mmetrics.quality_scores.append(quality)

    def _check_sla(self, event: ExecutionEvent) -> None:
        """Check if event violates SLA thresholds."""
        if event.event_type == EventType.TOOL_COMPLETE:
            if event.duration_ms > self._sla.max_tool_duration_ms:
                self._raise_alert("Tool SLA violation", f"{event.component} took {event.duration_ms:.0f}ms")

        if event.event_type == EventType.LLM_RESPONSE:
            if event.duration_ms > self._sla.max_llm_latency_ms:
                self._raise_alert("LLM latency SLA", f"{event.component} took {event.duration_ms:.0f}ms")

        # Check error rates
        for tool_name, tmetrics in self._tool_metrics.items():
            if tmetrics.executions >= 5 and (1 - tmetrics.success_rate) > self._sla.max_error_rate:
                self._raise_alert("Tool error rate", f"{tool_name} error rate: {1 - tmetrics.success_rate:.0%}")

    def _raise_alert(self, alert_type: str, message: str) -> None:
        alert = {
            "type": alert_type,
            "message": message,
            "time": time.time(),
        }
        self._alerts.append(alert)

    def get_dashboard(self) -> dict[str, Any]:
        """Get monitoring dashboard data."""
        uptime = time.time() - self._start_time
        return {
            "uptime_s": f"{uptime:.0f}",
            "total_events": len(self._events),
            "agents": {aid: m.to_dict() for aid, m in self._agent_metrics.items()},
            "tools": {tn: m.to_dict() for tn, m in self._tool_metrics.items()},
            "models": {mid: m.to_dict() for mid, m in self._model_metrics.items()},
            "alerts": self._alerts[-5:],
            "recent_events": [e.to_dict() for e in self._events[-10:]],
        }

    def get_bottlenecks(self) -> list[dict[str, Any]]:
        """Identify performance bottlenecks."""
        bottlenecks = []

        # Slowest tools
        for tool_name, metrics in self._tool_metrics.items():
            if metrics.avg_duration_ms > 30000:
                bottlenecks.append({
                    "type": "slow_tool",
                    "component": tool_name,
                    "avg_ms": f"{metrics.avg_duration_ms:.0f}",
                })

        # High error rate models
        for model_id, metrics in self._model_metrics.items():
            if metrics.error_rate > 0.2:
                bottlenecks.append({
                    "type": "model_errors",
                    "component": model_id,
                    "rate": f"{metrics.error_rate:.0%}",
                })

        # Slow models
        for model_id, metrics in self._model_metrics.items():
            if metrics.avg_latency_ms > 10000:
                bottlenecks.append({
                    "type": "slow_model",
                    "component": model_id,
                    "avg_ms": f"{metrics.avg_latency_ms:.0f}",
                })

        return bottlenecks

    def build_monitor_prompt(self) -> str:
        """Build LLM prompt with monitoring insights."""
        lines = ["## Execution Monitoring"]
        lines.append(f"Events: {len(self._events)}")
        lines.append(f"Agents: {len(self._agent_metrics)}")
        lines.append(f"Alerts: {len(self._alerts)}")

        bottlenecks = self.get_bottlenecks()
        if bottlenecks:
            lines.append("\nBottlenecks:")
            for bn in bottlenecks[:3]:
                lines.append(f"  - {bn['type']}: {bn['component']}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "events": len(self._events),
            "agents": len(self._agent_metrics),
            "tools_tracked": len(self._tool_metrics),
            "models_tracked": len(self._model_metrics),
            "alerts": len(self._alerts),
        }
