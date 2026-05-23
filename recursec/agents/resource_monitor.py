"""Resource monitor — tracks system resource usage and enforces limits.

Implements:
1. Token usage tracking per model/agent/phase
2. Time budget tracking
3. Memory usage estimation
4. Concurrent task tracking
5. Resource quota enforcement
6. Usage alerts and notifications
7. Resource prediction (will we run out?)
8. Resource optimization recommendations
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ResourceQuota:
    """A resource quota definition."""
    name: str = ""
    resource_type: str = ""        # tokens, time_s, concurrent, memory_mb
    limit: float = 0.0
    used: float = 0.0
    scope: str = ""                # global, agent, model, phase

    @property
    def remaining(self) -> float:
        return max(0.0, self.limit - self.used)

    @property
    def utilization(self) -> float:
        if self.limit <= 0:
            return 0.0
        return min(1.0, self.used / self.limit)

    @property
    def is_exceeded(self) -> bool:
        return self.used >= self.limit > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:30], "type": self.resource_type,
            "used": round(self.used, 1), "limit": round(self.limit, 1),
            "util": round(self.utilization * 100, 1),
        }


@dataclass
class UsageRecord:
    """A resource usage record."""
    resource_type: str = ""
    amount: float = 0.0
    agent_id: str = ""
    model: str = ""
    phase: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.resource_type,
            "amount": round(self.amount, 1),
            "agent": self.agent_id[:15],
            "model": self.model[:15],
        }


@dataclass
class ResourceAlert:
    """A resource usage alert."""
    alert_id: str = ""
    resource: str = ""
    level: str = "warning"         # warning, critical
    message: str = ""
    utilization: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.alert_id, "resource": self.resource[:20],
            "level": self.level,
            "util": round(self.utilization * 100, 1),
        }


class ResourceMonitor:
    """Tracks system resource usage and enforces limits.

    Monitors token usage, time budgets, concurrent tasks,
    and provides usage predictions and recommendations.
    """

    def __init__(
        self,
        total_token_budget: int = 10_000_000,
        total_time_budget_s: float = 7200.0,
        max_concurrent_tasks: int = 20,
    ) -> None:
        # Global quotas
        self._quotas: dict[str, ResourceQuota] = {
            "global_tokens": ResourceQuota(
                name="Global Token Budget",
                resource_type="tokens",
                limit=float(total_token_budget),
                scope="global",
            ),
            "global_time": ResourceQuota(
                name="Global Time Budget",
                resource_type="time_s",
                limit=total_time_budget_s,
                scope="global",
            ),
            "concurrent": ResourceQuota(
                name="Concurrent Tasks",
                resource_type="concurrent",
                limit=float(max_concurrent_tasks),
                scope="global",
            ),
        }

        # Per-agent quotas
        self._agent_quotas: dict[str, ResourceQuota] = {}
        # Per-model quotas
        self._model_quotas: dict[str, ResourceQuota] = {}
        # Per-phase quotas
        self._phase_quotas: dict[str, ResourceQuota] = {}

        self._records: list[UsageRecord] = []
        self._alerts: list[ResourceAlert] = []
        self._alert_counter = 0
        self._start_time = time.time()

        # Tracking
        self._agent_usage: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._model_usage: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._phase_usage: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))

        self._log = logger.bind(component="resource_monitor")

    def record_usage(
        self,
        resource_type: str,
        amount: float,
        agent_id: str = "",
        model: str = "",
        phase: str = "",
    ) -> bool:
        """Record resource usage. Returns False if quota exceeded."""
        # Update global quota
        quota_key = f"global_{resource_type}"
        quota = self._quotas.get(quota_key)
        if quota:
            quota.used += amount
            if quota.is_exceeded:
                self._create_alert(quota_key, quota)
                return False

        # Update per-agent tracking
        if agent_id:
            self._agent_usage[agent_id][resource_type] += amount
            agent_quota = self._agent_quotas.get(agent_id)
            if agent_quota and resource_type == agent_quota.resource_type:
                agent_quota.used += amount

        # Update per-model tracking
        if model:
            self._model_usage[model][resource_type] += amount

        # Update per-phase tracking
        if phase:
            self._phase_usage[phase][resource_type] += amount

        # Record
        self._records.append(UsageRecord(
            resource_type=resource_type,
            amount=amount,
            agent_id=agent_id,
            model=model,
            phase=phase,
        ))

        if len(self._records) > 5000:
            self._records = self._records[-5000:]

        # Check thresholds
        if quota and quota.utilization >= 0.8 and quota.utilization < 1.0:
            self._create_alert(quota_key, quota, "warning")

        return True

    def record_tokens(
        self,
        input_tokens: int,
        output_tokens: int,
        agent_id: str = "",
        model: str = "",
        phase: str = "",
    ) -> bool:
        """Record token usage."""
        total = input_tokens + output_tokens
        return self.record_usage("tokens", float(total), agent_id, model, phase)

    def acquire_concurrent(self) -> bool:
        """Acquire a concurrent task slot."""
        quota = self._quotas["concurrent"]
        if quota.used >= quota.limit:
            return False
        quota.used += 1.0
        return True

    def release_concurrent(self) -> None:
        """Release a concurrent task slot."""
        quota = self._quotas["concurrent"]
        quota.used = max(0.0, quota.used - 1.0)

    def set_agent_quota(
        self,
        agent_id: str,
        resource_type: str = "tokens",
        limit: float = 500_000,
    ) -> None:
        """Set a per-agent quota."""
        self._agent_quotas[agent_id] = ResourceQuota(
            name=f"Agent {agent_id}",
            resource_type=resource_type,
            limit=limit,
            scope="agent",
        )

    def predict_exhaustion(self) -> dict[str, float]:
        """Predict when resources will be exhausted."""
        elapsed = time.time() - self._start_time
        if elapsed < 10:
            return {}

        predictions = {}

        for key, quota in self._quotas.items():
            if quota.limit <= 0 or quota.used <= 0:
                continue

            rate = quota.used / elapsed  # Usage per second
            if rate > 0:
                remaining_s = quota.remaining / rate
                predictions[key] = remaining_s

        return predictions

    def get_recommendations(self) -> list[str]:
        """Get resource optimization recommendations."""
        recs = []

        for key, quota in self._quotas.items():
            if quota.utilization > 0.9:
                recs.append(f"CRITICAL: {quota.name} at {quota.utilization * 100:.0f}% usage")
            elif quota.utilization > 0.7:
                recs.append(f"WARNING: {quota.name} at {quota.utilization * 100:.0f}% usage")

        # Model usage balance
        if self._model_usage:
            usages = {m: sum(v.values()) for m, v in self._model_usage.items()}
            if usages:
                max_model = max(usages, key=usages.get)
                min_model = min(usages, key=usages.get)
                if usages[max_model] > usages[min_model] * 3:
                    recs.append(
                        f"Rebalance: {max_model} has 3x more usage than {min_model}"
                    )

        return recs

    def _create_alert(
        self,
        resource_key: str,
        quota: ResourceQuota,
        level: str = "critical",
    ) -> None:
        """Create a resource alert."""
        # Debounce: don't spam alerts
        for alert in self._alerts[-5:]:
            if alert.resource == resource_key:
                return

        self._alert_counter += 1
        alert = ResourceAlert(
            alert_id=f"alert-{self._alert_counter}",
            resource=resource_key,
            level=level,
            message=f"{quota.name}: {quota.utilization * 100:.0f}% used",
            utilization=quota.utilization,
        )
        self._alerts.append(alert)

    def get_usage_by_agent(self) -> dict[str, dict[str, float]]:
        return dict(self._agent_usage)

    def get_usage_by_model(self) -> dict[str, dict[str, float]]:
        return dict(self._model_usage)

    def get_alerts(self, limit: int = 10) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._alerts[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        return {
            "quotas": {k: v.to_dict() for k, v in self._quotas.items()},
            "agents_tracked": len(self._agent_usage),
            "models_tracked": len(self._model_usage),
            "records": len(self._records),
            "alerts": len(self._alerts),
            "elapsed_s": round(time.time() - self._start_time, 0),
        }
