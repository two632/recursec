"""Budget manager — resource tracking and allocation for agent operations.

Manages:
- Token budgets (per-agent and global)
- Time budgets (wall clock limits)
- Step budgets (maximum operations)
- API call budgets (rate limiting)
- Memory budgets (context window management)
- Cost estimation and tracking

Features:
- Hierarchical budgets (global → team → agent)
- Budget borrowing (agents can request more from global pool)
- Budget alerts (warnings at thresholds)
- Budget forecasting (estimated remaining capacity)
- Budget reporting (usage analytics)
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

import structlog

logger = structlog.get_logger()


class ResourceType(str, Enum):
    TOKENS = "tokens"
    TIME_S = "time_s"
    STEPS = "steps"
    API_CALLS = "api_calls"
    MEMORY_BYTES = "memory_bytes"


class BudgetAlert(str, Enum):
    WARNING_75 = "warning_75"    # 75% used
    WARNING_90 = "warning_90"    # 90% used
    CRITICAL_95 = "critical_95"  # 95% used
    EXHAUSTED = "exhausted"      # 100% used


@dataclass
class ResourceBudget:
    """Budget for a single resource type."""
    resource_type: ResourceType
    limit: float
    used: float = 0.0
    reserved: float = 0.0  # Reserved by in-progress operations
    alerts_fired: set[str] = field(default_factory=set)

    @property
    def available(self) -> float:
        return max(0.0, self.limit - self.used - self.reserved)

    @property
    def utilization(self) -> float:
        return (self.used / self.limit * 100) if self.limit > 0 else 0.0

    @property
    def is_exhausted(self) -> bool:
        return self.used >= self.limit

    def consume(self, amount: float) -> bool:
        """Consume resources. Returns True if successful."""
        if self.used + amount > self.limit:
            return False
        self.used += amount
        return True

    def reserve(self, amount: float) -> bool:
        """Reserve resources for upcoming use."""
        if self.used + self.reserved + amount > self.limit:
            return False
        self.reserved += amount
        return True

    def commit_reservation(self, amount: float) -> None:
        """Convert a reservation into actual usage."""
        self.reserved = max(0.0, self.reserved - amount)
        self.used += amount

    def release_reservation(self, amount: float) -> None:
        """Release a reservation without consuming."""
        self.reserved = max(0.0, self.reserved - amount)

    def check_alerts(self) -> BudgetAlert | None:
        """Check if any alert thresholds are crossed."""
        pct = self.utilization
        if pct >= 100 and "exhausted" not in self.alerts_fired:
            self.alerts_fired.add("exhausted")
            return BudgetAlert.EXHAUSTED
        if pct >= 95 and "critical_95" not in self.alerts_fired:
            self.alerts_fired.add("critical_95")
            return BudgetAlert.CRITICAL_95
        if pct >= 90 and "warning_90" not in self.alerts_fired:
            self.alerts_fired.add("warning_90")
            return BudgetAlert.WARNING_90
        if pct >= 75 and "warning_75" not in self.alerts_fired:
            self.alerts_fired.add("warning_75")
            return BudgetAlert.WARNING_75
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.resource_type.value,
            "limit": self.limit, "used": round(self.used, 1),
            "reserved": round(self.reserved, 1),
            "available": round(self.available, 1),
            "utilization": round(self.utilization, 1),
        }


@dataclass
class AgentBudget:
    """Budget allocation for a single agent."""
    agent_id: str
    budgets: dict[ResourceType, ResourceBudget] = field(default_factory=dict)
    parent_pool: str = ""  # ID of parent budget pool
    started_at: float = field(default_factory=time.time)

    def add_budget(self, resource_type: ResourceType, limit: float) -> None:
        self.budgets[resource_type] = ResourceBudget(resource_type=resource_type, limit=limit)

    def consume(self, resource_type: ResourceType, amount: float) -> bool:
        budget = self.budgets.get(resource_type)
        if not budget:
            return True  # No budget means unlimited
        return budget.consume(amount)

    def available(self, resource_type: ResourceType) -> float:
        budget = self.budgets.get(resource_type)
        if not budget:
            return float("inf")
        return budget.available

    def is_exhausted(self, resource_type: ResourceType | None = None) -> bool:
        if resource_type:
            budget = self.budgets.get(resource_type)
            return budget.is_exhausted if budget else False
        return any(b.is_exhausted for b in self.budgets.values())

    def check_alerts(self) -> list[tuple[ResourceType, BudgetAlert]]:
        alerts = []
        for rtype, budget in self.budgets.items():
            alert = budget.check_alerts()
            if alert:
                alerts.append((rtype, alert))
        return alerts

    def elapsed_time(self) -> float:
        return time.time() - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "budgets": {k.value: v.to_dict() for k, v in self.budgets.items()},
            "elapsed_s": round(self.elapsed_time(), 1),
        }


AlertCallback = Callable[[str, ResourceType, BudgetAlert], None]


class BudgetManager:
    """Global budget manager for multi-agent operations.

    Manages hierarchical budgets:
    - Global pool (total resources available)
    - Per-assessment budgets (allocated from global)
    - Per-agent budgets (allocated from assessment)
    """

    def __init__(
        self,
        global_token_limit: int = 2000000,
        global_time_limit_s: float = 7200.0,
        global_step_limit: int = 1000,
        global_api_call_limit: int = 5000,
    ) -> None:
        self._global = AgentBudget(agent_id="global")
        self._global.add_budget(ResourceType.TOKENS, global_token_limit)
        self._global.add_budget(ResourceType.TIME_S, global_time_limit_s)
        self._global.add_budget(ResourceType.STEPS, global_step_limit)
        self._global.add_budget(ResourceType.API_CALLS, global_api_call_limit)

        self._agent_budgets: dict[str, AgentBudget] = {}
        self._alert_callbacks: list[AlertCallback] = []
        self._usage_log: list[dict[str, Any]] = []
        self._max_log_size = 5000

    def allocate(
        self,
        agent_id: str,
        token_limit: int = 100000,
        time_limit_s: float = 600.0,
        step_limit: int = 100,
        api_call_limit: int = 500,
    ) -> AgentBudget:
        """Allocate budgets to an agent."""
        budget = AgentBudget(agent_id=agent_id, parent_pool="global")
        budget.add_budget(ResourceType.TOKENS, token_limit)
        budget.add_budget(ResourceType.TIME_S, time_limit_s)
        budget.add_budget(ResourceType.STEPS, step_limit)
        budget.add_budget(ResourceType.API_CALLS, api_call_limit)
        self._agent_budgets[agent_id] = budget
        return budget

    def consume(self, agent_id: str, resource_type: ResourceType, amount: float) -> bool:
        """Consume resources from an agent's budget."""
        # Check agent budget
        agent_budget = self._agent_budgets.get(agent_id)
        if agent_budget:
            if not agent_budget.consume(resource_type, amount):
                self._fire_alert(agent_id, resource_type, BudgetAlert.EXHAUSTED)
                return False

        # Also consume from global
        if not self._global.consume(resource_type, amount):
            self._fire_alert("global", resource_type, BudgetAlert.EXHAUSTED)
            return False

        # Log usage
        self._log_usage(agent_id, resource_type, amount)

        # Check alerts
        if agent_budget:
            for rtype, alert in agent_budget.check_alerts():
                self._fire_alert(agent_id, rtype, alert)
        for rtype, alert in self._global.check_alerts():
            self._fire_alert("global", rtype, alert)

        return True

    def can_afford(self, agent_id: str, resource_type: ResourceType, amount: float) -> bool:
        """Check if an agent can afford a resource consumption."""
        agent_budget = self._agent_budgets.get(agent_id)
        if agent_budget:
            if agent_budget.available(resource_type) < amount:
                return False
        return self._global.available(resource_type) >= amount

    def borrow(self, agent_id: str, resource_type: ResourceType, amount: float) -> bool:
        """Try to borrow additional budget from the global pool.

        This increases the agent's budget limit if global resources are available.
        """
        if self._global.available(resource_type) < amount:
            return False

        agent_budget = self._agent_budgets.get(agent_id)
        if not agent_budget:
            return False

        budget = agent_budget.budgets.get(resource_type)
        if budget:
            budget.limit += amount

        logger.info(
            "budget_borrowed",
            agent=agent_id, resource=resource_type.value,
            amount=amount,
        )
        return True

    def register_alert_callback(self, callback: AlertCallback) -> None:
        self._alert_callbacks.append(callback)

    def forecast(self, agent_id: str) -> dict[str, Any]:
        """Forecast remaining capacity for an agent."""
        budget = self._agent_budgets.get(agent_id)
        if not budget:
            return {"error": "Agent not found"}

        elapsed = budget.elapsed_time()
        if elapsed < 1.0:
            return {"status": "too_early"}

        forecasts: dict[str, Any] = {}
        for rtype, rb in budget.budgets.items():
            if rb.used == 0:
                continue
            rate = rb.used / elapsed
            remaining = rb.available
            if rate > 0:
                time_remaining = remaining / rate
            else:
                time_remaining = float("inf")

            forecasts[rtype.value] = {
                "rate_per_s": round(rate, 2),
                "remaining": round(remaining, 1),
                "estimated_exhaustion_s": round(time_remaining, 1) if time_remaining != float("inf") else None,
            }

        return forecasts

    def get_global_status(self) -> dict[str, Any]:
        return self._global.to_dict()

    def get_agent_status(self, agent_id: str) -> dict[str, Any] | None:
        budget = self._agent_budgets.get(agent_id)
        return budget.to_dict() if budget else None

    def get_all_status(self) -> dict[str, Any]:
        return {
            "global": self._global.to_dict(),
            "agents": {
                aid: b.to_dict() for aid, b in self._agent_budgets.items()
            },
        }

    def get_usage_report(self, agent_id: str = "") -> dict[str, Any]:
        """Get usage report with analytics."""
        logs = self._usage_log
        if agent_id:
            logs = [entry for entry in logs if entry["agent"] == agent_id]

        by_resource: dict[str, float] = defaultdict(float)
        by_agent: dict[str, float] = defaultdict(float)
        for entry in logs:
            by_resource[entry["resource"]] += entry["amount"]
            by_agent[entry["agent"]] += entry["amount"]

        return {
            "total_entries": len(logs),
            "by_resource": dict(by_resource),
            "by_agent": dict(by_agent),
        }

    def _fire_alert(self, agent_id: str, resource_type: ResourceType, alert: BudgetAlert) -> None:
        logger.warning(
            "budget_alert",
            agent=agent_id, resource=resource_type.value, alert=alert.value,
        )
        for cb in self._alert_callbacks:
            try:
                cb(agent_id, resource_type, alert)
            except Exception:
                pass

    def _log_usage(self, agent_id: str, resource_type: ResourceType, amount: float) -> None:
        self._usage_log.append({
            "agent": agent_id,
            "resource": resource_type.value,
            "amount": amount,
            "timestamp": time.time(),
        })
        if len(self._usage_log) > self._max_log_size:
            self._usage_log = self._usage_log[-self._max_log_size:]


class ConvergenceDetector:
    """Detects when an agent or assessment has converged (stopped making progress).

    Uses multiple signals:
    1. Finding rate — are we still discovering new things?
    2. Information gain — are tool outputs giving new information?
    3. Action diversity — are we repeating the same actions?
    4. Confidence trend — is our confidence stabilizing?
    5. Coverage — have we tested all attack surfaces?
    """

    def __init__(
        self,
        min_cycles: int = 5,
        finding_rate_threshold: float = 0.1,
        diversity_threshold: float = 0.3,
        confidence_stability_window: int = 5,
    ) -> None:
        self._min_cycles = min_cycles
        self._finding_rate_threshold = finding_rate_threshold
        self._diversity_threshold = diversity_threshold
        self._confidence_window = confidence_stability_window

        self._finding_timestamps: list[float] = []
        self._action_history: list[str] = []
        self._confidence_history: list[float] = []
        self._info_gain_history: list[float] = []

    def record_finding(self) -> None:
        self._finding_timestamps.append(time.time())

    def record_action(self, action_type: str) -> None:
        self._action_history.append(action_type)

    def record_confidence(self, confidence: float) -> None:
        self._confidence_history.append(confidence)

    def record_info_gain(self, gain: float) -> None:
        """Record information gain (0.0 = no new info, 1.0 = lots of new info)."""
        self._info_gain_history.append(gain)

    def has_converged(self) -> tuple[bool, str]:
        """Check if the process has converged. Returns (converged, reason)."""
        if len(self._action_history) < self._min_cycles:
            return False, "insufficient_data"

        signals = []

        # 1. Finding rate declining
        if self._finding_timestamps:
            recent = sum(1 for t in self._finding_timestamps if time.time() - t < 120)
            older = sum(1 for t in self._finding_timestamps if 120 <= time.time() - t < 240)
            if older > 0 and recent / max(1, older) < self._finding_rate_threshold:
                signals.append("finding_rate_declining")

        # 2. Action diversity low (repeating same actions)
        if len(self._action_history) >= 10:
            recent_10 = self._action_history[-10:]
            unique_ratio = len(set(recent_10)) / 10.0
            if unique_ratio < self._diversity_threshold:
                signals.append("low_action_diversity")

        # 3. Confidence stabilized
        if len(self._confidence_history) >= self._confidence_window:
            recent_conf = self._confidence_history[-self._confidence_window:]
            conf_range = max(recent_conf) - min(recent_conf)
            if conf_range < 0.05:
                signals.append("confidence_stabilized")

        # 4. No information gain
        if len(self._info_gain_history) >= 5:
            recent_gain = self._info_gain_history[-5:]
            if all(g < 0.1 for g in recent_gain):
                signals.append("no_info_gain")

        # Converged if 2+ signals agree
        if len(signals) >= 2:
            return True, f"converged: {', '.join(signals)}"

        return False, "in_progress"

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_findings": len(self._finding_timestamps),
            "total_actions": len(self._action_history),
            "confidence_samples": len(self._confidence_history),
            "current_confidence": self._confidence_history[-1] if self._confidence_history else 0,
            "action_diversity": (
                len(set(self._action_history[-10:])) / 10.0
                if len(self._action_history) >= 10 else 1.0
            ),
        }
