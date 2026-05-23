"""Token budget manager — tracks and allocates token budgets across agents and tasks.

Implements:
1. Global token budget tracking
2. Per-agent budget allocation
3. Per-task budget allocation
4. Budget alerts and enforcement
5. Token usage prediction
6. Cost optimization recommendations
7. Budget rebalancing
8. Usage analytics
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class BudgetAllocation:
    """A token budget allocation."""
    allocation_id: str = ""
    name: str = ""
    budget: int = 10000
    used: int = 0
    reserved: int = 0
    parent_id: str = ""

    @property
    def remaining(self) -> int:
        return max(0, self.budget - self.used - self.reserved)

    @property
    def utilization(self) -> float:
        if self.budget == 0:
            return 0.0
        return self.used / self.budget

    @property
    def is_exhausted(self) -> bool:
        return self.remaining <= 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.allocation_id,
            "name": self.name[:20],
            "budget": self.budget,
            "used": self.used,
            "remaining": self.remaining,
            "utilization": round(self.utilization, 2),
        }


@dataclass
class UsageRecord:
    """A token usage record."""
    agent_id: str = ""
    model_id: str = ""
    task: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id[:15],
            "model": self.model_id[:15],
            "tokens": self.total_tokens,
        }


@dataclass
class BudgetAlert:
    """A budget alert."""
    alert_id: str = ""
    allocation_id: str = ""
    message: str = ""
    severity: str = "warning"      # info, warning, critical
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.alert_id,
            "allocation": self.allocation_id[:15],
            "message": self.message[:40],
            "severity": self.severity,
        }


# ── Default Budget Allocation ─────────────────────────────────

DEFAULT_ALLOCATIONS: dict[str, float] = {
    "recon": 0.15,           # 15% of budget
    "scanning": 0.10,
    "analysis": 0.25,        # Most budget for analysis
    "exploitation": 0.15,
    "validation": 0.15,
    "planning": 0.10,
    "reporting": 0.05,
    "reserve": 0.05,         # Emergency reserve
}


class TokenBudget:
    """Tracks and allocates token budgets across agents and tasks.

    Manages global and per-agent budgets, enforces limits,
    and provides usage analytics.
    """

    def __init__(
        self,
        total_budget: int = 500000,
        alert_thresholds: list[float] | None = None,
    ) -> None:
        self._total_budget = total_budget
        self._total_used = 0
        self._allocations: dict[str, BudgetAllocation] = {}
        self._usage_records: list[UsageRecord] = []
        self._alerts: list[BudgetAlert] = []
        self._allocation_counter = 0
        self._alert_counter = 0
        self._alert_thresholds = alert_thresholds or [0.5, 0.75, 0.9, 0.95]
        self._alerted_thresholds: set[float] = set()
        self._log = logger.bind(component="token_budget")

        self._initialize_allocations()

    def _initialize_allocations(self) -> None:
        """Initialize default budget allocations."""
        for name, fraction in DEFAULT_ALLOCATIONS.items():
            self._allocation_counter += 1
            allocation = BudgetAllocation(
                allocation_id=f"ba-{self._allocation_counter}",
                name=name,
                budget=int(self._total_budget * fraction),
            )
            self._allocations[name] = allocation

    def allocate(
        self,
        name: str,
        budget: int,
        parent_id: str = "",
    ) -> BudgetAllocation:
        """Create a new budget allocation."""
        self._allocation_counter += 1
        allocation = BudgetAllocation(
            allocation_id=f"ba-{self._allocation_counter}",
            name=name,
            budget=budget,
            parent_id=parent_id,
        )
        self._allocations[name] = allocation
        return allocation

    def spend(
        self,
        allocation_name: str,
        tokens: int,
        agent_id: str = "",
        model_id: str = "",
        task: str = "",
    ) -> bool:
        """Spend tokens from an allocation."""
        allocation = self._allocations.get(allocation_name)

        if allocation:
            if tokens > allocation.remaining:
                self._create_alert(
                    allocation.allocation_id,
                    f"Budget exhausted for {allocation_name}",
                    "critical",
                )
                return False

            allocation.used += tokens
        else:
            # Spend from general pool
            pass

        self._total_used += tokens

        # Record usage
        self._usage_records.append(UsageRecord(
            agent_id=agent_id,
            model_id=model_id,
            task=task,
            prompt_tokens=tokens // 2,  # Rough split
            completion_tokens=tokens - tokens // 2,
        ))

        if len(self._usage_records) > 2000:
            self._usage_records = self._usage_records[-2000:]

        # Check thresholds
        self._check_thresholds()

        return True

    def reserve(
        self,
        allocation_name: str,
        tokens: int,
    ) -> bool:
        """Reserve tokens for future use."""
        allocation = self._allocations.get(allocation_name)
        if not allocation:
            return False

        if tokens > allocation.remaining:
            return False

        allocation.reserved += tokens
        return True

    def release_reserve(
        self,
        allocation_name: str,
        tokens: int,
    ) -> None:
        """Release reserved tokens."""
        allocation = self._allocations.get(allocation_name)
        if allocation:
            allocation.reserved = max(0, allocation.reserved - tokens)

    def rebalance(self) -> dict[str, int]:
        """Rebalance budgets based on usage patterns."""
        changes: dict[str, int] = {}

        # Find underutilized allocations
        underutilized = []
        overutilized = []

        for name, alloc in self._allocations.items():
            if name == "reserve":
                continue
            if alloc.utilization < 0.3 and alloc.remaining > 1000:
                underutilized.append((name, alloc))
            elif alloc.utilization > 0.8:
                overutilized.append((name, alloc))

        # Transfer from under to over
        for under_name, under_alloc in underutilized:
            transferable = int(under_alloc.remaining * 0.5)
            if not overutilized:
                break

            over_name, over_alloc = overutilized[0]
            over_alloc.budget += transferable
            under_alloc.budget -= transferable
            changes[f"{under_name}→{over_name}"] = transferable

        return changes

    def predict_usage(self, remaining_tasks: int = 10) -> dict[str, Any]:
        """Predict future token usage."""
        if not self._usage_records:
            return {"prediction": "insufficient_data"}

        recent = self._usage_records[-50:]
        avg_per_task = sum(r.total_tokens for r in recent) / len(recent)

        predicted_total = avg_per_task * remaining_tasks
        budget_remaining = self._total_budget - self._total_used

        return {
            "avg_tokens_per_task": int(avg_per_task),
            "predicted_remaining": int(predicted_total),
            "budget_remaining": budget_remaining,
            "will_exhaust": predicted_total > budget_remaining,
            "tasks_affordable": int(budget_remaining / max(1, avg_per_task)),
        }

    def _check_thresholds(self) -> None:
        """Check budget thresholds and create alerts."""
        utilization = self._total_used / max(1, self._total_budget)
        for threshold in self._alert_thresholds:
            if utilization >= threshold and threshold not in self._alerted_thresholds:
                self._create_alert(
                    "global",
                    f"Global budget {utilization:.0%} utilized ({threshold:.0%} threshold)",
                    "critical" if threshold >= 0.9 else "warning",
                )
                self._alerted_thresholds.add(threshold)

    def _create_alert(
        self,
        allocation_id: str,
        message: str,
        severity: str,
    ) -> None:
        """Create a budget alert."""
        self._alert_counter += 1
        alert = BudgetAlert(
            alert_id=f"alert-{self._alert_counter}",
            allocation_id=allocation_id,
            message=message,
            severity=severity,
        )
        self._alerts.append(alert)
        if len(self._alerts) > 100:
            self._alerts = self._alerts[-100:]

    def get_usage_by_model(self) -> dict[str, int]:
        """Get token usage grouped by model."""
        by_model: dict[str, int] = defaultdict(int)
        for record in self._usage_records:
            by_model[record.model_id] += record.total_tokens
        return dict(by_model)

    def get_usage_by_agent(self) -> dict[str, int]:
        """Get token usage grouped by agent."""
        by_agent: dict[str, int] = defaultdict(int)
        for record in self._usage_records:
            by_agent[record.agent_id] += record.total_tokens
        return dict(by_agent)

    def get_allocations(self) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._allocations.values()]

    def get_alerts(self, limit: int = 10) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._alerts[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_budget": self._total_budget,
            "total_used": self._total_used,
            "remaining": self._total_budget - self._total_used,
            "utilization": round(self._total_used / max(1, self._total_budget), 3),
            "allocations": len(self._allocations),
            "records": len(self._usage_records),
            "alerts": len(self._alerts),
        }
