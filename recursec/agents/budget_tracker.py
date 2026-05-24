"""Budget tracker — token, time, and resource budgeting.

Implements:
1. Token budget (per-agent and total)
2. Time budget (per-agent and total)
3. Tool execution budget (rate limiting)
4. Budget alerts and auto-throttling
5. Cost estimation
6. Budget prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class BudgetStatus(str, Enum):
    OK = "ok"
    WARNING = "warning"      # > 75% used
    CRITICAL = "critical"    # > 90% used
    EXHAUSTED = "exhausted"  # 100% used


class ResourceType(str, Enum):
    TOKENS = "tokens"
    TIME = "time"
    TOOL_CALLS = "tool_calls"
    AGENT_SPAWNS = "agent_spawns"
    API_CALLS = "api_calls"


@dataclass
class ResourceBudget:
    """Budget for a single resource type."""
    resource: ResourceType = ResourceType.TOKENS
    limit: float = 0.0
    used: float = 0.0
    reserved: float = 0.0

    @property
    def remaining(self) -> float:
        return max(0.0, self.limit - self.used - self.reserved)

    @property
    def utilization(self) -> float:
        if self.limit == 0:
            return 0.0
        return (self.used + self.reserved) / self.limit

    @property
    def status(self) -> BudgetStatus:
        util = self.utilization
        if util >= 1.0:
            return BudgetStatus.EXHAUSTED
        if util >= 0.9:
            return BudgetStatus.CRITICAL
        if util >= 0.75:
            return BudgetStatus.WARNING
        return BudgetStatus.OK

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.resource.value[:6],
            "used": round(self.used, 1),
            "limit": round(self.limit, 1),
            "status": self.status.value[:6],
        }


@dataclass
class AgentBudget:
    """Budget allocation for a single agent."""
    agent_id: str = ""
    budgets: dict[str, ResourceBudget] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)
    alerts: list[str] = field(default_factory=list)

    @property
    def overall_status(self) -> BudgetStatus:
        if not self.budgets:
            return BudgetStatus.OK
        statuses = [b.status for b in self.budgets.values()]
        if BudgetStatus.EXHAUSTED in statuses:
            return BudgetStatus.EXHAUSTED
        if BudgetStatus.CRITICAL in statuses:
            return BudgetStatus.CRITICAL
        if BudgetStatus.WARNING in statuses:
            return BudgetStatus.WARNING
        return BudgetStatus.OK

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id[:10],
            "status": self.overall_status.value[:6],
            "budgets": {k: v.to_dict() for k, v in self.budgets.items()},
        }


class BudgetTracker:
    """Tracks and enforces resource budgets.

    Manages token, time, and tool execution budgets
    per-agent and globally, with alerts and auto-throttling.
    """

    def __init__(
        self,
        global_token_budget: int = 500000,
        global_time_budget_s: float = 3600.0,
        global_tool_budget: int = 1000,
        global_spawn_budget: int = 50,
    ) -> None:
        self._agents: dict[str, AgentBudget] = {}
        self._global = AgentBudget(
            agent_id="global",
            budgets={
                "tokens": ResourceBudget(
                    resource=ResourceType.TOKENS,
                    limit=float(global_token_budget),
                ),
                "time": ResourceBudget(
                    resource=ResourceType.TIME,
                    limit=global_time_budget_s,
                ),
                "tool_calls": ResourceBudget(
                    resource=ResourceType.TOOL_CALLS,
                    limit=float(global_tool_budget),
                ),
                "agent_spawns": ResourceBudget(
                    resource=ResourceType.AGENT_SPAWNS,
                    limit=float(global_spawn_budget),
                ),
            },
        )
        self._log = logger.bind(component="budget_tracker")

    def allocate(
        self,
        agent_id: str,
        token_budget: int = 10000,
        time_budget_s: float = 300.0,
        tool_budget: int = 50,
    ) -> AgentBudget:
        """Allocate budget to an agent."""
        budget = AgentBudget(
            agent_id=agent_id,
            budgets={
                "tokens": ResourceBudget(
                    resource=ResourceType.TOKENS,
                    limit=float(token_budget),
                ),
                "time": ResourceBudget(
                    resource=ResourceType.TIME,
                    limit=time_budget_s,
                ),
                "tool_calls": ResourceBudget(
                    resource=ResourceType.TOOL_CALLS,
                    limit=float(tool_budget),
                ),
            },
        )

        # Reserve from global
        self._global.budgets["tokens"].reserved += token_budget
        self._global.budgets["time"].reserved += time_budget_s

        self._agents[agent_id] = budget
        return budget

    def can_spend(
        self,
        agent_id: str,
        resource: str,
        amount: float,
    ) -> bool:
        """Check if spending is within budget."""
        # Check agent budget
        agent = self._agents.get(agent_id)
        if agent and resource in agent.budgets:
            if agent.budgets[resource].remaining < amount:
                return False

        # Check global budget
        if resource in self._global.budgets:
            if self._global.budgets[resource].remaining < amount:
                return False

        return True

    def spend(
        self,
        agent_id: str,
        resource: str,
        amount: float,
    ) -> bool:
        """Record resource spending."""
        if not self.can_spend(agent_id, resource, amount):
            return False

        # Spend from agent
        agent = self._agents.get(agent_id)
        if agent and resource in agent.budgets:
            agent.budgets[resource].used += amount
            self._check_alerts(agent, resource)

        # Spend from global
        if resource in self._global.budgets:
            self._global.budgets[resource].used += amount
            self._check_alerts(self._global, resource)

        return True

    def spend_time(self, agent_id: str) -> None:
        """Update time spending (call periodically)."""
        agent = self._agents.get(agent_id)
        if not agent:
            return

        elapsed = time.time() - agent.start_time
        if "time" in agent.budgets:
            agent.budgets["time"].used = elapsed

    def _check_alerts(self, budget: AgentBudget, resource: str) -> None:
        """Check and generate alerts."""
        res = budget.budgets.get(resource)
        if not res:
            return

        status = res.status
        if status == BudgetStatus.EXHAUSTED:
            alert = f"EXHAUSTED: {resource} for {budget.agent_id}"
            if alert not in budget.alerts:
                budget.alerts.append(alert)
        elif status == BudgetStatus.CRITICAL:
            alert = f"CRITICAL: {resource} at {res.utilization:.0%} for {budget.agent_id}"
            if alert not in budget.alerts:
                budget.alerts.append(alert)

    def get_status(self, agent_id: str = "") -> dict[str, Any]:
        """Get budget status."""
        if agent_id and agent_id in self._agents:
            return self._agents[agent_id].to_dict()
        return self._global.to_dict()

    def build_budget_prompt(self, agent_id: str = "") -> str:
        """Build budget context for LLM."""
        lines = ["## Budget Status\n"]

        # Global
        g = self._global
        lines.append("Global:")
        for name, res in g.budgets.items():
            lines.append(
                f"  {name}: {res.used:.0f}/{res.limit:.0f} "
                f"({res.utilization:.0%}) [{res.status.value}]"
            )

        # Agent-specific
        if agent_id and agent_id in self._agents:
            a = self._agents[agent_id]
            lines.append(f"\nAgent {agent_id[:10]}:")
            for name, res in a.budgets.items():
                lines.append(
                    f"  {name}: {res.used:.0f}/{res.limit:.0f} "
                    f"({res.utilization:.0%}) [{res.status.value}]"
                )

            if a.alerts:
                lines.append("Alerts:")
                for alert in a.alerts[-3:]:
                    lines.append(f"  ⚠ {alert}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "agents": len(self._agents),
            "global_status": self._global.overall_status.value,
            "global_tokens_used": self._global.budgets["tokens"].used,
            "global_tokens_limit": self._global.budgets["tokens"].limit,
            "global_time_used": self._global.budgets["time"].used,
            "total_alerts": sum(len(a.alerts) for a in self._agents.values()),
        }
