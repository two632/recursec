"""Budget allocator — distributes resources across agents and phases.

Implements:
1. Token budget allocation
2. Time budget distribution
3. Tool call budgeting
4. LLM query budgeting
5. Recursive budget decay (parent→child)
6. Dynamic reallocation
7. Budget exhaustion handling
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class BudgetType(str, Enum):
    TOKENS = "tokens"
    TIME_SECONDS = "time_seconds"
    TOOL_CALLS = "tool_calls"
    LLM_QUERIES = "llm_queries"


class BudgetStatus(str, Enum):
    AVAILABLE = "available"
    LOW = "low"              # <20% remaining
    CRITICAL = "critical"    # <5% remaining
    EXHAUSTED = "exhausted"  # 0% remaining


@dataclass
class Budget:
    """A resource budget."""
    budget_id: str = ""
    budget_type: BudgetType = BudgetType.TOKENS
    total: float = 0.0
    used: float = 0.0
    reserved: float = 0.0

    @property
    def remaining(self) -> float:
        return max(0.0, self.total - self.used - self.reserved)

    @property
    def utilization(self) -> float:
        if self.total == 0:
            return 0.0
        return self.used / self.total

    @property
    def status(self) -> BudgetStatus:
        if self.remaining <= 0:
            return BudgetStatus.EXHAUSTED
        ratio = self.remaining / max(1, self.total)
        if ratio < 0.05:
            return BudgetStatus.CRITICAL
        if ratio < 0.20:
            return BudgetStatus.LOW
        return BudgetStatus.AVAILABLE

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.budget_type.value,
            "total": round(self.total, 0),
            "used": round(self.used, 0),
            "remaining": round(self.remaining, 0),
            "status": self.status.value,
        }


@dataclass
class AgentBudget:
    """Combined budgets for an agent."""
    agent_id: str = ""
    budgets: dict[str, Budget] = field(default_factory=dict)
    parent_id: str = ""
    depth: int = 0
    started_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id[:10],
            "depth": self.depth,
            "budgets": {k: v.to_dict() for k, v in self.budgets.items()},
        }


# ── Default budget configurations ─────────────────────────────

DEFAULT_ROOT_BUDGET: dict[str, float] = {
    "tokens": 500_000,
    "time_seconds": 3600,       # 1 hour
    "tool_calls": 200,
    "llm_queries": 500,
}

PHASE_BUDGET_RATIOS: dict[str, dict[str, float]] = {
    "reconnaissance": {
        "tokens": 0.20, "time_seconds": 0.25,
        "tool_calls": 0.30, "llm_queries": 0.15,
    },
    "scanning": {
        "tokens": 0.25, "time_seconds": 0.30,
        "tool_calls": 0.35, "llm_queries": 0.20,
    },
    "exploitation": {
        "tokens": 0.25, "time_seconds": 0.25,
        "tool_calls": 0.20, "llm_queries": 0.30,
    },
    "validation": {
        "tokens": 0.15, "time_seconds": 0.10,
        "tool_calls": 0.10, "llm_queries": 0.20,
    },
    "reporting": {
        "tokens": 0.15, "time_seconds": 0.10,
        "tool_calls": 0.05, "llm_queries": 0.15,
    },
}

CHILD_DECAY_FACTOR = 0.70


class BudgetAllocator:
    """Distributes resource budgets across agents and phases.

    Manages token, time, tool call, and LLM query budgets
    with recursive decay for child agents.
    """

    def __init__(
        self,
        root_budget: dict[str, float] | None = None,
        decay_factor: float = CHILD_DECAY_FACTOR,
    ) -> None:
        self._agent_budgets: dict[str, AgentBudget] = {}
        self._decay_factor = decay_factor
        self._root_budget = root_budget or DEFAULT_ROOT_BUDGET
        self._counter = 0
        self._log = logger.bind(component="budget_allocator")

    def allocate_root(self, agent_id: str) -> AgentBudget:
        """Allocate budgets for the root agent."""
        self._counter += 1
        budgets = {}
        for btype_str, total in self._root_budget.items():
            try:
                btype = BudgetType(btype_str)
            except ValueError:
                continue
            budgets[btype_str] = Budget(
                budget_id=f"budget-{self._counter}",
                budget_type=btype,
                total=total,
            )
            self._counter += 1

        agent_budget = AgentBudget(
            agent_id=agent_id,
            budgets=budgets,
            depth=0,
        )
        self._agent_budgets[agent_id] = agent_budget
        return agent_budget

    def allocate_child(
        self,
        parent_id: str,
        child_id: str,
    ) -> AgentBudget | None:
        """Allocate budgets for a child agent with decay."""
        parent = self._agent_budgets.get(parent_id)
        if not parent:
            return None

        budgets = {}
        for btype_str, parent_budget in parent.budgets.items():
            child_total = parent_budget.remaining * self._decay_factor
            self._counter += 1
            budgets[btype_str] = Budget(
                budget_id=f"budget-{self._counter}",
                budget_type=parent_budget.budget_type,
                total=child_total,
            )
            # Reserve from parent
            parent_budget.reserved += child_total

        child_budget = AgentBudget(
            agent_id=child_id,
            budgets=budgets,
            parent_id=parent_id,
            depth=parent.depth + 1,
        )
        self._agent_budgets[child_id] = child_budget
        return child_budget

    def allocate_phase(
        self,
        agent_id: str,
        phase: str,
    ) -> dict[str, float]:
        """Get budget allocation for a specific phase."""
        agent = self._agent_budgets.get(agent_id)
        if not agent:
            return {}

        ratios = PHASE_BUDGET_RATIOS.get(phase, {})
        allocation = {}

        for btype_str, budget in agent.budgets.items():
            ratio = ratios.get(btype_str, 0.2)
            allocation[btype_str] = budget.remaining * ratio

        return allocation

    def spend(
        self,
        agent_id: str,
        budget_type: str,
        amount: float,
    ) -> bool:
        """Spend from an agent's budget."""
        agent = self._agent_budgets.get(agent_id)
        if not agent:
            return False

        budget = agent.budgets.get(budget_type)
        if not budget:
            return False

        if budget.remaining < amount:
            return False

        budget.used += amount
        return True

    def check_budget(
        self,
        agent_id: str,
        budget_type: str,
    ) -> BudgetStatus:
        """Check the status of an agent's budget."""
        agent = self._agent_budgets.get(agent_id)
        if not agent:
            return BudgetStatus.EXHAUSTED

        budget = agent.budgets.get(budget_type)
        if not budget:
            return BudgetStatus.EXHAUSTED

        return budget.status

    def any_exhausted(self, agent_id: str) -> bool:
        """Check if any budget is exhausted."""
        agent = self._agent_budgets.get(agent_id)
        if not agent:
            return True

        return any(
            b.status == BudgetStatus.EXHAUSTED
            for b in agent.budgets.values()
        )

    def return_unused(self, child_id: str) -> None:
        """Return unused budget from child to parent."""
        child = self._agent_budgets.get(child_id)
        if not child or not child.parent_id:
            return

        parent = self._agent_budgets.get(child.parent_id)
        if not parent:
            return

        for btype_str, child_budget in child.budgets.items():
            parent_budget = parent.budgets.get(btype_str)
            if parent_budget:
                unused = child_budget.remaining
                parent_budget.reserved -= (child_budget.total)
                parent_budget.reserved = max(0, parent_budget.reserved)
                # Return unused portion
                if unused > 0:
                    pass  # Simply unreserving is sufficient

    def build_budget_prompt(self, agent_id: str) -> str:
        """Build a prompt describing budget status."""
        agent = self._agent_budgets.get(agent_id)
        if not agent:
            return ""

        lines = ["## Budget Status\n"]
        for btype_str, budget in agent.budgets.items():
            pct = (1.0 - budget.utilization) * 100
            lines.append(
                f"- {btype_str}: {budget.remaining:.0f}/{budget.total:.0f} "
                f"({pct:.0f}% remaining) [{budget.status.value}]"
            )

        # Warnings
        critical = [
            btype for btype, b in agent.budgets.items()
            if b.status in (BudgetStatus.CRITICAL, BudgetStatus.EXHAUSTED)
        ]
        if critical:
            lines.append(f"\nWARNING: {', '.join(critical)} budget(s) critically low!")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        depth_counts: dict[int, int] = defaultdict(int)
        for agent in self._agent_budgets.values():
            depth_counts[agent.depth] += 1

        return {
            "agents": len(self._agent_budgets),
            "decay_factor": self._decay_factor,
            "by_depth": dict(depth_counts),
        }
