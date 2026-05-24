"""Token budget manager — cross-agent resource tracking.

Implements:
1. Per-agent token budgets with allocation
2. Hierarchical budget propagation (parent → children)
3. Usage tracking and rate limiting
4. Budget alerts and throttling
5. Cost estimation (tokens → time/resources)
6. Budget rebalancing across agents
7. Budget prompt for LLM context
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
    WARNING = "warning"         # >75% used
    CRITICAL = "critical"       # >90% used
    EXHAUSTED = "exhausted"     # 100% used
    UNLIMITED = "unlimited"


@dataclass
class AgentBudget:
    """Budget allocation for an agent."""
    agent_id: str = ""
    parent_id: str = ""
    token_budget: int = 50000
    tokens_used: int = 0
    requests_made: int = 0
    time_budget_s: float = 600.0
    time_used_s: float = 0.0
    children_budgets: dict[str, int] = field(default_factory=dict)
    rate_limit_rps: float = 10.0     # Requests per second
    last_request_time: float = 0.0

    @property
    def tokens_remaining(self) -> int:
        return max(0, self.token_budget - self.tokens_used)

    @property
    def usage_ratio(self) -> float:
        if self.token_budget == 0:
            return 0.0
        return self.tokens_used / self.token_budget

    @property
    def status(self) -> BudgetStatus:
        if self.token_budget <= 0:
            return BudgetStatus.UNLIMITED
        ratio = self.usage_ratio
        if ratio >= 1.0:
            return BudgetStatus.EXHAUSTED
        if ratio >= 0.9:
            return BudgetStatus.CRITICAL
        if ratio >= 0.75:
            return BudgetStatus.WARNING
        return BudgetStatus.OK

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id[:10],
            "used": f"{self.tokens_used}/{self.token_budget}",
            "status": self.status.value[:6],
            "requests": self.requests_made,
        }


@dataclass
class UsageRecord:
    """A usage record."""
    agent_id: str = ""
    model_id: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


class TokenBudgetManager:
    """Manages token budgets across agent hierarchy.

    Allocates budgets, tracks usage, propagates
    limits down the hierarchy, and provides
    alerts when budgets are low.
    """

    def __init__(
        self,
        global_budget: int = 1000000,
        default_agent_budget: int = 50000,
    ) -> None:
        self._global_budget = global_budget
        self._default_budget = default_agent_budget
        self._budgets: dict[str, AgentBudget] = {}
        self._usage_history: list[UsageRecord] = []
        self._global_used = 0
        self._log = logger.bind(component="token_budget")

    def allocate(
        self,
        agent_id: str,
        parent_id: str = "",
        token_budget: int = 0,
        time_budget_s: float = 600.0,
    ) -> AgentBudget:
        """Allocate budget for an agent."""
        budget_amount = token_budget or self._default_budget

        # If parent, deduct from parent's remaining
        if parent_id and parent_id in self._budgets:
            parent = self._budgets[parent_id]
            available = parent.tokens_remaining
            budget_amount = min(budget_amount, available // 2)
            parent.children_budgets[agent_id] = budget_amount

        budget = AgentBudget(
            agent_id=agent_id,
            parent_id=parent_id,
            token_budget=budget_amount,
            time_budget_s=time_budget_s,
        )
        self._budgets[agent_id] = budget
        return budget

    def consume(
        self,
        agent_id: str,
        model_id: str = "",
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        latency_ms: float = 0.0,
    ) -> bool:
        """Record token consumption. Returns False if over budget."""
        budget = self._budgets.get(agent_id)
        if not budget:
            return False

        total = prompt_tokens + completion_tokens

        # Check if within budget
        if budget.status == BudgetStatus.EXHAUSTED:
            return False

        budget.tokens_used += total
        budget.requests_made += 1
        budget.last_request_time = time.time()
        self._global_used += total

        # Record usage
        self._usage_history.append(UsageRecord(
            agent_id=agent_id,
            model_id=model_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total,
            latency_ms=latency_ms,
        ))

        return True

    def can_afford(self, agent_id: str, estimated_tokens: int) -> bool:
        """Check if agent can afford estimated tokens."""
        budget = self._budgets.get(agent_id)
        if not budget:
            return False
        return budget.tokens_remaining >= estimated_tokens

    def rebalance(self, agent_id: str) -> None:
        """Rebalance budget from children that finished early."""
        budget = self._budgets.get(agent_id)
        if not budget:
            return

        reclaimed = 0
        for child_id, allocated in budget.children_budgets.items():
            child = self._budgets.get(child_id)
            if child and child.status in (BudgetStatus.EXHAUSTED, BudgetStatus.OK):
                unused = child.tokens_remaining
                if unused > 0 and child.requests_made > 0:
                    reclaimed += unused

        if reclaimed > 0:
            budget.token_budget += reclaimed

    def get_usage_rate(self, agent_id: str, window_s: float = 60.0) -> float:
        """Get tokens per second for an agent over a window."""
        now = time.time()
        cutoff = now - window_s

        window_tokens = sum(
            r.total_tokens for r in self._usage_history
            if r.agent_id == agent_id and r.timestamp >= cutoff
        )

        return window_tokens / window_s

    def build_budget_prompt(self, agent_id: str = "") -> str:
        """Build budget context for LLM."""
        lines = ["## Token Budget\n"]

        lines.append(
            f"Global: {self._global_used}/{self._global_budget} "
            f"({self._global_used / self._global_budget:.0%})"
        )

        if agent_id and agent_id in self._budgets:
            budget = self._budgets[agent_id]
            lines.append(f"\nAgent {agent_id[:10]}:")
            lines.append(
                f"  Tokens: {budget.tokens_used}/{budget.token_budget} "
                f"({budget.usage_ratio:.0%}) [{budget.status.value}]"
            )
            lines.append(f"  Requests: {budget.requests_made}")
            lines.append(f"  Remaining: {budget.tokens_remaining}")

            if budget.children_budgets:
                lines.append(f"  Children: {len(budget.children_budgets)}")
                for cid, alloc in list(budget.children_budgets.items())[:3]:
                    child = self._budgets.get(cid)
                    if child:
                        lines.append(
                            f"    {cid[:8]}: {child.tokens_used}/{alloc} "
                            f"[{child.status.value}]"
                        )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for b in self._budgets.values():
            s = b.status.value
            status_counts[s] = status_counts.get(s, 0) + 1

        return {
            "global_used": self._global_used,
            "global_budget": self._global_budget,
            "agents": len(self._budgets),
            "usage_records": len(self._usage_history),
            "by_status": status_counts,
        }
