"""Agent resource manager — tracks and enforces budgets.

Implements:
1. Token budget tracking per agent
2. Time budget enforcement
3. Tool call counting and limits
4. LLM query rate limiting
5. Memory usage estimation
6. Budget allocation to child agents
7. Cost-benefit analysis for tool selection
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ResourceType(str, Enum):
    TOKENS = "tokens"
    TIME = "time"
    TOOL_CALLS = "tool_calls"
    LLM_QUERIES = "llm_queries"
    CHILD_AGENTS = "child_agents"
    MEMORY_MB = "memory_mb"


class BudgetStatus(str, Enum):
    OK = "ok"
    WARNING = "warning"      # >75% used
    CRITICAL = "critical"    # >90% used
    EXHAUSTED = "exhausted"  # 100% used


@dataclass
class ResourceBudget:
    """Budget for a single resource type."""
    resource_type: ResourceType = ResourceType.TOKENS
    allocated: float = 0.0
    used: float = 0.0
    reserved: float = 0.0       # Reserved for child agents

    @property
    def remaining(self) -> float:
        return max(0.0, self.allocated - self.used - self.reserved)

    @property
    def utilization(self) -> float:
        if self.allocated <= 0:
            return 0.0
        return self.used / self.allocated

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
            "type": self.resource_type.value,
            "allocated": round(self.allocated, 1),
            "used": round(self.used, 1),
            "remaining": round(self.remaining, 1),
            "status": self.status.value,
        }


@dataclass
class AgentBudget:
    """Full budget for an agent."""
    agent_id: str = ""
    parent_id: str = ""
    budgets: dict[str, ResourceBudget] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    last_check_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id[:10],
            "budgets": {k: v.to_dict() for k, v in self.budgets.items()},
        }


@dataclass
class ToolCostEstimate:
    """Estimated cost of running a tool."""
    tool_name: str = ""
    estimated_tokens: int = 0        # Tokens for output parsing
    estimated_time_s: float = 0.0
    estimated_memory_mb: float = 0.0
    expected_value: float = 0.0      # Expected findings value

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name,
            "tokens": self.estimated_tokens,
            "time_s": round(self.estimated_time_s, 1),
        }


# ── Default budgets ──────────────────────────────────────────

DEFAULT_BUDGETS: dict[str, float] = {
    "tokens": 100000,
    "time": 3600.0,           # 1 hour
    "tool_calls": 50,
    "llm_queries": 100,
    "child_agents": 5,
    "memory_mb": 512,
}

CHILD_BUDGET_DECAY = 0.7  # Children get 70% of parent's remaining budget

# ── Tool cost estimates ──────────────────────────────────────

TOOL_COST_ESTIMATES: dict[str, dict[str, float]] = {
    "nmap": {"tokens": 5000, "time_s": 120.0, "memory_mb": 50},
    "nuclei": {"tokens": 8000, "time_s": 300.0, "memory_mb": 100},
    "sqlmap": {"tokens": 10000, "time_s": 600.0, "memory_mb": 80},
    "ffuf": {"tokens": 3000, "time_s": 60.0, "memory_mb": 50},
    "gobuster": {"tokens": 2000, "time_s": 120.0, "memory_mb": 30},
    "subfinder": {"tokens": 1000, "time_s": 30.0, "memory_mb": 20},
    "httpx": {"tokens": 2000, "time_s": 60.0, "memory_mb": 30},
    "hydra": {"tokens": 1000, "time_s": 300.0, "memory_mb": 40},
    "nikto": {"tokens": 5000, "time_s": 180.0, "memory_mb": 50},
    "masscan": {"tokens": 2000, "time_s": 60.0, "memory_mb": 50},
    "semgrep": {"tokens": 6000, "time_s": 120.0, "memory_mb": 200},
    "trivy": {"tokens": 4000, "time_s": 60.0, "memory_mb": 100},
    "testssl": {"tokens": 3000, "time_s": 120.0, "memory_mb": 30},
    "dig": {"tokens": 500, "time_s": 5.0, "memory_mb": 5},
    "whois": {"tokens": 300, "time_s": 5.0, "memory_mb": 5},
}


class ResourceManager:
    """Manages resource budgets for agents.

    Tracks token usage, time, tool calls,
    and LLM queries. Enforces limits and
    allocates budgets to child agents.
    """

    def __init__(self) -> None:
        self._agents: dict[str, AgentBudget] = {}
        self._log = logger.bind(component="resource_manager")

    def create_budget(
        self,
        agent_id: str,
        parent_id: str = "",
        token_budget: int = 0,
        time_budget_s: float = 0.0,
        tool_call_limit: int = 0,
        llm_query_limit: int = 0,
    ) -> AgentBudget:
        """Create a budget for an agent."""
        budgets: dict[str, ResourceBudget] = {}

        configs = [
            (ResourceType.TOKENS, token_budget or DEFAULT_BUDGETS["tokens"]),
            (ResourceType.TIME, time_budget_s or DEFAULT_BUDGETS["time"]),
            (ResourceType.TOOL_CALLS, tool_call_limit or DEFAULT_BUDGETS["tool_calls"]),
            (ResourceType.LLM_QUERIES, llm_query_limit or DEFAULT_BUDGETS["llm_queries"]),
            (ResourceType.CHILD_AGENTS, DEFAULT_BUDGETS["child_agents"]),
            (ResourceType.MEMORY_MB, DEFAULT_BUDGETS["memory_mb"]),
        ]

        for res_type, allocated in configs:
            budgets[res_type.value] = ResourceBudget(
                resource_type=res_type,
                allocated=allocated,
            )

        agent_budget = AgentBudget(
            agent_id=agent_id,
            parent_id=parent_id,
            budgets=budgets,
        )
        self._agents[agent_id] = agent_budget
        return agent_budget

    def allocate_child_budget(
        self,
        parent_id: str,
        child_id: str,
    ) -> AgentBudget | None:
        """Allocate budget to a child agent from parent."""
        parent = self._agents.get(parent_id)
        if not parent:
            return None

        # Check child agent limit
        child_budget = parent.budgets.get(ResourceType.CHILD_AGENTS.value)
        if child_budget and child_budget.remaining <= 0:
            return None

        # Calculate child allocations
        child_budgets: dict[str, ResourceBudget] = {}
        for key, budget in parent.budgets.items():
            if key == ResourceType.CHILD_AGENTS.value:
                continue
            child_allocated = budget.remaining * CHILD_BUDGET_DECAY
            budget.reserved += child_allocated
            child_budgets[key] = ResourceBudget(
                resource_type=budget.resource_type,
                allocated=child_allocated,
            )

        # Track child spawn
        if child_budget:
            child_budget.used += 1

        agent_budget = AgentBudget(
            agent_id=child_id,
            parent_id=parent_id,
            budgets=child_budgets,
        )
        self._agents[child_id] = agent_budget
        return agent_budget

    def consume(
        self,
        agent_id: str,
        resource_type: ResourceType,
        amount: float,
    ) -> bool:
        """Consume a resource. Returns False if budget exhausted."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False

        budget = agent.budgets.get(resource_type.value)
        if not budget:
            return False

        if budget.remaining < amount:
            self._log.warning(
                "budget_exhausted",
                agent=agent_id[:10],
                resource=resource_type.value,
                remaining=budget.remaining,
                requested=amount,
            )
            return False

        budget.used += amount
        return True

    def check_budget(
        self,
        agent_id: str,
        resource_type: ResourceType,
    ) -> BudgetStatus:
        """Check budget status for a resource."""
        agent = self._agents.get(agent_id)
        if not agent:
            return BudgetStatus.EXHAUSTED

        budget = agent.budgets.get(resource_type.value)
        if not budget:
            return BudgetStatus.EXHAUSTED

        return budget.status

    def can_afford_tool(
        self,
        agent_id: str,
        tool_name: str,
    ) -> bool:
        """Check if agent can afford to run a tool."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False

        estimates = TOOL_COST_ESTIMATES.get(tool_name, {})
        token_cost = estimates.get("tokens", 2000)
        time_cost = estimates.get("time_s", 60.0)

        token_budget = agent.budgets.get(ResourceType.TOKENS.value)
        time_budget = agent.budgets.get(ResourceType.TIME.value)
        tool_budget = agent.budgets.get(ResourceType.TOOL_CALLS.value)

        if token_budget and token_budget.remaining < token_cost:
            return False
        if time_budget and time_budget.remaining < time_cost:
            return False
        if tool_budget and tool_budget.remaining < 1:
            return False

        return True

    def get_tool_cost_estimate(self, tool_name: str) -> ToolCostEstimate:
        """Get estimated cost for running a tool."""
        estimates = TOOL_COST_ESTIMATES.get(tool_name, {})
        return ToolCostEstimate(
            tool_name=tool_name,
            estimated_tokens=int(estimates.get("tokens", 2000)),
            estimated_time_s=estimates.get("time_s", 60.0),
            estimated_memory_mb=estimates.get("memory_mb", 50),
        )

    def build_budget_prompt(self, agent_id: str) -> str:
        """Build budget context for LLM."""
        agent = self._agents.get(agent_id)
        if not agent:
            return ""

        lines = ["## Resource Budget\n"]
        for budget in agent.budgets.values():
            pct = budget.utilization * 100
            lines.append(
                f"- {budget.resource_type.value}: "
                f"{budget.used:.0f}/{budget.allocated:.0f} "
                f"({pct:.0f}% used, {budget.status.value})"
            )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_tokens_used = 0
        total_tool_calls = 0
        for agent in self._agents.values():
            token_b = agent.budgets.get(ResourceType.TOKENS.value)
            if token_b:
                total_tokens_used += token_b.used
            tool_b = agent.budgets.get(ResourceType.TOOL_CALLS.value)
            if tool_b:
                total_tool_calls += tool_b.used

        return {
            "agents_tracked": len(self._agents),
            "total_tokens_used": round(total_tokens_used, 0),
            "total_tool_calls": round(total_tool_calls, 0),
        }
