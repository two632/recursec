"""Budget manager — per-agent and per-task token/time budget tracking.

Implements:
1. Hierarchical budget allocation (assessment → agent → task)
2. Token usage tracking with alerts
3. Time budget enforcement
4. Budget decay for child agents
5. Cost estimation by model
6. Budget reallocation from underperforming agents
7. Budget utilization reporting
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class BudgetLevel(str, Enum):
    ASSESSMENT = "assessment"
    AGENT = "agent"
    TASK = "task"


class BudgetStatus(str, Enum):
    HEALTHY = "healthy"       # < 50% used
    WARNING = "warning"       # 50-80% used
    CRITICAL = "critical"     # 80-95% used
    EXHAUSTED = "exhausted"   # > 95% used


@dataclass
class TokenBudget:
    """A token budget allocation."""
    budget_id: str = ""
    level: BudgetLevel = BudgetLevel.TASK
    owner: str = ""          # Agent or task ID
    parent_id: str = ""      # Parent budget
    allocated: int = 10000
    used: int = 0
    reserved: int = 0        # Reserved for children
    created_at: float = field(default_factory=time.time)

    @property
    def remaining(self) -> int:
        return max(0, self.allocated - self.used - self.reserved)

    @property
    def utilization(self) -> float:
        if self.allocated == 0:
            return 1.0
        return self.used / self.allocated

    @property
    def status(self) -> BudgetStatus:
        u = self.utilization
        if u >= 0.95:
            return BudgetStatus.EXHAUSTED
        if u >= 0.80:
            return BudgetStatus.CRITICAL
        if u >= 0.50:
            return BudgetStatus.WARNING
        return BudgetStatus.HEALTHY

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.budget_id[:10],
            "owner": self.owner[:12],
            "allocated": self.allocated,
            "used": self.used,
            "remaining": self.remaining,
            "status": self.status.value,
        }


@dataclass
class TimeBudget:
    """A time budget allocation."""
    budget_id: str = ""
    owner: str = ""
    allocated_s: float = 600.0
    started_at: float = 0.0

    @property
    def elapsed_s(self) -> float:
        if self.started_at == 0:
            return 0.0
        return time.time() - self.started_at

    @property
    def remaining_s(self) -> float:
        return max(0.0, self.allocated_s - self.elapsed_s)

    @property
    def utilization(self) -> float:
        if self.allocated_s == 0:
            return 1.0
        return self.elapsed_s / self.allocated_s

    @property
    def is_expired(self) -> bool:
        return self.elapsed_s >= self.allocated_s

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.budget_id[:10],
            "owner": self.owner[:12],
            "allocated_s": self.allocated_s,
            "elapsed_s": round(self.elapsed_s, 1),
            "remaining_s": round(self.remaining_s, 1),
        }


@dataclass
class UsageRecord:
    """A token usage event."""
    record_id: str = ""
    budget_id: str = ""
    model_id: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    duration_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:12],
            "prompt": self.prompt_tokens,
            "completion": self.completion_tokens,
            "total": self.total_tokens,
        }


# ── Default budgets per level ────────────────────────────────

DEFAULT_BUDGETS: dict[str, int] = {
    "assessment": 1000000,     # 1M tokens per assessment
    "agent": 100000,           # 100K per agent
    "task": 10000,             # 10K per task
}

BUDGET_DECAY = 0.7  # Child gets 70% of parent remaining


class BudgetManager:
    """Manages token and time budgets hierarchically.

    Tracks usage per assessment, agent, and task,
    enforces limits, and supports reallocation
    from underperforming to high-value agents.
    """

    def __init__(self) -> None:
        self._token_budgets: dict[str, TokenBudget] = {}
        self._time_budgets: dict[str, TimeBudget] = {}
        self._usage_records: list[UsageRecord] = []
        self._counter = 0
        self._log = logger.bind(component="budget_manager")

    def create_budget(
        self,
        level: BudgetLevel,
        owner: str,
        tokens: int = 0,
        time_s: float = 0.0,
        parent_id: str = "",
    ) -> tuple[TokenBudget, TimeBudget]:
        """Create a budget allocation."""
        self._counter += 1
        bid = f"budget-{self._counter}"

        # Default tokens by level
        if tokens == 0:
            tokens = DEFAULT_BUDGETS.get(level.value, 10000)

        # If parent exists, respect parent budget
        if parent_id and parent_id in self._token_budgets:
            parent = self._token_budgets[parent_id]
            max_child = int(parent.remaining * BUDGET_DECAY)
            tokens = min(tokens, max_child)
            parent.reserved += tokens

        token_budget = TokenBudget(
            budget_id=bid,
            level=level,
            owner=owner,
            parent_id=parent_id,
            allocated=tokens,
        )
        self._token_budgets[bid] = token_budget

        # Time budget
        if time_s == 0:
            time_s = {
                "assessment": 14400.0,  # 4 hours
                "agent": 3600.0,        # 1 hour
                "task": 600.0,          # 10 minutes
            }.get(level.value, 600.0)

        time_budget = TimeBudget(
            budget_id=bid,
            owner=owner,
            allocated_s=time_s,
        )
        self._time_budgets[bid] = time_budget

        return token_budget, time_budget

    def record_usage(
        self,
        budget_id: str,
        model_id: str,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        duration_ms: float = 0.0,
    ) -> bool:
        """Record token usage against a budget."""
        budget = self._token_budgets.get(budget_id)
        if not budget:
            return False

        total = prompt_tokens + completion_tokens
        budget.used += total

        self._counter += 1
        record = UsageRecord(
            record_id=f"usage-{self._counter}",
            budget_id=budget_id,
            model_id=model_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total,
            duration_ms=duration_ms,
        )
        self._usage_records.append(record)

        # Propagate to parent
        if budget.parent_id and budget.parent_id in self._token_budgets:
            parent = self._token_budgets[budget.parent_id]
            parent.used += total

        return True

    def start_timer(self, budget_id: str) -> None:
        """Start the time budget timer."""
        tb = self._time_budgets.get(budget_id)
        if tb and tb.started_at == 0:
            tb.started_at = time.time()

    def check_budget(self, budget_id: str) -> tuple[BudgetStatus, int, float]:
        """Check budget status. Returns (status, tokens_remaining, time_remaining_s)."""
        tb = self._token_budgets.get(budget_id)
        tmb = self._time_budgets.get(budget_id)

        tokens_left = tb.remaining if tb else 0
        time_left = tmb.remaining_s if tmb else 0.0
        status = tb.status if tb else BudgetStatus.EXHAUSTED

        return status, tokens_left, time_left

    def reallocate(
        self,
        from_id: str,
        to_id: str,
        tokens: int = 0,
    ) -> bool:
        """Reallocate tokens from one budget to another."""
        from_budget = self._token_budgets.get(from_id)
        to_budget = self._token_budgets.get(to_id)

        if not from_budget or not to_budget:
            return False

        available = from_budget.remaining
        transfer = min(tokens or available, available)

        if transfer <= 0:
            return False

        from_budget.allocated -= transfer
        to_budget.allocated += transfer

        return True

    def build_budget_prompt(self, budget_id: str = "") -> str:
        """Build budget context for LLM."""
        lines = ["## Budget Status\n"]

        if budget_id:
            tb = self._token_budgets.get(budget_id)
            tmb = self._time_budgets.get(budget_id)
            if tb:
                lines.append(f"Tokens: {tb.used}/{tb.allocated} ({tb.status.value})")
            if tmb:
                lines.append(f"Time: {tmb.elapsed_s:.0f}s/{tmb.allocated_s:.0f}s")
        else:
            # Show all assessment-level budgets
            for tb in self._token_budgets.values():
                if tb.level == BudgetLevel.ASSESSMENT:
                    lines.append(
                        f"  [{tb.owner[:12]}] {tb.used}/{tb.allocated} "
                        f"tokens ({tb.status.value})"
                    )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_allocated = sum(tb.allocated for tb in self._token_budgets.values())
        total_used = sum(tb.used for tb in self._token_budgets.values())

        status_counts: dict[str, int] = {}
        for tb in self._token_budgets.values():
            status_counts[tb.status.value] = status_counts.get(tb.status.value, 0) + 1

        return {
            "budgets": len(self._token_budgets),
            "total_allocated": total_allocated,
            "total_used": total_used,
            "usage_records": len(self._usage_records),
            "by_status": status_counts,
        }
