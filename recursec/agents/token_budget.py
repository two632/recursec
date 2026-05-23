"""Token budget manager — manages LLM token usage and allocation.

Implements:
1. Per-agent token budgets
2. Per-session token limits
3. Token usage tracking per model
4. Budget allocation across phases
5. Adaptive reallocation (shift budget to productive phases)
6. Token cost estimation
7. Token usage alerts
8. Budget enforcement (block requests over budget)
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class TokenBudget:
    """Token budget for an entity (agent, phase, session)."""
    entity: str = ""
    allocated: int = 0
    used: int = 0
    reserved: int = 0             # Reserved for future use

    @property
    def remaining(self) -> int:
        return max(0, self.allocated - self.used - self.reserved)

    @property
    def utilization(self) -> float:
        if self.allocated <= 0:
            return 0.0
        return min(1.0, self.used / self.allocated)

    @property
    def is_exceeded(self) -> bool:
        return self.used >= self.allocated

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity, "allocated": self.allocated,
            "used": self.used, "remaining": self.remaining,
            "utilization": round(self.utilization, 2),
        }


@dataclass
class TokenUsageRecord:
    """A record of token usage."""
    agent: str = ""
    model: str = ""
    phase: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class TokenBudgetManager:
    """Manages LLM token usage and budget allocation.

    Tracks usage per agent, model, and phase.
    Enforces limits and supports adaptive reallocation.
    """

    def __init__(self, session_budget: int = 10_000_000) -> None:
        self._session_budget = session_budget
        self._session_used = 0
        self._agent_budgets: dict[str, TokenBudget] = {}
        self._phase_budgets: dict[str, TokenBudget] = {}
        self._model_usage: dict[str, int] = defaultdict(int)
        self._records: list[TokenUsageRecord] = []
        self._log = logger.bind(component="token_budget")

    def set_agent_budget(self, agent: str, tokens: int) -> None:
        """Set token budget for an agent."""
        self._agent_budgets[agent] = TokenBudget(
            entity=agent, allocated=tokens,
        )

    def set_phase_budget(self, phase: str, tokens: int) -> None:
        """Set token budget for a phase."""
        self._phase_budgets[phase] = TokenBudget(
            entity=phase, allocated=tokens,
        )

    def allocate_session(
        self,
        phases: dict[str, float] | None = None,
    ) -> None:
        """Allocate session budget across phases."""
        default_phases = {
            "planning": 0.10,
            "recon": 0.15,
            "scanning": 0.25,
            "exploitation": 0.20,
            "validation": 0.15,
            "reporting": 0.15,
        }

        phase_ratios = phases or default_phases

        for phase, ratio in phase_ratios.items():
            self.set_phase_budget(
                phase, int(self._session_budget * ratio),
            )

    def can_spend(
        self,
        tokens: int,
        agent: str = "",
        phase: str = "",
    ) -> bool:
        """Check if token budget allows spending."""
        # Session limit
        if self._session_used + tokens > self._session_budget:
            return False

        # Agent limit
        if agent:
            budget = self._agent_budgets.get(agent)
            if budget and budget.used + tokens > budget.allocated:
                return False

        # Phase limit
        if phase:
            budget = self._phase_budgets.get(phase)
            if budget and budget.used + tokens > budget.allocated:
                return False

        return True

    def record_usage(
        self,
        agent: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        phase: str = "",
    ) -> None:
        """Record token usage."""
        total = input_tokens + output_tokens

        # Session total
        self._session_used += total

        # Agent budget
        budget = self._agent_budgets.get(agent)
        if budget:
            budget.used += total

        # Phase budget
        if phase:
            phase_budget = self._phase_budgets.get(phase)
            if phase_budget:
                phase_budget.used += total

        # Model usage
        self._model_usage[model] += total

        # Record
        record = TokenUsageRecord(
            agent=agent, model=model, phase=phase,
            input_tokens=input_tokens, output_tokens=output_tokens,
        )
        self._records.append(record)

        if len(self._records) > 5000:
            self._records = self._records[-5000:]

    def reallocate(self) -> None:
        """Adaptively reallocate budgets from underused to overused phases."""
        underused = []
        overused = []

        for phase, budget in self._phase_budgets.items():
            if budget.utilization < 0.3 and budget.remaining > 0:
                underused.append(budget)
            elif budget.utilization > 0.9:
                overused.append(budget)

        if not underused or not overused:
            return

        # Transfer from underused to overused
        for under in underused:
            transferable = under.remaining // 2
            if transferable <= 0:
                continue

            for over in overused:
                transfer = min(transferable, under.remaining // 2)
                under.allocated -= transfer
                over.allocated += transfer
                transferable -= transfer

                if transferable <= 0:
                    break

    def estimate_cost(self, tokens: int, model: str = "") -> float:
        """Estimate cost in terms of resource usage (0.0-1.0 scale)."""
        if self._session_budget <= 0:
            return 1.0
        return tokens / self._session_budget

    def get_session_status(self) -> dict[str, Any]:
        return {
            "budget": self._session_budget,
            "used": self._session_used,
            "remaining": self._session_budget - self._session_used,
            "utilization": round(
                self._session_used / max(1, self._session_budget), 2,
            ),
        }

    def get_model_usage(self) -> dict[str, int]:
        return dict(self._model_usage)

    def get_phase_status(self) -> dict[str, Any]:
        return {
            phase: budget.to_dict()
            for phase, budget in self._phase_budgets.items()
        }

    def get_agent_status(self) -> dict[str, Any]:
        return {
            agent: budget.to_dict()
            for agent, budget in self._agent_budgets.items()
        }

    def get_top_consumers(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get top token consumers."""
        agent_totals: dict[str, int] = defaultdict(int)
        for record in self._records:
            agent_totals[record.agent] += record.total_tokens

        sorted_agents = sorted(
            agent_totals.items(), key=lambda x: x[1], reverse=True,
        )

        return [
            {"agent": agent, "tokens": tokens}
            for agent, tokens in sorted_agents[:limit]
        ]

    def get_stats(self) -> dict[str, Any]:
        return {
            "session_budget": self._session_budget,
            "session_used": self._session_used,
            "agents": len(self._agent_budgets),
            "phases": len(self._phase_budgets),
            "models": len(self._model_usage),
            "records": len(self._records),
        }
