"""Reward system — multi-objective reward shaping for agent decision-making.

Implements:
1. Multi-objective reward functions
2. Reward shaping for desired behaviors
3. Intrinsic curiosity reward
4. Reward normalization and scaling
5. Reward history and trend analysis
6. Penalty system for undesired behaviors
7. Reward composition from multiple signals
8. Adaptive reward weighting
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class RewardSignal(str, Enum):
    FINDING = "finding"            # Found a vulnerability
    COVERAGE = "coverage"          # Explored new area
    DEPTH = "depth"                # Deep analysis
    EFFICIENCY = "efficiency"      # Good token usage
    NOVELTY = "novelty"            # Novel approach
    VALIDATION = "validation"      # Confirmed finding
    COLLABORATION = "collaboration"  # Helped another agent
    SAFETY = "safety"              # Stayed within scope


class PenaltySignal(str, Enum):
    FALSE_POSITIVE = "false_positive"
    SCOPE_VIOLATION = "scope_violation"
    WASTEFUL = "wasteful"           # Wasted tokens
    REDUNDANT = "redundant"         # Repeated work
    TIMEOUT = "timeout"             # Timed out
    ERROR = "error"                 # Caused an error


@dataclass
class RewardEvent:
    """A reward or penalty event."""
    event_id: str = ""
    agent_id: str = ""
    signal: str = ""
    value: float = 0.0
    context: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.event_id,
            "agent": self.agent_id[:15],
            "signal": self.signal[:15],
            "value": round(self.value, 3),
        }


@dataclass
class AgentRewardState:
    """Cumulative reward state for an agent."""
    agent_id: str = ""
    total_reward: float = 0.0
    reward_events: int = 0
    penalty_events: int = 0
    signal_totals: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    curiosity_bonus: float = 0.0
    visited_states: set[str] = field(default_factory=set)

    @property
    def net_reward(self) -> float:
        return self.total_reward + self.curiosity_bonus

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id[:15],
            "total": round(self.total_reward, 3),
            "curiosity": round(self.curiosity_bonus, 3),
            "net": round(self.net_reward, 3),
            "events": self.reward_events + self.penalty_events,
        }


# ── Reward Configuration ──────────────────────────────────────

REWARD_VALUES: dict[str, float] = {
    # Positive rewards
    RewardSignal.FINDING.value: 10.0,
    RewardSignal.COVERAGE.value: 2.0,
    RewardSignal.DEPTH.value: 3.0,
    RewardSignal.EFFICIENCY.value: 1.5,
    RewardSignal.NOVELTY.value: 5.0,
    RewardSignal.VALIDATION.value: 4.0,
    RewardSignal.COLLABORATION.value: 2.0,
    RewardSignal.SAFETY.value: 1.0,
    # Penalties (negative)
    PenaltySignal.FALSE_POSITIVE.value: -5.0,
    PenaltySignal.SCOPE_VIOLATION.value: -15.0,
    PenaltySignal.WASTEFUL.value: -2.0,
    PenaltySignal.REDUNDANT.value: -3.0,
    PenaltySignal.TIMEOUT.value: -1.0,
    PenaltySignal.ERROR.value: -1.5,
}

# Severity multipliers for findings
SEVERITY_MULTIPLIERS: dict[str, float] = {
    "critical": 4.0,
    "high": 2.5,
    "medium": 1.5,
    "low": 1.0,
    "info": 0.3,
}


class RewardSystem:
    """Multi-objective reward shaping for agent decision-making.

    Provides reward signals that guide agent behavior toward
    finding real vulnerabilities while staying efficient.
    """

    def __init__(
        self,
        curiosity_weight: float = 0.3,
        decay_rate: float = 0.01,
    ) -> None:
        self._agents: dict[str, AgentRewardState] = {}
        self._events: list[RewardEvent] = []
        self._event_counter = 0
        self._reward_weights: dict[str, float] = dict(REWARD_VALUES)
        self._curiosity_weight = curiosity_weight
        self._decay_rate = decay_rate
        self._weight_history: list[dict[str, float]] = []
        self._log = logger.bind(component="reward_system")

    def reward(
        self,
        agent_id: str,
        signal: RewardSignal,
        context: str = "",
        severity: str = "",
        multiplier: float = 1.0,
    ) -> float:
        """Give a reward to an agent."""
        base_value = self._reward_weights.get(signal.value, 0.0)

        # Apply severity multiplier for findings
        if signal == RewardSignal.FINDING and severity:
            base_value *= SEVERITY_MULTIPLIERS.get(severity, 1.0)

        value = base_value * multiplier
        return self._record_event(agent_id, signal.value, value, context)

    def penalize(
        self,
        agent_id: str,
        signal: PenaltySignal,
        context: str = "",
        multiplier: float = 1.0,
    ) -> float:
        """Apply a penalty to an agent."""
        base_value = self._reward_weights.get(signal.value, -1.0)
        value = base_value * multiplier
        return self._record_event(agent_id, signal.value, value, context)

    def curiosity_reward(
        self,
        agent_id: str,
        state_description: str,
    ) -> float:
        """Give intrinsic curiosity reward for visiting new states."""
        agent_state = self._get_or_create(agent_id)

        if state_description in agent_state.visited_states:
            return 0.0

        agent_state.visited_states.add(state_description)

        # Curiosity decays with number of visited states
        novelty = 1.0 / (1.0 + math.log1p(len(agent_state.visited_states)))
        bonus = novelty * self._curiosity_weight

        agent_state.curiosity_bonus += bonus
        return bonus

    def _record_event(
        self,
        agent_id: str,
        signal: str,
        value: float,
        context: str,
    ) -> float:
        """Record a reward/penalty event."""
        self._event_counter += 1
        event = RewardEvent(
            event_id=f"rw-{self._event_counter}",
            agent_id=agent_id,
            signal=signal,
            value=value,
            context=context,
        )

        self._events.append(event)
        if len(self._events) > 2000:
            self._events = self._events[-2000:]

        # Update agent state
        agent_state = self._get_or_create(agent_id)
        agent_state.total_reward += value
        agent_state.signal_totals[signal] += value

        if value >= 0:
            agent_state.reward_events += 1
        else:
            agent_state.penalty_events += 1

        return value

    def _get_or_create(self, agent_id: str) -> AgentRewardState:
        if agent_id not in self._agents:
            self._agents[agent_id] = AgentRewardState(agent_id=agent_id)
        return self._agents[agent_id]

    def get_agent_reward(self, agent_id: str) -> float:
        """Get total reward for an agent."""
        state = self._agents.get(agent_id)
        return state.net_reward if state else 0.0

    def get_leaderboard(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get agent leaderboard by reward."""
        sorted_agents = sorted(
            self._agents.values(),
            key=lambda a: a.net_reward,
            reverse=True,
        )
        return [a.to_dict() for a in sorted_agents[:limit]]

    def adapt_weights(self) -> dict[str, float]:
        """Adapt reward weights based on current performance."""
        changes: dict[str, float] = {}

        # Count signal frequency
        signal_counts: dict[str, int] = defaultdict(int)
        for event in self._events[-200:]:
            signal_counts[event.signal] += 1

        # If too many false positives, increase FP penalty
        fp_count = signal_counts.get(PenaltySignal.FALSE_POSITIVE.value, 0)
        finding_count = signal_counts.get(RewardSignal.FINDING.value, 0)
        if finding_count > 0 and fp_count / max(1, finding_count) > 0.3:
            old = self._reward_weights[PenaltySignal.FALSE_POSITIVE.value]
            new = old * 1.2
            self._reward_weights[PenaltySignal.FALSE_POSITIVE.value] = new
            changes["false_positive_penalty"] = new

        # If low coverage, increase coverage reward
        coverage_count = signal_counts.get(RewardSignal.COVERAGE.value, 0)
        if coverage_count < 5 and len(self._events) > 50:
            old = self._reward_weights[RewardSignal.COVERAGE.value]
            new = old * 1.3
            self._reward_weights[RewardSignal.COVERAGE.value] = new
            changes["coverage_reward"] = new

        self._weight_history.append(dict(self._reward_weights))
        if len(self._weight_history) > 50:
            self._weight_history = self._weight_history[-50:]

        return changes

    def get_stats(self) -> dict[str, Any]:
        total_reward = sum(a.total_reward for a in self._agents.values())
        total_curiosity = sum(a.curiosity_bonus for a in self._agents.values())

        return {
            "agents": len(self._agents),
            "events": len(self._events),
            "total_reward": round(total_reward, 2),
            "total_curiosity": round(total_curiosity, 2),
            "weight_adaptations": len(self._weight_history),
        }
