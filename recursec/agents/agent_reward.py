"""Agent reward system — reinforcement learning signals.

Implements:
1. Reward signal computation for agent actions
2. Multi-factor reward scoring
3. Penalty detection (wasteful/dangerous actions)
4. Cumulative reward tracking
5. Action-reward history for learning
6. Reward prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class RewardType(str, Enum):
    FINDING = "finding"               # Discovered vulnerability
    EXPLOITATION = "exploitation"     # Confirmed exploitable
    EFFICIENCY = "efficiency"         # Completed with fewer tokens
    NOVELTY = "novelty"               # New attack path
    VALIDATION = "validation"         # Finding validated
    PENALTY_LOOP = "penalty_loop"     # Stuck in loop
    PENALTY_WASTE = "penalty_waste"   # Wasted tokens
    PENALTY_FALSE = "penalty_false"   # False positive


# Base reward values per type
REWARD_VALUES: dict[RewardType, float] = {
    RewardType.FINDING: 1.0,
    RewardType.EXPLOITATION: 2.0,
    RewardType.EFFICIENCY: 0.5,
    RewardType.NOVELTY: 1.5,
    RewardType.VALIDATION: 0.8,
    RewardType.PENALTY_LOOP: -0.5,
    RewardType.PENALTY_WASTE: -0.3,
    RewardType.PENALTY_FALSE: -1.0,
}

# Severity multipliers for findings
SEVERITY_MULTIPLIERS: dict[str, float] = {
    "critical": 4.0,
    "high": 2.0,
    "medium": 1.0,
    "low": 0.5,
    "info": 0.1,
}


@dataclass
class RewardSignal:
    """A single reward signal."""
    reward_id: str = ""
    reward_type: RewardType = RewardType.FINDING
    value: float = 0.0
    reason: str = ""
    agent_id: str = ""
    action: str = ""
    severity: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.reward_type.value[:8],
            "value": f"{self.value:+.2f}",
            "reason": self.reason[:20],
        }


@dataclass
class AgentRewardState:
    """Reward state for a single agent."""
    agent_id: str = ""
    cumulative_reward: float = 0.0
    signals: list[RewardSignal] = field(default_factory=list)
    findings_rewarded: int = 0
    penalties_received: int = 0
    best_action: str = ""
    best_reward: float = 0.0

    @property
    def avg_reward(self) -> float:
        if not self.signals:
            return 0.0
        return self.cumulative_reward / len(self.signals)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id[:10],
            "cum_reward": f"{self.cumulative_reward:+.2f}",
            "signals": len(self.signals),
            "avg": f"{self.avg_reward:+.2f}",
        }


class AgentRewardSystem:
    """RL reward system for agent actions.

    Computes reward signals for agent behaviors,
    tracks cumulative rewards, and provides
    learning signals back to the agent.
    """

    def __init__(self) -> None:
        self._agents: dict[str, AgentRewardState] = {}
        self._reward_counter = 0
        self._global_rewards: list[RewardSignal] = []
        self._log = logger.bind(component="reward")

    def _get_agent(self, agent_id: str) -> AgentRewardState:
        if agent_id not in self._agents:
            self._agents[agent_id] = AgentRewardState(agent_id=agent_id)
        return self._agents[agent_id]

    def reward_finding(
        self,
        agent_id: str,
        severity: str = "medium",
        action: str = "",
        reason: str = "",
    ) -> RewardSignal:
        """Reward for discovering a vulnerability."""
        multiplier = SEVERITY_MULTIPLIERS.get(severity, 1.0)
        value = REWARD_VALUES[RewardType.FINDING] * multiplier

        return self._emit(
            agent_id=agent_id,
            reward_type=RewardType.FINDING,
            value=value,
            action=action,
            reason=reason or f"Found {severity} vulnerability",
            severity=severity,
        )

    def reward_exploitation(
        self,
        agent_id: str,
        severity: str = "medium",
        action: str = "",
    ) -> RewardSignal:
        """Reward for confirming exploitability."""
        multiplier = SEVERITY_MULTIPLIERS.get(severity, 1.0)
        value = REWARD_VALUES[RewardType.EXPLOITATION] * multiplier

        return self._emit(
            agent_id=agent_id,
            reward_type=RewardType.EXPLOITATION,
            value=value,
            action=action,
            reason=f"Confirmed {severity} exploit",
            severity=severity,
        )

    def reward_novelty(
        self,
        agent_id: str,
        action: str = "",
        reason: str = "",
    ) -> RewardSignal:
        """Reward for discovering a new attack path."""
        return self._emit(
            agent_id=agent_id,
            reward_type=RewardType.NOVELTY,
            value=REWARD_VALUES[RewardType.NOVELTY],
            action=action,
            reason=reason or "New attack path discovered",
        )

    def reward_efficiency(
        self,
        agent_id: str,
        tokens_saved: int = 0,
    ) -> RewardSignal:
        """Reward for efficient token usage."""
        bonus = min(1.0, tokens_saved / 10000) * 0.5
        value = REWARD_VALUES[RewardType.EFFICIENCY] + bonus

        return self._emit(
            agent_id=agent_id,
            reward_type=RewardType.EFFICIENCY,
            value=value,
            reason=f"Saved {tokens_saved} tokens",
        )

    def penalize_loop(self, agent_id: str, loop_pattern: str = "") -> RewardSignal:
        """Penalize for getting stuck in loops."""
        return self._emit(
            agent_id=agent_id,
            reward_type=RewardType.PENALTY_LOOP,
            value=REWARD_VALUES[RewardType.PENALTY_LOOP],
            reason=f"Loop: {loop_pattern[:20]}",
        )

    def penalize_false_positive(self, agent_id: str, finding: str = "") -> RewardSignal:
        """Penalize for false positive findings."""
        return self._emit(
            agent_id=agent_id,
            reward_type=RewardType.PENALTY_FALSE,
            value=REWARD_VALUES[RewardType.PENALTY_FALSE],
            reason=f"FP: {finding[:20]}",
        )

    def penalize_waste(self, agent_id: str, tokens_wasted: int = 0) -> RewardSignal:
        """Penalize for wasting tokens."""
        return self._emit(
            agent_id=agent_id,
            reward_type=RewardType.PENALTY_WASTE,
            value=REWARD_VALUES[RewardType.PENALTY_WASTE],
            reason=f"Wasted {tokens_wasted} tokens",
        )

    def _emit(
        self,
        agent_id: str,
        reward_type: RewardType,
        value: float,
        action: str = "",
        reason: str = "",
        severity: str = "",
    ) -> RewardSignal:
        """Emit a reward signal."""
        self._reward_counter += 1
        state = self._get_agent(agent_id)

        signal = RewardSignal(
            reward_id=f"rwd-{self._reward_counter}",
            reward_type=reward_type,
            value=value,
            reason=reason,
            agent_id=agent_id,
            action=action,
            severity=severity,
        )

        state.signals.append(signal)
        state.cumulative_reward += value
        self._global_rewards.append(signal)

        if value > 0:
            state.findings_rewarded += 1
            if value > state.best_reward:
                state.best_reward = value
                state.best_action = action
        else:
            state.penalties_received += 1

        return signal

    def get_top_agents(self, n: int = 5) -> list[AgentRewardState]:
        """Get agents with highest cumulative reward."""
        agents = list(self._agents.values())
        agents.sort(key=lambda a: a.cumulative_reward, reverse=True)
        return agents[:n]

    def build_reward_prompt(self, agent_id: str = "") -> str:
        """Build reward context for LLM."""
        lines = ["## Reward System\n"]

        if agent_id:
            state = self._get_agent(agent_id)
            lines.append(f"Cumulative: {state.cumulative_reward:+.2f}")
            lines.append(f"Avg: {state.avg_reward:+.2f}")
            lines.append(f"Findings rewarded: {state.findings_rewarded}")
            lines.append(f"Penalties: {state.penalties_received}")

            # Recent signals
            recent = state.signals[-5:]
            if recent:
                lines.append("\nRecent:")
                for s in recent:
                    lines.append(f"  {s.value:+.2f} {s.reason[:25]}")

            if state.best_action:
                lines.append(f"\nBest: {state.best_action[:30]} ({state.best_reward:+.2f})")
        else:
            lines.append(f"Total agents: {len(self._agents)}")
            lines.append(f"Total signals: {len(self._global_rewards)}")

            top = self.get_top_agents(3)
            for a in top:
                lines.append(f"  {a.agent_id[:10]}: {a.cumulative_reward:+.2f}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_positive = sum(s.value for s in self._global_rewards if s.value > 0)
        total_negative = sum(s.value for s in self._global_rewards if s.value < 0)

        return {
            "total_signals": len(self._global_rewards),
            "agents": len(self._agents),
            "total_positive": f"{total_positive:+.2f}",
            "total_negative": f"{total_negative:+.2f}",
        }
