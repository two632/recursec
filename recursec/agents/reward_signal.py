"""Reward signal engine — RL-inspired feedback.

Implements:
1. Reward calculation for agent actions
2. Severity-weighted scoring
3. Penalty detection (false positives, loops)
4. Cumulative reward tracking
5. Policy gradient signals
6. Reward prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ActionOutcome(str, Enum):
    FINDING = "finding"             # Found a vulnerability
    FALSE_POSITIVE = "false_positive"  # False positive
    INFO = "info"                   # Informational
    FAILURE = "failure"             # Action failed
    TIMEOUT = "timeout"             # Action timed out
    DUPLICATE = "duplicate"         # Duplicate finding
    PROGRESS = "progress"           # Made progress
    LOOP = "loop"                   # Repeated action
    NOVEL = "novel"                 # Novel technique


SEVERITY_MULTIPLIERS: dict[str, float] = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
    "info": 0.3,
}

OUTCOME_REWARDS: dict[ActionOutcome, float] = {
    ActionOutcome.FINDING: 10.0,
    ActionOutcome.FALSE_POSITIVE: -5.0,
    ActionOutcome.INFO: 1.0,
    ActionOutcome.FAILURE: -1.0,
    ActionOutcome.TIMEOUT: -2.0,
    ActionOutcome.DUPLICATE: -3.0,
    ActionOutcome.PROGRESS: 2.0,
    ActionOutcome.LOOP: -4.0,
    ActionOutcome.NOVEL: 5.0,
}


@dataclass
class RewardEvent:
    """A single reward event."""
    event_id: str = ""
    action: str = ""
    outcome: ActionOutcome = ActionOutcome.INFO
    severity: str = "medium"
    raw_reward: float = 0.0
    multiplied_reward: float = 0.0
    agent_id: str = ""
    tool_used: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action[:15],
            "outcome": self.outcome.value[:8],
            "reward": f"{self.multiplied_reward:+.1f}",
        }


@dataclass
class AgentRewardProfile:
    """Cumulative reward profile for an agent."""
    agent_id: str = ""
    total_reward: float = 0.0
    event_count: int = 0
    findings: int = 0
    false_positives: int = 0
    loops_detected: int = 0
    best_action: str = ""
    best_reward: float = 0.0
    worst_action: str = ""
    worst_reward: float = 0.0

    @property
    def avg_reward(self) -> float:
        if self.event_count == 0:
            return 0.0
        return self.total_reward / self.event_count

    @property
    def precision(self) -> float:
        total = self.findings + self.false_positives
        if total == 0:
            return 0.0
        return self.findings / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": f"{self.total_reward:+.1f}",
            "avg": f"{self.avg_reward:+.2f}",
            "findings": self.findings,
            "fp": self.false_positives,
        }


class RewardSignalEngine:
    """RL-inspired reward signal for agent learning.

    Calculates rewards, tracks cumulative scores,
    and provides policy gradient signals.
    """

    def __init__(
        self,
        gamma: float = 0.95,  # Discount factor
        novelty_bonus: float = 2.0,
    ) -> None:
        self._events: list[RewardEvent] = []
        self._profiles: dict[str, AgentRewardProfile] = {}
        self._event_counter = 0
        self._gamma = gamma
        self._novelty_bonus = novelty_bonus
        self._seen_actions: set[str] = set()
        self._log = logger.bind(component="reward")

    def calculate_reward(
        self,
        outcome: ActionOutcome,
        severity: str = "medium",
        is_novel: bool = False,
    ) -> float:
        """Calculate reward for an action."""
        base = OUTCOME_REWARDS.get(outcome, 0.0)
        multiplier = SEVERITY_MULTIPLIERS.get(severity.lower(), 1.0)

        reward = base * multiplier

        if is_novel and reward > 0:
            reward += self._novelty_bonus

        return reward

    def record(
        self,
        action: str,
        outcome: ActionOutcome,
        severity: str = "medium",
        agent_id: str = "",
        tool_used: str = "",
    ) -> RewardEvent:
        """Record a reward event."""
        self._event_counter += 1

        # Check novelty
        action_key = f"{action}:{tool_used}"
        is_novel = action_key not in self._seen_actions
        self._seen_actions.add(action_key)

        raw_reward = OUTCOME_REWARDS.get(outcome, 0.0)
        multiplied = self.calculate_reward(outcome, severity, is_novel)

        event = RewardEvent(
            event_id=f"re-{self._event_counter}",
            action=action,
            outcome=outcome,
            severity=severity,
            raw_reward=raw_reward,
            multiplied_reward=multiplied,
            agent_id=agent_id,
            tool_used=tool_used,
        )
        self._events.append(event)

        # Update agent profile
        self._update_profile(agent_id, event)

        return event

    def _update_profile(
        self,
        agent_id: str,
        event: RewardEvent,
    ) -> None:
        """Update agent reward profile."""
        if agent_id not in self._profiles:
            self._profiles[agent_id] = AgentRewardProfile(
                agent_id=agent_id,
            )

        profile = self._profiles[agent_id]
        profile.total_reward += event.multiplied_reward
        profile.event_count += 1

        if event.outcome == ActionOutcome.FINDING:
            profile.findings += 1
        elif event.outcome == ActionOutcome.FALSE_POSITIVE:
            profile.false_positives += 1
        elif event.outcome == ActionOutcome.LOOP:
            profile.loops_detected += 1

        if event.multiplied_reward > profile.best_reward:
            profile.best_reward = event.multiplied_reward
            profile.best_action = event.action

        if event.multiplied_reward < profile.worst_reward:
            profile.worst_reward = event.multiplied_reward
            profile.worst_action = event.action

    def get_discounted_return(
        self,
        agent_id: str,
        last_n: int = 20,
    ) -> float:
        """Calculate discounted return for an agent."""
        agent_events = [
            e for e in self._events
            if e.agent_id == agent_id
        ][-last_n:]

        if not agent_events:
            return 0.0

        total = 0.0
        for i, event in enumerate(reversed(agent_events)):
            total += event.multiplied_reward * (self._gamma ** i)

        return total

    def get_gradient_signal(self, agent_id: str) -> dict[str, float]:
        """Get policy gradient signal for actions.

        Returns action→advantage mapping indicating
        which actions to prefer.
        """
        agent_events = [
            e for e in self._events
            if e.agent_id == agent_id
        ]

        if not agent_events:
            return {}

        # Calculate per-action average reward
        action_rewards: dict[str, list[float]] = {}
        for e in agent_events:
            key = e.action
            if key not in action_rewards:
                action_rewards[key] = []
            action_rewards[key].append(e.multiplied_reward)

        # Baseline: overall average
        all_rewards = [e.multiplied_reward for e in agent_events]
        baseline = sum(all_rewards) / len(all_rewards)

        # Advantage = action_avg - baseline
        advantages: dict[str, float] = {}
        for action, rewards in action_rewards.items():
            avg = sum(rewards) / len(rewards)
            advantages[action] = avg - baseline

        return advantages

    def build_reward_prompt(self, agent_id: str = "") -> str:
        """Build reward context for LLM."""
        lines = ["## Rewards\n"]
        lines.append(f"Events: {len(self._events)}")

        if agent_id and agent_id in self._profiles:
            profile = self._profiles[agent_id]
            lines.append(f"Total: {profile.total_reward:+.1f}")
            lines.append(f"Avg: {profile.avg_reward:+.2f}")
            lines.append(f"Findings: {profile.findings}")
            lines.append(f"FP: {profile.false_positives}")
            lines.append(f"Precision: {profile.precision:.0%}")

            # Gradient signal
            gradient = self.get_gradient_signal(agent_id)
            if gradient:
                preferred = sorted(
                    gradient.items(), key=lambda x: x[1], reverse=True,
                )[:3]
                lines.append("\nPreferred actions:")
                for action, adv in preferred:
                    lines.append(f"  {action[:15]}: {adv:+.2f}")

                avoided = sorted(gradient.items(), key=lambda x: x[1])[:3]
                lines.append("Avoid:")
                for action, adv in avoided:
                    if adv < 0:
                        lines.append(f"  {action[:15]}: {adv:+.2f}")
        else:
            # Global stats
            total = sum(e.multiplied_reward for e in self._events)
            lines.append(f"Total reward: {total:+.1f}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        outcome_counts: dict[str, int] = {}
        for e in self._events:
            outcome_counts[e.outcome.value] = outcome_counts.get(e.outcome.value, 0) + 1

        return {
            "events": len(self._events),
            "total_reward": sum(e.multiplied_reward for e in self._events),
            "agents": len(self._profiles),
            "by_outcome": outcome_counts,
        }
