"""Experience replay engine — learn from past assessments.

Implements:
1. Experience buffer with prioritized replay
2. Successful strategy extraction
3. Target-type → strategy mapping
4. Historical finding analysis
5. Anti-pattern detection (what doesn't work)
6. Skill accumulation over sessions
7. Transfer learning between similar targets
8. Temporal difference tracking
"""

from __future__ import annotations

import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ExperienceType(str, Enum):
    TOOL_EXECUTION = "tool_execution"
    STRATEGY_APPLICATION = "strategy_application"
    FINDING_DISCOVERY = "finding_discovery"
    FALSE_POSITIVE = "false_positive"
    EXPLOITATION_ATTEMPT = "exploitation_attempt"
    RECONNAISSANCE = "reconnaissance"
    ANALYSIS_DECISION = "analysis_decision"


class OutcomeType(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"


@dataclass
class Experience:
    """A single experience (state-action-reward tuple)."""
    experience_id: str = ""
    exp_type: ExperienceType = ExperienceType.TOOL_EXECUTION
    target_type: str = ""            # web_app, api, network, cloud, etc.
    state: dict[str, Any] = field(default_factory=dict)
    action: str = ""
    tool: str = ""
    strategy: str = ""
    model: str = ""
    outcome: OutcomeType = OutcomeType.SUCCESS
    reward: float = 0.0
    findings_count: int = 0
    duration_s: float = 0.0
    timestamp: float = field(default_factory=time.time)
    priority: float = 1.0
    replay_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.experience_id[:10],
            "type": self.exp_type.value,
            "target": self.target_type[:10],
            "action": self.action[:20],
            "outcome": self.outcome.value,
            "reward": round(self.reward, 2),
            "priority": round(self.priority, 2),
        }


@dataclass
class StrategyProfile:
    """Profile of a strategy's effectiveness."""
    strategy: str = ""
    total_uses: int = 0
    successes: int = 0
    failures: int = 0
    total_reward: float = 0.0
    avg_duration_s: float = 0.0
    total_findings: int = 0
    best_target_types: list[str] = field(default_factory=list)
    worst_target_types: list[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_uses == 0:
            return 0.0
        return self.successes / self.total_uses

    @property
    def avg_reward(self) -> float:
        if self.total_uses == 0:
            return 0.0
        return self.total_reward / self.total_uses

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy[:20],
            "uses": self.total_uses,
            "success_rate": round(self.success_rate, 2),
            "avg_reward": round(self.avg_reward, 2),
            "findings": self.total_findings,
        }


@dataclass
class TargetProfile:
    """Profile of experiences with a target type."""
    target_type: str = ""
    assessments: int = 0
    total_findings: int = 0
    best_strategies: list[str] = field(default_factory=list)
    worst_strategies: list[str] = field(default_factory=list)
    best_tools: list[str] = field(default_factory=list)
    avg_assessment_time_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target_type[:15],
            "assessments": self.assessments,
            "findings": self.total_findings,
            "best_strategies": self.best_strategies[:3],
            "best_tools": self.best_tools[:3],
        }


class ExperienceReplayEngine:
    """Learns from past assessment experiences.

    Implements prioritized experience replay:
    - Higher reward experiences are replayed more often
    - Surprising outcomes (unexpected success/failure) get higher priority
    - Builds strategy profiles and target profiles
    - Provides recommendations based on accumulated knowledge
    """

    def __init__(
        self,
        buffer_size: int = 10000,
        priority_alpha: float = 0.6,
        priority_beta: float = 0.4,
    ) -> None:
        self._buffer: list[Experience] = []
        self._buffer_size = buffer_size
        self._priority_alpha = priority_alpha
        self._priority_beta = priority_beta
        self._counter = 0
        self._strategy_profiles: dict[str, StrategyProfile] = {}
        self._target_profiles: dict[str, TargetProfile] = {}
        self._strategy_target_rewards: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
        self._tool_target_rewards: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
        self._anti_patterns: list[dict[str, Any]] = []
        self._log = logger.bind(component="experience_replay")

    def record(
        self,
        exp_type: ExperienceType,
        target_type: str,
        action: str,
        outcome: OutcomeType,
        reward: float = 0.0,
        tool: str = "",
        strategy: str = "",
        model: str = "",
        state: dict[str, Any] | None = None,
        findings_count: int = 0,
        duration_s: float = 0.0,
    ) -> Experience:
        """Record a new experience."""
        self._counter += 1

        # Compute priority based on reward magnitude
        priority = abs(reward) ** self._priority_alpha + 0.01

        exp = Experience(
            experience_id=f"exp-{self._counter}",
            exp_type=exp_type,
            target_type=target_type,
            state=state or {},
            action=action,
            tool=tool,
            strategy=strategy,
            model=model,
            outcome=outcome,
            reward=reward,
            findings_count=findings_count,
            duration_s=duration_s,
            priority=priority,
        )

        # Add to buffer (circular)
        if len(self._buffer) >= self._buffer_size:
            # Remove lowest priority
            min_idx = min(range(len(self._buffer)), key=lambda i: self._buffer[i].priority)
            self._buffer[min_idx] = exp
        else:
            self._buffer.append(exp)

        # Update profiles
        self._update_strategy_profile(exp)
        self._update_target_profile(exp)

        # Track strategy-target reward
        if strategy:
            self._strategy_target_rewards[strategy][target_type].append(reward)
        if tool:
            self._tool_target_rewards[tool][target_type].append(reward)

        # Detect anti-patterns
        if outcome == OutcomeType.FAILURE and reward < -1.0:
            self._anti_patterns.append({
                "action": action,
                "tool": tool,
                "strategy": strategy,
                "target_type": target_type,
                "reward": reward,
            })

        return exp

    def sample_batch(self, batch_size: int = 32) -> list[Experience]:
        """Sample a batch using prioritized replay."""
        if not self._buffer:
            return []

        batch_size = min(batch_size, len(self._buffer))
        total_priority = sum(e.priority for e in self._buffer)

        if total_priority == 0:
            return random.sample(self._buffer, batch_size)

        # Weighted sampling by priority
        weights = [e.priority / total_priority for e in self._buffer]
        indices = []
        for _ in range(batch_size):
            r = random.random()
            cumulative = 0.0
            for i, w in enumerate(weights):
                cumulative += w
                if cumulative >= r:
                    if i not in indices:
                        indices.append(i)
                    break

        batch = [self._buffer[i] for i in indices]

        for exp in batch:
            exp.replay_count += 1

        return batch

    def recommend_strategies(
        self,
        target_type: str,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Recommend strategies for a target type."""
        strategy_scores: dict[str, float] = {}

        for strategy, target_rewards in self._strategy_target_rewards.items():
            rewards = target_rewards.get(target_type, [])
            if rewards:
                avg = sum(rewards) / len(rewards)
                count = len(rewards)
                # UCB1-like score: avg + exploration bonus
                score = avg + math.sqrt(2 * math.log(max(1, self._counter)) / max(1, count))
                strategy_scores[strategy] = score

        sorted_strategies = sorted(strategy_scores.items(), key=lambda x: x[1], reverse=True)

        recommendations = []
        for strategy, score in sorted_strategies[:top_k]:
            profile = self._strategy_profiles.get(strategy)
            recommendations.append({
                "strategy": strategy,
                "score": round(score, 3),
                "success_rate": round(profile.success_rate, 2) if profile else 0.0,
                "avg_reward": round(profile.avg_reward, 2) if profile else 0.0,
                "uses": profile.total_uses if profile else 0,
            })

        return recommendations

    def recommend_tools(
        self,
        target_type: str,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Recommend tools for a target type."""
        tool_scores: dict[str, float] = {}

        for tool, target_rewards in self._tool_target_rewards.items():
            rewards = target_rewards.get(target_type, [])
            if rewards:
                avg = sum(rewards) / len(rewards)
                tool_scores[tool] = avg

        sorted_tools = sorted(tool_scores.items(), key=lambda x: x[1], reverse=True)

        recommendations = []
        for tool, score in sorted_tools[:top_k]:
            recommendations.append({
                "tool": tool,
                "avg_reward": round(score, 2),
            })

        return recommendations

    def get_anti_patterns(
        self,
        target_type: str = "",
    ) -> list[dict[str, Any]]:
        """Get anti-patterns (things that don't work)."""
        if target_type:
            return [
                ap for ap in self._anti_patterns
                if ap.get("target_type") == target_type
            ]
        return list(self._anti_patterns)

    def get_transfer_knowledge(
        self,
        source_target: str,
        dest_target: str,
    ) -> dict[str, Any]:
        """Get transferable knowledge between target types."""
        source_strategies = set()
        dest_strategies = set()

        for strategy, target_rewards in self._strategy_target_rewards.items():
            if source_target in target_rewards:
                source_strategies.add(strategy)
            if dest_target in target_rewards:
                dest_strategies.add(strategy)

        # Strategies that work on source but haven't been tried on dest
        untried = source_strategies - dest_strategies
        # Strategies that work on both
        shared = source_strategies & dest_strategies

        return {
            "untried_strategies": sorted(untried),
            "shared_strategies": sorted(shared),
            "source_best": self.recommend_strategies(source_target, top_k=3),
        }

    def _update_strategy_profile(self, exp: Experience) -> None:
        """Update strategy profile from experience."""
        if not exp.strategy:
            return

        if exp.strategy not in self._strategy_profiles:
            self._strategy_profiles[exp.strategy] = StrategyProfile(strategy=exp.strategy)

        profile = self._strategy_profiles[exp.strategy]
        profile.total_uses += 1
        profile.total_reward += exp.reward
        profile.total_findings += exp.findings_count

        # EMA duration
        if profile.avg_duration_s == 0:
            profile.avg_duration_s = exp.duration_s
        else:
            profile.avg_duration_s = 0.9 * profile.avg_duration_s + 0.1 * exp.duration_s

        if exp.outcome == OutcomeType.SUCCESS:
            profile.successes += 1
        elif exp.outcome == OutcomeType.FAILURE:
            profile.failures += 1

    def _update_target_profile(self, exp: Experience) -> None:
        """Update target profile from experience."""
        if not exp.target_type:
            return

        if exp.target_type not in self._target_profiles:
            self._target_profiles[exp.target_type] = TargetProfile(target_type=exp.target_type)

        profile = self._target_profiles[exp.target_type]
        profile.assessments += 1
        profile.total_findings += exp.findings_count

    def export_experiences(self) -> list[dict[str, Any]]:
        """Export all experiences for persistence."""
        return [exp.to_dict() for exp in self._buffer]

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        outcome_counts: dict[str, int] = defaultdict(int)
        for exp in self._buffer:
            type_counts[exp.exp_type.value] += 1
            outcome_counts[exp.outcome.value] += 1

        return {
            "buffer_size": len(self._buffer),
            "max_buffer": self._buffer_size,
            "total_recorded": self._counter,
            "strategies_profiled": len(self._strategy_profiles),
            "targets_profiled": len(self._target_profiles),
            "anti_patterns": len(self._anti_patterns),
            "by_type": dict(type_counts),
            "by_outcome": dict(outcome_counts),
        }
