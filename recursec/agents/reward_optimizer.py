"""Reward optimizer — reward signal design for bandit/RL components.

Implements:
1. Multi-objective reward computation
2. Reward shaping for exploration vs exploitation
3. Novelty bonus for discovering new vulnerability classes
4. Severity-weighted rewards
5. Time-decay rewards (faster is better)
6. Cross-validation bonus (confirmed by multiple tools)
7. Reward normalization and scaling
8. Reward history and trend analysis
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class RewardComponent(str, Enum):
    SEVERITY = "severity"                # Higher severity → higher reward
    NOVELTY = "novelty"                  # New vuln class → bonus
    CONFIDENCE = "confidence"            # Higher confidence → higher reward
    SPEED = "speed"                      # Faster discovery → bonus
    COVERAGE = "coverage"                # New coverage area → bonus
    CROSS_VALIDATION = "cross_validation"  # Multi-tool confirmation → bonus
    EXPLOIT_SUCCESS = "exploit_success"    # Successful exploitation → big bonus
    FALSE_POSITIVE = "false_positive"      # FP penalty


class RewardSignalType(str, Enum):
    FINDING = "finding"              # Discovered a vulnerability
    TOOL_SUCCESS = "tool_success"    # Tool ran successfully
    TOOL_FAILURE = "tool_failure"    # Tool failed
    STRATEGY_SUCCESS = "strategy_success"
    STRATEGY_FAILURE = "strategy_failure"
    PHASE_COMPLETE = "phase_complete"
    STAGNATION = "stagnation"


@dataclass
class RewardSignal:
    """A reward signal from an action."""
    signal_id: str = ""
    signal_type: RewardSignalType = RewardSignalType.FINDING
    raw_reward: float = 0.0
    shaped_reward: float = 0.0
    components: dict[str, float] = field(default_factory=dict)
    action: str = ""
    strategy: str = ""
    tool: str = ""
    model: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.signal_id[:10],
            "type": self.signal_type.value,
            "raw": round(self.raw_reward, 3),
            "shaped": round(self.shaped_reward, 3),
            "action": self.action[:20],
        }


@dataclass
class RewardConfig:
    """Configuration for reward computation."""
    # Severity weights
    severity_weights: dict[str, float] = field(default_factory=lambda: {
        "critical": 10.0,
        "high": 5.0,
        "medium": 2.0,
        "low": 0.5,
        "info": 0.1,
    })

    # Component weights (sum to 1.0)
    component_weights: dict[str, float] = field(default_factory=lambda: {
        "severity": 0.30,
        "novelty": 0.15,
        "confidence": 0.15,
        "speed": 0.10,
        "coverage": 0.10,
        "cross_validation": 0.10,
        "exploit_success": 0.10,
    })

    # Bonuses
    novelty_bonus: float = 2.0
    cross_validation_bonus: float = 1.5
    exploit_success_bonus: float = 5.0
    phase_complete_bonus: float = 1.0

    # Penalties
    false_positive_penalty: float = -3.0
    stagnation_penalty: float = -0.5
    tool_failure_penalty: float = -0.2
    timeout_penalty: float = -0.3

    # Time decay (rewards decrease with time)
    time_decay_factor: float = 0.001  # per second

    # Exploration bonus
    exploration_weight: float = 0.1


class RewardOptimizer:
    """Computes and optimizes reward signals for agent learning.

    Produces reward signals that guide the multi-armed bandit
    (UCB1) strategy selector and experience replay system.
    """

    def __init__(self, config: RewardConfig | None = None) -> None:
        self._config = config or RewardConfig()
        self._signals: list[RewardSignal] = []
        self._signal_counter = 0
        self._seen_vuln_classes: set[str] = set()
        self._seen_targets: set[str] = set()
        self._strategy_rewards: dict[str, list[float]] = defaultdict(list)
        self._tool_rewards: dict[str, list[float]] = defaultdict(list)
        self._model_rewards: dict[str, list[float]] = defaultdict(list)
        self._start_time = time.time()
        self._log = logger.bind(component="reward_optimizer")

    def compute_finding_reward(
        self,
        severity: str = "medium",
        confidence: float = 0.5,
        vuln_class: str = "",
        target: str = "",
        tool: str = "",
        strategy: str = "",
        model: str = "",
        cross_validated: bool = False,
        exploit_confirmed: bool = False,
        time_elapsed_s: float = 0.0,
    ) -> RewardSignal:
        """Compute reward for discovering a finding."""
        self._signal_counter += 1
        components: dict[str, float] = {}

        # 1. Severity component
        sev_weight = self._config.severity_weights.get(severity.lower(), 1.0)
        components["severity"] = sev_weight

        # 2. Novelty component
        is_novel = vuln_class and vuln_class not in self._seen_vuln_classes
        if is_novel:
            components["novelty"] = self._config.novelty_bonus
            self._seen_vuln_classes.add(vuln_class)
        else:
            components["novelty"] = 0.0

        # 3. Confidence component
        components["confidence"] = confidence * 3.0

        # 4. Speed component (faster → higher)
        if time_elapsed_s > 0:
            speed_factor = max(0.1, 1.0 - self._config.time_decay_factor * time_elapsed_s)
            components["speed"] = speed_factor * 2.0
        else:
            components["speed"] = 2.0

        # 5. Coverage component
        is_new_target = target and target not in self._seen_targets
        if is_new_target:
            components["coverage"] = 1.5
            self._seen_targets.add(target)
        else:
            components["coverage"] = 0.0

        # 6. Cross-validation component
        if cross_validated:
            components["cross_validation"] = self._config.cross_validation_bonus
        else:
            components["cross_validation"] = 0.0

        # 7. Exploit success component
        if exploit_confirmed:
            components["exploit_success"] = self._config.exploit_success_bonus
        else:
            components["exploit_success"] = 0.0

        # Compute weighted sum
        raw_reward = 0.0
        for comp_name, comp_value in components.items():
            weight = self._config.component_weights.get(comp_name, 0.1)
            raw_reward += weight * comp_value

        # Shape reward (add exploration bonus)
        shaped_reward = raw_reward
        shaped_reward += self._exploration_bonus(strategy)

        signal = RewardSignal(
            signal_id=f"rwd-{self._signal_counter}",
            signal_type=RewardSignalType.FINDING,
            raw_reward=raw_reward,
            shaped_reward=shaped_reward,
            components=components,
            action="finding_discovered",
            strategy=strategy,
            tool=tool,
            model=model,
        )

        self._record_signal(signal)
        return signal

    def compute_tool_reward(
        self,
        tool: str,
        success: bool,
        findings_count: int = 0,
        duration_s: float = 0.0,
        strategy: str = "",
    ) -> RewardSignal:
        """Compute reward for a tool execution."""
        self._signal_counter += 1

        if success:
            raw_reward = 0.5 + findings_count * 0.3
            if duration_s > 0:
                speed_bonus = max(0, 1.0 - duration_s / 300.0)
                raw_reward += speed_bonus * 0.2
            signal_type = RewardSignalType.TOOL_SUCCESS
        else:
            raw_reward = self._config.tool_failure_penalty
            signal_type = RewardSignalType.TOOL_FAILURE

        signal = RewardSignal(
            signal_id=f"rwd-{self._signal_counter}",
            signal_type=signal_type,
            raw_reward=raw_reward,
            shaped_reward=raw_reward,
            action=f"tool_{tool}",
            tool=tool,
            strategy=strategy,
        )

        self._record_signal(signal)
        return signal

    def compute_strategy_reward(
        self,
        strategy: str,
        findings_count: int = 0,
        critical_count: int = 0,
        novel_count: int = 0,
        time_spent_s: float = 0.0,
    ) -> RewardSignal:
        """Compute reward for a strategy execution."""
        self._signal_counter += 1

        raw_reward = (
            findings_count * 1.0
            + critical_count * 3.0
            + novel_count * 2.0
        )

        # Penalize slow strategies
        if time_spent_s > 300:
            raw_reward *= max(0.3, 1.0 - (time_spent_s - 300) / 600)

        signal_type = (
            RewardSignalType.STRATEGY_SUCCESS
            if findings_count > 0
            else RewardSignalType.STRATEGY_FAILURE
        )

        signal = RewardSignal(
            signal_id=f"rwd-{self._signal_counter}",
            signal_type=signal_type,
            raw_reward=raw_reward,
            shaped_reward=raw_reward + self._exploration_bonus(strategy),
            action=f"strategy_{strategy}",
            strategy=strategy,
        )

        self._record_signal(signal)
        return signal

    def compute_penalty(
        self,
        penalty_type: str,
        tool: str = "",
        strategy: str = "",
    ) -> RewardSignal:
        """Compute a penalty signal."""
        self._signal_counter += 1

        penalties = {
            "false_positive": self._config.false_positive_penalty,
            "stagnation": self._config.stagnation_penalty,
            "timeout": self._config.timeout_penalty,
            "tool_failure": self._config.tool_failure_penalty,
        }

        raw_reward = penalties.get(penalty_type, -0.5)

        signal = RewardSignal(
            signal_id=f"rwd-{self._signal_counter}",
            signal_type=RewardSignalType.STAGNATION,
            raw_reward=raw_reward,
            shaped_reward=raw_reward,
            action=f"penalty_{penalty_type}",
            tool=tool,
            strategy=strategy,
        )

        self._record_signal(signal)
        return signal

    def _exploration_bonus(self, strategy: str) -> float:
        """Compute exploration bonus for under-explored strategies."""
        if not strategy:
            return 0.0

        history = self._strategy_rewards.get(strategy, [])
        if len(history) < 3:
            return self._config.exploration_weight * 2.0
        if len(history) < 10:
            return self._config.exploration_weight
        return 0.0

    def _record_signal(self, signal: RewardSignal) -> None:
        """Record a reward signal for analysis."""
        self._signals.append(signal)

        if signal.strategy:
            self._strategy_rewards[signal.strategy].append(signal.shaped_reward)
        if signal.tool:
            self._tool_rewards[signal.tool].append(signal.shaped_reward)
        if signal.model:
            self._model_rewards[signal.model].append(signal.shaped_reward)

    def get_strategy_scores(self) -> dict[str, float]:
        """Get average reward per strategy."""
        scores: dict[str, float] = {}
        for strategy, rewards in self._strategy_rewards.items():
            if rewards:
                scores[strategy] = sum(rewards) / len(rewards)
        return scores

    def get_tool_scores(self) -> dict[str, float]:
        """Get average reward per tool."""
        scores: dict[str, float] = {}
        for tool, rewards in self._tool_rewards.items():
            if rewards:
                scores[tool] = sum(rewards) / len(rewards)
        return scores

    def get_model_scores(self) -> dict[str, float]:
        """Get average reward per model."""
        scores: dict[str, float] = {}
        for model, rewards in self._model_rewards.items():
            if rewards:
                scores[model] = sum(rewards) / len(rewards)
        return scores

    def get_best_strategy(self) -> str:
        """Get the highest-scoring strategy."""
        scores = self.get_strategy_scores()
        if not scores:
            return ""
        return max(scores, key=lambda k: scores[k])

    def normalize_rewards(self) -> None:
        """Normalize all rewards to [0, 1] range."""
        if not self._signals:
            return

        rewards = [s.raw_reward for s in self._signals]
        min_r = min(rewards)
        max_r = max(rewards)
        range_r = max_r - min_r

        if range_r == 0:
            return

        for signal in self._signals:
            signal.shaped_reward = (signal.raw_reward - min_r) / range_r

    def get_reward_trend(self, window: int = 20) -> float:
        """Get reward trend (positive = improving)."""
        if len(self._signals) < 4:
            return 0.0

        recent = self._signals[-window:]
        n = len(recent)
        mid = n // 2

        first_half = sum(s.shaped_reward for s in recent[:mid]) / max(1, mid)
        second_half = sum(s.shaped_reward for s in recent[mid:]) / max(1, n - mid)

        return second_half - first_half

    def get_stats(self) -> dict[str, Any]:
        total_reward = sum(s.shaped_reward for s in self._signals)
        type_counts: dict[str, int] = defaultdict(int)
        for s in self._signals:
            type_counts[s.signal_type.value] += 1

        return {
            "signals": len(self._signals),
            "total_reward": round(total_reward, 2),
            "avg_reward": round(total_reward / max(1, len(self._signals)), 3),
            "trend": round(self.get_reward_trend(), 3),
            "unique_vulns": len(self._seen_vuln_classes),
            "unique_targets": len(self._seen_targets),
            "strategies_scored": len(self._strategy_rewards),
            "tools_scored": len(self._tool_rewards),
            "by_type": dict(type_counts),
        }
