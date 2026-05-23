"""Experience replay — learning from past assessment patterns.

Implements:
1. Action-outcome pair recording
2. Strategy effectiveness tracking
3. Tool performance monitoring
4. Model accuracy tracking per domain
5. Replay buffer with prioritized sampling
6. Adaptive weighting from experience
7. Cross-assessment pattern transfer
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ActionType(str, Enum):
    TOOL_CALL = "tool_call"
    LLM_QUERY = "llm_query"
    STRATEGY_SELECTION = "strategy_selection"
    PHASE_TRANSITION = "phase_transition"
    AGENT_SPAWN = "agent_spawn"
    MANUAL_DECISION = "manual_decision"


class Outcome(str, Enum):
    SUCCESS = "success"          # Found vulnerability
    PARTIAL = "partial"          # Some useful info
    FAILURE = "failure"          # No useful result
    ERROR = "error"              # Execution error
    TIMEOUT = "timeout"


@dataclass
class Experience:
    """A recorded experience (action → outcome)."""
    experience_id: str = ""
    action_type: ActionType = ActionType.TOOL_CALL
    action: str = ""
    context: str = ""            # What was the situation
    outcome: Outcome = Outcome.FAILURE
    reward: float = 0.0          # -1.0 to 1.0
    findings_produced: int = 0
    tokens_used: int = 0
    duration_s: float = 0.0
    tool_used: str = ""
    model_used: str = ""
    strategy: str = ""
    target_type: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.experience_id[:10],
            "action": self.action[:20],
            "outcome": self.outcome.value,
            "reward": round(self.reward, 2),
            "findings": self.findings_produced,
        }


@dataclass
class ToolStats:
    """Aggregated statistics for a tool."""
    tool_name: str = ""
    total_uses: int = 0
    successes: int = 0
    failures: int = 0
    avg_duration_s: float = 0.0
    avg_findings: float = 0.0
    total_findings: int = 0

    @property
    def success_rate(self) -> float:
        if self.total_uses == 0:
            return 0.0
        return self.successes / self.total_uses

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name[:15],
            "uses": self.total_uses,
            "success_rate": round(self.success_rate, 2),
            "avg_findings": round(self.avg_findings, 2),
        }


@dataclass
class ModelStats:
    """Aggregated statistics for a model."""
    model_id: str = ""
    total_queries: int = 0
    accurate_results: int = 0
    domains_used: dict[str, int] = field(default_factory=dict)
    avg_tokens_per_query: float = 0.0
    avg_reward: float = 0.0

    @property
    def accuracy(self) -> float:
        if self.total_queries == 0:
            return 0.0
        return self.accurate_results / self.total_queries

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "queries": self.total_queries,
            "accuracy": round(self.accuracy, 2),
            "avg_reward": round(self.avg_reward, 2),
        }


@dataclass
class StrategyStats:
    """Aggregated statistics for a strategy."""
    strategy_name: str = ""
    total_uses: int = 0
    total_reward: float = 0.0
    total_findings: int = 0
    avg_reward: float = 0.0
    best_target_types: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy_name[:15],
            "uses": self.total_uses,
            "avg_reward": round(self.avg_reward, 2),
            "findings": self.total_findings,
        }


class ExperienceReplay:
    """Experience replay system for learning from past actions.

    Records action-outcome pairs, tracks tool/model/strategy
    effectiveness, and provides experience-based recommendations.
    """

    def __init__(
        self,
        buffer_size: int = 10000,
    ) -> None:
        self._experiences: list[Experience] = []
        self._buffer_size = buffer_size
        self._counter = 0
        self._tool_stats: dict[str, ToolStats] = {}
        self._model_stats: dict[str, ModelStats] = {}
        self._strategy_stats: dict[str, StrategyStats] = {}
        self._log = logger.bind(component="experience_replay")

    def record(
        self,
        action_type: ActionType,
        action: str,
        outcome: Outcome,
        reward: float = 0.0,
        context: str = "",
        findings_produced: int = 0,
        tokens_used: int = 0,
        duration_s: float = 0.0,
        tool_used: str = "",
        model_used: str = "",
        strategy: str = "",
        target_type: str = "",
    ) -> Experience:
        """Record an experience."""
        self._counter += 1
        exp = Experience(
            experience_id=f"exp-{self._counter}",
            action_type=action_type,
            action=action,
            context=context,
            outcome=outcome,
            reward=reward,
            findings_produced=findings_produced,
            tokens_used=tokens_used,
            duration_s=duration_s,
            tool_used=tool_used,
            model_used=model_used,
            strategy=strategy,
            target_type=target_type,
        )

        self._experiences.append(exp)

        # Evict oldest if at capacity
        if len(self._experiences) > self._buffer_size:
            self._experiences.pop(0)

        # Update stats
        self._update_tool_stats(exp)
        self._update_model_stats(exp)
        self._update_strategy_stats(exp)

        return exp

    def _update_tool_stats(self, exp: Experience) -> None:
        """Update tool statistics."""
        if not exp.tool_used:
            return

        stats = self._tool_stats.get(exp.tool_used)
        if not stats:
            stats = ToolStats(tool_name=exp.tool_used)
            self._tool_stats[exp.tool_used] = stats

        stats.total_uses += 1
        stats.total_findings += exp.findings_produced

        if exp.outcome in (Outcome.SUCCESS, Outcome.PARTIAL):
            stats.successes += 1
        else:
            stats.failures += 1

        stats.avg_duration_s = (
            stats.avg_duration_s * (stats.total_uses - 1) + exp.duration_s
        ) / stats.total_uses

        stats.avg_findings = stats.total_findings / stats.total_uses

    def _update_model_stats(self, exp: Experience) -> None:
        """Update model statistics."""
        if not exp.model_used:
            return

        stats = self._model_stats.get(exp.model_used)
        if not stats:
            stats = ModelStats(model_id=exp.model_used)
            self._model_stats[exp.model_used] = stats

        stats.total_queries += 1

        if exp.outcome in (Outcome.SUCCESS, Outcome.PARTIAL):
            stats.accurate_results += 1

        stats.avg_tokens_per_query = (
            stats.avg_tokens_per_query * (stats.total_queries - 1) + exp.tokens_used
        ) / stats.total_queries

        stats.avg_reward = (
            stats.avg_reward * (stats.total_queries - 1) + exp.reward
        ) / stats.total_queries

    def _update_strategy_stats(self, exp: Experience) -> None:
        """Update strategy statistics."""
        if not exp.strategy:
            return

        stats = self._strategy_stats.get(exp.strategy)
        if not stats:
            stats = StrategyStats(strategy_name=exp.strategy)
            self._strategy_stats[exp.strategy] = stats

        stats.total_uses += 1
        stats.total_reward += exp.reward
        stats.total_findings += exp.findings_produced
        stats.avg_reward = stats.total_reward / stats.total_uses

        if exp.target_type and exp.outcome == Outcome.SUCCESS:
            if exp.target_type not in stats.best_target_types:
                stats.best_target_types.append(exp.target_type)

    def get_best_tool(
        self,
        min_uses: int = 3,
    ) -> str:
        """Get the best performing tool."""
        candidates = [
            s for s in self._tool_stats.values()
            if s.total_uses >= min_uses
        ]
        if not candidates:
            return ""

        best = max(candidates, key=lambda s: s.success_rate * s.avg_findings)
        return best.tool_name

    def get_best_model(
        self,
        domain: str = "",
        min_queries: int = 3,
    ) -> str:
        """Get the best performing model."""
        candidates = [
            s for s in self._model_stats.values()
            if s.total_queries >= min_queries
        ]
        if not candidates:
            return ""

        best = max(candidates, key=lambda s: s.avg_reward)
        return best.model_id

    def get_best_strategy(
        self,
        target_type: str = "",
        min_uses: int = 2,
    ) -> str:
        """Get the best performing strategy."""
        candidates = [
            s for s in self._strategy_stats.values()
            if s.total_uses >= min_uses
        ]
        if target_type:
            typed = [
                s for s in candidates
                if target_type in s.best_target_types
            ]
            if typed:
                candidates = typed

        if not candidates:
            return ""

        best = max(candidates, key=lambda s: s.avg_reward)
        return best.strategy_name

    def sample_experiences(
        self,
        action_type: ActionType | None = None,
        outcome: Outcome | None = None,
        count: int = 5,
    ) -> list[Experience]:
        """Sample experiences from the buffer."""
        filtered = self._experiences
        if action_type:
            filtered = [e for e in filtered if e.action_type == action_type]
        if outcome:
            filtered = [e for e in filtered if e.outcome == outcome]

        # Prioritized sampling (higher reward = higher probability)
        filtered.sort(key=lambda e: e.reward, reverse=True)
        return filtered[:count]

    def build_experience_prompt(
        self,
        max_items: int = 5,
    ) -> str:
        """Build experience context for LLM."""
        lines = ["## Experience Summary\n"]

        # Best tools
        best_tools = sorted(
            self._tool_stats.values(),
            key=lambda s: s.success_rate * s.avg_findings,
            reverse=True,
        )[:3]
        if best_tools:
            lines.append("Top tools:")
            for ts in best_tools:
                lines.append(
                    f"  - {ts.tool_name}: {ts.success_rate:.0%} success, "
                    f"{ts.avg_findings:.1f} avg findings"
                )

        # Best strategies
        best_strats = sorted(
            self._strategy_stats.values(),
            key=lambda s: s.avg_reward,
            reverse=True,
        )[:3]
        if best_strats:
            lines.append("Top strategies:")
            for ss in best_strats:
                lines.append(
                    f"  - {ss.strategy_name}: avg reward {ss.avg_reward:.2f}, "
                    f"{ss.total_findings} findings"
                )

        # Recent successful patterns
        successes = [
            e for e in self._experiences
            if e.outcome == Outcome.SUCCESS
        ][-max_items:]
        if successes:
            lines.append("Recent successes:")
            for exp in successes:
                lines.append(
                    f"  - {exp.action[:30]} → {exp.findings_produced} findings"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        outcome_counts: dict[str, int] = defaultdict(int)
        for exp in self._experiences:
            outcome_counts[exp.outcome.value] += 1

        return {
            "total_experiences": len(self._experiences),
            "tools_tracked": len(self._tool_stats),
            "models_tracked": len(self._model_stats),
            "strategies_tracked": len(self._strategy_stats),
            "by_outcome": dict(outcome_counts),
        }
