"""Experience replay — learn from past assessments.

Implements:
1. Episode recording (actions, observations, rewards)
2. Experience storage and retrieval
3. Strategy effectiveness scoring
4. Tool effectiveness tracking
5. Replay buffer for learning
6. Cross-assessment pattern extraction
7. Adaptive strategy optimization
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
    AGENT_SPAWN = "agent_spawn"
    STRATEGY_CHANGE = "strategy_change"
    FINDING_REPORT = "finding_report"


class Outcome(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class Experience:
    """A single experience tuple (state, action, reward, next_state)."""
    experience_id: str = ""
    target: str = ""
    phase: str = ""
    action_type: ActionType = ActionType.TOOL_CALL
    action: str = ""
    tool: str = ""
    model: str = ""
    outcome: Outcome = Outcome.SUCCESS
    reward: float = 0.0
    findings_produced: int = 0
    tokens_used: int = 0
    time_taken_s: float = 0.0
    context_tags: list[str] = field(default_factory=list)
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
class ToolEffectiveness:
    """Tracked effectiveness of a tool."""
    tool: str = ""
    total_uses: int = 0
    successful_uses: int = 0
    findings_produced: int = 0
    avg_time_s: float = 0.0
    avg_findings_per_use: float = 0.0

    @property
    def success_rate(self) -> float:
        if self.total_uses == 0:
            return 0.0
        return self.successful_uses / self.total_uses

    @property
    def effectiveness_score(self) -> float:
        return self.success_rate * 0.3 + min(1.0, self.avg_findings_per_use / 3) * 0.7

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool[:15],
            "uses": self.total_uses,
            "success_rate": round(self.success_rate, 2),
            "effectiveness": round(self.effectiveness_score, 2),
        }


@dataclass
class StrategyRecord:
    """Record of a strategy's effectiveness."""
    strategy: str = ""
    target_type: str = ""
    total_uses: int = 0
    findings_produced: int = 0
    avg_reward: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy[:20],
            "target": self.target_type[:10],
            "uses": self.total_uses,
            "avg_reward": round(self.avg_reward, 2),
        }


# ── Reward calculation ───────────────────────────────────────

REWARD_TABLE: dict[str, float] = {
    "finding_critical": 10.0,
    "finding_high": 5.0,
    "finding_medium": 2.0,
    "finding_low": 1.0,
    "finding_info": 0.5,
    "new_attack_surface": 3.0,
    "tool_success": 1.0,
    "tool_failure": -0.5,
    "tool_timeout": -1.0,
    "false_positive": -2.0,
    "duplicate_finding": -0.5,
    "coverage_increase": 2.0,
}


class ExperienceReplay:
    """Learns from past assessment experiences.

    Records experiences, tracks tool/strategy
    effectiveness, and provides optimized
    recommendations based on historical data.
    """

    def __init__(self, max_buffer: int = 10_000) -> None:
        self._experiences: list[Experience] = []
        self._tool_stats: dict[str, ToolEffectiveness] = {}
        self._strategy_stats: dict[str, StrategyRecord] = {}
        self._counter = 0
        self._max_buffer = max_buffer
        self._log = logger.bind(component="experience_replay")

    def record(
        self,
        action: str,
        action_type: ActionType = ActionType.TOOL_CALL,
        tool: str = "",
        model: str = "",
        outcome: Outcome = Outcome.SUCCESS,
        findings_produced: int = 0,
        tokens_used: int = 0,
        time_taken_s: float = 0.0,
        target: str = "",
        phase: str = "",
        context_tags: list[str] | None = None,
    ) -> Experience:
        """Record an experience."""
        self._counter += 1

        reward = self._calculate_reward(outcome, findings_produced)

        exp = Experience(
            experience_id=f"exp-{self._counter}",
            target=target,
            phase=phase,
            action_type=action_type,
            action=action,
            tool=tool,
            model=model,
            outcome=outcome,
            reward=reward,
            findings_produced=findings_produced,
            tokens_used=tokens_used,
            time_taken_s=time_taken_s,
            context_tags=context_tags or [],
        )

        self._experiences.append(exp)

        # Trim buffer
        if len(self._experiences) > self._max_buffer:
            self._experiences = self._experiences[-self._max_buffer:]

        # Update tool stats
        if tool:
            self._update_tool_stats(tool, exp)

        return exp

    def _calculate_reward(
        self,
        outcome: Outcome,
        findings: int,
    ) -> float:
        """Calculate reward for an experience."""
        reward = 0.0

        if outcome == Outcome.SUCCESS:
            reward += REWARD_TABLE["tool_success"]
        elif outcome == Outcome.FAILURE:
            reward += REWARD_TABLE["tool_failure"]
        elif outcome == Outcome.TIMEOUT:
            reward += REWARD_TABLE["tool_timeout"]

        reward += findings * REWARD_TABLE["finding_medium"]

        return reward

    def _update_tool_stats(
        self,
        tool: str,
        exp: Experience,
    ) -> None:
        """Update tool effectiveness stats."""
        if tool not in self._tool_stats:
            self._tool_stats[tool] = ToolEffectiveness(tool=tool)

        stats = self._tool_stats[tool]
        stats.total_uses += 1

        if exp.outcome == Outcome.SUCCESS:
            stats.successful_uses += 1

        stats.findings_produced += exp.findings_produced

        # Running average
        total = stats.total_uses
        stats.avg_time_s = (stats.avg_time_s * (total - 1) + exp.time_taken_s) / total
        stats.avg_findings_per_use = stats.findings_produced / total

    def record_strategy(
        self,
        strategy: str,
        target_type: str,
        reward: float,
        findings: int = 0,
    ) -> None:
        """Record strategy effectiveness."""
        key = f"{strategy}:{target_type}"
        if key not in self._strategy_stats:
            self._strategy_stats[key] = StrategyRecord(
                strategy=strategy,
                target_type=target_type,
            )

        record = self._strategy_stats[key]
        record.total_uses += 1
        record.findings_produced += findings
        record.avg_reward = (
            record.avg_reward * (record.total_uses - 1) + reward
        ) / record.total_uses

    def get_best_tools(
        self,
        phase: str = "",
        limit: int = 5,
    ) -> list[ToolEffectiveness]:
        """Get the most effective tools."""
        tools = list(self._tool_stats.values())

        if phase:
            phase_tools = set()
            for exp in self._experiences:
                if exp.phase == phase and exp.tool:
                    phase_tools.add(exp.tool)
            tools = [t for t in tools if t.tool in phase_tools]

        tools.sort(key=lambda t: t.effectiveness_score, reverse=True)
        return tools[:limit]

    def get_best_strategies(
        self,
        target_type: str = "",
        limit: int = 5,
    ) -> list[StrategyRecord]:
        """Get the most effective strategies."""
        records = list(self._strategy_stats.values())

        if target_type:
            records = [r for r in records if r.target_type == target_type]

        records.sort(key=lambda r: r.avg_reward, reverse=True)
        return records[:limit]

    def get_similar_experiences(
        self,
        target_type: str = "",
        phase: str = "",
        tool: str = "",
        limit: int = 10,
    ) -> list[Experience]:
        """Get similar past experiences."""
        matches = []
        for exp in reversed(self._experiences):
            score = 0
            if target_type and target_type in exp.context_tags:
                score += 1
            if phase and exp.phase == phase:
                score += 1
            if tool and exp.tool == tool:
                score += 1

            if score > 0:
                matches.append((score, exp))

        matches.sort(key=lambda x: x[0], reverse=True)
        return [exp for _, exp in matches[:limit]]

    def build_experience_prompt(
        self,
        phase: str = "",
        target_type: str = "",
    ) -> str:
        """Build a prompt from experience data."""
        lines = ["## Past Experience\n"]

        # Best tools
        best_tools = self.get_best_tools(phase=phase, limit=3)
        if best_tools:
            lines.append("### Most Effective Tools")
            for tool in best_tools:
                lines.append(
                    f"- {tool.tool}: {tool.success_rate:.0%} success, "
                    f"{tool.avg_findings_per_use:.1f} findings/use"
                )

        # Best strategies
        best_strats = self.get_best_strategies(target_type=target_type, limit=3)
        if best_strats:
            lines.append("\n### Most Effective Strategies")
            for strat in best_strats:
                lines.append(
                    f"- {strat.strategy}: avg reward {strat.avg_reward:.1f}, "
                    f"{strat.findings_produced} findings"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        outcome_counts: dict[str, int] = defaultdict(int)
        for exp in self._experiences:
            outcome_counts[exp.outcome.value] += 1

        return {
            "total_experiences": len(self._experiences),
            "tools_tracked": len(self._tool_stats),
            "strategies_tracked": len(self._strategy_stats),
            "total_reward": round(sum(e.reward for e in self._experiences), 1),
            "by_outcome": dict(outcome_counts),
        }
