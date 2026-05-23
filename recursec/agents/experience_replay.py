"""Experience replay — learning from past assessment outcomes.

Implements:
1. Experience recording (state/action/reward tuples)
2. Outcome-based learning (what worked, what didn't)
3. Strategy effectiveness tracking
4. Tool success rate analysis
5. Similar-situation retrieval
6. Reward shaping for agent behavior
7. Experience summarization for LLM context
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ExperienceOutcome(str, Enum):
    SUCCESS = "success"         # Found a real vulnerability
    PARTIAL = "partial"         # Found something interesting
    FAILURE = "failure"         # No results or false positive
    ERROR = "error"            # Tool/agent error
    TIMEOUT = "timeout"        # Timed out before completion


class ExperienceCategory(str, Enum):
    TOOL_USE = "tool_use"
    STRATEGY = "strategy"
    MODEL_SELECTION = "model_selection"
    TASK_DECOMPOSITION = "task_decomposition"
    FINDING_VALIDATION = "finding_validation"
    TARGET_ANALYSIS = "target_analysis"


@dataclass
class Experience:
    """A recorded experience (state-action-outcome)."""
    experience_id: str = ""
    category: ExperienceCategory = ExperienceCategory.TOOL_USE
    outcome: ExperienceOutcome = ExperienceOutcome.FAILURE

    # State: What was the situation?
    target_type: str = ""      # web, network, host, api, etc.
    service_type: str = ""     # http, ssh, ftp, etc.
    tech_stack: str = ""       # nginx, apache, nodejs, etc.

    # Action: What was tried?
    strategy: str = ""
    tool_used: str = ""
    model_used: str = ""
    action_description: str = ""

    # Outcome: What happened?
    reward: float = 0.0        # -1 to 1
    findings_count: int = 0
    tokens_used: int = 0
    duration_s: float = 0.0
    lesson: str = ""           # What was learned

    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.experience_id[:10],
            "category": self.category.value,
            "outcome": self.outcome.value,
            "reward": round(self.reward, 2),
            "tool": self.tool_used[:12],
            "target": self.target_type[:10],
        }


# ── Reward shaping ───────────────────────────────────────────

OUTCOME_REWARDS: dict[str, float] = {
    "success": 1.0,
    "partial": 0.3,
    "failure": -0.2,
    "error": -0.5,
    "timeout": -0.3,
}


class ExperienceReplay:
    """Experience replay buffer for agent learning.

    Records agent experiences (state-action-outcome)
    and provides retrieval of relevant past experiences
    to inform future decisions.
    """

    def __init__(self, max_experiences: int = 5000) -> None:
        self._experiences: list[Experience] = []
        self._max_size = max_experiences
        self._counter = 0

        # Aggregated statistics
        self._tool_stats: dict[str, dict[str, int]] = {}    # tool → {success, fail, total}
        self._strategy_stats: dict[str, dict[str, int]] = {}  # strategy → {success, fail, total}
        self._model_stats: dict[str, dict[str, int]] = {}    # model → {success, fail, total}

        self._log = logger.bind(component="experience_replay")

    def record(
        self,
        category: ExperienceCategory,
        outcome: ExperienceOutcome,
        target_type: str = "",
        service_type: str = "",
        tech_stack: str = "",
        strategy: str = "",
        tool_used: str = "",
        model_used: str = "",
        action_description: str = "",
        findings_count: int = 0,
        tokens_used: int = 0,
        duration_s: float = 0.0,
        lesson: str = "",
    ) -> Experience:
        """Record a new experience."""
        self._counter += 1
        reward = OUTCOME_REWARDS.get(outcome.value, 0.0)

        exp = Experience(
            experience_id=f"exp-{self._counter}",
            category=category,
            outcome=outcome,
            target_type=target_type,
            service_type=service_type,
            tech_stack=tech_stack,
            strategy=strategy,
            tool_used=tool_used,
            model_used=model_used,
            action_description=action_description,
            reward=reward,
            findings_count=findings_count,
            tokens_used=tokens_used,
            duration_s=duration_s,
            lesson=lesson,
        )

        self._experiences.append(exp)

        # Update aggregated stats
        if tool_used:
            self._update_stats(self._tool_stats, tool_used, outcome)
        if strategy:
            self._update_stats(self._strategy_stats, strategy, outcome)
        if model_used:
            self._update_stats(self._model_stats, model_used, outcome)

        # Evict oldest if full
        while len(self._experiences) > self._max_size:
            self._experiences.pop(0)

        return exp

    def find_similar(
        self,
        target_type: str = "",
        service_type: str = "",
        tech_stack: str = "",
        max_results: int = 5,
    ) -> list[Experience]:
        """Find experiences from similar situations."""
        scored: list[tuple[float, Experience]] = []

        for exp in self._experiences:
            score = 0.0
            if target_type and exp.target_type == target_type:
                score += 1.0
            if service_type and exp.service_type == service_type:
                score += 1.0
            if tech_stack and exp.tech_stack == tech_stack:
                score += 1.5
            if score > 0:
                scored.append((score, exp))

        scored.sort(key=lambda x: (x[0], x[1].reward), reverse=True)
        return [exp for _, exp in scored[:max_results]]

    def get_tool_success_rate(self, tool_name: str) -> float:
        """Get success rate for a tool."""
        stats = self._tool_stats.get(tool_name, {})
        total = stats.get("total", 0)
        if total == 0:
            return 0.5  # Unknown, assume neutral
        success = stats.get("success", 0) + stats.get("partial", 0) * 0.5
        return success / total

    def get_best_strategy(self, target_type: str = "") -> str:
        """Get the best-performing strategy."""
        candidates: dict[str, float] = {}
        for exp in self._experiences:
            if target_type and exp.target_type != target_type:
                continue
            if not exp.strategy:
                continue
            candidates.setdefault(exp.strategy, 0.0)
            candidates[exp.strategy] += exp.reward

        if not candidates:
            return ""
        return max(candidates, key=lambda k: candidates[k])

    def get_best_model(self, category: str = "default") -> str:
        """Get the best-performing model for a task category."""
        candidates: dict[str, float] = {}
        for exp in self._experiences:
            if not exp.model_used:
                continue
            candidates.setdefault(exp.model_used, 0.0)
            candidates[exp.model_used] += exp.reward

        if not candidates:
            return ""
        return max(candidates, key=lambda k: candidates[k])

    def build_experience_prompt(
        self,
        target_type: str = "",
        max_experiences: int = 5,
    ) -> str:
        """Build experience context for LLM."""
        lines = ["## Past Experience\n"]

        # Similar experiences
        similar = self.find_similar(target_type=target_type, max_results=max_experiences)
        if similar:
            lines.append("Relevant past experiences:")
            for exp in similar:
                outcome_icon = {
                    "success": "[+]", "partial": "[~]",
                    "failure": "[-]", "error": "[!]", "timeout": "[T]",
                }.get(exp.outcome.value, "[ ]")
                lines.append(
                    f"  {outcome_icon} {exp.strategy[:15]} + {exp.tool_used[:10]} "
                    f"on {exp.target_type}/{exp.service_type} → "
                    f"reward={exp.reward:.1f}"
                )
                if exp.lesson:
                    lines.append(f"    Lesson: {exp.lesson[:40]}")

        # Tool effectiveness
        tool_rates: list[tuple[str, float]] = []
        for tool, stats in self._tool_stats.items():
            total = stats.get("total", 0)
            if total >= 3:
                rate = self.get_tool_success_rate(tool)
                tool_rates.append((tool, rate))

        if tool_rates:
            tool_rates.sort(key=lambda x: x[1], reverse=True)
            lines.append("\nTool effectiveness (3+ uses):")
            for tool, rate in tool_rates[:5]:
                lines.append(f"  {tool}: {rate:.0%} success")

        # Best strategy
        best = self.get_best_strategy(target_type)
        if best:
            lines.append(f"\nBest strategy for {target_type or 'general'}: {best}")

        return "\n".join(lines)

    def _update_stats(
        self,
        stats_dict: dict[str, dict[str, int]],
        key: str,
        outcome: ExperienceOutcome,
    ) -> None:
        """Update aggregated statistics."""
        if key not in stats_dict:
            stats_dict[key] = {"success": 0, "partial": 0, "failure": 0, "error": 0, "timeout": 0, "total": 0}
        stats_dict[key][outcome.value] = stats_dict[key].get(outcome.value, 0) + 1
        stats_dict[key]["total"] += 1

    def get_stats(self) -> dict[str, Any]:
        outcome_counts: dict[str, int] = {}
        for exp in self._experiences:
            outcome_counts[exp.outcome.value] = outcome_counts.get(exp.outcome.value, 0) + 1

        return {
            "total_experiences": len(self._experiences),
            "by_outcome": outcome_counts,
            "unique_tools": len(self._tool_stats),
            "unique_strategies": len(self._strategy_stats),
            "avg_reward": (
                sum(e.reward for e in self._experiences) / len(self._experiences)
                if self._experiences else 0
            ),
        }
