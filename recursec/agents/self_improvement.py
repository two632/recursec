"""Self-improvement engine — agents that get better over time.

Implements continuous improvement through:
1. Performance tracking (per-task success rates)
2. Skill acquisition (learn new patterns from successes)
3. Strategy refinement (adjust weights based on outcomes)
4. Prompt optimization (evolve prompts that produce better results)
5. Tool proficiency (learn which tools work best for what)
6. Error pattern recognition (avoid repeating mistakes)
7. Meta-learning (learn how to learn faster)

The self-improvement engine observes agent behavior over time
and makes systematic adjustments to improve future performance.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class PerformanceMetric:
    """Performance metric for a specific skill/strategy."""
    metric_id: str = ""
    name: str = ""
    category: str = ""
    total_attempts: int = 0
    successes: int = 0
    failures: int = 0
    avg_quality: float = 0.0
    avg_time_s: float = 0.0
    avg_tokens: int = 0
    trend: str = "stable"  # improving, degrading, stable
    history: list[float] = field(default_factory=list)  # Recent quality scores

    @property
    def success_rate(self) -> float:
        return self.successes / max(1, self.total_attempts)

    def record(self, success: bool, quality: float = 0.5, time_s: float = 0.0, tokens: int = 0) -> None:
        self.total_attempts += 1
        if success:
            self.successes += 1
        else:
            self.failures += 1

        # Running average
        n = self.total_attempts
        self.avg_quality = (self.avg_quality * (n - 1) + quality) / n
        self.avg_time_s = (self.avg_time_s * (n - 1) + time_s) / n
        self.avg_tokens = int((self.avg_tokens * (n - 1) + tokens) / n)

        # Track trend
        self.history.append(quality)
        if len(self.history) > 20:
            self.history = self.history[-20:]

        if len(self.history) >= 5:
            recent_avg = sum(self.history[-5:]) / 5
            older_avg = sum(self.history[:5]) / 5
            if recent_avg > older_avg + 0.05:
                self.trend = "improving"
            elif recent_avg < older_avg - 0.05:
                self.trend = "degrading"
            else:
                self.trend = "stable"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "category": self.category,
            "attempts": self.total_attempts,
            "success_rate": round(self.success_rate, 3),
            "avg_quality": round(self.avg_quality, 3),
            "avg_time_s": round(self.avg_time_s, 1),
            "trend": self.trend,
        }


@dataclass
class LearnedSkill:
    """A skill the agent has learned from experience."""
    skill_id: str = ""
    name: str = ""
    description: str = ""
    trigger_pattern: str = ""  # When to apply this skill
    action_sequence: list[str] = field(default_factory=list)  # Steps to execute
    success_rate: float = 0.5
    times_applied: int = 0
    times_successful: int = 0
    source: str = ""  # How this skill was learned
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.skill_id:
            self.skill_id = hashlib.md5(self.name.encode()).hexdigest()[:8]

    def apply(self, success: bool) -> None:
        self.times_applied += 1
        if success:
            self.times_successful += 1
        self.success_rate = self.times_successful / max(1, self.times_applied)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.skill_id, "name": self.name,
            "trigger": self.trigger_pattern[:100],
            "success_rate": round(self.success_rate, 3),
            "times_applied": self.times_applied,
        }


@dataclass
class ErrorPattern:
    """A recognized error pattern to avoid."""
    pattern_id: str = ""
    description: str = ""
    trigger_conditions: list[str] = field(default_factory=list)
    error_type: str = ""
    avoidance_strategy: str = ""
    occurrences: int = 0
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id, "description": self.description[:200],
            "error_type": self.error_type,
            "avoidance": self.avoidance_strategy[:200],
            "occurrences": self.occurrences,
        }


@dataclass
class StrategyWeight:
    """Weighted strategy selection."""
    strategy_name: str = ""
    weight: float = 1.0
    successes: int = 0
    failures: int = 0
    avg_quality: float = 0.5

    def update(self, success: bool, quality: float = 0.5) -> None:
        if success:
            self.successes += 1
            self.weight = min(3.0, self.weight * 1.05)
        else:
            self.failures += 1
            self.weight = max(0.1, self.weight * 0.95)
        total = self.successes + self.failures
        self.avg_quality = (self.avg_quality * (total - 1) + quality) / total


class SelfImprovementEngine:
    """Continuous improvement engine for agent performance.

    Tracks performance, learns skills, and adjusts strategies
    to systematically improve over time.
    """

    def __init__(self, storage_dir: str = "data/improvement") -> None:
        self._storage_dir = Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)

        self._metrics: dict[str, PerformanceMetric] = {}
        self._skills: dict[str, LearnedSkill] = {}
        self._error_patterns: dict[str, ErrorPattern] = {}
        self._strategy_weights: dict[str, StrategyWeight] = {}
        self._improvement_log: list[dict[str, Any]] = []

        self._log = logger.bind(component="self_improvement")
        self._load()

    # ── Performance Tracking ─────────────────────────────

    def record_performance(
        self,
        task_type: str,
        success: bool,
        quality: float = 0.5,
        time_s: float = 0.0,
        tokens: int = 0,
        strategy: str = "",
    ) -> None:
        """Record performance data for a completed task."""
        # Update task-level metrics
        if task_type not in self._metrics:
            self._metrics[task_type] = PerformanceMetric(
                metric_id=task_type, name=task_type, category="task",
            )
        self._metrics[task_type].record(success, quality, time_s, tokens)

        # Update strategy weights
        if strategy:
            if strategy not in self._strategy_weights:
                self._strategy_weights[strategy] = StrategyWeight(strategy_name=strategy)
            self._strategy_weights[strategy].update(success, quality)

        # Log improvement data
        self._improvement_log.append({
            "task_type": task_type, "success": success,
            "quality": quality, "time_s": time_s,
            "strategy": strategy, "timestamp": time.time(),
        })

        # Trim log
        if len(self._improvement_log) > 1000:
            self._improvement_log = self._improvement_log[-1000:]

    # ── Skill Learning ────────────────────────────────────

    def learn_skill(
        self,
        name: str,
        description: str,
        trigger_pattern: str,
        action_sequence: list[str],
        source: str = "experience",
    ) -> LearnedSkill:
        """Learn a new skill from a successful experience."""
        skill = LearnedSkill(
            name=name, description=description,
            trigger_pattern=trigger_pattern,
            action_sequence=action_sequence,
            source=source,
        )
        self._skills[skill.skill_id] = skill
        self._log.info("skill_learned", name=name, trigger=trigger_pattern[:50])
        return skill

    def find_applicable_skills(self, situation: str) -> list[LearnedSkill]:
        """Find skills applicable to the current situation."""
        results = []
        situation_lower = situation.lower()
        for skill in self._skills.values():
            trigger_lower = skill.trigger_pattern.lower()
            if any(word in situation_lower for word in trigger_lower.split()):
                results.append(skill)

        # Sort by success rate
        results.sort(key=lambda s: -s.success_rate)
        return results

    def apply_skill(self, skill_id: str, success: bool) -> None:
        """Record the result of applying a skill."""
        skill = self._skills.get(skill_id)
        if skill:
            skill.apply(success)

    # ── Error Pattern Recognition ─────────────────────────

    def record_error(
        self,
        description: str,
        error_type: str,
        conditions: list[str] | None = None,
    ) -> ErrorPattern:
        """Record an error for pattern recognition."""
        pattern_id = hashlib.md5(f"{error_type}:{description}".encode()).hexdigest()[:8]

        if pattern_id in self._error_patterns:
            self._error_patterns[pattern_id].occurrences += 1
            self._error_patterns[pattern_id].last_seen = time.time()
            return self._error_patterns[pattern_id]

        pattern = ErrorPattern(
            pattern_id=pattern_id,
            description=description,
            error_type=error_type,
            trigger_conditions=conditions or [],
            occurrences=1,
        )
        self._error_patterns[pattern_id] = pattern
        return pattern

    def set_avoidance_strategy(self, pattern_id: str, strategy: str) -> None:
        """Set how to avoid a known error pattern."""
        pattern = self._error_patterns.get(pattern_id)
        if pattern:
            pattern.avoidance_strategy = strategy

    def get_warnings_for_context(self, context: str) -> list[ErrorPattern]:
        """Get error patterns relevant to the current context."""
        context_lower = context.lower()
        warnings = []
        for pattern in self._error_patterns.values():
            if any(cond.lower() in context_lower for cond in pattern.trigger_conditions):
                warnings.append(pattern)
        return warnings

    # ── Strategy Optimization ─────────────────────────────

    def get_best_strategy(self, candidates: list[str]) -> str:
        """Get the best strategy based on historical performance."""
        if not candidates:
            return ""

        best = candidates[0]
        best_score = 0.0

        for candidate in candidates:
            sw = self._strategy_weights.get(candidate)
            if sw:
                score = sw.weight * sw.avg_quality
            else:
                score = 1.0  # Unexplored strategies get default weight
            if score > best_score:
                best = candidate
                best_score = score

        return best

    def get_strategy_weights(self) -> dict[str, float]:
        """Get current strategy weights."""
        return {
            name: round(sw.weight, 3)
            for name, sw in self._strategy_weights.items()
        }

    # ── Meta-Learning ─────────────────────────────────────

    def get_improvement_trend(self) -> dict[str, Any]:
        """Analyze overall improvement trend."""
        if len(self._improvement_log) < 10:
            return {"trend": "insufficient_data"}

        recent = self._improvement_log[-50:]
        older = self._improvement_log[:-50] if len(self._improvement_log) > 50 else []

        recent_success = sum(1 for x in recent if x["success"]) / len(recent)
        recent_quality = sum(x["quality"] for x in recent) / len(recent)

        if older:
            older_success = sum(1 for x in older if x["success"]) / len(older)
            older_quality = sum(x["quality"] for x in older) / len(older)
            trend = "improving" if recent_quality > older_quality else "degrading"
        else:
            older_success = recent_success
            older_quality = recent_quality
            trend = "stable"

        return {
            "trend": trend,
            "recent_success_rate": round(recent_success, 3),
            "older_success_rate": round(older_success, 3),
            "recent_avg_quality": round(recent_quality, 3),
            "older_avg_quality": round(older_quality, 3),
            "total_tasks_tracked": len(self._improvement_log),
        }

    def get_recommendations(self) -> list[str]:
        """Generate improvement recommendations."""
        recommendations = []

        # Find degrading metrics
        for name, metric in self._metrics.items():
            if metric.trend == "degrading":
                recommendations.append(
                    f"Performance for '{name}' is degrading. "
                    f"Success rate: {metric.success_rate:.1%}. Consider strategy adjustment."
                )

        # Find frequently occurring errors
        for pattern in self._error_patterns.values():
            if pattern.occurrences >= 3 and not pattern.avoidance_strategy:
                recommendations.append(
                    f"Error pattern '{pattern.description[:50]}' has occurred "
                    f"{pattern.occurrences} times. Define an avoidance strategy."
                )

        # Find underperforming strategies
        for name, sw in self._strategy_weights.items():
            if sw.failures > sw.successes and (sw.successes + sw.failures) > 5:
                recommendations.append(
                    f"Strategy '{name}' has more failures ({sw.failures}) than "
                    f"successes ({sw.successes}). Consider deprecating."
                )

        return recommendations

    # ── Persistence ──────────────────────────────────────

    def save(self) -> None:
        """Persist improvement data to disk."""
        try:
            data = {
                "metrics": {k: v.to_dict() for k, v in self._metrics.items()},
                "skills": {k: v.to_dict() for k, v in self._skills.items()},
                "errors": {k: v.to_dict() for k, v in self._error_patterns.items()},
                "strategies": {k: {"weight": v.weight, "successes": v.successes, "failures": v.failures}
                               for k, v in self._strategy_weights.items()},
                "log_tail": self._improvement_log[-100:],
            }
            path = self._storage_dir / "improvement_data.json"
            path.write_text(json.dumps(data, indent=2))
        except OSError as e:
            self._log.warning("save_failed", error=str(e))

    def _load(self) -> None:
        """Load persisted improvement data."""
        path = self._storage_dir / "improvement_data.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            # Load strategy weights
            for name, sw_data in data.get("strategies", {}).items():
                self._strategy_weights[name] = StrategyWeight(
                    strategy_name=name,
                    weight=sw_data.get("weight", 1.0),
                    successes=sw_data.get("successes", 0),
                    failures=sw_data.get("failures", 0),
                )
            self._improvement_log = data.get("log_tail", [])
        except (json.JSONDecodeError, OSError) as e:
            self._log.warning("load_failed", error=str(e))

    def get_stats(self) -> dict[str, Any]:
        return {
            "metrics_tracked": len(self._metrics),
            "skills_learned": len(self._skills),
            "error_patterns": len(self._error_patterns),
            "strategies_tracked": len(self._strategy_weights),
            "total_log_entries": len(self._improvement_log),
            "trend": self.get_improvement_trend(),
        }
