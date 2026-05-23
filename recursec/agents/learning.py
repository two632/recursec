"""Learning and adaptation engine — agents that improve over time.

Implements experience-based learning so agents get better at:
- Selecting the right tools for different target types
- Choosing effective exploitation strategies
- Avoiding false positive patterns
- Estimating task difficulty and time
- Routing to optimal models for task types

Learning mechanisms:
1. Experience replay — store and recall past actions and outcomes
2. Strategy scoring — track success rates of different approaches
3. Tool effectiveness — learn which tools work best for what
4. Pattern recognition — detect recurring vulnerability patterns
5. Failure analysis — learn from mistakes
6. Model preference learning — track which models produce best results
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class Experience:
    """A single experience record — an action and its outcome."""
    experience_id: str = ""
    agent_id: str = ""
    action_type: str = ""
    tool_name: str = ""
    target_type: str = ""  # web, network, api, code, cloud, etc.
    strategy: str = ""
    model_used: str = ""
    success: bool = False
    quality_score: float = 0.0  # 0.0 = terrible, 1.0 = perfect
    findings_produced: int = 0
    tokens_used: int = 0
    time_s: float = 0.0
    error: str = ""
    context_hash: str = ""  # Hash of relevant context for similarity
    timestamp: float = field(default_factory=time.time)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.experience_id, "action": self.action_type,
            "tool": self.tool_name, "target_type": self.target_type,
            "strategy": self.strategy, "model": self.model_used,
            "success": self.success, "quality": round(self.quality_score, 2),
            "findings": self.findings_produced, "time_s": round(self.time_s, 1),
            "timestamp": self.timestamp,
        }


@dataclass
class StrategyScore:
    """Tracks the effectiveness of a strategy."""
    strategy: str
    total_uses: int = 0
    successes: int = 0
    total_quality: float = 0.0
    total_findings: int = 0
    total_time_s: float = 0.0
    total_tokens: int = 0
    recent_scores: list[float] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        return self.successes / self.total_uses if self.total_uses > 0 else 0.0

    @property
    def avg_quality(self) -> float:
        return self.total_quality / self.total_uses if self.total_uses > 0 else 0.0

    @property
    def avg_time(self) -> float:
        return self.total_time_s / self.total_uses if self.total_uses > 0 else 0.0

    @property
    def trend(self) -> str:
        """Is performance improving, declining, or stable?"""
        if len(self.recent_scores) < 3:
            return "insufficient_data"
        recent = self.recent_scores[-5:]
        older = self.recent_scores[-10:-5] if len(self.recent_scores) >= 10 else self.recent_scores[:5]
        if not older:
            return "insufficient_data"
        recent_avg = sum(recent) / len(recent)
        older_avg = sum(older) / len(older)
        diff = recent_avg - older_avg
        if diff > 0.1:
            return "improving"
        if diff < -0.1:
            return "declining"
        return "stable"

    def update(self, experience: Experience) -> None:
        self.total_uses += 1
        if experience.success:
            self.successes += 1
        self.total_quality += experience.quality_score
        self.total_findings += experience.findings_produced
        self.total_time_s += experience.time_s
        self.total_tokens += experience.tokens_used
        self.recent_scores.append(experience.quality_score)
        if len(self.recent_scores) > 50:
            self.recent_scores = self.recent_scores[-50:]


@dataclass
class ToolEffectiveness:
    """Tracks how effective a tool is for different target types."""
    tool_name: str
    by_target_type: dict[str, StrategyScore] = field(default_factory=dict)

    def update(self, target_type: str, experience: Experience) -> None:
        if target_type not in self.by_target_type:
            self.by_target_type[target_type] = StrategyScore(strategy=f"{self.tool_name}_{target_type}")
        self.by_target_type[target_type].update(experience)

    def best_for(self) -> str:
        """What target type is this tool best for?"""
        if not self.by_target_type:
            return "unknown"
        return max(self.by_target_type.items(), key=lambda x: x[1].avg_quality)[0]

    def effectiveness_for(self, target_type: str) -> float:
        """Get effectiveness score for a target type."""
        score = self.by_target_type.get(target_type)
        if not score:
            return 0.5  # Unknown = neutral
        return score.avg_quality


@dataclass
class ModelPreference:
    """Tracks which LLM models produce best results for task types."""
    task_type: str
    model_scores: dict[str, StrategyScore] = field(default_factory=dict)

    def update(self, model: str, experience: Experience) -> None:
        if model not in self.model_scores:
            self.model_scores[model] = StrategyScore(strategy=f"{model}_{self.task_type}")
        self.model_scores[model].update(experience)

    def best_model(self) -> str:
        """Get the best performing model for this task type."""
        if not self.model_scores:
            return ""
        return max(self.model_scores.items(), key=lambda x: x[1].avg_quality)[0]

    def ranked_models(self) -> list[tuple[str, float]]:
        """Get models ranked by effectiveness."""
        return sorted(
            [(m, s.avg_quality) for m, s in self.model_scores.items()],
            key=lambda x: -x[1],
        )


@dataclass
class FailurePattern:
    """A recognized failure pattern to avoid."""
    pattern_id: str = ""
    description: str = ""
    conditions: dict[str, str] = field(default_factory=dict)  # context conditions
    occurrences: int = 0
    last_seen: float = 0.0
    avoidance_strategy: str = ""


class LearningEngine:
    """Experience-based learning engine for agents.

    Stores experiences and derives actionable insights that improve
    future agent performance.
    """

    def __init__(self, persistence_path: str = "data/learning") -> None:
        self._path = Path(persistence_path)
        self._path.mkdir(parents=True, exist_ok=True)

        self._experiences: list[Experience] = []
        self._strategy_scores: dict[str, StrategyScore] = {}
        self._tool_effectiveness: dict[str, ToolEffectiveness] = {}
        self._model_preferences: dict[str, ModelPreference] = {}
        self._failure_patterns: dict[str, FailurePattern] = {}
        self._max_experiences = 5000

        self._load()

    def record(self, experience: Experience) -> None:
        """Record a new experience."""
        self._experiences.append(experience)
        if len(self._experiences) > self._max_experiences:
            self._experiences = self._experiences[-self._max_experiences:]

        # Update strategy scores
        if experience.strategy:
            if experience.strategy not in self._strategy_scores:
                self._strategy_scores[experience.strategy] = StrategyScore(strategy=experience.strategy)
            self._strategy_scores[experience.strategy].update(experience)

        # Update tool effectiveness
        if experience.tool_name:
            if experience.tool_name not in self._tool_effectiveness:
                self._tool_effectiveness[experience.tool_name] = ToolEffectiveness(tool_name=experience.tool_name)
            self._tool_effectiveness[experience.tool_name].update(experience.target_type, experience)

        # Update model preferences
        if experience.model_used and experience.action_type:
            task_type = experience.action_type
            if task_type not in self._model_preferences:
                self._model_preferences[task_type] = ModelPreference(task_type=task_type)
            self._model_preferences[task_type].update(experience.model_used, experience)

        # Check for failure patterns
        if not experience.success:
            self._detect_failure_pattern(experience)

    def recommend_strategy(self, target_type: str, context: dict[str, Any] | None = None) -> str:
        """Recommend the best strategy for a given target type."""
        # Filter strategies that have been used for this target type
        candidates: list[tuple[str, float]] = []
        for name, score in self._strategy_scores.items():
            if score.total_uses >= 3:  # Minimum usage threshold
                effectiveness = score.avg_quality * score.success_rate
                # Bonus for improving trends
                if score.trend == "improving":
                    effectiveness *= 1.2
                elif score.trend == "declining":
                    effectiveness *= 0.8
                candidates.append((name, effectiveness))

        if not candidates:
            return "chain_of_thought"  # Default

        candidates.sort(key=lambda x: -x[1])
        return candidates[0][0]

    def recommend_tools(self, target_type: str, top_k: int = 5) -> list[tuple[str, float]]:
        """Recommend the most effective tools for a target type."""
        scored: list[tuple[str, float]] = []
        for tool_name, effectiveness in self._tool_effectiveness.items():
            score = effectiveness.effectiveness_for(target_type)
            if score > 0:
                scored.append((tool_name, score))

        scored.sort(key=lambda x: -x[1])
        return scored[:top_k]

    def recommend_model(self, task_type: str) -> str:
        """Recommend the best model for a task type."""
        pref = self._model_preferences.get(task_type)
        if pref:
            best = pref.best_model()
            if best:
                return best
        return ""  # No recommendation

    def get_failure_patterns(self) -> list[dict[str, Any]]:
        """Get recognized failure patterns."""
        return [
            {
                "description": fp.description,
                "occurrences": fp.occurrences,
                "avoidance": fp.avoidance_strategy,
            }
            for fp in self._failure_patterns.values()
        ]

    def should_avoid(self, action_type: str, tool_name: str = "", context: dict[str, Any] | None = None) -> tuple[bool, str]:
        """Check if an action should be avoided based on failure patterns."""
        for fp in self._failure_patterns.values():
            if fp.occurrences < 3:
                continue
            conditions = fp.conditions
            if conditions.get("action_type") == action_type:
                if not tool_name or conditions.get("tool") == tool_name:
                    return True, fp.avoidance_strategy
        return False, ""

    def get_insights(self) -> dict[str, Any]:
        """Get actionable insights from learned experiences."""
        insights: dict[str, Any] = {
            "total_experiences": len(self._experiences),
            "strategies": {},
            "best_tools_by_target": {},
            "best_models_by_task": {},
            "failure_patterns": len(self._failure_patterns),
        }

        # Strategy insights
        for name, score in self._strategy_scores.items():
            if score.total_uses >= 3:
                insights["strategies"][name] = {
                    "success_rate": round(score.success_rate, 2),
                    "avg_quality": round(score.avg_quality, 2),
                    "trend": score.trend,
                    "uses": score.total_uses,
                }

        # Tool insights by target type
        target_types = set()
        for te in self._tool_effectiveness.values():
            target_types.update(te.by_target_type.keys())
        for tt in target_types:
            top_tools = self.recommend_tools(tt, top_k=3)
            if top_tools:
                insights["best_tools_by_target"][tt] = [
                    {"tool": t, "score": round(s, 2)} for t, s in top_tools
                ]

        # Model insights
        for task_type, pref in self._model_preferences.items():
            ranked = pref.ranked_models()
            if ranked:
                insights["best_models_by_task"][task_type] = [
                    {"model": m, "score": round(s, 2)} for m, s in ranked[:3]
                ]

        return insights

    def _detect_failure_pattern(self, experience: Experience) -> None:
        """Detect recurring failure patterns."""
        # Simple pattern: same action+tool failing repeatedly
        pattern_key = f"{experience.action_type}_{experience.tool_name}_{experience.target_type}"

        if pattern_key not in self._failure_patterns:
            self._failure_patterns[pattern_key] = FailurePattern(
                pattern_id=pattern_key,
                description=f"{experience.action_type} with {experience.tool_name} on {experience.target_type}",
                conditions={
                    "action_type": experience.action_type,
                    "tool": experience.tool_name,
                    "target_type": experience.target_type,
                },
                avoidance_strategy=f"Try alternative tool or approach for {experience.target_type}",
            )

        fp = self._failure_patterns[pattern_key]
        fp.occurrences += 1
        fp.last_seen = time.time()

    def _save(self) -> None:
        """Persist learning data to disk."""
        try:
            data = {
                "experiences": [e.to_dict() for e in self._experiences[-500:]],
                "strategy_scores": {
                    k: {"uses": v.total_uses, "successes": v.successes, "quality": v.total_quality}
                    for k, v in self._strategy_scores.items()
                },
            }
            (self._path / "learning_state.json").write_text(json.dumps(data, indent=2))
        except OSError as e:
            logger.warning("learning_save_failed", error=str(e))

    def _load(self) -> None:
        """Load learning data from disk."""
        state_file = self._path / "learning_state.json"
        if not state_file.exists():
            return
        try:
            data = json.loads(state_file.read_text())
            # Reconstruct strategy scores
            for name, score_data in data.get("strategy_scores", {}).items():
                score = StrategyScore(strategy=name)
                score.total_uses = score_data.get("uses", 0)
                score.successes = score_data.get("successes", 0)
                score.total_quality = score_data.get("quality", 0.0)
                self._strategy_scores[name] = score
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("learning_load_failed", error=str(e))
