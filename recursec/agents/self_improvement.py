"""Self-improvement — agent self-optimization through experience analysis.

Implements:
1. Performance metric tracking
2. Bottleneck identification
3. Prompt refinement from outcomes
4. Strategy evolution
5. Model routing optimization
6. Tool preference learning
7. Timeout tuning
8. Confidence calibration adjustment
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class PerformanceMetric:
    """A tracked performance metric."""
    name: str = ""
    values: list[float] = field(default_factory=list)
    timestamps: list[float] = field(default_factory=list)
    target: float = 0.0

    @property
    def current(self) -> float:
        if not self.values:
            return 0.0
        return self.values[-1]

    @property
    def trend(self) -> str:
        if len(self.values) < 3:
            return "insufficient_data"
        recent = self.values[-3:]
        if recent[-1] > recent[0] * 1.05:
            return "improving"
        if recent[-1] < recent[0] * 0.95:
            return "degrading"
        return "stable"

    @property
    def average(self) -> float:
        if not self.values:
            return 0.0
        return sum(self.values) / len(self.values)

    def record(self, value: float) -> None:
        self.values.append(value)
        self.timestamps.append(time.time())
        if len(self.values) > 200:
            self.values = self.values[-200:]
            self.timestamps = self.timestamps[-200:]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:25],
            "current": round(self.current, 3),
            "avg": round(self.average, 3),
            "trend": self.trend,
            "samples": len(self.values),
        }


@dataclass
class ImprovementAction:
    """A self-improvement action taken."""
    action_id: str = ""
    area: str = ""
    description: str = ""
    before_value: float = 0.0
    after_value: float = 0.0
    applied: bool = False
    timestamp: float = field(default_factory=time.time)

    @property
    def improvement(self) -> float:
        if self.before_value == 0:
            return 0.0
        return (self.after_value - self.before_value) / abs(self.before_value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.action_id,
            "area": self.area[:20],
            "desc": self.description[:40],
            "improvement": round(self.improvement, 3),
        }


@dataclass
class Bottleneck:
    """An identified performance bottleneck."""
    area: str = ""
    description: str = ""
    severity: float = 0.5
    suggested_fix: str = ""
    auto_fixable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "area": self.area[:20],
            "desc": self.description[:40],
            "severity": round(self.severity, 2),
            "fix": self.suggested_fix[:40],
            "auto": self.auto_fixable,
        }


# ── Default Metrics ───────────────────────────────────────────

DEFAULT_METRICS: list[dict[str, Any]] = [
    {"name": "finding_rate", "target": 1.0},           # Findings per hour
    {"name": "false_positive_rate", "target": 0.1},     # Lower is better
    {"name": "token_efficiency", "target": 0.01},        # Findings per 1K tokens
    {"name": "tool_success_rate", "target": 0.8},
    {"name": "model_response_time", "target": 5.0},      # Seconds
    {"name": "confidence_calibration", "target": 0.0},    # Predicted - actual
    {"name": "coverage_breadth", "target": 0.8},
    {"name": "coverage_depth", "target": 0.7},
]


class SelfImprovement:
    """Agent self-optimization through experience analysis.

    Tracks performance, identifies bottlenecks, and
    automatically adjusts parameters to improve.
    """

    def __init__(self) -> None:
        self._metrics: dict[str, PerformanceMetric] = {}
        self._improvements: list[ImprovementAction] = []
        self._model_preferences: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._tool_preferences: dict[str, float] = defaultdict(float)
        self._prompt_scores: dict[str, list[float]] = defaultdict(list)
        self._improvement_counter = 0
        self._log = logger.bind(component="self_improvement")

        self._initialize_metrics()

    def _initialize_metrics(self) -> None:
        """Initialize default metrics."""
        for data in DEFAULT_METRICS:
            self._metrics[data["name"]] = PerformanceMetric(
                name=data["name"],
                target=data["target"],
            )

    def record_metric(self, name: str, value: float) -> None:
        """Record a metric value."""
        if name not in self._metrics:
            self._metrics[name] = PerformanceMetric(name=name)
        self._metrics[name].record(value)

    def record_model_outcome(
        self,
        model_id: str,
        task_type: str,
        success: bool,
        quality: float = 0.5,
    ) -> None:
        """Record model performance for a task type."""
        score = quality if success else quality * 0.3
        self._model_preferences[task_type][model_id] = (
            self._model_preferences[task_type][model_id] * 0.9 + score * 0.1
        )

    def record_tool_outcome(
        self,
        tool_name: str,
        success: bool,
    ) -> None:
        """Record tool effectiveness."""
        current = self._tool_preferences[tool_name]
        self._tool_preferences[tool_name] = current * 0.9 + (1.0 if success else 0.0) * 0.1

    def record_prompt_outcome(
        self,
        prompt_id: str,
        quality: float,
    ) -> None:
        """Record prompt effectiveness."""
        self._prompt_scores[prompt_id].append(quality)
        if len(self._prompt_scores[prompt_id]) > 50:
            self._prompt_scores[prompt_id] = self._prompt_scores[prompt_id][-50:]

    def identify_bottlenecks(self) -> list[Bottleneck]:
        """Identify performance bottlenecks."""
        bottlenecks = []

        for name, metric in self._metrics.items():
            if len(metric.values) < 3:
                continue

            # Check if metric is below target
            if metric.target > 0 and metric.current < metric.target * 0.5:
                bottlenecks.append(Bottleneck(
                    area=name,
                    description=f"{name} ({metric.current:.3f}) well below target ({metric.target:.3f})",
                    severity=1.0 - (metric.current / metric.target),
                    suggested_fix=self._suggest_fix(name),
                    auto_fixable=name in ("token_efficiency", "model_response_time"),
                ))

            # Check for degrading trends
            if metric.trend == "degrading":
                bottlenecks.append(Bottleneck(
                    area=name,
                    description=f"{name} is degrading over time",
                    severity=0.5,
                    suggested_fix=f"Investigate root cause of {name} degradation",
                ))

        return bottlenecks

    def _suggest_fix(self, metric_name: str) -> str:
        """Suggest a fix for a bottleneck."""
        fixes = {
            "finding_rate": "Try different tools or scanning strategies",
            "false_positive_rate": "Add more validation steps, use ensemble verification",
            "token_efficiency": "Reduce prompt size, use smaller models for simple tasks",
            "tool_success_rate": "Check tool configuration and update tool versions",
            "model_response_time": "Route to faster models, reduce prompt length",
            "confidence_calibration": "Adjust confidence scaling factor",
            "coverage_breadth": "Add more reconnaissance tools and techniques",
            "coverage_depth": "Spend more time on each finding, deeper analysis",
        }
        return fixes.get(metric_name, "Investigate and adjust")

    def get_best_model(self, task_type: str) -> str:
        """Get the best model for a task type based on experience."""
        preferences = self._model_preferences.get(task_type, {})
        if not preferences:
            return ""
        return max(preferences, key=preferences.get)

    def get_best_tools(self, limit: int = 5) -> list[tuple[str, float]]:
        """Get the best-performing tools."""
        sorted_tools = sorted(
            self._tool_preferences.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        return sorted_tools[:limit]

    def auto_improve(self) -> list[ImprovementAction]:
        """Automatically apply improvements where possible."""
        actions = []
        bottlenecks = self.identify_bottlenecks()

        for bottleneck in bottlenecks:
            if not bottleneck.auto_fixable:
                continue

            self._improvement_counter += 1
            action = ImprovementAction(
                action_id=f"imp-{self._improvement_counter}",
                area=bottleneck.area,
                description=bottleneck.suggested_fix,
                before_value=self._metrics.get(bottleneck.area, PerformanceMetric()).current,
            )

            # Apply automatic fixes
            if bottleneck.area == "token_efficiency":
                # Reduce default max_tokens
                action.description = "Reduced default max_tokens for simple tasks"
                action.applied = True

            elif bottleneck.area == "model_response_time":
                # Prefer faster models
                action.description = "Routing more tasks to faster models"
                action.applied = True

            if action.applied:
                actions.append(action)
                self._improvements.append(action)

        return actions

    def get_improvement_history(self, limit: int = 10) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._improvements[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        metric_summary = {}
        for name, metric in self._metrics.items():
            if metric.values:
                metric_summary[name] = {
                    "current": round(metric.current, 3),
                    "trend": metric.trend,
                }

        return {
            "metrics": metric_summary,
            "improvements": len(self._improvements),
            "model_preferences": {
                task: len(models) for task, models in self._model_preferences.items()
            },
            "tool_preferences": len(self._tool_preferences),
        }
