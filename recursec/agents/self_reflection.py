"""Self-reflection engine — agent self-assessment after task completion.

Implements:
1. Performance self-evaluation
2. Mistake detection and learning
3. Strategy effectiveness review
4. Knowledge gap identification
5. Improvement suggestions
6. Reflection prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ReflectionCategory(str, Enum):
    PERFORMANCE = "performance"
    STRATEGY = "strategy"
    KNOWLEDGE = "knowledge"
    EFFICIENCY = "efficiency"
    ACCURACY = "accuracy"


class InsightType(str, Enum):
    STRENGTH = "strength"
    WEAKNESS = "weakness"
    OPPORTUNITY = "opportunity"
    GAP = "gap"
    LESSON = "lesson"


@dataclass
class Insight:
    """A self-reflection insight."""
    insight_id: str = ""
    insight_type: InsightType = InsightType.LESSON
    category: ReflectionCategory = ReflectionCategory.PERFORMANCE
    description: str = ""
    impact: float = 0.5        # 0-1
    actionable: bool = True
    action: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.insight_id[:8],
            "type": self.insight_type.value[:6],
            "cat": self.category.value[:6],
            "impact": f"{self.impact:.0%}",
            "desc": self.description[:30],
        }


@dataclass
class TaskReflection:
    """Reflection on a completed task."""
    task_id: str = ""
    task_description: str = ""
    outcome: str = "partial"     # success, partial, failure
    duration_s: float = 0.0
    tokens_used: int = 0
    tools_used: list[str] = field(default_factory=list)
    findings_count: int = 0
    insights: list[Insight] = field(default_factory=list)
    overall_score: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task_id[:10],
            "outcome": self.outcome[:7],
            "score": f"{self.overall_score:.0%}",
            "insights": len(self.insights),
        }


@dataclass
class PerformanceMetrics:
    """Aggregated performance metrics."""
    total_tasks: int = 0
    successful: int = 0
    partial: int = 0
    failed: int = 0
    avg_score: float = 0.0
    avg_duration: float = 0.0
    total_findings: int = 0
    most_used_tools: list[str] = field(default_factory=list)
    common_weaknesses: list[str] = field(default_factory=list)
    common_strengths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tasks": self.total_tasks,
            "success_rate": f"{self.successful / max(1, self.total_tasks):.0%}",
            "avg_score": f"{self.avg_score:.0%}",
        }


class SelfReflection:
    """Agent self-assessment and learning from past tasks.

    After each task, the agent reflects on what went well,
    what could be improved, and what knowledge gaps exist.
    These reflections feed back into future planning.
    """

    def __init__(self, max_reflections: int = 100) -> None:
        self._reflections: list[TaskReflection] = []
        self._max_reflections = max_reflections
        self._insight_counter = 0
        self._log = logger.bind(component="self_reflection")

    def reflect(
        self,
        task_id: str,
        task_description: str,
        outcome: str,
        duration_s: float = 0.0,
        tokens_used: int = 0,
        tools_used: list[str] | None = None,
        findings_count: int = 0,
    ) -> TaskReflection:
        """Perform self-reflection on a completed task."""
        reflection = TaskReflection(
            task_id=task_id,
            task_description=task_description,
            outcome=outcome,
            duration_s=duration_s,
            tokens_used=tokens_used,
            tools_used=tools_used or [],
            findings_count=findings_count,
        )

        # Generate insights
        reflection.insights = self._generate_insights(reflection)

        # Score
        reflection.overall_score = self._score_task(reflection)

        # Store
        self._reflections.append(reflection)

        # Trim old
        while len(self._reflections) > self._max_reflections:
            self._reflections.pop(0)

        return reflection

    def _generate_insights(self, reflection: TaskReflection) -> list[Insight]:
        """Generate insights from task reflection."""
        insights: list[Insight] = []

        # Outcome-based
        if reflection.outcome == "success":
            self._insight_counter += 1
            insights.append(Insight(
                insight_id=f"ins-{self._insight_counter}",
                insight_type=InsightType.STRENGTH,
                category=ReflectionCategory.PERFORMANCE,
                description="Task completed successfully",
                impact=0.8,
            ))
        elif reflection.outcome == "failure":
            self._insight_counter += 1
            insights.append(Insight(
                insight_id=f"ins-{self._insight_counter}",
                insight_type=InsightType.WEAKNESS,
                category=ReflectionCategory.PERFORMANCE,
                description="Task failed — review approach",
                impact=0.9,
                action="Consider alternative strategies",
            ))

        # Efficiency insights
        if reflection.tokens_used > 50000:
            self._insight_counter += 1
            insights.append(Insight(
                insight_id=f"ins-{self._insight_counter}",
                insight_type=InsightType.WEAKNESS,
                category=ReflectionCategory.EFFICIENCY,
                description="High token usage — optimize prompts",
                impact=0.6,
                action="Use more concise prompts and fewer reasoning steps",
            ))

        if reflection.duration_s > 600:
            self._insight_counter += 1
            insights.append(Insight(
                insight_id=f"ins-{self._insight_counter}",
                insight_type=InsightType.WEAKNESS,
                category=ReflectionCategory.EFFICIENCY,
                description="Long task duration — consider parallelization",
                impact=0.5,
                action="Spawn child agents for independent subtasks",
            ))

        # Tool usage
        if not reflection.tools_used:
            self._insight_counter += 1
            insights.append(Insight(
                insight_id=f"ins-{self._insight_counter}",
                insight_type=InsightType.GAP,
                category=ReflectionCategory.STRATEGY,
                description="No tools used — missed automation opportunity",
                impact=0.7,
                action="Review available tools for the task type",
            ))

        # Finding count
        if reflection.outcome == "success" and reflection.findings_count == 0:
            self._insight_counter += 1
            insights.append(Insight(
                insight_id=f"ins-{self._insight_counter}",
                insight_type=InsightType.OPPORTUNITY,
                category=ReflectionCategory.ACCURACY,
                description="Success with no findings — target may be hardened",
                impact=0.4,
            ))

        return insights

    def _score_task(self, reflection: TaskReflection) -> float:
        """Score task performance."""
        score = 0.0

        # Outcome weight (50%)
        outcome_scores = {"success": 1.0, "partial": 0.5, "failure": 0.1}
        score += outcome_scores.get(reflection.outcome, 0.3) * 0.5

        # Efficiency (20%)
        if reflection.tokens_used > 0:
            token_efficiency = min(1.0, 10000 / reflection.tokens_used)
            score += token_efficiency * 0.2

        # Tool usage (15%)
        if reflection.tools_used:
            score += min(0.15, len(reflection.tools_used) * 0.03)

        # Findings (15%)
        if reflection.findings_count > 0:
            score += min(0.15, reflection.findings_count * 0.03)

        return min(1.0, score)

    def get_metrics(self) -> PerformanceMetrics:
        """Compute aggregated performance metrics."""
        if not self._reflections:
            return PerformanceMetrics()

        metrics = PerformanceMetrics(
            total_tasks=len(self._reflections),
            successful=sum(1 for r in self._reflections if r.outcome == "success"),
            partial=sum(1 for r in self._reflections if r.outcome == "partial"),
            failed=sum(1 for r in self._reflections if r.outcome == "failure"),
            avg_score=sum(r.overall_score for r in self._reflections) / len(self._reflections),
            avg_duration=sum(r.duration_s for r in self._reflections) / len(self._reflections),
            total_findings=sum(r.findings_count for r in self._reflections),
        )

        # Most used tools
        tool_counts: dict[str, int] = {}
        for r in self._reflections:
            for tool in r.tools_used:
                tool_counts[tool] = tool_counts.get(tool, 0) + 1
        metrics.most_used_tools = sorted(tool_counts, key=tool_counts.get, reverse=True)[:5]  # type: ignore[arg-type]

        # Common insights
        weakness_counts: dict[str, int] = {}
        strength_counts: dict[str, int] = {}
        for r in self._reflections:
            for ins in r.insights:
                if ins.insight_type == InsightType.WEAKNESS:
                    weakness_counts[ins.description] = weakness_counts.get(ins.description, 0) + 1
                elif ins.insight_type == InsightType.STRENGTH:
                    strength_counts[ins.description] = strength_counts.get(ins.description, 0) + 1

        metrics.common_weaknesses = sorted(weakness_counts, key=weakness_counts.get, reverse=True)[:3]  # type: ignore[arg-type]
        metrics.common_strengths = sorted(strength_counts, key=strength_counts.get, reverse=True)[:3]  # type: ignore[arg-type]

        return metrics

    def build_reflection_prompt(self) -> str:
        """Build reflection context for LLM."""
        lines = ["## Self-Reflection\n"]

        metrics = self.get_metrics()
        lines.append(
            f"Tasks: {metrics.total_tasks} — "
            f"success={metrics.successful}, "
            f"partial={metrics.partial}, "
            f"failed={metrics.failed}"
        )
        lines.append(f"Avg score: {metrics.avg_score:.0%}")

        if metrics.common_weaknesses:
            lines.append("\nCommon weaknesses:")
            for w in metrics.common_weaknesses:
                lines.append(f"  - {w[:40]}")

        if metrics.common_strengths:
            lines.append("Strengths:")
            for s in metrics.common_strengths:
                lines.append(f"  + {s[:40]}")

        # Recent reflections
        recent = self._reflections[-3:]
        if recent:
            lines.append("\nRecent tasks:")
            for r in recent:
                lines.append(
                    f"  [{r.outcome[:4]}] {r.task_description[:30]} "
                    f"score={r.overall_score:.0%}"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        metrics = self.get_metrics()
        return {
            "total_tasks": metrics.total_tasks,
            "success_rate": metrics.successful / max(1, metrics.total_tasks),
            "avg_score": metrics.avg_score,
            "total_insights": sum(len(r.insights) for r in self._reflections),
        }
