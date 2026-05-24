"""Agent reflection engine — self-analysis and improvement.

After each task, the agent reflects on its performance:
1. What went well? What failed?
2. Were the right tools/models/KBs used?
3. Was the reasoning strategy optimal?
4. What should be done differently next time?
5. Update strategy weights based on outcomes
6. Generate improvement recommendations

This is the "learn from mistakes" capability that makes
the agent continuously better over time.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class TaskReflection:
    """Reflection on a completed task."""
    reflection_id: str = ""
    task_description: str = ""
    target: str = ""
    success: bool = False
    findings_count: int = 0
    duration_s: float = 0.0
    tools_used: list[str] = field(default_factory=list)
    models_used: list[str] = field(default_factory=list)
    kbs_used: list[str] = field(default_factory=list)
    strategy_used: str = ""
    what_worked: list[str] = field(default_factory=list)
    what_failed: list[str] = field(default_factory=list)
    improvements: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task_description[:25],
            "success": self.success,
            "findings": self.findings_count,
            "worked": len(self.what_worked),
            "failed": len(self.what_failed),
            "improvements": len(self.improvements),
        }


@dataclass
class ToolEffectiveness:
    """Track how effective each tool is."""
    tool_name: str = ""
    uses: int = 0
    findings_produced: int = 0
    false_positives: int = 0
    avg_duration_s: float = 0.0
    last_used: float = 0.0

    @property
    def precision(self) -> float:
        total = self.findings_produced + self.false_positives
        return self.findings_produced / max(total, 1)

    @property
    def productivity(self) -> float:
        return self.findings_produced / max(self.uses, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name[:12],
            "uses": self.uses,
            "findings": self.findings_produced,
            "precision": f"{self.precision:.2f}",
            "productivity": f"{self.productivity:.1f}",
        }


@dataclass
class ModelEffectiveness:
    """Track how effective each model is per task type."""
    model_id: str = ""
    task_type: str = ""
    uses: int = 0
    quality_scores: list[float] = field(default_factory=list)
    avg_latency_ms: float = 0.0
    hallucination_count: int = 0

    @property
    def avg_quality(self) -> float:
        return sum(self.quality_scores) / max(len(self.quality_scores), 1)

    @property
    def hallucination_rate(self) -> float:
        return self.hallucination_count / max(self.uses, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:12],
            "task": self.task_type[:10],
            "uses": self.uses,
            "quality": f"{self.avg_quality:.2f}",
            "hallucination_rate": f"{self.hallucination_rate:.2f}",
        }


# Reflection prompt templates
REFLECTION_PROMPTS: dict[str, str] = {
    "success": """Task completed successfully with {findings_count} findings.

Tools used: {tools}
Models used: {models}
Strategy: {strategy}
Duration: {duration:.1f}s

Analyze what went well:
1. Were the right tools chosen for this target type?
2. Was the model routing optimal?
3. Was the strategy effective?
4. Were there false positives that could be reduced?
5. Could this have been done faster?""",

    "failure": """Task FAILED.

Tools used: {tools}
Models used: {models}
Strategy: {strategy}
Duration: {duration:.1f}s
Error patterns: {errors}

Analyze the failure:
1. Was the target correctly profiled?
2. Were the right tools available?
3. Did the LLM provide useful analysis?
4. Was the strategy appropriate?
5. What should be tried differently?""",

    "improvement": """Based on {task_count} completed tasks:

Best performing tools: {best_tools}
Worst performing tools: {worst_tools}
Best model-task combos: {best_models}
Common failure patterns: {failure_patterns}

Generate improvement recommendations:
1. Tool substitutions
2. Strategy adjustments
3. KB gaps to fill
4. Model routing changes""",
}


class AgentReflection:
    """Manages agent self-reflection and continuous improvement."""

    def __init__(self) -> None:
        self._reflections: list[TaskReflection] = []
        self._tool_effectiveness: dict[str, ToolEffectiveness] = {}
        self._model_effectiveness: dict[str, ModelEffectiveness] = {}
        self._reflection_counter = 0
        self._log = logger.bind(component="agent_reflection")

    def reflect_on_task(
        self,
        task_description: str,
        target: str = "",
        success: bool = True,
        findings_count: int = 0,
        duration_s: float = 0.0,
        tools_used: list[str] | None = None,
        models_used: list[str] | None = None,
        kbs_used: list[str] | None = None,
        strategy_used: str = "",
    ) -> TaskReflection:
        """Create a reflection on a completed task."""
        self._reflection_counter += 1
        reflection = TaskReflection(
            reflection_id=f"reflect-{self._reflection_counter}",
            task_description=task_description,
            target=target,
            success=success,
            findings_count=findings_count,
            duration_s=duration_s,
            tools_used=tools_used or [],
            models_used=models_used or [],
            kbs_used=kbs_used or [],
            strategy_used=strategy_used,
        )

        # Auto-analyze what worked/failed
        if success and findings_count > 0:
            reflection.what_worked.append(f"Found {findings_count} findings using {strategy_used}")
            if tools_used:
                reflection.what_worked.append(f"Tool chain: {' → '.join(tools_used[:5])}")
        elif not success:
            reflection.what_failed.append(f"Strategy {strategy_used} did not produce results")

        # Generate improvements
        if findings_count == 0:
            reflection.improvements.append("Consider broadening scan scope or using different tools")
        if duration_s > 300:
            reflection.improvements.append("Task took too long. Consider parallel execution or timeout tuning")

        # Update tool effectiveness
        for tool in (tools_used or []):
            self._update_tool(tool, findings_count, duration_s)

        # Update model effectiveness
        for model in (models_used or []):
            self._update_model(model, "general", 0.7 if success else 0.3)

        self._reflections.append(reflection)
        return reflection

    def _update_tool(self, tool: str, findings: int, duration: float) -> None:
        if tool not in self._tool_effectiveness:
            self._tool_effectiveness[tool] = ToolEffectiveness(tool_name=tool)
        eff = self._tool_effectiveness[tool]
        eff.uses += 1
        eff.findings_produced += findings
        eff.last_used = time.time()
        n = eff.uses
        eff.avg_duration_s = eff.avg_duration_s * (n - 1) / n + duration / n

    def _update_model(self, model: str, task_type: str, quality: float) -> None:
        key = f"{model}:{task_type}"
        if key not in self._model_effectiveness:
            self._model_effectiveness[key] = ModelEffectiveness(model_id=model, task_type=task_type)
        eff = self._model_effectiveness[key]
        eff.uses += 1
        eff.quality_scores.append(quality)
        if len(eff.quality_scores) > 50:
            eff.quality_scores = eff.quality_scores[-25:]

    def get_best_tools(self, top_n: int = 5) -> list[ToolEffectiveness]:
        """Get the most effective tools."""
        tools = list(self._tool_effectiveness.values())
        return sorted(tools, key=lambda t: t.productivity, reverse=True)[:top_n]

    def get_best_models(self, task_type: str = "") -> list[ModelEffectiveness]:
        """Get the best performing models for a task type."""
        models = list(self._model_effectiveness.values())
        if task_type:
            models = [m for m in models if m.task_type == task_type]
        return sorted(models, key=lambda m: m.avg_quality, reverse=True)

    def get_common_failures(self) -> list[str]:
        """Get common failure patterns."""
        failures: dict[str, int] = {}
        for ref in self._reflections:
            if not ref.success:
                for fail in ref.what_failed:
                    failures[fail] = failures.get(fail, 0) + 1
        return [f for f, _ in sorted(failures.items(), key=lambda x: x[1], reverse=True)[:5]]

    def build_reflection_prompt(self) -> str:
        """Build LLM prompt with reflection context."""
        lines = ["## Agent Self-Reflection"]

        total = len(self._reflections)
        successes = sum(1 for r in self._reflections if r.success)
        total_findings = sum(r.findings_count for r in self._reflections)

        lines.append(f"Tasks completed: {total}")
        lines.append(f"Success rate: {successes}/{total} ({successes/max(total,1):.0%})")
        lines.append(f"Total findings: {total_findings}")

        # Best tools
        best = self.get_best_tools(3)
        if best:
            lines.append("\nMost effective tools:")
            for tool in best:
                lines.append(f"  - {tool.tool_name}: {tool.productivity:.1f} findings/use, {tool.precision:.0%} precision")

        # Common failures
        failures = self.get_common_failures()
        if failures:
            lines.append("\nCommon failure patterns:")
            for fail in failures[:3]:
                lines.append(f"  - {fail}")

        # Recent reflections
        if self._reflections:
            lines.append("\nRecent task reflections:")
            for ref in self._reflections[-3:]:
                status = "✓" if ref.success else "✗"
                lines.append(f"  {status} {ref.task_description[:40]} ({ref.findings_count} findings)")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total = len(self._reflections)
        successes = sum(1 for r in self._reflections if r.success)
        return {
            "total_reflections": total,
            "success_rate": f"{successes/max(total,1):.2f}",
            "total_findings": sum(r.findings_count for r in self._reflections),
            "tools_tracked": len(self._tool_effectiveness),
            "models_tracked": len(self._model_effectiveness),
        }
