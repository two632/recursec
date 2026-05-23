"""Reflection engine — post-action analysis and learning.

After each phase, task, or assessment, the reflection engine:
1. Analyzes what went well and what didn't
2. Identifies patterns in successes and failures
3. Extracts lessons for future assessments
4. Suggests strategy adjustments
5. Evaluates tool effectiveness
6. Detects blind spots and missed opportunities
7. Generates improvement recommendations

Reflection types:
- Micro: After each tool execution or LLM call
- Phase: After each assessment phase completes
- Assessment: After an entire assessment
- Meta: Periodic cross-assessment reflection
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class ReflectionLevel(str, Enum):
    MICRO = "micro"         # After individual actions
    PHASE = "phase"         # After assessment phases
    ASSESSMENT = "assessment"  # After complete assessments
    META = "meta"           # Cross-assessment patterns


class ReflectionCategory(str, Enum):
    STRATEGY = "strategy"
    TOOL_USE = "tool_use"
    COVERAGE = "coverage"
    EFFICIENCY = "efficiency"
    ACCURACY = "accuracy"
    BLIND_SPOT = "blind_spot"


@dataclass
class ReflectionInsight:
    """A single insight from reflection."""
    insight_id: str = ""
    level: ReflectionLevel = ReflectionLevel.MICRO
    category: ReflectionCategory = ReflectionCategory.STRATEGY
    description: str = ""
    lesson: str = ""
    actionable: bool = False
    suggested_action: str = ""
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.insight_id,
            "level": self.level.value,
            "category": self.category.value,
            "description": self.description[:200],
            "lesson": self.lesson[:200],
            "actionable": self.actionable,
            "action": self.suggested_action[:200] if self.actionable else "",
            "confidence": round(self.confidence, 2),
        }


@dataclass
class ReflectionReport:
    """Comprehensive reflection report."""
    level: ReflectionLevel = ReflectionLevel.ASSESSMENT
    insights: list[ReflectionInsight] = field(default_factory=list)
    what_worked: list[str] = field(default_factory=list)
    what_failed: list[str] = field(default_factory=list)
    improvements: list[str] = field(default_factory=list)
    tool_effectiveness: dict[str, float] = field(default_factory=dict)
    coverage_gaps: list[str] = field(default_factory=list)
    overall_quality: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "insights": len(self.insights),
            "worked": self.what_worked[:5],
            "failed": self.what_failed[:5],
            "improvements": self.improvements[:5],
            "coverage_gaps": self.coverage_gaps[:5],
            "quality": round(self.overall_quality, 2),
        }


# ── Prompt Templates ────────────────────────────────────────

MICRO_REFLECT_PROMPT = """Briefly reflect on this action's result.

Action: {action}
Tool used: {tool}
Target: {target}
Result: {result}
Success: {success}
Duration: {duration}s

In 2-3 sentences:
1. Was this the right action?
2. What did we learn?
3. What should we do next?

Respond as JSON:
{{
  "assessment": "good|ok|poor",
  "lesson": "what we learned",
  "next_action": "what to do next",
  "confidence": 0.X
}}"""

PHASE_REFLECT_PROMPT = """Reflect on this completed assessment phase.

Phase: {phase}
Tasks completed: {tasks_completed}
Tasks failed: {tasks_failed}
Findings: {findings_count}
Duration: {duration}s
Tools used: {tools_used}

Analyze:
1. What went well in this phase?
2. What could have been done better?
3. Were the right tools used?
4. What coverage gaps exist?
5. What should the next phase focus on?

Respond as JSON:
{{
  "what_worked": ["things that went well"],
  "what_failed": ["things that didn't work"],
  "improvements": ["suggestions for improvement"],
  "coverage_gaps": ["areas not adequately tested"],
  "tool_effectiveness": {{"tool_name": 0.X}},
  "next_phase_focus": ["priorities for next phase"],
  "quality": 0.X
}}"""

ASSESSMENT_REFLECT_PROMPT = """Reflect on this completed security assessment.

Target: {target}
Goal: {goal}
Duration: {duration}s
Total findings: {findings_count}
Critical findings: {critical_count}
Phases completed: {phases}
Agents used: {agents_count}
Tools used: {tools_used}

Top findings:
{top_findings}

Analyze comprehensively:
1. Was the assessment thorough?
2. Were the right strategies used?
3. What was missed?
4. How could coverage be improved?
5. Were there efficiency issues?
6. What lessons should be learned for future assessments?

Respond as JSON:
{{
  "thoroughness": 0.X,
  "what_worked": ["successful strategies"],
  "what_failed": ["unsuccessful approaches"],
  "missed_areas": ["things we should have tested"],
  "efficiency_issues": ["time/resource waste"],
  "key_lessons": ["important takeaways"],
  "improvements": ["concrete suggestions"],
  "overall_quality": 0.X
}}"""


class ReflectionEngine:
    """Reflection engine for post-action analysis and learning.

    Analyzes actions, phases, and assessments to extract
    lessons and improve future performance.
    """

    def __init__(self, model_router: ModelRouter | None = None) -> None:
        self._router = model_router
        self._insights: list[ReflectionInsight] = []
        self._reports: list[ReflectionReport] = []
        self._insight_counter = 0
        self._log = logger.bind(component="reflection")

    async def reflect_micro(
        self,
        action: str,
        tool: str,
        target: str,
        result: str,
        success: bool,
        duration_s: float,
    ) -> ReflectionInsight:
        """Micro-reflection after a single action."""
        insight = ReflectionInsight(
            level=ReflectionLevel.MICRO,
            category=ReflectionCategory.TOOL_USE,
        )

        if self._router:
            prompt = MICRO_REFLECT_PROMPT.format(
                action=action[:200], tool=tool, target=target,
                result=result[:500], success=success,
                duration=round(duration_s, 1),
            )

            response = await self._router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type="reasoning",
                temperature=0.2,
                max_tokens=256,
            )

            data = self._parse_json(response)
            insight.description = data.get("lesson", "")
            insight.lesson = data.get("lesson", "")
            insight.suggested_action = data.get("next_action", "")
            insight.actionable = bool(insight.suggested_action)
            insight.confidence = data.get("confidence", 0.5)
        else:
            insight.description = f"{'Success' if success else 'Failure'}: {action[:100]}"
            insight.lesson = f"Tool {tool} {'worked' if success else 'failed'} on {target}"

        return self._store_insight(insight)

    async def reflect_phase(
        self,
        phase: str,
        tasks_completed: int,
        tasks_failed: int,
        findings_count: int,
        duration_s: float,
        tools_used: list[str],
    ) -> ReflectionReport:
        """Reflection after an assessment phase."""
        report = ReflectionReport(level=ReflectionLevel.PHASE)

        if self._router:
            prompt = PHASE_REFLECT_PROMPT.format(
                phase=phase,
                tasks_completed=tasks_completed,
                tasks_failed=tasks_failed,
                findings_count=findings_count,
                duration=round(duration_s, 1),
                tools_used=", ".join(tools_used[:10]),
            )

            response = await self._router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type="reasoning",
                temperature=0.3,
                max_tokens=512,
            )

            data = self._parse_json(response)
            report.what_worked = data.get("what_worked", [])
            report.what_failed = data.get("what_failed", [])
            report.improvements = data.get("improvements", [])
            report.coverage_gaps = data.get("coverage_gaps", [])
            report.tool_effectiveness = data.get("tool_effectiveness", {})
            report.overall_quality = data.get("quality", 0.5)

            # Convert improvements to insights
            for improvement in report.improvements[:5]:
                insight = ReflectionInsight(
                    level=ReflectionLevel.PHASE,
                    category=ReflectionCategory.STRATEGY,
                    description=improvement,
                    lesson=improvement,
                    actionable=True,
                    suggested_action=improvement,
                )
                self._store_insight(insight)

        else:
            report.overall_quality = findings_count / max(1, tasks_completed) if tasks_completed > 0 else 0
            if tasks_failed > 0:
                report.what_failed.append(f"{tasks_failed} tasks failed")
            report.what_worked.append(f"Completed {tasks_completed} tasks")

        self._reports.append(report)
        return report

    async def reflect_assessment(
        self,
        target: str,
        goal: str,
        duration_s: float,
        findings: list[dict[str, Any]],
        phases: list[str],
        agents_count: int,
        tools_used: list[str],
    ) -> ReflectionReport:
        """Full reflection after an assessment."""
        report = ReflectionReport(level=ReflectionLevel.ASSESSMENT)
        critical_count = sum(1 for f in findings if f.get("severity") == "critical")

        top_findings_text = "\n".join(
            f"- [{f.get('severity', 'N/A')}] {f.get('title', 'N/A')}"
            for f in findings[:10]
        )

        if self._router:
            prompt = ASSESSMENT_REFLECT_PROMPT.format(
                target=target, goal=goal[:200],
                duration=round(duration_s, 1),
                findings_count=len(findings),
                critical_count=critical_count,
                phases=", ".join(phases),
                agents_count=agents_count,
                tools_used=", ".join(tools_used[:15]),
                top_findings=top_findings_text or "None",
            )

            response = await self._router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type="reasoning",
                temperature=0.3,
                max_tokens=1024,
            )

            data = self._parse_json(response)
            report.what_worked = data.get("what_worked", [])
            report.what_failed = data.get("what_failed", [])
            report.improvements = data.get("improvements", [])
            report.coverage_gaps = data.get("missed_areas", [])
            report.overall_quality = data.get("overall_quality", 0.5)

            for lesson in data.get("key_lessons", []):
                insight = ReflectionInsight(
                    level=ReflectionLevel.ASSESSMENT,
                    category=ReflectionCategory.STRATEGY,
                    description=lesson,
                    lesson=lesson,
                )
                self._store_insight(insight)

        else:
            report.overall_quality = min(1.0, len(findings) * 0.05)
            report.what_worked.append(f"Found {len(findings)} findings")

        self._reports.append(report)
        return report

    def reflect_meta(self) -> ReflectionReport:
        """Cross-assessment meta-reflection using accumulated insights."""
        report = ReflectionReport(level=ReflectionLevel.META)

        # Analyze patterns across all insights
        category_counts: dict[str, int] = defaultdict(int)
        for insight in self._insights:
            category_counts[insight.category.value] += 1

        # Find most common improvement areas
        lesson_freq: dict[str, int] = defaultdict(int)
        for insight in self._insights:
            if insight.lesson:
                key = insight.lesson[:50]
                lesson_freq[key] += 1

        # Generate meta-insights
        if category_counts:
            most_common = max(category_counts, key=category_counts.get)
            report.improvements.append(
                f"Most frequent issue area: {most_common} ({category_counts[most_common]} instances)"
            )

        # Calculate average quality from assessment reports
        assessment_reports = [r for r in self._reports if r.level == ReflectionLevel.ASSESSMENT]
        if assessment_reports:
            report.overall_quality = sum(r.overall_quality for r in assessment_reports) / len(assessment_reports)

        self._reports.append(report)
        return report

    # ── Insight Management ───────────────────────────────

    def _store_insight(self, insight: ReflectionInsight) -> ReflectionInsight:
        self._insight_counter += 1
        insight.insight_id = f"insight-{self._insight_counter}"
        self._insights.append(insight)
        if len(self._insights) > 1000:
            self._insights = self._insights[-1000:]
        return insight

    def get_insights(
        self,
        level: ReflectionLevel | None = None,
        category: ReflectionCategory | None = None,
        actionable_only: bool = False,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Get insights, optionally filtered."""
        insights = self._insights
        if level:
            insights = [i for i in insights if i.level == level]
        if category:
            insights = [i for i in insights if i.category == category]
        if actionable_only:
            insights = [i for i in insights if i.actionable]
        return [i.to_dict() for i in insights[-limit:]]

    def get_reports(self, limit: int = 10) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._reports[-limit:]]

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}

    def get_stats(self) -> dict[str, Any]:
        by_level: dict[str, int] = defaultdict(int)
        by_category: dict[str, int] = defaultdict(int)
        for i in self._insights:
            by_level[i.level.value] += 1
            by_category[i.category.value] += 1
        return {
            "total_insights": len(self._insights),
            "total_reports": len(self._reports),
            "by_level": dict(by_level),
            "by_category": dict(by_category),
        }
