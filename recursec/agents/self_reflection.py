"""Self-reflection engine — agent introspection.

The agent reviews its own performance and adapts:
1. Assess reasoning quality
2. Detect reasoning errors
3. Identify missed opportunities
4. Calibrate confidence levels
5. Generate improvement suggestions
6. Track performance over time
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ReflectionType(str, Enum):
    TASK_REVIEW = "task_review"       # After completing a task
    PHASE_REVIEW = "phase_review"     # After completing a phase
    FINDING_REVIEW = "finding_review" # After a finding
    ERROR_REVIEW = "error_review"     # After an error
    PERIODIC = "periodic"             # Periodic check-in
    FINAL = "final"                   # End of assessment


class ReflectionArea(str, Enum):
    COVERAGE = "coverage"               # Was enough checked?
    DEPTH = "depth"                     # Was checking deep enough?
    ACCURACY = "accuracy"               # Were findings accurate?
    EFFICIENCY = "efficiency"           # Was time used well?
    TOOL_USAGE = "tool_usage"           # Right tools used?
    MODEL_SELECTION = "model_selection" # Right models chosen?
    REASONING = "reasoning"             # Sound reasoning?
    MISSED_VULNS = "missed_vulns"       # What was missed?


class PerformanceLevel(str, Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    ADEQUATE = "adequate"
    POOR = "poor"
    CRITICAL = "critical"


@dataclass
class ReflectionEntry:
    """A single reflection entry."""
    reflection_id: str = ""
    reflection_type: ReflectionType = ReflectionType.PERIODIC
    area: ReflectionArea = ReflectionArea.COVERAGE
    performance: PerformanceLevel = PerformanceLevel.ADEQUATE
    observation: str = ""
    suggestion: str = ""
    confidence: float = 0.5
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.reflection_id[:8],
            "type": self.reflection_type.value[:8],
            "area": self.area.value[:10],
            "perf": self.performance.value[:8],
            "conf": f"{self.confidence:.2f}",
        }


@dataclass
class PerformanceSnapshot:
    """A point-in-time performance snapshot."""
    timestamp: float = field(default_factory=time.time)
    total_findings: int = 0
    confirmed_findings: int = 0
    false_positives: int = 0
    tools_run: int = 0
    tokens_used: int = 0
    phases_completed: int = 0
    coverage_pct: float = 0.0

    @property
    def accuracy_pct(self) -> float:
        total = self.confirmed_findings + self.false_positives
        if total == 0:
            return 100.0
        return (self.confirmed_findings / total) * 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": self.total_findings,
            "confirmed": self.confirmed_findings,
            "fp": self.false_positives,
            "accuracy": f"{self.accuracy_pct:.0f}%",
            "coverage": f"{self.coverage_pct:.0f}%",
        }


# Reflection prompts for each area
REFLECTION_PROMPTS: dict[ReflectionArea, str] = {
    ReflectionArea.COVERAGE: (
        "Assess attack surface coverage:\n"
        "- Were all target components enumerated?\n"
        "- Were all service ports checked?\n"
        "- Were all web endpoints crawled?\n"
        "- Were all technologies identified?\n"
        "- Are there blind spots in the assessment?"
    ),
    ReflectionArea.DEPTH: (
        "Assess testing depth:\n"
        "- Were vulnerabilities tested beyond automated scanning?\n"
        "- Were business logic flaws checked?\n"
        "- Were authentication mechanisms tested thoroughly?\n"
        "- Were authorization checks comprehensive?\n"
        "- Were edge cases and chained attacks explored?"
    ),
    ReflectionArea.ACCURACY: (
        "Assess finding accuracy:\n"
        "- Were all findings confirmed with proof?\n"
        "- Were false positives identified and removed?\n"
        "- Were severity ratings calibrated correctly?\n"
        "- Were CVSS scores accurate?\n"
        "- Were remediation suggestions practical?"
    ),
    ReflectionArea.EFFICIENCY: (
        "Assess time/resource efficiency:\n"
        "- Was the token budget used wisely?\n"
        "- Were redundant scans avoided?\n"
        "- Were the right tools selected first?\n"
        "- Was parallelism used effectively?\n"
        "- Were there wasted LLM calls?"
    ),
    ReflectionArea.TOOL_USAGE: (
        "Assess tool usage:\n"
        "- Were the optimal tools selected for each task?\n"
        "- Were tool outputs parsed and used effectively?\n"
        "- Were tool chains used to combine results?\n"
        "- Were any important tools overlooked?\n"
        "- Were tool configurations optimal?"
    ),
    ReflectionArea.MODEL_SELECTION: (
        "Assess model selection:\n"
        "- Was WhiteRabbitNeo used for security tasks?\n"
        "- Was Qwen-Coder used for code analysis?\n"
        "- Was DeepSeek-R1 used for complex reasoning?\n"
        "- Was Yi-200K used for long context analysis?\n"
        "- Were fast models used for simple tasks?"
    ),
    ReflectionArea.REASONING: (
        "Assess reasoning quality:\n"
        "- Were conclusions supported by evidence?\n"
        "- Were hypotheses tested before claiming?\n"
        "- Were alternative explanations considered?\n"
        "- Were reasoning chains logical?\n"
        "- Were assumptions made explicit?"
    ),
    ReflectionArea.MISSED_VULNS: (
        "Assess for missed vulnerabilities:\n"
        "- Were authentication endpoints all tested?\n"
        "- Were file upload functions checked?\n"
        "- Were API endpoints individually tested?\n"
        "- Were privilege boundaries verified?\n"
        "- Were race conditions considered?"
    ),
}

# Phase → what to reflect on
PHASE_REFLECTION_MAP: dict[str, list[ReflectionArea]] = {
    "recon": [
        ReflectionArea.COVERAGE,
        ReflectionArea.EFFICIENCY,
        ReflectionArea.TOOL_USAGE,
    ],
    "scanning": [
        ReflectionArea.COVERAGE,
        ReflectionArea.DEPTH,
        ReflectionArea.ACCURACY,
        ReflectionArea.TOOL_USAGE,
    ],
    "exploitation": [
        ReflectionArea.ACCURACY,
        ReflectionArea.REASONING,
        ReflectionArea.MISSED_VULNS,
        ReflectionArea.MODEL_SELECTION,
    ],
    "validation": [
        ReflectionArea.ACCURACY,
        ReflectionArea.DEPTH,
        ReflectionArea.REASONING,
    ],
    "reporting": [
        ReflectionArea.COVERAGE,
        ReflectionArea.ACCURACY,
        ReflectionArea.MISSED_VULNS,
    ],
}


class SelfReflection:
    """Agent self-reflection engine.

    Enables the agent to critically evaluate
    its own performance and adapt its strategy.
    """

    def __init__(self) -> None:
        self._entries: list[ReflectionEntry] = []
        self._snapshots: list[PerformanceSnapshot] = []
        self._entry_counter = 0
        self._log = logger.bind(component="reflection")

    def reflect_on_phase(
        self,
        phase: str,
        snapshot: PerformanceSnapshot | None = None,
    ) -> list[ReflectionEntry]:
        """Generate reflection entries for a phase."""
        areas = PHASE_REFLECTION_MAP.get(
            phase,
            [ReflectionArea.COVERAGE, ReflectionArea.ACCURACY],
        )

        entries: list[ReflectionEntry] = []
        for area in areas:
            self._entry_counter += 1
            entry = ReflectionEntry(
                reflection_id=f"ref-{self._entry_counter}",
                reflection_type=ReflectionType.PHASE_REVIEW,
                area=area,
            )

            # Auto-assess based on snapshot
            if snapshot:
                entry = self._auto_assess(entry, snapshot)

            entries.append(entry)
            self._entries.append(entry)

        if snapshot:
            self._snapshots.append(snapshot)

        return entries

    def _auto_assess(
        self,
        entry: ReflectionEntry,
        snapshot: PerformanceSnapshot,
    ) -> ReflectionEntry:
        """Auto-assess performance from snapshot."""
        if entry.area == ReflectionArea.ACCURACY:
            accuracy = snapshot.accuracy_pct
            if accuracy >= 95:
                entry.performance = PerformanceLevel.EXCELLENT
                entry.confidence = 0.9
            elif accuracy >= 80:
                entry.performance = PerformanceLevel.GOOD
                entry.confidence = 0.7
            elif accuracy >= 60:
                entry.performance = PerformanceLevel.ADEQUATE
                entry.confidence = 0.5
            else:
                entry.performance = PerformanceLevel.POOR
                entry.suggestion = "Review false positive detection"
                entry.confidence = 0.3

        elif entry.area == ReflectionArea.COVERAGE:
            coverage = snapshot.coverage_pct
            if coverage >= 90:
                entry.performance = PerformanceLevel.EXCELLENT
            elif coverage >= 70:
                entry.performance = PerformanceLevel.GOOD
            elif coverage >= 50:
                entry.performance = PerformanceLevel.ADEQUATE
                entry.suggestion = "Expand scanning scope"
            else:
                entry.performance = PerformanceLevel.POOR
                entry.suggestion = "Significant coverage gaps detected"

        elif entry.area == ReflectionArea.EFFICIENCY:
            if snapshot.tokens_used > 0 and snapshot.total_findings > 0:
                tokens_per_finding = snapshot.tokens_used / snapshot.total_findings
                if tokens_per_finding < 500:
                    entry.performance = PerformanceLevel.EXCELLENT
                elif tokens_per_finding < 1000:
                    entry.performance = PerformanceLevel.GOOD
                elif tokens_per_finding < 2000:
                    entry.performance = PerformanceLevel.ADEQUATE
                else:
                    entry.performance = PerformanceLevel.POOR
                    entry.suggestion = "Optimize token usage"

        return entry

    def reflect_on_finding(
        self,
        finding_type: str,
        confirmed: bool,
    ) -> ReflectionEntry:
        """Reflect on a specific finding."""
        self._entry_counter += 1
        entry = ReflectionEntry(
            reflection_id=f"ref-{self._entry_counter}",
            reflection_type=ReflectionType.FINDING_REVIEW,
            area=ReflectionArea.ACCURACY,
        )

        if confirmed:
            entry.performance = PerformanceLevel.GOOD
            entry.observation = f"Finding {finding_type} confirmed"
            entry.confidence = 0.8
        else:
            entry.performance = PerformanceLevel.POOR
            entry.observation = f"Finding {finding_type} was false positive"
            entry.suggestion = "Improve validation before reporting"
            entry.confidence = 0.4

        self._entries.append(entry)
        return entry

    def get_improvement_suggestions(self) -> list[str]:
        """Get suggestions from reflection."""
        suggestions: list[str] = []
        for entry in self._entries:
            if entry.suggestion:
                suggestions.append(entry.suggestion)
        return list(set(suggestions))

    def get_performance_trend(self) -> str:
        """Get performance trend description."""
        if len(self._snapshots) < 2:
            return "insufficient_data"

        recent = self._snapshots[-1]
        previous = self._snapshots[-2]

        if recent.accuracy_pct > previous.accuracy_pct:
            return "improving"
        elif recent.accuracy_pct < previous.accuracy_pct:
            return "declining"
        return "stable"

    def build_reflection_prompt(self, phase: str = "") -> str:
        """Build reflection context for LLM."""
        lines = ["## Self-Reflection\n"]

        # Overall stats
        total = len(self._entries)
        poor = sum(
            1 for e in self._entries
            if e.performance == PerformanceLevel.POOR
        )
        good = sum(
            1 for e in self._entries
            if e.performance in (PerformanceLevel.GOOD, PerformanceLevel.EXCELLENT)
        )
        lines.append(f"Reflections: {total} (good={good}, poor={poor})")

        # Phase-specific prompt
        if phase:
            areas = PHASE_REFLECTION_MAP.get(phase, [])
            for area in areas[:2]:
                area_prompt = REFLECTION_PROMPTS.get(area, "")
                if area_prompt:
                    lines.append(f"\n{area_prompt[:80]}...")

        # Suggestions
        suggestions = self.get_improvement_suggestions()
        if suggestions:
            lines.append("\nSuggestions:")
            for sug in suggestions[:3]:
                lines.append(f"  - {sug}")

        # Trend
        trend = self.get_performance_trend()
        lines.append(f"\nTrend: {trend}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        perf_counts: dict[str, int] = {}
        for e in self._entries:
            perf_counts[e.performance.value] = (
                perf_counts.get(e.performance.value, 0) + 1
            )

        return {
            "reflections": len(self._entries),
            "snapshots": len(self._snapshots),
            "suggestions": len(self.get_improvement_suggestions()),
            "trend": self.get_performance_trend(),
            "by_performance": perf_counts,
        }
