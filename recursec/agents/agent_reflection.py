"""Agent reflection — self-assessment and improvement through introspection.

Implements:
1. Performance self-assessment after each task
2. Mistake pattern detection
3. Capability gap identification
4. Strategy effectiveness review
5. Confidence calibration (predicted vs actual outcomes)
6. Improvement plan generation
7. Reflection journal persistence
8. Cross-session learning transfer
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ReflectionEntry:
    """A single reflection entry."""
    entry_id: str = ""
    agent_id: str = ""
    task_description: str = ""
    outcome: str = ""              # success, partial, failure
    predicted_confidence: float = 0.5
    actual_confidence: float = 0.5
    mistakes: list[str] = field(default_factory=list)
    lessons: list[str] = field(default_factory=list)
    improvements: list[str] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    model_used: str = ""
    duration_s: float = 0.0
    tokens_used: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def calibration_error(self) -> float:
        """How far off was the confidence prediction?"""
        return abs(self.predicted_confidence - self.actual_confidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entry_id,
            "agent": self.agent_id[:15],
            "outcome": self.outcome,
            "predicted": round(self.predicted_confidence, 2),
            "actual": round(self.actual_confidence, 2),
            "cal_error": round(self.calibration_error, 2),
            "mistakes": len(self.mistakes),
            "lessons": len(self.lessons),
        }


@dataclass
class MistakePattern:
    """A recurring mistake pattern."""
    pattern_id: str = ""
    description: str = ""
    occurrences: int = 0
    severity: float = 0.5
    contexts: list[str] = field(default_factory=list)
    mitigation: str = ""
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "desc": self.description[:60],
            "occurrences": self.occurrences,
            "severity": round(self.severity, 2),
            "mitigation": self.mitigation[:40],
        }


@dataclass
class CapabilityGap:
    """An identified capability gap."""
    gap_id: str = ""
    area: str = ""
    description: str = ""
    frequency: int = 0
    impact: float = 0.5
    suggested_fix: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.gap_id,
            "area": self.area[:20],
            "desc": self.description[:40],
            "frequency": self.frequency,
            "impact": round(self.impact, 2),
        }


@dataclass
class ImprovementPlan:
    """A plan for improvement based on reflection."""
    plan_id: str = ""
    focus_areas: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    expected_improvement: float = 0.0
    priority: float = 0.5
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.plan_id,
            "areas": self.focus_areas[:3],
            "actions": len(self.actions),
            "expected_improvement": round(self.expected_improvement, 2),
        }


# ── Known Mistake Patterns ────────────────────────────────────

KNOWN_MISTAKE_PATTERNS: list[dict[str, Any]] = [
    {
        "desc": "False positive: reported vuln that doesn't exist",
        "severity": 0.8,
        "mitigation": "Cross-validate with second tool and manual verification",
    },
    {
        "desc": "Missed finding: vuln exists but wasn't detected",
        "severity": 0.9,
        "mitigation": "Use multiple scanning tools and techniques",
    },
    {
        "desc": "Wrong severity: misclassified vulnerability severity",
        "severity": 0.6,
        "mitigation": "Apply CVSS scoring consistently and verify with context",
    },
    {
        "desc": "Scope violation: scanned out-of-scope target",
        "severity": 0.9,
        "mitigation": "Always check scope before executing tools",
    },
    {
        "desc": "Tool timeout: tool execution exceeded time limit",
        "severity": 0.4,
        "mitigation": "Set appropriate timeouts and use faster alternatives",
    },
    {
        "desc": "Hallucinated evidence: LLM generated fake evidence",
        "severity": 0.95,
        "mitigation": "Always verify LLM claims against actual tool output",
    },
    {
        "desc": "Infinite loop: agent stuck in reasoning loop",
        "severity": 0.7,
        "mitigation": "Implement convergence detection and max iteration limits",
    },
    {
        "desc": "Resource waste: excessive tokens on low-value task",
        "severity": 0.5,
        "mitigation": "Budget allocation based on expected value of information",
    },
]


class AgentReflection:
    """Self-assessment and improvement through introspection.

    After each task, the agent reflects on performance,
    identifies mistakes, and generates improvement plans.
    """

    def __init__(self, data_dir: str = "data/reflections") -> None:
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._entries: list[ReflectionEntry] = []
        self._mistake_patterns: dict[str, MistakePattern] = {}
        self._capability_gaps: dict[str, CapabilityGap] = {}
        self._improvement_plans: list[ImprovementPlan] = []
        self._entry_counter = 0
        self._pattern_counter = 0
        self._gap_counter = 0
        self._plan_counter = 0
        self._log = logger.bind(component="agent_reflection")

        self._initialize_patterns()

    def _initialize_patterns(self) -> None:
        """Initialize known mistake patterns."""
        for data in KNOWN_MISTAKE_PATTERNS:
            self._pattern_counter += 1
            pattern = MistakePattern(
                pattern_id=f"mp-{self._pattern_counter}",
                description=data["desc"],
                severity=data["severity"],
                mitigation=data["mitigation"],
            )
            self._mistake_patterns[pattern.pattern_id] = pattern

    def reflect(
        self,
        agent_id: str,
        task_description: str,
        outcome: str,
        predicted_confidence: float,
        actual_confidence: float,
        mistakes: list[str] | None = None,
        lessons: list[str] | None = None,
        tools_used: list[str] | None = None,
        model_used: str = "",
        duration_s: float = 0.0,
        tokens_used: int = 0,
    ) -> ReflectionEntry:
        """Record a reflection after task completion."""
        self._entry_counter += 1
        entry = ReflectionEntry(
            entry_id=f"ref-{self._entry_counter}",
            agent_id=agent_id,
            task_description=task_description,
            outcome=outcome,
            predicted_confidence=predicted_confidence,
            actual_confidence=actual_confidence,
            mistakes=mistakes or [],
            lessons=lessons or [],
            tools_used=tools_used or [],
            model_used=model_used,
            duration_s=duration_s,
            tokens_used=tokens_used,
        )

        self._entries.append(entry)

        # Analyze for patterns
        self._detect_patterns(entry)

        # Generate improvements
        entry.improvements = self._suggest_improvements(entry)

        # Persist
        self._save_entry(entry)

        if len(self._entries) > 1000:
            self._entries = self._entries[-1000:]

        return entry

    def _detect_patterns(self, entry: ReflectionEntry) -> None:
        """Detect mistake patterns in reflection."""
        for mistake in entry.mistakes:
            mistake_lower = mistake.lower()
            for pattern in self._mistake_patterns.values():
                # Match keywords from pattern description
                keywords = pattern.description.lower().split()
                matches = sum(1 for kw in keywords if kw in mistake_lower)
                if matches >= 2:
                    pattern.occurrences += 1
                    pattern.last_seen = time.time()
                    if entry.task_description[:60] not in pattern.contexts:
                        pattern.contexts.append(entry.task_description[:60])
                        if len(pattern.contexts) > 10:
                            pattern.contexts = pattern.contexts[-10:]
                    break

    def _suggest_improvements(self, entry: ReflectionEntry) -> list[str]:
        """Generate improvement suggestions."""
        suggestions = []

        # Calibration-based
        if entry.calibration_error > 0.3:
            if entry.predicted_confidence > entry.actual_confidence:
                suggestions.append("Overconfident: lower confidence estimates for similar tasks")
            else:
                suggestions.append("Underconfident: increase confidence for similar tasks")

        # Outcome-based
        if entry.outcome == "failure":
            suggestions.append("Review tool selection and execution approach")
            if entry.mistakes:
                suggestions.append(f"Address mistakes: {entry.mistakes[0][:60]}")

        # Efficiency-based
        if entry.tokens_used > 10000 and entry.outcome != "success":
            suggestions.append("Reduce token usage on failed tasks — fail faster")

        return suggestions

    def identify_capability_gaps(self) -> list[CapabilityGap]:
        """Identify capability gaps from reflection history."""
        failure_areas: dict[str, int] = defaultdict(int)

        for entry in self._entries:
            if entry.outcome == "failure":
                for tool in entry.tools_used:
                    failure_areas[f"tool:{tool}"] += 1
                for mistake in entry.mistakes:
                    area = mistake.split(":")[0] if ":" in mistake else mistake[:30]
                    failure_areas[area] += 1

        gaps = []
        for area, count in sorted(failure_areas.items(), key=lambda x: x[1], reverse=True)[:10]:
            self._gap_counter += 1
            gap = CapabilityGap(
                gap_id=f"gap-{self._gap_counter}",
                area=area,
                description=f"Recurring failures in area: {area}",
                frequency=count,
                impact=min(1.0, count * 0.1),
                suggested_fix=self._suggest_gap_fix(area),
            )
            gaps.append(gap)
            self._capability_gaps[gap.gap_id] = gap

        return gaps

    def _suggest_gap_fix(self, area: str) -> str:
        """Suggest a fix for a capability gap."""
        if area.startswith("tool:"):
            return f"Review usage of {area[5:]} and explore alternatives"
        return f"Increase focus on {area} with more thorough analysis"

    def generate_improvement_plan(self) -> ImprovementPlan:
        """Generate an improvement plan from reflections."""
        self._plan_counter += 1

        # Find top issues
        top_patterns = sorted(
            self._mistake_patterns.values(),
            key=lambda p: p.occurrences * p.severity,
            reverse=True,
        )[:3]

        focus_areas = [p.description[:40] for p in top_patterns]
        actions = [p.mitigation for p in top_patterns if p.mitigation]

        # Calculate calibration stats
        if self._entries:
            avg_cal_error = sum(e.calibration_error for e in self._entries) / len(self._entries)
            if avg_cal_error > 0.2:
                focus_areas.append("Improve confidence calibration")
                actions.append("Track prediction accuracy and adjust confidence scaling")

        plan = ImprovementPlan(
            plan_id=f"plan-{self._plan_counter}",
            focus_areas=focus_areas,
            actions=actions,
            expected_improvement=0.1 * len(actions),
        )

        self._improvement_plans.append(plan)
        return plan

    def get_calibration_stats(self) -> dict[str, Any]:
        """Get confidence calibration statistics."""
        if not self._entries:
            return {"entries": 0}

        errors = [e.calibration_error for e in self._entries]
        outcomes: dict[str, int] = defaultdict(int)
        for entry in self._entries:
            outcomes[entry.outcome] += 1

        return {
            "entries": len(self._entries),
            "avg_cal_error": round(sum(errors) / len(errors), 3),
            "max_cal_error": round(max(errors), 3),
            "min_cal_error": round(min(errors), 3),
            "outcomes": dict(outcomes),
        }

    def _save_entry(self, entry: ReflectionEntry) -> None:
        """Save a reflection entry to disk."""
        path = self._data_dir / f"{entry.entry_id}.json"
        try:
            path.write_text(json.dumps(entry.to_dict(), indent=2, default=str))
        except OSError:
            pass

    def get_recent(self, limit: int = 10) -> list[dict[str, Any]]:
        return [e.to_dict() for e in self._entries[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        return {
            "reflections": len(self._entries),
            "patterns": len(self._mistake_patterns),
            "gaps": len(self._capability_gaps),
            "plans": len(self._improvement_plans),
        }
