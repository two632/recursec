"""Agent self-reflection — metacognitive monitoring and self-improvement.

Implements systematic self-reflection for agents:
1. Action review: Was the last action effective?
2. Strategy assessment: Is the current approach working?
3. Knowledge gaps: What don't we know that we should?
4. Blind spot detection: What are we missing?
5. Bias detection: Are we favoring certain approaches?
6. Performance monitoring: Are we getting better or worse?
7. Self-critique: What would a human expert do differently?

Reflection happens at three scales:
- Micro: After each action (quick check)
- Meso: After each phase (strategy review)
- Macro: After assessment (full retrospective)
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


class ReflectionScale(str, Enum):
    MICRO = "micro"    # After each action
    MESO = "meso"      # After each phase
    MACRO = "macro"    # After full assessment


class InsightType(str, Enum):
    STRATEGY_CHANGE = "strategy_change"
    KNOWLEDGE_GAP = "knowledge_gap"
    BLIND_SPOT = "blind_spot"
    BIAS_DETECTED = "bias_detected"
    EFFICIENCY_ISSUE = "efficiency_issue"
    MISSED_OPPORTUNITY = "missed_opportunity"
    SUCCESS_PATTERN = "success_pattern"
    FAILURE_PATTERN = "failure_pattern"


@dataclass
class Insight:
    """An insight from self-reflection."""
    insight_type: InsightType
    description: str
    severity: str = "medium"  # low, medium, high
    actionable: bool = True
    suggested_action: str = ""
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.insight_type.value,
            "description": self.description[:200],
            "severity": self.severity,
            "actionable": self.actionable,
            "action": self.suggested_action[:200],
            "confidence": round(self.confidence, 2),
        }


@dataclass
class ReflectionResult:
    """Result of a reflection session."""
    scale: ReflectionScale
    insights: list[Insight] = field(default_factory=list)
    overall_assessment: str = ""
    confidence: float = 0.5
    should_change_approach: bool = False
    suggested_changes: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scale": self.scale.value,
            "insights": [i.to_dict() for i in self.insights],
            "assessment": self.overall_assessment[:300],
            "confidence": round(self.confidence, 2),
            "change_approach": self.should_change_approach,
            "changes": self.suggested_changes[:5],
        }


# ── Prompt Templates ────────────────────────────────────────

MICRO_REFLECTION_PROMPT = """Quickly review the last action. Was it effective?

Action: {action}
Result: {result}
Goal: {goal}

In 2-3 sentences: Was this useful? Should we adjust our approach?
Respond as JSON:
{{
  "effective": true/false,
  "insight": "what we learned",
  "adjustment": "what to change (or empty)",
  "confidence": 0.X
}}"""

MESO_REFLECTION_PROMPT = """Review the current phase of security assessment.

Phase: {phase}
Actions taken so far: {actions}
Findings so far: {findings}
Goals: {goals}
Time elapsed: {elapsed_s}s
Budget remaining: {budget}

Analyze:
1. Are we making good progress?
2. What are we missing?
3. Are we biased toward certain approaches?
4. What would an expert do differently?
5. Should we change strategy?

Respond as JSON:
{{
  "progress_assessment": "good|fair|poor",
  "missing": ["things we should check"],
  "biases": ["detected biases"],
  "expert_would": ["what an expert would do"],
  "change_strategy": true/false,
  "strategy_suggestion": "...",
  "knowledge_gaps": ["what we don't know"],
  "confidence": 0.X
}}"""

MACRO_REFLECTION_PROMPT = """Conduct a full retrospective of this security assessment.

Target: {target}
Total actions: {total_actions}
Total findings: {findings_count}
Findings by severity: {by_severity}
Phases completed: {phases}
Total time: {total_time_s}s
Tools used: {tools_used}
Models used: {models_used}

Retrospective questions:
1. What went well?
2. What went poorly?
3. What vulnerabilities might we have missed?
4. Were our tool selections optimal?
5. Was our model usage efficient?
6. What would we do differently next time?
7. Overall confidence in the assessment completeness?

Respond as JSON:
{{
  "what_went_well": ["..."],
  "what_went_poorly": ["..."],
  "potentially_missed": ["vulnerability types we may have missed"],
  "tool_optimization": "suggestions for better tool usage",
  "model_optimization": "suggestions for better model usage",
  "improvements": ["what to do differently"],
  "completeness_confidence": 0.X,
  "overall_quality": "excellent|good|fair|poor"
}}"""

BLIND_SPOT_PROMPT = """Identify potential blind spots in this security assessment.

Target type: {target_type}
Approaches used: {approaches}
Findings: {findings}
Tools NOT used: {unused_tools}
Areas NOT tested: {untested_areas}

What are we likely missing? What attack vectors have we overlooked?
Consider: supply chain, social engineering, physical, wireless, insider threats,
logic bugs, race conditions, business logic, API abuse, etc.

Respond as JSON:
{{
  "blind_spots": [
    {{
      "area": "description of blind spot",
      "severity": "high|medium|low",
      "recommendation": "how to address it"
    }}
  ]
}}"""

BIAS_DETECTION_PROMPT = """Analyze these security assessment actions for cognitive biases.

Action history: {actions}
Finding distribution: {findings}
Tool usage distribution: {tool_usage}

Check for:
1. Confirmation bias (only looking for expected vulns)
2. Anchoring (over-focusing on first finding)
3. Availability bias (using familiar tools over better ones)
4. Automation bias (trusting tool output without verification)
5. Recency bias (over-weighting recent findings)

Respond as JSON:
{{
  "biases_detected": [
    {{
      "bias_type": "...",
      "evidence": "...",
      "impact": "high|medium|low",
      "mitigation": "..."
    }}
  ],
  "overall_bias_risk": "high|medium|low"
}}"""


class ReflectionEngine:
    """Metacognitive monitoring and self-improvement for agents.

    Implements systematic self-reflection at multiple scales to
    detect problems, identify blind spots, and improve performance.
    """

    def __init__(self, model_router: ModelRouter) -> None:
        self._router = model_router
        self._insights: list[Insight] = []
        self._reflections: list[ReflectionResult] = []
        self._action_history: list[dict[str, Any]] = []
        self._log = logger.bind(component="reflection")

    async def micro_reflect(
        self,
        action: dict[str, Any],
        result: dict[str, Any],
        goal: str = "",
    ) -> ReflectionResult:
        """Quick reflection after a single action."""
        prompt = MICRO_REFLECTION_PROMPT.format(
            action=json.dumps(action)[:500],
            result=json.dumps(result)[:500],
            goal=goal[:200],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="fast",
            temperature=0.1,
            max_tokens=256,
        )

        data = self._parse_json(response)
        rr = ReflectionResult(scale=ReflectionScale.MICRO)

        if not data.get("effective", True):
            rr.insights.append(Insight(
                insight_type=InsightType.EFFICIENCY_ISSUE,
                description=data.get("insight", "Action was not effective"),
                suggested_action=data.get("adjustment", ""),
                confidence=data.get("confidence", 0.5),
            ))
            rr.should_change_approach = bool(data.get("adjustment"))

        rr.confidence = data.get("confidence", 0.5)
        self._action_history.append(action)
        self._reflections.append(rr)

        return rr

    async def meso_reflect(
        self,
        phase: str,
        actions: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        goals: list[str],
        elapsed_s: float = 0.0,
        budget_remaining: dict[str, Any] | None = None,
    ) -> ReflectionResult:
        """Phase-level reflection — assess overall strategy."""
        actions_summary = json.dumps([
            {"type": a.get("type", ""), "tool": a.get("tool", ""), "success": a.get("success", False)}
            for a in actions[-20:]
        ])

        prompt = MESO_REFLECTION_PROMPT.format(
            phase=phase,
            actions=actions_summary,
            findings=json.dumps(findings[:10])[:1000],
            goals=json.dumps(goals),
            elapsed_s=round(elapsed_s),
            budget=json.dumps(budget_remaining or {}),
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=1024,
        )

        data = self._parse_json(response)
        rr = ReflectionResult(scale=ReflectionScale.MESO)

        # Extract insights
        for gap in data.get("knowledge_gaps", []):
            rr.insights.append(Insight(
                insight_type=InsightType.KNOWLEDGE_GAP,
                description=gap,
                suggested_action=f"Investigate: {gap}",
            ))

        for bias in data.get("biases", []):
            rr.insights.append(Insight(
                insight_type=InsightType.BIAS_DETECTED,
                description=bias,
                severity="medium",
            ))

        for missing in data.get("missing", []):
            rr.insights.append(Insight(
                insight_type=InsightType.BLIND_SPOT,
                description=missing,
                suggested_action=f"Check: {missing}",
            ))

        for expert_action in data.get("expert_would", []):
            rr.insights.append(Insight(
                insight_type=InsightType.MISSED_OPPORTUNITY,
                description=expert_action,
            ))

        rr.should_change_approach = data.get("change_strategy", False)
        if data.get("strategy_suggestion"):
            rr.suggested_changes.append(data["strategy_suggestion"])

        rr.overall_assessment = data.get("progress_assessment", "fair")
        rr.confidence = data.get("confidence", 0.5)

        self._insights.extend(rr.insights)
        self._reflections.append(rr)

        self._log.info(
            "meso_reflection",
            insights=len(rr.insights),
            change_approach=rr.should_change_approach,
        )

        return rr

    async def macro_reflect(
        self,
        target: str,
        total_actions: int,
        findings: list[dict[str, Any]],
        phases_completed: list[str],
        total_time_s: float,
        tools_used: list[str],
        models_used: list[str],
    ) -> ReflectionResult:
        """Full retrospective after assessment completion."""
        by_severity: dict[str, int] = defaultdict(int)
        for f in findings:
            sev = f.get("severity", "info")
            by_severity[sev] += 1

        prompt = MACRO_REFLECTION_PROMPT.format(
            target=target,
            total_actions=total_actions,
            findings_count=len(findings),
            by_severity=json.dumps(dict(by_severity)),
            phases=json.dumps(phases_completed),
            total_time_s=round(total_time_s),
            tools_used=json.dumps(tools_used[:20]),
            models_used=json.dumps(models_used[:10]),
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.3,
            max_tokens=2048,
        )

        data = self._parse_json(response)
        rr = ReflectionResult(scale=ReflectionScale.MACRO)

        for item in data.get("what_went_well", []):
            rr.insights.append(Insight(
                insight_type=InsightType.SUCCESS_PATTERN,
                description=item,
            ))

        for item in data.get("what_went_poorly", []):
            rr.insights.append(Insight(
                insight_type=InsightType.FAILURE_PATTERN,
                description=item,
                severity="high",
            ))

        for item in data.get("potentially_missed", []):
            rr.insights.append(Insight(
                insight_type=InsightType.BLIND_SPOT,
                description=item,
                severity="high",
                suggested_action=f"Test for: {item}",
            ))

        for item in data.get("improvements", []):
            rr.suggested_changes.append(item)

        rr.overall_assessment = data.get("overall_quality", "fair")
        rr.confidence = data.get("completeness_confidence", 0.5)

        self._insights.extend(rr.insights)
        self._reflections.append(rr)

        return rr

    async def detect_blind_spots(
        self,
        target_type: str,
        approaches_used: list[str],
        findings: list[dict[str, Any]],
        unused_tools: list[str],
        untested_areas: list[str],
    ) -> list[Insight]:
        """Specifically check for blind spots."""
        prompt = BLIND_SPOT_PROMPT.format(
            target_type=target_type,
            approaches=json.dumps(approaches_used),
            findings=json.dumps(findings[:10])[:1000],
            unused_tools=json.dumps(unused_tools[:20]),
            untested_areas=json.dumps(untested_areas),
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="security",
            temperature=0.3,
            max_tokens=1024,
        )

        data = self._parse_json(response)
        insights = []
        for bs in data.get("blind_spots", []):
            insight = Insight(
                insight_type=InsightType.BLIND_SPOT,
                description=bs.get("area", ""),
                severity=bs.get("severity", "medium"),
                suggested_action=bs.get("recommendation", ""),
            )
            insights.append(insight)
            self._insights.append(insight)

        return insights

    async def detect_biases(
        self,
        actions: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        tool_usage: dict[str, int],
    ) -> list[Insight]:
        """Detect cognitive biases in the assessment approach."""
        prompt = BIAS_DETECTION_PROMPT.format(
            actions=json.dumps([
                {"type": a.get("type", ""), "tool": a.get("tool", "")}
                for a in actions[-30:]
            ]),
            findings=json.dumps([
                {"severity": f.get("severity", ""), "category": f.get("category", "")}
                for f in findings
            ]),
            tool_usage=json.dumps(tool_usage),
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=1024,
        )

        data = self._parse_json(response)
        insights = []
        for bias in data.get("biases_detected", []):
            insight = Insight(
                insight_type=InsightType.BIAS_DETECTED,
                description=f"{bias.get('bias_type', '')}: {bias.get('evidence', '')}",
                severity=bias.get("impact", "medium"),
                suggested_action=bias.get("mitigation", ""),
            )
            insights.append(insight)
            self._insights.append(insight)

        return insights

    def get_all_insights(self, min_severity: str = "low") -> list[dict[str, Any]]:
        """Get all accumulated insights."""
        severity_order = {"low": 0, "medium": 1, "high": 2}
        min_level = severity_order.get(min_severity, 0)
        return [
            i.to_dict() for i in self._insights
            if severity_order.get(i.severity, 0) >= min_level
        ]

    def get_summary(self) -> dict[str, Any]:
        by_type: dict[str, int] = defaultdict(int)
        for i in self._insights:
            by_type[i.insight_type.value] += 1
        return {
            "total_reflections": len(self._reflections),
            "total_insights": len(self._insights),
            "by_type": dict(by_type),
            "micro": sum(1 for r in self._reflections if r.scale == ReflectionScale.MICRO),
            "meso": sum(1 for r in self._reflections if r.scale == ReflectionScale.MESO),
            "macro": sum(1 for r in self._reflections if r.scale == ReflectionScale.MACRO),
        }

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}
