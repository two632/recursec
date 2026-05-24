"""Self-improvement engine — the agent learns and gets better over time.

Implements:
1. Performance tracking per strategy/tool/model/KB
2. Automatic parameter tuning based on results
3. Strategy evolution (promote successful, demote failing)
4. Knowledge gap detection and filling
5. Tool reliability scoring
6. Model quality tracking per task type
7. Prompt effectiveness measurement
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MetricType(str, Enum):
    TOOL_RELIABILITY = "tool_reliability"
    MODEL_QUALITY = "model_quality"
    STRATEGY_EFFECTIVENESS = "strategy_effectiveness"
    KB_RELEVANCE = "kb_relevance"
    PROMPT_EFFECTIVENESS = "prompt_effectiveness"
    FINDING_ACCURACY = "finding_accuracy"
    PHASE_EFFICIENCY = "phase_efficiency"


@dataclass
class PerformanceMetric:
    """A tracked performance metric."""
    metric_id: str = ""
    metric_type: MetricType = MetricType.TOOL_RELIABILITY
    subject: str = ""
    total_uses: int = 0
    successes: int = 0
    failures: int = 0
    total_duration_s: float = 0.0
    total_findings: int = 0
    total_tokens: int = 0
    false_positive_count: int = 0
    last_updated: float = field(default_factory=time.time)

    @property
    def success_rate(self) -> float:
        if self.total_uses == 0:
            return 0.0
        return self.successes / self.total_uses

    @property
    def avg_duration(self) -> float:
        if self.total_uses == 0:
            return 0.0
        return self.total_duration_s / self.total_uses

    @property
    def avg_findings_per_use(self) -> float:
        if self.total_uses == 0:
            return 0.0
        return self.total_findings / self.total_uses

    @property
    def false_positive_rate(self) -> float:
        if self.total_findings == 0:
            return 0.0
        return self.false_positive_count / self.total_findings

    @property
    def score(self) -> float:
        """Overall performance score (0-1)."""
        sr = self.success_rate
        fpr = 1.0 - self.false_positive_rate
        efficiency = min(1.0, self.avg_findings_per_use / 5.0)
        return (sr * 0.4 + fpr * 0.3 + efficiency * 0.3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.metric_type.value[:10],
            "subject": self.subject[:15],
            "uses": self.total_uses,
            "success": f"{self.success_rate:.1%}",
            "score": f"{self.score:.2f}",
        }


@dataclass
class ImprovementAction:
    """An action taken to improve performance."""
    action_id: str = ""
    action_type: str = ""
    description: str = ""
    applied_to: str = ""
    before_score: float = 0.0
    after_score: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.action_type[:12],
            "applied_to": self.applied_to[:15],
            "improvement": f"{self.after_score - self.before_score:+.2f}",
        }


@dataclass
class KnowledgeGap:
    """A detected gap in the agent's knowledge."""
    gap_id: str = ""
    domain: str = ""
    description: str = ""
    detected_from: str = ""
    severity: str = "medium"
    filled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"domain": self.domain[:12], "severity": self.severity[:4], "filled": self.filled}


class SelfImprovementEngine:
    """Tracks performance and drives self-improvement."""

    def __init__(self) -> None:
        self._metrics: dict[str, PerformanceMetric] = {}
        self._actions: list[ImprovementAction] = []
        self._gaps: list[KnowledgeGap] = []
        self._action_counter = 0
        self._gap_counter = 0
        self._log = logger.bind(component="self_improvement")

    def _get_or_create_metric(
        self, metric_type: MetricType, subject: str,
    ) -> PerformanceMetric:
        key = f"{metric_type.value}:{subject}"
        if key not in self._metrics:
            self._metrics[key] = PerformanceMetric(
                metric_id=key,
                metric_type=metric_type,
                subject=subject,
            )
        return self._metrics[key]

    def record_tool_use(
        self,
        tool_name: str,
        success: bool,
        duration_s: float = 0.0,
        findings_count: int = 0,
        false_positives: int = 0,
    ) -> None:
        """Record a tool execution result."""
        metric = self._get_or_create_metric(MetricType.TOOL_RELIABILITY, tool_name)
        metric.total_uses += 1
        if success:
            metric.successes += 1
        else:
            metric.failures += 1
        metric.total_duration_s += duration_s
        metric.total_findings += findings_count
        metric.false_positive_count += false_positives
        metric.last_updated = time.time()

    def record_model_use(
        self,
        model_id: str,
        task_type: str,
        success: bool,
        tokens_used: int = 0,
        quality_score: float = 0.0,
    ) -> None:
        """Record a model usage result."""
        metric = self._get_or_create_metric(MetricType.MODEL_QUALITY, f"{model_id}:{task_type}")
        metric.total_uses += 1
        if success:
            metric.successes += 1
        else:
            metric.failures += 1
        metric.total_tokens += tokens_used
        metric.last_updated = time.time()

    def record_strategy_use(
        self,
        strategy_name: str,
        success: bool,
        findings_count: int = 0,
        duration_s: float = 0.0,
    ) -> None:
        """Record a strategy execution result."""
        metric = self._get_or_create_metric(MetricType.STRATEGY_EFFECTIVENESS, strategy_name)
        metric.total_uses += 1
        if success:
            metric.successes += 1
        else:
            metric.failures += 1
        metric.total_findings += findings_count
        metric.total_duration_s += duration_s
        metric.last_updated = time.time()

    def record_kb_use(
        self,
        kb_domain: str,
        relevant: bool,
        findings_enabled: int = 0,
    ) -> None:
        """Record KB relevance."""
        metric = self._get_or_create_metric(MetricType.KB_RELEVANCE, kb_domain)
        metric.total_uses += 1
        if relevant:
            metric.successes += 1
        else:
            metric.failures += 1
        metric.total_findings += findings_enabled
        metric.last_updated = time.time()

    def detect_knowledge_gap(
        self,
        domain: str,
        description: str,
        detected_from: str = "",
    ) -> KnowledgeGap:
        """Record a detected knowledge gap."""
        self._gap_counter += 1
        gap = KnowledgeGap(
            gap_id=f"gap-{self._gap_counter}",
            domain=domain,
            description=description,
            detected_from=detected_from,
        )
        self._gaps.append(gap)
        return gap

    def get_top_tools(self, n: int = 5) -> list[PerformanceMetric]:
        """Get top performing tools."""
        tool_metrics = [
            m for m in self._metrics.values()
            if m.metric_type == MetricType.TOOL_RELIABILITY and m.total_uses >= 3
        ]
        return sorted(tool_metrics, key=lambda m: m.score, reverse=True)[:n]

    def get_worst_tools(self, n: int = 5) -> list[PerformanceMetric]:
        """Get worst performing tools."""
        tool_metrics = [
            m for m in self._metrics.values()
            if m.metric_type == MetricType.TOOL_RELIABILITY and m.total_uses >= 3
        ]
        return sorted(tool_metrics, key=lambda m: m.score)[:n]

    def get_best_model_for_task(self, task_type: str) -> str:
        """Get the best performing model for a task type."""
        candidates = [
            m for m in self._metrics.values()
            if m.metric_type == MetricType.MODEL_QUALITY and task_type in m.subject
        ]
        if not candidates:
            return "mistral-7b"
        best = max(candidates, key=lambda m: m.score)
        return best.subject.split(":")[0]

    def get_unfilled_gaps(self) -> list[KnowledgeGap]:
        """Get knowledge gaps not yet filled."""
        return [g for g in self._gaps if not g.filled]

    def suggest_improvements(self) -> list[str]:
        """Suggest improvements based on tracked metrics."""
        suggestions = []

        # Poor performing tools
        worst = self.get_worst_tools(3)
        for m in worst:
            if m.success_rate < 0.5:
                suggestions.append(f"Tool '{m.subject}' has {m.success_rate:.0%} success rate — consider alternative or different parameters")

        # High false positive tools
        for m in self._metrics.values():
            if m.metric_type == MetricType.TOOL_RELIABILITY and m.false_positive_rate > 0.3 and m.total_uses >= 5:
                suggestions.append(f"Tool '{m.subject}' has {m.false_positive_rate:.0%} FP rate — needs validation pass")

        # Knowledge gaps
        gaps = self.get_unfilled_gaps()
        for gap in gaps[:3]:
            suggestions.append(f"Knowledge gap in '{gap.domain}': {gap.description}")

        return suggestions

    def build_improvement_prompt(self) -> str:
        """Build LLM prompt with self-improvement insights."""
        lines = ["## Self-Improvement Insights\n"]
        top = self.get_top_tools(3)
        if top:
            lines.append("Top performing tools:")
            for m in top:
                lines.append(f"  {m.subject}: {m.score:.2f} ({m.success_rate:.0%} success, {m.avg_findings_per_use:.1f} findings/use)")

        worst = self.get_worst_tools(3)
        if worst:
            lines.append("\nUnderperforming tools:")
            for m in worst:
                lines.append(f"  {m.subject}: {m.score:.2f} ({m.success_rate:.0%} success)")

        suggestions = self.suggest_improvements()
        if suggestions:
            lines.append("\nSuggested improvements:")
            for s in suggestions[:5]:
                lines.append(f"  → {s}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for m in self._metrics.values():
            key = m.metric_type.value
            type_counts[key] = type_counts.get(key, 0) + 1
        return {
            "total_metrics": len(self._metrics),
            "by_type": type_counts,
            "improvements": len(self._actions),
            "knowledge_gaps": len(self._gaps),
            "unfilled_gaps": len(self.get_unfilled_gaps()),
        }
