"""Introspection engine — agent self-awareness and self-monitoring.

Implements:
1. Performance self-assessment
2. Cognitive load monitoring
3. Confidence calibration
4. Blind spot detection
5. Decision quality review
6. Behavioral pattern analysis
7. Self-correction triggers
8. Meta-cognitive monitoring

Allows agents to reason about their own reasoning,
detect when they're stuck, and self-correct.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CognitiveState:
    """Current cognitive state of an agent."""
    # Performance
    actions_taken: int = 0
    actions_successful: int = 0
    actions_failed: int = 0
    findings_produced: int = 0
    confidence_avg: float = 0.5

    # Load
    token_usage: int = 0
    time_elapsed_s: float = 0.0
    context_size: int = 0
    pending_tasks: int = 0

    # Quality
    false_positives: int = 0
    validated_findings: int = 0
    unique_techniques: int = 0

    # Patterns
    repeated_actions: int = 0
    strategy_switches: int = 0
    help_requests: int = 0

    @property
    def success_rate(self) -> float:
        if self.actions_taken == 0:
            return 0.0
        return self.actions_successful / self.actions_taken

    @property
    def cognitive_load(self) -> float:
        """0 = idle, 1 = overloaded."""
        load = 0.0
        if self.pending_tasks > 5:
            load += 0.3
        if self.context_size > 3000:
            load += 0.2
        if self.actions_taken > 50:
            load += 0.2
        if self.repeated_actions > 5:
            load += 0.3
        return min(1.0, load)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success_rate": round(self.success_rate, 2),
            "cognitive_load": round(self.cognitive_load, 2),
            "confidence": round(self.confidence_avg, 2),
            "actions": self.actions_taken,
            "findings": self.findings_produced,
            "fp_rate": round(
                self.false_positives / max(1, self.findings_produced), 2
            ),
        }


@dataclass
class IntrospectionInsight:
    """An insight from self-reflection."""
    category: str = ""        # performance, pattern, blind_spot, quality, meta
    description: str = ""
    severity: str = "info"    # info, warning, critical
    action_suggested: str = ""
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "description": self.description[:100],
            "severity": self.severity,
            "action": self.action_suggested[:100],
            "confidence": round(self.confidence, 2),
        }


@dataclass
class ConfidenceRecord:
    """Record of a confidence prediction and its outcome."""
    prediction_id: str = ""
    predicted_confidence: float = 0.5
    actual_outcome: float = 0.0   # 0 = wrong, 1 = correct
    domain: str = ""
    timestamp: float = field(default_factory=time.time)


class IntrospectionEngine:
    """Self-monitoring and meta-cognitive engine.

    Allows agents to assess their own performance,
    detect patterns, identify blind spots, and self-correct.
    """

    def __init__(self) -> None:
        self._state = CognitiveState()
        self._insights: list[IntrospectionInsight] = []
        self._confidence_records: list[ConfidenceRecord] = []
        self._action_history: list[str] = []
        self._technique_coverage: set[str] = set()
        self._domain_performance: dict[str, list[float]] = defaultdict(list)
        self._record_counter = 0
        self._log = logger.bind(component="introspection")

    # ── State Updates ────────────────────────────────────

    def record_action(self, action: str, success: bool, confidence: float = 0.5) -> None:
        """Record an action and its outcome."""
        self._state.actions_taken += 1
        if success:
            self._state.actions_successful += 1
        else:
            self._state.actions_failed += 1

        self._action_history.append(action)
        if len(self._action_history) > 200:
            self._action_history = self._action_history[-200:]

        # Track repetitions
        if len(self._action_history) > 1 and action == self._action_history[-2]:
            self._state.repeated_actions += 1

        # Update confidence
        n = self._state.actions_taken
        self._state.confidence_avg = (
            self._state.confidence_avg * (n - 1) + confidence
        ) / n

    def record_finding(self, is_validated: bool = False) -> None:
        self._state.findings_produced += 1
        if is_validated:
            self._state.validated_findings += 1

    def record_false_positive(self) -> None:
        self._state.false_positives += 1

    def record_technique(self, technique: str) -> None:
        self._technique_coverage.add(technique)
        self._state.unique_techniques = len(self._technique_coverage)

    def update_context(self, token_usage: int, context_size: int, pending: int) -> None:
        self._state.token_usage = token_usage
        self._state.context_size = context_size
        self._state.pending_tasks = pending

    def record_time(self, elapsed_s: float) -> None:
        self._state.time_elapsed_s = elapsed_s

    # ── Confidence Calibration ───────────────────────────

    def record_confidence_prediction(
        self,
        confidence: float,
        actual: float,
        domain: str = "",
    ) -> None:
        """Record a confidence prediction and its actual outcome."""
        self._record_counter += 1
        record = ConfidenceRecord(
            prediction_id=f"conf-{self._record_counter}",
            predicted_confidence=confidence,
            actual_outcome=actual,
            domain=domain,
        )
        self._confidence_records.append(record)
        if len(self._confidence_records) > 500:
            self._confidence_records = self._confidence_records[-500:]

        self._domain_performance[domain].append(actual)

    def get_calibration_error(self) -> float:
        """Calculate expected calibration error (ECE)."""
        if not self._confidence_records:
            return 0.0

        # Bin predictions into 10 buckets
        bins: dict[int, list[ConfidenceRecord]] = defaultdict(list)
        for record in self._confidence_records:
            bucket = min(9, int(record.predicted_confidence * 10))
            bins[bucket].append(record)

        total_error = 0.0
        total_samples = len(self._confidence_records)

        for records in bins.values():
            if not records:
                continue
            avg_confidence = sum(r.predicted_confidence for r in records) / len(records)
            avg_accuracy = sum(r.actual_outcome for r in records) / len(records)
            weight = len(records) / total_samples
            total_error += weight * abs(avg_confidence - avg_accuracy)

        return total_error

    # ── Self-Assessment ──────────────────────────────────

    def introspect(self) -> list[IntrospectionInsight]:
        """Perform self-assessment and generate insights."""
        insights = []

        # Performance check
        insights.extend(self._check_performance())

        # Pattern detection
        insights.extend(self._detect_patterns())

        # Blind spot detection
        insights.extend(self._detect_blind_spots())

        # Quality assessment
        insights.extend(self._assess_quality())

        # Cognitive load
        insights.extend(self._check_cognitive_load())

        self._insights.extend(insights)
        return insights

    def _check_performance(self) -> list[IntrospectionInsight]:
        insights = []

        if self._state.actions_taken > 10 and self._state.success_rate < 0.3:
            insights.append(IntrospectionInsight(
                category="performance",
                description=f"Low success rate: {self._state.success_rate:.0%}",
                severity="warning",
                action_suggested="Consider changing approach or tools",
                confidence=0.8,
            ))

        if self._state.actions_taken > 20 and self._state.findings_produced == 0:
            insights.append(IntrospectionInsight(
                category="performance",
                description="No findings after 20+ actions",
                severity="warning",
                action_suggested="Reassess target or switch strategy",
                confidence=0.7,
            ))

        return insights

    def _detect_patterns(self) -> list[IntrospectionInsight]:
        insights = []

        if self._state.repeated_actions > 5:
            insights.append(IntrospectionInsight(
                category="pattern",
                description=f"High action repetition: {self._state.repeated_actions} repeats",
                severity="warning",
                action_suggested="Break out of repetitive loop",
                confidence=0.9,
            ))

        # Check for oscillation (A→B→A→B)
        if len(self._action_history) >= 6:
            last_6 = self._action_history[-6:]
            if last_6[0] == last_6[2] == last_6[4] and last_6[1] == last_6[3] == last_6[5]:
                insights.append(IntrospectionInsight(
                    category="pattern",
                    description="Oscillating between two actions",
                    severity="critical",
                    action_suggested="Break oscillation — try a completely different approach",
                    confidence=0.95,
                ))

        return insights

    def _detect_blind_spots(self) -> list[IntrospectionInsight]:
        insights = []

        standard_techniques = {
            "port_scan", "web_scan", "vuln_scan",
            "auth_test", "injection_test", "config_check",
        }
        missing = standard_techniques - self._technique_coverage
        if self._state.actions_taken > 15 and len(missing) > 3:
            insights.append(IntrospectionInsight(
                category="blind_spot",
                description=f"Missing coverage: {', '.join(list(missing)[:3])}",
                severity="info",
                action_suggested="Consider testing these areas",
                confidence=0.6,
            ))

        # Overconfidence detection
        calibration_error = self.get_calibration_error()
        if calibration_error > 0.2 and len(self._confidence_records) > 10:
            insights.append(IntrospectionInsight(
                category="blind_spot",
                description=f"Confidence miscalibration: ECE={calibration_error:.2f}",
                severity="warning",
                action_suggested="Reduce confidence in predictions",
                confidence=0.8,
            ))

        return insights

    def _assess_quality(self) -> list[IntrospectionInsight]:
        insights = []

        fp_rate = (
            self._state.false_positives / max(1, self._state.findings_produced)
        )
        if fp_rate > 0.3 and self._state.findings_produced > 5:
            insights.append(IntrospectionInsight(
                category="quality",
                description=f"High false positive rate: {fp_rate:.0%}",
                severity="warning",
                action_suggested="Increase validation rigor",
                confidence=0.8,
            ))

        return insights

    def _check_cognitive_load(self) -> list[IntrospectionInsight]:
        insights = []

        if self._state.cognitive_load > 0.8:
            insights.append(IntrospectionInsight(
                category="meta",
                description=f"High cognitive load: {self._state.cognitive_load:.0%}",
                severity="warning",
                action_suggested="Reduce pending tasks or simplify context",
                confidence=0.7,
            ))

        return insights

    def get_state(self) -> CognitiveState:
        return self._state

    def get_insights(self, limit: int = 20) -> list[dict[str, Any]]:
        return [i.to_dict() for i in self._insights[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        return {
            **self._state.to_dict(),
            "calibration_error": round(self.get_calibration_error(), 3),
            "insights": len(self._insights),
            "techniques_covered": len(self._technique_coverage),
        }
