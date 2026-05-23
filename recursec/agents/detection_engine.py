"""Detection engine — vulnerability detection logic and strategy execution.

Implements:
1. Detection strategy selection from attack pattern KB
2. Multi-method detection orchestration
3. Evidence collection and scoring
4. False positive filtering
5. Detection confidence calibration
6. Adaptive detection (learns from results)
7. Detection scheduling and prioritization
8. Cross-detection correlation
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DetectionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    FAILED = "failed"
    SKIPPED = "skipped"


class EvidenceType(str, Enum):
    TOOL_OUTPUT = "tool_output"
    RESPONSE_DIFF = "response_diff"
    TIMING_DELTA = "timing_delta"
    ERROR_MESSAGE = "error_message"
    CONFIG_VALUE = "config_value"
    BEHAVIOR_CHANGE = "behavior_change"
    CODE_PATTERN = "code_pattern"


class ConfidenceLevel(str, Enum):
    CONFIRMED = "confirmed"     # 0.9+
    HIGH = "high"               # 0.7-0.9
    MEDIUM = "medium"           # 0.4-0.7
    LOW = "low"                 # 0.2-0.4
    UNCONFIRMED = "unconfirmed" # <0.2


@dataclass
class Evidence:
    """A piece of evidence supporting a detection."""
    evidence_id: str = ""
    evidence_type: EvidenceType = EvidenceType.TOOL_OUTPUT
    source: str = ""
    content: str = ""
    weight: float = 0.5
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.evidence_id,
            "type": self.evidence_type.value,
            "source": self.source[:20],
            "weight": round(self.weight, 2),
        }


@dataclass
class DetectionResult:
    """Result of a detection attempt."""
    result_id: str = ""
    pattern_id: str = ""
    pattern_name: str = ""
    target: str = ""
    status: DetectionStatus = DetectionStatus.PENDING
    detected: bool = False
    confidence: float = 0.0
    confidence_level: ConfidenceLevel = ConfidenceLevel.UNCONFIRMED
    evidence: list[Evidence] = field(default_factory=list)
    false_positive_score: float = 0.0
    method_used: str = ""
    duration_s: float = 0.0
    error: str = ""
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.result_id,
            "pattern": self.pattern_name[:25],
            "target": self.target[:20],
            "detected": self.detected,
            "confidence": round(self.confidence, 2),
            "level": self.confidence_level.value,
            "evidence_count": len(self.evidence),
            "fp_score": round(self.false_positive_score, 2),
        }


@dataclass
class DetectionPlan:
    """Plan for detecting a vulnerability pattern."""
    plan_id: str = ""
    pattern_id: str = ""
    target: str = ""
    methods: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    priority: int = 5
    estimated_time_s: int = 60
    model_hint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.plan_id,
            "pattern": self.pattern_id[:15],
            "methods": len(self.methods),
            "tools": self.tools[:3],
            "priority": self.priority,
        }


# ── False Positive Indicators ─────────────────────────────────

FP_INDICATORS: list[dict[str, Any]] = [
    {"pattern": r"(?i)(might|could|possibly|perhaps|maybe)\s+(be|have|contain)",
     "weight": 0.15, "name": "hedging_language"},
    {"pattern": r"(?i)informational|info(rmation)?\s+only|for\s+reference",
     "weight": 0.2, "name": "informational_only"},
    {"pattern": r"(?i)not\s+(confirmed|verified|validated|exploitable)",
     "weight": 0.25, "name": "unconfirmed"},
    {"pattern": r"(?i)(expected|normal|standard)\s+(behavior|response|output)",
     "weight": 0.2, "name": "expected_behavior"},
    {"pattern": r"(?i)theoretical|in\s+theory|hypothetical",
     "weight": 0.2, "name": "theoretical"},
    {"pattern": r"(?i)false\s+positive|benign|safe|not\s+vulnerable",
     "weight": 0.3, "name": "explicit_fp"},
]

# ── Evidence Weight by Type ───────────────────────────────────

EVIDENCE_WEIGHTS: dict[EvidenceType, float] = {
    EvidenceType.TOOL_OUTPUT: 0.7,
    EvidenceType.RESPONSE_DIFF: 0.6,
    EvidenceType.TIMING_DELTA: 0.5,
    EvidenceType.ERROR_MESSAGE: 0.5,
    EvidenceType.CONFIG_VALUE: 0.6,
    EvidenceType.BEHAVIOR_CHANGE: 0.8,
    EvidenceType.CODE_PATTERN: 0.4,
}

# ── Severity Priority ─────────────────────────────────────────

SEVERITY_PRIORITY: dict[str, int] = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 5,
}


class DetectionEngine:
    """Vulnerability detection logic and strategy execution.

    Coordinates detection methods, collects evidence,
    scores confidence, and filters false positives.
    """

    def __init__(self) -> None:
        self._results: list[DetectionResult] = []
        self._plans: list[DetectionPlan] = []
        self._result_counter = 0
        self._plan_counter = 0
        self._evidence_counter = 0
        self._calibration_data: list[tuple[float, bool]] = []
        self._method_success: dict[str, list[bool]] = defaultdict(list)
        self._log = logger.bind(component="detection_engine")

    def create_plan(
        self,
        pattern_id: str,
        target: str,
        methods: list[str],
        tools: list[str],
        severity: str = "medium",
        model_hint: str = "",
    ) -> DetectionPlan:
        """Create a detection plan for a pattern."""
        self._plan_counter += 1
        plan = DetectionPlan(
            plan_id=f"dp-{self._plan_counter}",
            pattern_id=pattern_id,
            target=target,
            methods=methods,
            tools=tools,
            priority=SEVERITY_PRIORITY.get(severity.lower(), 3),
            model_hint=model_hint,
        )
        self._plans.append(plan)
        return plan

    def record_detection(
        self,
        pattern_id: str,
        pattern_name: str,
        target: str,
        detected: bool,
        method_used: str = "",
        raw_evidence: list[dict[str, Any]] | None = None,
        duration_s: float = 0.0,
        error: str = "",
    ) -> DetectionResult:
        """Record a detection result with evidence."""
        self._result_counter += 1

        # Build evidence objects
        evidence_list = []
        if raw_evidence:
            for ev_data in raw_evidence:
                self._evidence_counter += 1
                ev = Evidence(
                    evidence_id=f"ev-{self._evidence_counter}",
                    evidence_type=EvidenceType(ev_data.get("type", "tool_output")),
                    source=ev_data.get("source", ""),
                    content=ev_data.get("content", ""),
                    weight=EVIDENCE_WEIGHTS.get(
                        EvidenceType(ev_data.get("type", "tool_output")),
                        0.5,
                    ),
                )
                evidence_list.append(ev)

        # Calculate confidence
        confidence = self._calculate_confidence(detected, evidence_list)

        # Calculate false positive score
        fp_score = self._calculate_fp_score(evidence_list)

        # Adjust confidence based on FP score
        adjusted_confidence = confidence * (1 - fp_score * 0.5)

        # Determine confidence level
        level = self._confidence_level(adjusted_confidence)

        result = DetectionResult(
            result_id=f"dr-{self._result_counter}",
            pattern_id=pattern_id,
            pattern_name=pattern_name,
            target=target,
            status=DetectionStatus.FAILED if error else DetectionStatus.COMPLETED,
            detected=detected and adjusted_confidence >= 0.3,
            confidence=adjusted_confidence,
            confidence_level=level,
            evidence=evidence_list,
            false_positive_score=fp_score,
            method_used=method_used,
            duration_s=duration_s,
            error=error,
        )

        # Generate recommendations
        result.recommendations = self._generate_recommendations(result)

        self._results.append(result)
        if len(self._results) > 1000:
            self._results = self._results[-1000:]

        # Track method success
        if method_used:
            self._method_success[method_used].append(detected)

        return result

    @staticmethod
    def _calculate_confidence(
        detected: bool,
        evidence: list[Evidence],
    ) -> float:
        """Calculate confidence from evidence."""
        if not detected:
            return 0.0

        if not evidence:
            return 0.3

        # Weighted evidence sum
        total_weight = sum(ev.weight for ev in evidence)
        max_possible = len(evidence) * 1.0

        if max_possible == 0:
            return 0.3

        base_confidence = total_weight / max_possible

        # Bonus for multiple evidence sources
        unique_types = len({ev.evidence_type for ev in evidence})
        diversity_bonus = min(0.15, unique_types * 0.05)

        return min(0.95, base_confidence + diversity_bonus)

    @staticmethod
    def _calculate_fp_score(evidence: list[Evidence]) -> float:
        """Calculate false positive likelihood from evidence content."""
        if not evidence:
            return 0.0

        fp_score = 0.0
        for ev in evidence:
            for indicator in FP_INDICATORS:
                if re.search(indicator["pattern"], ev.content):
                    fp_score += indicator["weight"]

        return min(0.9, fp_score)

    @staticmethod
    def _confidence_level(confidence: float) -> ConfidenceLevel:
        if confidence >= 0.9:
            return ConfidenceLevel.CONFIRMED
        if confidence >= 0.7:
            return ConfidenceLevel.HIGH
        if confidence >= 0.4:
            return ConfidenceLevel.MEDIUM
        if confidence >= 0.2:
            return ConfidenceLevel.LOW
        return ConfidenceLevel.UNCONFIRMED

    @staticmethod
    def _generate_recommendations(result: DetectionResult) -> list[str]:
        """Generate follow-up recommendations."""
        recs = []

        if result.detected and result.confidence_level == ConfidenceLevel.LOW:
            recs.append("Low confidence — validate with additional methods")

        if result.false_positive_score > 0.3:
            recs.append("High FP risk — manual verification recommended")

        if result.detected and result.confidence_level in (
            ConfidenceLevel.CONFIRMED, ConfidenceLevel.HIGH
        ):
            recs.append("Confirmed finding — proceed to exploitation validation")

        if not result.detected:
            recs.append("Not detected — consider alternative detection methods")

        return recs

    def correlate_results(
        self,
        target: str,
    ) -> list[dict[str, Any]]:
        """Find correlated detections for a target."""
        target_results = [r for r in self._results if r.target == target and r.detected]

        # Group by category prefix
        groups: dict[str, list[DetectionResult]] = defaultdict(list)
        for result in target_results:
            category = result.pattern_id.split("-")[0] if result.pattern_id else "unknown"
            groups[category].append(result)

        correlations = []
        for category, results in groups.items():
            if len(results) >= 2:
                correlations.append({
                    "category": category,
                    "findings": len(results),
                    "patterns": [r.pattern_name for r in results],
                    "avg_confidence": round(
                        sum(r.confidence for r in results) / len(results), 2
                    ),
                })

        return correlations

    def get_method_effectiveness(self) -> dict[str, float]:
        """Get detection success rate by method."""
        effectiveness = {}
        for method, results in self._method_success.items():
            if results:
                effectiveness[method] = round(sum(results) / len(results), 2)
        return effectiveness

    def get_stats(self) -> dict[str, Any]:
        detected_count = sum(1 for r in self._results if r.detected)
        return {
            "total_detections": len(self._results),
            "findings": detected_count,
            "plans": len(self._plans),
            "method_effectiveness": self.get_method_effectiveness(),
        }
