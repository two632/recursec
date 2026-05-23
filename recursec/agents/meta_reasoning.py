"""Meta-reasoning engine — agent reasons about its own reasoning.

Implements:
1. Reasoning quality assessment
2. Confidence calibration
3. Bias detection in reasoning
4. Strategy selection based on meta-analysis
5. Reasoning trace evaluation
6. Self-critique loop
7. Meta-reasoning prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ReasoningQuality(str, Enum):
    EXCELLENT = "excellent"     # Well-structured, evidence-based
    GOOD = "good"               # Mostly sound reasoning
    FAIR = "fair"               # Some gaps or assumptions
    POOR = "poor"               # Significant issues
    INVALID = "invalid"         # Circular or contradictory


class BiasType(str, Enum):
    CONFIRMATION = "confirmation"        # Seeking confirming evidence
    ANCHORING = "anchoring"              # Over-relying on first info
    AVAILABILITY = "availability"        # Favoring recent/memorable
    SUNK_COST = "sunk_cost"              # Continuing failed approach
    BANDWAGON = "bandwagon"              # Following previous findings
    AUTHORITY = "authority"              # Over-trusting a model
    RECENCY = "recency"                  # Over-weighting recent results
    TUNNEL_VISION = "tunnel_vision"      # Ignoring alternatives


class CritiqueLevel(str, Enum):
    SURFACE = "surface"         # Quick check
    MODERATE = "moderate"       # Standard review
    DEEP = "deep"               # Thorough analysis


@dataclass
class ReasoningTrace:
    """A trace of agent reasoning."""
    trace_id: str = ""
    agent_id: str = ""
    task: str = ""
    steps: list[str] = field(default_factory=list)
    conclusion: str = ""
    confidence: float = 0.5
    evidence: list[str] = field(default_factory=list)
    quality: ReasoningQuality = ReasoningQuality.FAIR
    biases_detected: list[BiasType] = field(default_factory=list)
    critique: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.trace_id[:10],
            "steps": len(self.steps),
            "quality": self.quality.value[:6],
            "conf": round(self.confidence, 2),
            "biases": len(self.biases_detected),
        }


@dataclass
class CalibrationRecord:
    """Record for confidence calibration."""
    predicted_confidence: float = 0.5
    actual_outcome: bool = False
    task_type: str = ""
    timestamp: float = field(default_factory=time.time)


class MetaReasoningEngine:
    """Agent meta-reasoning — reasoning about reasoning.

    Evaluates reasoning quality, detects biases,
    calibrates confidence, and generates self-critique
    to improve decision-making.
    """

    def __init__(self) -> None:
        self._traces: list[ReasoningTrace] = []
        self._calibration: list[CalibrationRecord] = []
        self._counter = 0
        self._log = logger.bind(component="meta_reasoning")

    def evaluate_reasoning(
        self,
        agent_id: str,
        task: str,
        steps: list[str],
        conclusion: str,
        confidence: float,
        evidence: list[str] | None = None,
    ) -> ReasoningTrace:
        """Evaluate a reasoning trace."""
        self._counter += 1
        trace = ReasoningTrace(
            trace_id=f"trace-{self._counter}",
            agent_id=agent_id,
            task=task,
            steps=steps,
            conclusion=conclusion,
            confidence=confidence,
            evidence=evidence or [],
        )

        # Assess quality
        trace.quality = self._assess_quality(trace)

        # Detect biases
        trace.biases_detected = self._detect_biases(trace)

        # Generate critique
        trace.critique = self._generate_critique(trace)

        # Calibrate confidence
        trace.confidence = self._calibrate_confidence(
            trace.confidence, trace.quality, len(trace.biases_detected)
        )

        self._traces.append(trace)
        return trace

    def _assess_quality(self, trace: ReasoningTrace) -> ReasoningQuality:
        """Assess reasoning quality."""
        score = 0.5

        # More steps = more thorough (up to a point)
        step_count = len(trace.steps)
        if step_count >= 3:
            score += 0.1
        if step_count >= 5:
            score += 0.1

        # Evidence-backed is better
        if trace.evidence:
            score += 0.15
            if len(trace.evidence) >= 3:
                score += 0.1

        # Non-empty conclusion
        if trace.conclusion:
            score += 0.05

        # Penalize very short reasoning
        if step_count <= 1:
            score -= 0.2

        # Penalize very high confidence without evidence
        if trace.confidence > 0.9 and not trace.evidence:
            score -= 0.15

        if score >= 0.8:
            return ReasoningQuality.EXCELLENT
        if score >= 0.6:
            return ReasoningQuality.GOOD
        if score >= 0.4:
            return ReasoningQuality.FAIR
        if score >= 0.2:
            return ReasoningQuality.POOR
        return ReasoningQuality.INVALID

    def _detect_biases(self, trace: ReasoningTrace) -> list[BiasType]:
        """Detect potential biases in reasoning."""
        biases: list[BiasType] = []

        # Check for confirmation bias indicators
        step_text = " ".join(trace.steps).lower()
        if "confirms" in step_text and "contradicts" not in step_text:
            biases.append(BiasType.CONFIRMATION)

        # Anchoring: heavily influenced by first piece of info
        if len(trace.steps) >= 3:
            first_step_words = set(trace.steps[0].lower().split())
            last_step_words = set(trace.steps[-1].lower().split())
            overlap = len(first_step_words & last_step_words)
            if overlap > len(first_step_words) * 0.5:
                biases.append(BiasType.ANCHORING)

        # Tunnel vision: no alternative considerations
        alternative_words = {"alternative", "however", "but", "counterpoint", "on the other hand"}
        if not any(w in step_text for w in alternative_words):
            if len(trace.steps) >= 3:
                biases.append(BiasType.TUNNEL_VISION)

        # High confidence without sufficient evidence
        if trace.confidence > 0.85 and len(trace.evidence) < 2:
            biases.append(BiasType.AVAILABILITY)

        return biases

    def _generate_critique(self, trace: ReasoningTrace) -> str:
        """Generate self-critique of reasoning."""
        issues: list[str] = []

        if len(trace.steps) < 2:
            issues.append("Reasoning too brief — needs more steps")

        if not trace.evidence:
            issues.append("No evidence cited — conclusions unsupported")

        if trace.confidence > 0.9 and trace.quality != ReasoningQuality.EXCELLENT:
            issues.append("Confidence too high for reasoning quality")

        for bias in trace.biases_detected:
            if bias == BiasType.CONFIRMATION:
                issues.append("Consider contradicting evidence")
            elif bias == BiasType.TUNNEL_VISION:
                issues.append("Explore alternative hypotheses")
            elif bias == BiasType.ANCHORING:
                issues.append("Conclusion may be anchored to initial data")

        if not issues:
            return "Reasoning appears sound"

        return "; ".join(issues)

    def _calibrate_confidence(
        self,
        raw_confidence: float,
        quality: ReasoningQuality,
        bias_count: int,
    ) -> float:
        """Calibrate confidence based on quality and biases."""
        calibrated = raw_confidence

        # Quality adjustment
        quality_multiplier = {
            ReasoningQuality.EXCELLENT: 1.0,
            ReasoningQuality.GOOD: 0.95,
            ReasoningQuality.FAIR: 0.85,
            ReasoningQuality.POOR: 0.70,
            ReasoningQuality.INVALID: 0.50,
        }
        calibrated *= quality_multiplier.get(quality, 0.85)

        # Bias penalty
        calibrated *= max(0.5, 1.0 - bias_count * 0.1)

        # Historical calibration
        if self._calibration:
            avg_accuracy = self._get_calibration_accuracy()
            if avg_accuracy < 0.7:
                calibrated *= 0.9

        return min(1.0, max(0.0, calibrated))

    def record_outcome(
        self,
        predicted_confidence: float,
        actual_outcome: bool,
        task_type: str = "",
    ) -> None:
        """Record actual outcome for calibration."""
        self._calibration.append(CalibrationRecord(
            predicted_confidence=predicted_confidence,
            actual_outcome=actual_outcome,
            task_type=task_type,
        ))

    def _get_calibration_accuracy(self) -> float:
        """Get historical calibration accuracy."""
        if not self._calibration:
            return 0.5

        correct = 0
        for rec in self._calibration[-50:]:
            predicted = rec.predicted_confidence > 0.5
            if predicted == rec.actual_outcome:
                correct += 1
        return correct / min(len(self._calibration), 50)

    def build_meta_prompt(self) -> str:
        """Build meta-reasoning context for LLM."""
        lines = ["## Meta-Reasoning\n"]

        lines.append(f"Traces: {len(self._traces)} | Calibration records: {len(self._calibration)}")

        if self._calibration:
            accuracy = self._get_calibration_accuracy()
            lines.append(f"Calibration accuracy: {accuracy:.0%}")

        # Quality distribution
        if self._traces:
            quality_counts: dict[str, int] = {}
            for t in self._traces:
                q = t.quality.value
                quality_counts[q] = quality_counts.get(q, 0) + 1
            lines.append("Quality: " + " ".join(f"{k}={v}" for k, v in quality_counts.items()))

        # Common biases
        if self._traces:
            bias_counts: dict[str, int] = {}
            for t in self._traces:
                for b in t.biases_detected:
                    bias_counts[b.value] = bias_counts.get(b.value, 0) + 1
            if bias_counts:
                lines.append("Biases detected: " + " ".join(f"{k}={v}" for k, v in sorted(bias_counts.items(), key=lambda x: x[1], reverse=True)[:3]))

        # Recent critique
        if self._traces:
            recent = self._traces[-1]
            lines.append(f"\nLast critique: {recent.critique[:80]}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        quality_counts: dict[str, int] = {}
        for t in self._traces:
            q = t.quality.value
            quality_counts[q] = quality_counts.get(q, 0) + 1

        return {
            "total_traces": len(self._traces),
            "calibration_records": len(self._calibration),
            "quality_dist": quality_counts,
            "avg_confidence": (
                sum(t.confidence for t in self._traces) / len(self._traces)
                if self._traces else 0
            ),
        }
