"""Agent introspection — self-analysis of reasoning quality.

Implements:
1. Reasoning trace analysis
2. Decision quality scoring
3. Hallucination detection patterns
4. Confidence calibration
5. Cognitive bias detection
6. Introspection prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ReasoningQuality(str, Enum):
    EXCELLENT = "excellent"     # Evidence-based, novel
    GOOD = "good"               # Logical, supported
    ADEQUATE = "adequate"       # Acceptable, some gaps
    POOR = "poor"               # Unsupported, vague
    HALLUCINATION = "hallucination"  # Fabricated content


class CognitiveBias(str, Enum):
    CONFIRMATION = "confirmation"       # Seeking confirming evidence only
    ANCHORING = "anchoring"             # Over-relying on first finding
    AVAILABILITY = "availability"       # Over-weighting recent events
    AUTOMATION = "automation"           # Trusting tool output blindly
    TUNNELING = "tunneling"             # Fixating on one attack path
    OPTIMISM = "optimism"               # Underestimating difficulty
    COMPLETENESS = "completeness"       # Assuming complete coverage


@dataclass
class ReasoningTrace:
    """A trace of agent reasoning."""
    trace_id: str = ""
    agent_id: str = ""
    action: str = ""
    reasoning: str = ""
    evidence: list[str] = field(default_factory=list)
    quality: ReasoningQuality = ReasoningQuality.ADEQUATE
    confidence_claimed: float = 0.5
    confidence_calibrated: float = 0.5
    biases_detected: list[CognitiveBias] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action[:15],
            "quality": self.quality.value[:6],
            "claimed": f"{self.confidence_claimed:.2f}",
            "calibrated": f"{self.confidence_calibrated:.2f}",
            "biases": len(self.biases_detected),
        }


@dataclass
class CalibrationRecord:
    """Record for confidence calibration."""
    predicted_confidence: float = 0.0
    actual_outcome: bool = False
    timestamp: float = field(default_factory=time.time)


class AgentIntrospection:
    """Agent self-analysis and reasoning quality system.

    Monitors reasoning quality, detects hallucination
    patterns, calibrates confidence, and identifies
    cognitive biases in agent decisions.
    """

    def __init__(self) -> None:
        self._traces: list[ReasoningTrace] = []
        self._trace_counter = 0
        self._calibration: list[CalibrationRecord] = []
        self._bias_history: dict[str, list[CognitiveBias]] = {}
        self._log = logger.bind(component="introspection")

    def record_trace(
        self,
        agent_id: str,
        action: str,
        reasoning: str,
        evidence: list[str] | None = None,
        confidence: float = 0.5,
    ) -> ReasoningTrace:
        """Record and analyze a reasoning trace."""
        self._trace_counter += 1

        quality = self._assess_quality(reasoning, evidence or [])
        biases = self._detect_biases(reasoning, action)
        calibrated = self._calibrate_confidence(confidence, quality)

        trace = ReasoningTrace(
            trace_id=f"trace-{self._trace_counter}",
            agent_id=agent_id,
            action=action,
            reasoning=reasoning,
            evidence=evidence or [],
            quality=quality,
            confidence_claimed=confidence,
            confidence_calibrated=calibrated,
            biases_detected=biases,
        )

        self._traces.append(trace)

        # Track biases per agent
        if biases:
            self._bias_history.setdefault(agent_id, []).extend(biases)

        return trace

    def _assess_quality(self, reasoning: str, evidence: list[str]) -> ReasoningQuality:
        """Assess reasoning quality."""
        lower = reasoning.lower()

        # Hallucination indicators
        hallucination_markers = [
            "i found a critical", "this confirms",
            "clearly shows", "definitely vulnerable",
            "100% certain",
        ]
        if any(m in lower for m in hallucination_markers) and not evidence:
            return ReasoningQuality.HALLUCINATION

        # Evidence-based indicators
        if len(evidence) >= 3 and len(reasoning) > 100:
            return ReasoningQuality.EXCELLENT

        if len(evidence) >= 1 and len(reasoning) > 50:
            return ReasoningQuality.GOOD

        if len(reasoning) > 30:
            return ReasoningQuality.ADEQUATE

        return ReasoningQuality.POOR

    def _detect_biases(self, reasoning: str, action: str) -> list[CognitiveBias]:
        """Detect cognitive biases in reasoning."""
        biases = []
        lower = reasoning.lower()

        # Confirmation bias
        if "confirms my hypothesis" in lower or "as expected" in lower:
            biases.append(CognitiveBias.CONFIRMATION)

        # Anchoring
        if "first finding" in lower or "initial scan showed" in lower:
            biases.append(CognitiveBias.ANCHORING)

        # Automation bias
        tool_trust_markers = [
            "tool reported", "scanner found",
            "nuclei detected", "nmap shows",
        ]
        no_verification = "verif" not in lower and "confirm" not in lower
        if any(m in lower for m in tool_trust_markers) and no_verification:
            biases.append(CognitiveBias.AUTOMATION)

        # Tunneling
        recent_actions = [t.action for t in self._traces[-5:]]
        if len(set(recent_actions)) <= 2 and len(recent_actions) >= 4:
            biases.append(CognitiveBias.TUNNELING)

        # Optimism
        optimism_markers = ["easy to exploit", "trivial", "simple vulnerability"]
        if any(m in lower for m in optimism_markers):
            biases.append(CognitiveBias.OPTIMISM)

        return biases

    def _calibrate_confidence(
        self,
        claimed: float,
        quality: ReasoningQuality,
    ) -> float:
        """Calibrate confidence based on quality."""
        quality_multipliers = {
            ReasoningQuality.EXCELLENT: 1.0,
            ReasoningQuality.GOOD: 0.85,
            ReasoningQuality.ADEQUATE: 0.7,
            ReasoningQuality.POOR: 0.4,
            ReasoningQuality.HALLUCINATION: 0.1,
        }

        multiplier = quality_multipliers.get(quality, 0.5)

        # Check historical calibration
        if self._calibration:
            overconfidence_ratio = self._calculate_overconfidence()
            if overconfidence_ratio > 0.3:
                multiplier *= 0.8  # Reduce confidence if historically overconfident

        return max(0.01, min(0.99, claimed * multiplier))

    def _calculate_overconfidence(self) -> float:
        """Calculate historical overconfidence ratio."""
        if not self._calibration:
            return 0.0

        overconfident = 0
        for record in self._calibration:
            if record.predicted_confidence > 0.7 and not record.actual_outcome:
                overconfident += 1

        return overconfident / len(self._calibration)

    def record_outcome(self, confidence_was: float, actual_outcome: bool) -> None:
        """Record actual outcome for calibration."""
        self._calibration.append(CalibrationRecord(
            predicted_confidence=confidence_was,
            actual_outcome=actual_outcome,
        ))

    def get_agent_biases(self, agent_id: str) -> dict[str, int]:
        """Get bias frequency for an agent."""
        biases = self._bias_history.get(agent_id, [])
        counts: dict[str, int] = {}
        for b in biases:
            counts[b.value] = counts.get(b.value, 0) + 1
        return counts

    def get_quality_distribution(self) -> dict[str, int]:
        """Get quality distribution across all traces."""
        dist: dict[str, int] = {}
        for trace in self._traces:
            q = trace.quality.value
            dist[q] = dist.get(q, 0) + 1
        return dist

    def build_introspection_prompt(self, agent_id: str = "") -> str:
        """Build introspection context for LLM."""
        lines = ["## Introspection\n"]

        recent = [
            t for t in self._traces[-5:]
            if not agent_id or t.agent_id == agent_id
        ]

        if not recent:
            lines.append("No reasoning traces recorded.")
            return "\n".join(lines)

        # Quality summary
        dist = self.get_quality_distribution()
        lines.append("Quality distribution:")
        for quality, count in dist.items():
            lines.append(f"  {quality}: {count}")

        # Recent traces
        lines.append(f"\nRecent traces ({len(recent)}):")
        for t in recent:
            lines.append(
                f"  {t.action[:15]}: {t.quality.value[:6]} "
                f"(conf: {t.confidence_claimed:.2f}→{t.confidence_calibrated:.2f})"
            )
            if t.biases_detected:
                bias_names = ", ".join(b.value[:8] for b in t.biases_detected)
                lines.append(f"    Biases: {bias_names}")

        # Calibration
        if self._calibration:
            overconf = self._calculate_overconfidence()
            lines.append(f"\nOverconfidence: {overconf:.0%}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "traces": len(self._traces),
            "quality_dist": self.get_quality_distribution(),
            "calibration_records": len(self._calibration),
            "agents_tracked": len(self._bias_history),
        }
