"""Hypothesis tracker — scientific method for vulnerability hunting.

Implements:
1. Hypothesis creation and lifecycle
2. Evidence collection (supporting/contradicting)
3. Confidence scoring with Bayesian updates
4. Experiment design and tracking
5. Hypothesis prioritization
6. Hypothesis prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    TESTING = "testing"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class EvidenceType(str, Enum):
    SUPPORTING = "supporting"
    CONTRADICTING = "contradicting"
    NEUTRAL = "neutral"


@dataclass
class Evidence:
    """A piece of evidence for/against a hypothesis."""
    evidence_id: str = ""
    evidence_type: EvidenceType = EvidenceType.NEUTRAL
    source: str = ""           # Tool or analysis that produced it
    description: str = ""
    strength: float = 0.5      # 0=weak, 1=strong
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.evidence_type.value[:4],
            "source": self.source[:12],
            "strength": f"{self.strength:.1f}",
        }


@dataclass
class Experiment:
    """An experiment designed to test a hypothesis."""
    experiment_id: str = ""
    hypothesis_id: str = ""
    description: str = ""
    tool: str = ""
    expected_if_true: str = ""
    expected_if_false: str = ""
    status: str = "planned"     # planned/running/completed
    result: str = ""
    evidence_produced: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.experiment_id[:10],
            "tool": self.tool[:12],
            "status": self.status[:8],
        }


@dataclass
class Hypothesis:
    """A security hypothesis to test."""
    hypothesis_id: str = ""
    statement: str = ""
    category: str = ""          # vuln_type, attack_surface, etc.
    target: str = ""
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    prior_confidence: float = 0.5
    current_confidence: float = 0.5
    evidence: list[Evidence] = field(default_factory=list)
    experiments: list[Experiment] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    resolved_at: float = 0.0

    @property
    def supporting_count(self) -> int:
        return sum(1 for e in self.evidence if e.evidence_type == EvidenceType.SUPPORTING)

    @property
    def contradicting_count(self) -> int:
        return sum(1 for e in self.evidence if e.evidence_type == EvidenceType.CONTRADICTING)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id[:10],
            "statement": self.statement[:30],
            "status": self.status.value[:8],
            "conf": f"{self.current_confidence:.0%}",
            "evidence": len(self.evidence),
        }


class HypothesisTracker:
    """Scientific method for vulnerability hunting.

    Manages hypotheses about potential vulnerabilities,
    designs experiments to test them, collects evidence,
    and updates confidence using Bayesian reasoning.
    """

    def __init__(self) -> None:
        self._hypotheses: dict[str, Hypothesis] = {}
        self._hypothesis_counter = 0
        self._experiment_counter = 0
        self._evidence_counter = 0
        self._log = logger.bind(component="hypothesis_tracker")

    def create_hypothesis(
        self,
        statement: str,
        category: str = "",
        target: str = "",
        prior_confidence: float = 0.5,
    ) -> Hypothesis:
        """Create a new hypothesis."""
        self._hypothesis_counter += 1

        h = Hypothesis(
            hypothesis_id=f"hyp-{self._hypothesis_counter}",
            statement=statement,
            category=category,
            target=target,
            prior_confidence=prior_confidence,
            current_confidence=prior_confidence,
        )

        self._hypotheses[h.hypothesis_id] = h
        return h

    def add_evidence(
        self,
        hypothesis_id: str,
        evidence_type: EvidenceType,
        source: str,
        description: str,
        strength: float = 0.5,
    ) -> Evidence | None:
        """Add evidence and update confidence."""
        h = self._hypotheses.get(hypothesis_id)
        if not h:
            return None

        self._evidence_counter += 1
        evidence = Evidence(
            evidence_id=f"ev-{self._evidence_counter}",
            evidence_type=evidence_type,
            source=source,
            description=description,
            strength=strength,
        )
        h.evidence.append(evidence)

        # Bayesian update
        self._update_confidence(h, evidence)

        # Auto-resolve
        if h.current_confidence > 0.9:
            h.status = HypothesisStatus.SUPPORTED
            h.resolved_at = time.time()
        elif h.current_confidence < 0.1:
            h.status = HypothesisStatus.REFUTED
            h.resolved_at = time.time()

        return evidence

    def _update_confidence(self, h: Hypothesis, evidence: Evidence) -> None:
        """Bayesian confidence update."""
        prior = h.current_confidence
        strength = evidence.strength

        if evidence.evidence_type == EvidenceType.SUPPORTING:
            # P(H|E) increases
            likelihood_ratio = 1.0 + strength * 2.0
        elif evidence.evidence_type == EvidenceType.CONTRADICTING:
            # P(H|E) decreases
            likelihood_ratio = 1.0 / (1.0 + strength * 2.0)
        else:
            return

        # Bayes' rule simplified
        posterior_odds = (prior / (1.0 - prior + 1e-10)) * likelihood_ratio
        h.current_confidence = max(0.01, min(0.99, posterior_odds / (1.0 + posterior_odds)))

    def design_experiment(
        self,
        hypothesis_id: str,
        description: str,
        tool: str = "",
        expected_if_true: str = "",
        expected_if_false: str = "",
    ) -> Experiment | None:
        """Design an experiment to test a hypothesis."""
        h = self._hypotheses.get(hypothesis_id)
        if not h:
            return None

        self._experiment_counter += 1
        exp = Experiment(
            experiment_id=f"exp-{self._experiment_counter}",
            hypothesis_id=hypothesis_id,
            description=description,
            tool=tool,
            expected_if_true=expected_if_true,
            expected_if_false=expected_if_false,
        )
        h.experiments.append(exp)

        if h.status == HypothesisStatus.PROPOSED:
            h.status = HypothesisStatus.TESTING

        return exp

    def get_active(self) -> list[Hypothesis]:
        """Get active hypotheses (not resolved)."""
        return [
            h for h in self._hypotheses.values()
            if h.status in (HypothesisStatus.PROPOSED, HypothesisStatus.TESTING)
        ]

    def get_by_confidence(self, min_conf: float = 0.0, max_conf: float = 1.0) -> list[Hypothesis]:
        """Get hypotheses within confidence range."""
        return [
            h for h in self._hypotheses.values()
            if min_conf <= h.current_confidence <= max_conf
        ]

    def prioritize(self) -> list[Hypothesis]:
        """Prioritize hypotheses by information value.

        Hypotheses near 0.5 confidence have highest
        information value (most uncertain).
        """
        active = self.get_active()
        return sorted(
            active,
            key=lambda h: abs(h.current_confidence - 0.5),
        )

    def build_hypothesis_prompt(self) -> str:
        """Build hypothesis context for LLM."""
        lines = ["## Hypothesis Tracker\n"]

        active = self.get_active()
        resolved = [
            h for h in self._hypotheses.values()
            if h.status in (HypothesisStatus.SUPPORTED, HypothesisStatus.REFUTED)
        ]

        lines.append(f"Active: {len(active)} | Resolved: {len(resolved)}")

        if active:
            prioritized = self.prioritize()
            lines.append("\nPrioritized hypotheses:")
            for h in prioritized[:5]:
                lines.append(
                    f"  [{h.current_confidence:.0%}] {h.statement[:40]} "
                    f"(+{h.supporting_count}/-{h.contradicting_count})"
                )

        if resolved:
            lines.append("\nRecent conclusions:")
            for h in resolved[-3:]:
                result = "CONFIRMED" if h.status == HypothesisStatus.SUPPORTED else "REFUTED"
                lines.append(
                    f"  [{result}] {h.statement[:40]} "
                    f"conf={h.current_confidence:.0%}"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for h in self._hypotheses.values():
            s = h.status.value
            status_counts[s] = status_counts.get(s, 0) + 1

        return {
            "total": len(self._hypotheses),
            "by_status": status_counts,
            "total_evidence": sum(len(h.evidence) for h in self._hypotheses.values()),
            "total_experiments": sum(len(h.experiments) for h in self._hypotheses.values()),
        }
