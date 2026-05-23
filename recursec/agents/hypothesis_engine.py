"""Hypothesis engine — scientific method for vulnerability discovery.

Implements:
1. Hypothesis generation from observations
2. Evidence collection and evaluation
3. Hypothesis testing and validation
4. Bayesian belief updating
5. Competing hypothesis analysis
6. Evidence weighting
7. Confidence interval estimation
8. Hypothesis prioritization
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    TESTING = "testing"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class EvidenceType(str, Enum):
    TOOL_OUTPUT = "tool_output"
    LLM_ANALYSIS = "llm_analysis"
    PATTERN_MATCH = "pattern_match"
    BEHAVIORAL = "behavioral"
    NEGATIVE = "negative"        # Evidence AGAINST hypothesis
    CORROBORATING = "corroborating"


@dataclass
class Evidence:
    """A piece of evidence for or against a hypothesis."""
    evidence_id: str = ""
    evidence_type: EvidenceType = EvidenceType.TOOL_OUTPUT
    source: str = ""              # Which tool or model produced it
    description: str = ""
    supports: bool = True         # True = supports, False = contradicts
    strength: float = 0.5         # 0-1, how strong is this evidence
    reliability: float = 0.8      # 0-1, how reliable is the source
    timestamp: float = field(default_factory=time.time)

    @property
    def weighted_strength(self) -> float:
        """Evidence strength weighted by source reliability."""
        return self.strength * self.reliability

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.evidence_id[:10],
            "type": self.evidence_type.value,
            "source": self.source[:15],
            "supports": self.supports,
            "strength": round(self.weighted_strength, 2),
        }


@dataclass
class Hypothesis:
    """A hypothesis about a vulnerability or security issue."""
    hypothesis_id: str = ""
    statement: str = ""           # The hypothesis statement
    category: str = ""            # xss, sqli, auth_bypass, etc.
    target: str = ""
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    prior_probability: float = 0.5
    posterior_probability: float = 0.5
    evidence: list[Evidence] = field(default_factory=list)
    tests_planned: list[str] = field(default_factory=list)
    tests_completed: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    resolved_at: float = 0.0
    parent_hypothesis: str = ""   # For sub-hypotheses
    child_hypotheses: list[str] = field(default_factory=list)

    @property
    def evidence_count(self) -> int:
        return len(self.evidence)

    @property
    def supporting_evidence(self) -> list[Evidence]:
        return [e for e in self.evidence if e.supports]

    @property
    def contradicting_evidence(self) -> list[Evidence]:
        return [e for e in self.evidence if not e.supports]

    @property
    def confidence(self) -> float:
        """Confidence in the hypothesis (distance from 0.5)."""
        return abs(self.posterior_probability - 0.5) * 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id[:10],
            "statement": self.statement[:40],
            "status": self.status.value,
            "prior": round(self.prior_probability, 3),
            "posterior": round(self.posterior_probability, 3),
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence_count,
            "supporting": len(self.supporting_evidence),
            "contradicting": len(self.contradicting_evidence),
        }


class HypothesisEngine:
    """Scientific method for vulnerability discovery.

    Uses Bayesian reasoning to generate, test, and update
    hypotheses about security vulnerabilities. Each hypothesis
    is treated as a scientific claim to be validated or refuted
    through evidence collection.
    """

    def __init__(
        self,
        confirmation_threshold: float = 0.85,
        refutation_threshold: float = 0.15,
    ) -> None:
        self._hypotheses: dict[str, Hypothesis] = {}
        self._counter = 0
        self._confirmation_threshold = confirmation_threshold
        self._refutation_threshold = refutation_threshold
        self._log = logger.bind(component="hypothesis_engine")

    def propose(
        self,
        statement: str,
        category: str = "",
        target: str = "",
        prior: float = 0.5,
        parent: str = "",
        tests: list[str] | None = None,
    ) -> Hypothesis:
        """Propose a new hypothesis."""
        self._counter += 1

        h = Hypothesis(
            hypothesis_id=f"hyp-{self._counter}",
            statement=statement,
            category=category,
            target=target,
            prior_probability=prior,
            posterior_probability=prior,
            tests_planned=tests or [],
            parent_hypothesis=parent,
        )

        self._hypotheses[h.hypothesis_id] = h

        # Link to parent
        if parent and parent in self._hypotheses:
            self._hypotheses[parent].child_hypotheses.append(h.hypothesis_id)

        return h

    def add_evidence(
        self,
        hypothesis_id: str,
        evidence_type: EvidenceType,
        source: str,
        description: str,
        supports: bool,
        strength: float = 0.5,
        reliability: float = 0.8,
    ) -> Evidence | None:
        """Add evidence and update hypothesis probability."""
        h = self._hypotheses.get(hypothesis_id)
        if not h:
            return None

        self._counter += 1
        evidence = Evidence(
            evidence_id=f"ev-{self._counter}",
            evidence_type=evidence_type,
            source=source,
            description=description,
            supports=supports,
            strength=strength,
            reliability=reliability,
        )

        h.evidence.append(evidence)

        # Bayesian update
        self._bayesian_update(h, evidence)

        # Check if hypothesis is resolved
        if h.posterior_probability >= self._confirmation_threshold:
            h.status = HypothesisStatus.CONFIRMED
            h.resolved_at = time.time()
        elif h.posterior_probability <= self._refutation_threshold:
            h.status = HypothesisStatus.REFUTED
            h.resolved_at = time.time()

        return evidence

    def _bayesian_update(self, h: Hypothesis, evidence: Evidence) -> None:
        """Update hypothesis probability using Bayes' theorem.

        P(H|E) = P(E|H) * P(H) / P(E)
        P(E) = P(E|H) * P(H) + P(E|~H) * P(~H)
        """
        prior = h.posterior_probability
        ws = evidence.weighted_strength

        if evidence.supports:
            # Likelihood: P(E|H) is high when evidence supports
            p_e_given_h = 0.5 + ws * 0.5     # 0.5 to 1.0
            p_e_given_not_h = 0.5 - ws * 0.4  # 0.1 to 0.5
        else:
            # Contradicting evidence
            p_e_given_h = 0.5 - ws * 0.4     # 0.1 to 0.5
            p_e_given_not_h = 0.5 + ws * 0.5  # 0.5 to 1.0

        # Bayes' theorem
        p_e = p_e_given_h * prior + p_e_given_not_h * (1 - prior)

        if p_e > 0:
            posterior = (p_e_given_h * prior) / p_e
        else:
            posterior = prior

        # Clamp to [0.01, 0.99]
        h.posterior_probability = max(0.01, min(0.99, posterior))

    def mark_testing(self, hypothesis_id: str, test_name: str) -> bool:
        """Mark a hypothesis as being tested."""
        h = self._hypotheses.get(hypothesis_id)
        if not h:
            return False

        h.status = HypothesisStatus.TESTING
        h.tests_completed.append(test_name)
        return True

    def get_hypothesis(self, hypothesis_id: str) -> Hypothesis | None:
        """Get a hypothesis by ID."""
        return self._hypotheses.get(hypothesis_id)

    def get_active_hypotheses(self) -> list[Hypothesis]:
        """Get all active (unresolved) hypotheses."""
        return [
            h for h in self._hypotheses.values()
            if h.status in (HypothesisStatus.PROPOSED, HypothesisStatus.TESTING)
        ]

    def get_confirmed(self) -> list[Hypothesis]:
        """Get all confirmed hypotheses."""
        return [
            h for h in self._hypotheses.values()
            if h.status == HypothesisStatus.CONFIRMED
        ]

    def get_prioritized(self) -> list[Hypothesis]:
        """Get active hypotheses prioritized by expected value.

        Priority = posterior_probability * (1 - confidence)
        This favors hypotheses that are likely true but not yet
        confirmed (most value from additional testing).
        """
        active = self.get_active_hypotheses()
        active.sort(
            key=lambda h: h.posterior_probability * (1 - h.confidence),
            reverse=True,
        )
        return active

    def generate_competing(
        self,
        observation: str,
        category: str = "",
        target: str = "",
        count: int = 3,
    ) -> list[Hypothesis]:
        """Generate competing hypotheses for an observation.

        For a given observation (e.g., "server returns 500"),
        generate multiple competing explanations.
        """
        competing_templates = {
            "500_error": [
                "Server-side injection vulnerability (SQLi/SSTI)",
                "Application error due to malformed input handling",
                "Rate limiting or WAF blocking the request",
            ],
            "auth_bypass": [
                "Authentication logic has a bypass vulnerability",
                "Session management is misconfigured",
                "Default credentials are in use",
            ],
            "data_exposure": [
                "Sensitive data exposed through API response",
                "Debug mode is enabled in production",
                "Access control is missing for this endpoint",
            ],
            "redirect": [
                "Open redirect vulnerability exists",
                "Server-side redirect is intentional behavior",
                "URL rewriting rule is misconfigured",
            ],
        }

        templates = competing_templates.get(category, [
            f"Observation '{observation[:30]}' indicates a security vulnerability",
            f"Observation '{observation[:30]}' is benign behavior",
            f"Observation '{observation[:30]}' is a false positive from the tool",
        ])

        hypotheses = []
        for i, template in enumerate(templates[:count]):
            # Assign priors that sum to ~1
            prior = 1.0 / count
            h = self.propose(
                statement=template,
                category=category,
                target=target,
                prior=prior,
            )
            hypotheses.append(h)

        return hypotheses

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        category_counts: dict[str, int] = defaultdict(int)
        for h in self._hypotheses.values():
            status_counts[h.status.value] += 1
            if h.category:
                category_counts[h.category] += 1

        total_evidence = sum(h.evidence_count for h in self._hypotheses.values())
        avg_confidence = 0.0
        confirmed = self.get_confirmed()
        if confirmed:
            avg_confidence = sum(h.confidence for h in confirmed) / len(confirmed)

        return {
            "hypotheses": len(self._hypotheses),
            "active": len(self.get_active_hypotheses()),
            "confirmed": len(confirmed),
            "total_evidence": total_evidence,
            "avg_confirmed_confidence": round(avg_confidence, 2),
            "by_status": dict(status_counts),
            "by_category": dict(category_counts),
        }
