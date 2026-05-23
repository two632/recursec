"""Hypothesis tracker — tracks and evaluates security hypotheses.

Implements:
1. Hypothesis formulation from observations
2. Evidence collection for/against hypotheses
3. Bayesian probability updates
4. Hypothesis testing and validation
5. Competing hypothesis analysis
6. Hypothesis lifecycle management
7. Confidence interval tracking
8. Decision support based on hypotheses
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
    INVESTIGATING = "investigating"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class EvidenceType(str, Enum):
    SUPPORTING = "supporting"
    CONTRADICTING = "contradicting"
    NEUTRAL = "neutral"


@dataclass
class Evidence:
    """Evidence for or against a hypothesis."""
    evidence_id: str = ""
    evidence_type: EvidenceType = EvidenceType.NEUTRAL
    description: str = ""
    source: str = ""
    strength: float = 0.5       # 0.0-1.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.evidence_id,
            "type": self.evidence_type.value,
            "strength": round(self.strength, 2),
            "source": self.source[:30],
        }


@dataclass
class Hypothesis:
    """A security hypothesis."""
    hypothesis_id: str = ""
    statement: str = ""
    category: str = ""             # vuln, config, access, network, crypto
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    prior_probability: float = 0.5
    current_probability: float = 0.5
    evidence: list[Evidence] = field(default_factory=list)
    related_findings: list[str] = field(default_factory=list)
    tests_planned: list[str] = field(default_factory=list)
    tests_completed: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    resolved_at: float = 0.0

    @property
    def supporting_count(self) -> int:
        return sum(1 for e in self.evidence if e.evidence_type == EvidenceType.SUPPORTING)

    @property
    def contradicting_count(self) -> int:
        return sum(1 for e in self.evidence if e.evidence_type == EvidenceType.CONTRADICTING)

    @property
    def confidence(self) -> float:
        """Confidence in the current probability estimate."""
        if not self.evidence:
            return 0.0
        total = len(self.evidence)
        avg_strength = sum(e.strength for e in self.evidence) / total
        return min(0.95, avg_strength * (1.0 - 1.0 / (total + 1)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id,
            "statement": self.statement[:60],
            "status": self.status.value,
            "probability": round(self.current_probability, 3),
            "confidence": round(self.confidence, 2),
            "supporting": self.supporting_count,
            "contradicting": self.contradicting_count,
        }


# ── Common Security Hypotheses ────────────────────────────────

HYPOTHESIS_TEMPLATES: list[dict[str, Any]] = [
    {
        "category": "vuln",
        "statement": "Target is vulnerable to SQL injection",
        "prior": 0.3,
        "tests": ["Run sqlmap against input fields", "Check for error-based SQL injection",
                  "Test for blind SQL injection"],
    },
    {
        "category": "vuln",
        "statement": "Target is vulnerable to XSS",
        "prior": 0.4,
        "tests": ["Inject XSS payloads in input fields", "Check for reflected XSS in parameters",
                  "Test for stored XSS in forms"],
    },
    {
        "category": "vuln",
        "statement": "Target is vulnerable to command injection",
        "prior": 0.15,
        "tests": ["Test command injection in input fields", "Check for OS command execution"],
    },
    {
        "category": "config",
        "statement": "Target uses default credentials",
        "prior": 0.2,
        "tests": ["Try common default credential pairs", "Check admin panels"],
    },
    {
        "category": "config",
        "statement": "Target exposes debug information",
        "prior": 0.25,
        "tests": ["Check for debug endpoints", "Look for verbose error messages",
                  "Scan for exposed stack traces"],
    },
    {
        "category": "config",
        "statement": "Target has directory listing enabled",
        "prior": 0.15,
        "tests": ["Request directory paths", "Check for index.html absence"],
    },
    {
        "category": "access",
        "statement": "Target has IDOR vulnerabilities",
        "prior": 0.25,
        "tests": ["Enumerate sequential IDs", "Test horizontal privilege escalation"],
    },
    {
        "category": "access",
        "statement": "Target has broken authentication",
        "prior": 0.2,
        "tests": ["Test password reset flow", "Check session management",
                  "Test for brute force protection"],
    },
    {
        "category": "crypto",
        "statement": "Target uses weak TLS configuration",
        "prior": 0.3,
        "tests": ["Run SSL scan", "Check cipher suites", "Verify certificate chain"],
    },
    {
        "category": "network",
        "statement": "Target has unnecessary open ports",
        "prior": 0.4,
        "tests": ["Full port scan", "Service enumeration on open ports"],
    },
]


class HypothesisTracker:
    """Tracks and evaluates security hypotheses.

    Uses Bayesian updates to maintain probability
    estimates based on collected evidence.
    """

    def __init__(self) -> None:
        self._hypotheses: dict[str, Hypothesis] = {}
        self._hyp_counter = 0
        self._evidence_counter = 0
        self._log = logger.bind(component="hypothesis_tracker")

    def propose(
        self,
        statement: str,
        category: str = "vuln",
        prior: float = 0.5,
        tests: list[str] | None = None,
    ) -> Hypothesis:
        """Propose a new hypothesis."""
        self._hyp_counter += 1
        hyp_id = f"hyp-{self._hyp_counter}"

        hyp = Hypothesis(
            hypothesis_id=hyp_id,
            statement=statement,
            category=category,
            prior_probability=prior,
            current_probability=prior,
            tests_planned=tests or [],
        )

        self._hypotheses[hyp_id] = hyp
        return hyp

    def propose_from_templates(
        self,
        categories: list[str] | None = None,
    ) -> list[Hypothesis]:
        """Propose hypotheses from common templates."""
        proposed = []
        for template in HYPOTHESIS_TEMPLATES:
            if categories and template["category"] not in categories:
                continue
            hyp = self.propose(
                statement=template["statement"],
                category=template["category"],
                prior=template.get("prior", 0.5),
                tests=template.get("tests", []),
            )
            proposed.append(hyp)
        return proposed

    def add_evidence(
        self,
        hypothesis_id: str,
        evidence_type: EvidenceType,
        description: str,
        strength: float = 0.5,
        source: str = "",
    ) -> Evidence | None:
        """Add evidence for/against a hypothesis."""
        hyp = self._hypotheses.get(hypothesis_id)
        if not hyp:
            return None

        self._evidence_counter += 1
        evidence = Evidence(
            evidence_id=f"ev-{self._evidence_counter}",
            evidence_type=evidence_type,
            description=description[:500],
            source=source,
            strength=strength,
        )

        hyp.evidence.append(evidence)
        hyp.status = HypothesisStatus.INVESTIGATING

        # Bayesian update
        self._bayesian_update(hyp, evidence)

        # Auto-resolve
        if hyp.current_probability >= 0.9 and hyp.confidence >= 0.7:
            hyp.status = HypothesisStatus.SUPPORTED
            hyp.resolved_at = time.time()
        elif hyp.current_probability <= 0.1 and hyp.confidence >= 0.7:
            hyp.status = HypothesisStatus.REFUTED
            hyp.resolved_at = time.time()

        return evidence

    def _bayesian_update(self, hyp: Hypothesis, evidence: Evidence) -> None:
        """Update hypothesis probability using Bayes' theorem."""
        prior = hyp.current_probability

        # Likelihood ratios based on evidence type and strength
        if evidence.evidence_type == EvidenceType.SUPPORTING:
            likelihood_ratio = 1.0 + evidence.strength * 3.0
        elif evidence.evidence_type == EvidenceType.CONTRADICTING:
            likelihood_ratio = 1.0 / (1.0 + evidence.strength * 3.0)
        else:
            likelihood_ratio = 1.0

        # Bayes update: posterior = prior * LR / (prior * LR + (1-prior))
        numerator = prior * likelihood_ratio
        denominator = numerator + (1.0 - prior)

        if denominator > 0:
            hyp.current_probability = max(0.01, min(0.99, numerator / denominator))

    def get_active(self) -> list[dict[str, Any]]:
        """Get active (unresolved) hypotheses."""
        active = [
            h for h in self._hypotheses.values()
            if h.status in (HypothesisStatus.PROPOSED, HypothesisStatus.INVESTIGATING)
        ]
        active.sort(key=lambda h: h.current_probability, reverse=True)
        return [h.to_dict() for h in active]

    def get_supported(self) -> list[dict[str, Any]]:
        """Get supported (likely true) hypotheses."""
        return [
            h.to_dict() for h in self._hypotheses.values()
            if h.status == HypothesisStatus.SUPPORTED
        ]

    def competing_analysis(self) -> list[dict[str, Any]]:
        """Analysis of Competing Hypotheses (ACH)."""
        active = [
            h for h in self._hypotheses.values()
            if h.status in (HypothesisStatus.PROPOSED, HypothesisStatus.INVESTIGATING)
        ]

        results = []
        for hyp in active:
            consistency_score = 0.0
            for evidence in hyp.evidence:
                if evidence.evidence_type == EvidenceType.SUPPORTING:
                    consistency_score += evidence.strength
                elif evidence.evidence_type == EvidenceType.CONTRADICTING:
                    consistency_score -= evidence.strength

            results.append({
                "hypothesis": hyp.statement[:60],
                "probability": round(hyp.current_probability, 3),
                "consistency": round(consistency_score, 2),
                "evidence_count": len(hyp.evidence),
            })

        results.sort(key=lambda r: r["probability"], reverse=True)
        return results

    def get_next_test(self) -> dict[str, Any] | None:
        """Get the highest-priority test to run next."""
        best_value = 0.0
        best_test = None
        best_hyp = None

        for hyp in self._hypotheses.values():
            if hyp.status not in (HypothesisStatus.PROPOSED, HypothesisStatus.INVESTIGATING):
                continue

            for test in hyp.tests_planned:
                if test in hyp.tests_completed:
                    continue

                # Value = uncertainty * prior
                uncertainty = 1.0 - abs(hyp.current_probability - 0.5) * 2
                value = uncertainty * hyp.prior_probability

                if value > best_value:
                    best_value = value
                    best_test = test
                    best_hyp = hyp

        if best_test and best_hyp:
            return {
                "hypothesis_id": best_hyp.hypothesis_id,
                "test": best_test,
                "value": round(best_value, 2),
            }

        return None

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for hyp in self._hypotheses.values():
            status_counts[hyp.status.value] += 1

        return {
            "total": len(self._hypotheses),
            "evidence": self._evidence_counter,
            "status": dict(status_counts),
        }
