"""Hypothesis engine — generates, tests, and refines security hypotheses.

Implements:
1. Hypothesis generation from observations
2. Hypothesis scoring and ranking
3. Evidence tracking (supporting + contradicting)
4. Hypothesis refinement from new evidence
5. Hypothesis tree (parent-child relationships)
6. Automated test design for hypotheses
7. Bayesian confidence updating
8. Hypothesis pruning (low-confidence removal)
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
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    MERGED = "merged"


class EvidenceType(str, Enum):
    SUPPORTING = "supporting"
    CONTRADICTING = "contradicting"
    NEUTRAL = "neutral"


class HypothesisCategory(str, Enum):
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    INFORMATION_LEAK = "information_leak"
    ACCESS_CONTROL = "access_control"
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    CRYPTOGRAPHIC = "cryptographic"
    BUSINESS_LOGIC = "business_logic"


@dataclass
class Evidence:
    """A piece of evidence for or against a hypothesis."""
    evidence_id: str = ""
    evidence_type: EvidenceType = EvidenceType.NEUTRAL
    source: str = ""              # tool/model that produced it
    content: str = ""
    strength: float = 0.5         # 0.0 (weak) to 1.0 (definitive)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.evidence_id,
            "type": self.evidence_type.value,
            "source": self.source[:15],
            "content": self.content[:40],
            "strength": round(self.strength, 2),
        }


@dataclass
class HypothesisTest:
    """A test designed to evaluate a hypothesis."""
    test_id: str = ""
    description: str = ""
    tool: str = ""
    command_template: str = ""
    expected_if_true: str = ""
    expected_if_false: str = ""
    executed: bool = False
    result: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.test_id,
            "desc": self.description[:35],
            "tool": self.tool[:15],
            "executed": self.executed,
        }


@dataclass
class Hypothesis:
    """A security hypothesis."""
    hypothesis_id: str = ""
    title: str = ""
    description: str = ""
    category: HypothesisCategory = HypothesisCategory.VULNERABILITY
    target: str = ""
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    prior_probability: float = 0.5
    posterior_probability: float = 0.5
    evidence: list[Evidence] = field(default_factory=list)
    tests: list[HypothesisTest] = field(default_factory=list)
    parent_id: str = ""
    child_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    @property
    def supporting_evidence_count(self) -> int:
        return sum(1 for e in self.evidence if e.evidence_type == EvidenceType.SUPPORTING)

    @property
    def contradicting_evidence_count(self) -> int:
        return sum(1 for e in self.evidence if e.evidence_type == EvidenceType.CONTRADICTING)

    @property
    def net_evidence_strength(self) -> float:
        supporting = sum(
            e.strength for e in self.evidence if e.evidence_type == EvidenceType.SUPPORTING
        )
        contradicting = sum(
            e.strength for e in self.evidence if e.evidence_type == EvidenceType.CONTRADICTING
        )
        return supporting - contradicting

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id,
            "title": self.title[:35],
            "category": self.category.value,
            "status": self.status.value,
            "prior": round(self.prior_probability, 3),
            "posterior": round(self.posterior_probability, 3),
            "evidence": len(self.evidence),
            "tests": len(self.tests),
            "children": len(self.child_ids),
        }


# ── Prior Probabilities by Category ──────────────────────────

CATEGORY_PRIORS: dict[HypothesisCategory, float] = {
    HypothesisCategory.VULNERABILITY: 0.3,
    HypothesisCategory.MISCONFIGURATION: 0.4,
    HypothesisCategory.INFORMATION_LEAK: 0.5,
    HypothesisCategory.ACCESS_CONTROL: 0.25,
    HypothesisCategory.INJECTION: 0.2,
    HypothesisCategory.AUTHENTICATION: 0.3,
    HypothesisCategory.CRYPTOGRAPHIC: 0.15,
    HypothesisCategory.BUSINESS_LOGIC: 0.1,
}

# ── Hypothesis Templates ─────────────────────────────────────

HYPOTHESIS_TEMPLATES: list[dict[str, Any]] = [
    {
        "trigger": "open_port_80",
        "title": "Web application vulnerabilities present",
        "category": "vulnerability",
        "desc": "Web server on port 80/443 may have common web vulnerabilities",
        "tests": [
            {"tool": "nuclei", "desc": "Run nuclei vulnerability scan"},
            {"tool": "nikto", "desc": "Run nikto web scan"},
        ],
    },
    {
        "trigger": "open_port_22",
        "title": "SSH may allow weak authentication",
        "category": "authentication",
        "desc": "SSH service may accept weak passwords or have vulnerable config",
        "tests": [
            {"tool": "nmap", "desc": "Check SSH auth methods: nmap --script ssh-auth-methods"},
        ],
    },
    {
        "trigger": "directory_listing",
        "title": "Directory listing reveals sensitive files",
        "category": "information_leak",
        "desc": "Enabled directory listing may expose sensitive files or paths",
        "tests": [
            {"tool": "ffuf", "desc": "Enumerate exposed directories"},
        ],
    },
    {
        "trigger": "version_disclosure",
        "title": "Outdated software version with known CVEs",
        "category": "vulnerability",
        "desc": "Disclosed software version may have known vulnerabilities",
        "tests": [
            {"tool": "searchsploit", "desc": "Search for known exploits for this version"},
        ],
    },
    {
        "trigger": "form_input",
        "title": "Form input susceptible to injection",
        "category": "injection",
        "desc": "Input forms may be vulnerable to SQL injection, XSS, or command injection",
        "tests": [
            {"tool": "sqlmap", "desc": "Test for SQL injection"},
            {"tool": "dalfox", "desc": "Test for XSS"},
        ],
    },
    {
        "trigger": "api_endpoint",
        "title": "API endpoint lacks proper authorization",
        "category": "access_control",
        "desc": "API endpoints may allow unauthorized access or IDOR",
        "tests": [
            {"tool": "arjun", "desc": "Discover API parameters"},
        ],
    },
    {
        "trigger": "tls_weak",
        "title": "TLS/SSL misconfiguration",
        "category": "cryptographic",
        "desc": "TLS configuration may use weak ciphers or protocols",
        "tests": [
            {"tool": "testssl", "desc": "Full TLS analysis"},
        ],
    },
]


class HypothesisEngine:
    """Generates, tests, and refines security hypotheses.

    Uses Bayesian updating to maintain hypothesis confidence
    and automatically designs tests to evaluate them.
    """

    def __init__(self) -> None:
        self._hypotheses: dict[str, Hypothesis] = {}
        self._hypothesis_counter = 0
        self._evidence_counter = 0
        self._test_counter = 0
        self._log = logger.bind(component="hypothesis_engine")

    def generate(
        self,
        title: str,
        description: str = "",
        category: HypothesisCategory = HypothesisCategory.VULNERABILITY,
        target: str = "",
        prior: float = 0.0,
        parent_id: str = "",
        tags: list[str] | None = None,
    ) -> Hypothesis:
        """Generate a new hypothesis."""
        self._hypothesis_counter += 1

        if prior <= 0:
            prior = CATEGORY_PRIORS.get(category, 0.3)

        hypothesis = Hypothesis(
            hypothesis_id=f"hyp-{self._hypothesis_counter}",
            title=title,
            description=description,
            category=category,
            target=target,
            prior_probability=prior,
            posterior_probability=prior,
            parent_id=parent_id,
            tags=tags or [],
        )

        self._hypotheses[hypothesis.hypothesis_id] = hypothesis

        # Link to parent
        if parent_id and parent_id in self._hypotheses:
            self._hypotheses[parent_id].child_ids.append(hypothesis.hypothesis_id)

        return hypothesis

    def generate_from_trigger(
        self,
        trigger: str,
        target: str = "",
    ) -> list[Hypothesis]:
        """Generate hypotheses from an observation trigger."""
        generated = []

        for template in HYPOTHESIS_TEMPLATES:
            if template["trigger"] == trigger:
                hyp = self.generate(
                    title=template["title"],
                    description=template["desc"],
                    category=HypothesisCategory(template["category"]),
                    target=target,
                )

                # Add tests from template
                for test_data in template.get("tests", []):
                    self._test_counter += 1
                    test = HypothesisTest(
                        test_id=f"ht-{self._test_counter}",
                        description=test_data["desc"],
                        tool=test_data["tool"],
                    )
                    hyp.tests.append(test)

                generated.append(hyp)

        return generated

    def add_evidence(
        self,
        hypothesis_id: str,
        evidence_type: EvidenceType,
        source: str,
        content: str,
        strength: float = 0.5,
    ) -> Evidence | None:
        """Add evidence to a hypothesis and update belief."""
        hyp = self._hypotheses.get(hypothesis_id)
        if not hyp:
            return None

        self._evidence_counter += 1
        evidence = Evidence(
            evidence_id=f"ev-{self._evidence_counter}",
            evidence_type=evidence_type,
            source=source,
            content=content,
            strength=strength,
        )

        hyp.evidence.append(evidence)
        hyp.updated_at = time.time()

        # Bayesian update
        self._bayesian_update(hyp, evidence)

        # Auto-update status
        if hyp.posterior_probability > 0.8:
            hyp.status = HypothesisStatus.SUPPORTED
        elif hyp.posterior_probability < 0.1:
            hyp.status = HypothesisStatus.REFUTED

        return evidence

    @staticmethod
    def _bayesian_update(hyp: Hypothesis, evidence: Evidence) -> None:
        """Update hypothesis probability using Bayes' theorem.

        P(H|E) = P(E|H) * P(H) / P(E)
        """
        prior = hyp.posterior_probability

        if evidence.evidence_type == EvidenceType.SUPPORTING:
            # P(E|H) is high for supporting evidence
            likelihood = 0.5 + evidence.strength * 0.5
            # P(E|¬H) is lower
            likelihood_not_h = 0.5 - evidence.strength * 0.3
        elif evidence.evidence_type == EvidenceType.CONTRADICTING:
            # P(E|H) is low for contradicting evidence
            likelihood = 0.5 - evidence.strength * 0.4
            # P(E|¬H) is higher
            likelihood_not_h = 0.5 + evidence.strength * 0.4
        else:
            return  # Neutral evidence doesn't update

        # P(E) = P(E|H)*P(H) + P(E|¬H)*P(¬H)
        marginal = likelihood * prior + likelihood_not_h * (1 - prior)

        if marginal > 0:
            posterior = (likelihood * prior) / marginal
            hyp.posterior_probability = max(0.001, min(0.999, posterior))

    def get_testable(self, limit: int = 5) -> list[Hypothesis]:
        """Get hypotheses that need testing, ranked by value of information."""
        testable = []

        for hyp in self._hypotheses.values():
            if hyp.status not in (HypothesisStatus.PROPOSED, HypothesisStatus.TESTING):
                continue

            untested = [t for t in hyp.tests if not t.executed]
            if not untested:
                continue

            # Value of information: highest near 0.5 (maximum uncertainty)
            uncertainty = 1.0 - abs(hyp.posterior_probability - 0.5) * 2
            testable.append((uncertainty, hyp))

        testable.sort(key=lambda x: x[0], reverse=True)
        return [h for _, h in testable[:limit]]

    def prune(self, threshold: float = 0.05) -> int:
        """Prune low-confidence hypotheses."""
        to_remove = []
        for hyp_id, hyp in self._hypotheses.items():
            if hyp.posterior_probability < threshold and not hyp.child_ids:
                to_remove.append(hyp_id)

        for hyp_id in to_remove:
            del self._hypotheses[hyp_id]

        return len(to_remove)

    def get_by_category(
        self,
        category: HypothesisCategory,
    ) -> list[Hypothesis]:
        return [
            h for h in self._hypotheses.values()
            if h.category == category
        ]

    def get_supported(self) -> list[Hypothesis]:
        return [
            h for h in self._hypotheses.values()
            if h.status == HypothesisStatus.SUPPORTED
        ]

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for hyp in self._hypotheses.values():
            status_counts[hyp.status.value] += 1

        return {
            "hypotheses": len(self._hypotheses),
            "statuses": dict(status_counts),
            "evidence": self._evidence_counter,
            "tests": self._test_counter,
        }
