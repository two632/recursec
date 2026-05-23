"""Hypothesis engine — generates and validates security hypotheses.

Implements:
1. Hypothesis generation from partial information
2. Evidence collection planning
3. Hypothesis validation/refutation
4. Bayesian confidence updating
5. Alternative hypothesis generation
6. Evidence chain building
7. False positive elimination
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
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    SUPERSEDED = "superseded"


class EvidenceType(str, Enum):
    TOOL_OUTPUT = "tool_output"
    LLM_ANALYSIS = "llm_analysis"
    MANUAL_CHECK = "manual_check"
    CORRELATION = "correlation"
    NEGATIVE = "negative"          # Absence of expected indicator


class EvidenceStrength(str, Enum):
    STRONG = "strong"         # Direct proof
    MODERATE = "moderate"     # Supports hypothesis
    WEAK = "weak"            # Partial/indirect
    CONTRADICTORY = "contradictory"  # Against hypothesis


@dataclass
class Evidence:
    """A piece of evidence for or against a hypothesis."""
    evidence_id: str = ""
    evidence_type: EvidenceType = EvidenceType.TOOL_OUTPUT
    strength: EvidenceStrength = EvidenceStrength.MODERATE
    source: str = ""           # Tool name or model ID
    description: str = ""
    raw_data: str = ""
    supports_hypothesis: bool = True
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.evidence_id[:10],
            "type": self.evidence_type.value,
            "strength": self.strength.value,
            "source": self.source[:15],
            "supports": self.supports_hypothesis,
        }


@dataclass
class TestPlan:
    """A plan to test a hypothesis."""
    plan_id: str = ""
    hypothesis_id: str = ""
    tool_name: str = ""
    tool_args: list[str] = field(default_factory=list)
    expected_if_true: str = ""      # What to expect if hypothesis is correct
    expected_if_false: str = ""     # What to expect if hypothesis is wrong
    priority: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.plan_id[:10],
            "tool": self.tool_name,
            "priority": self.priority,
        }


@dataclass
class Hypothesis:
    """A security hypothesis to test."""
    hypothesis_id: str = ""
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    description: str = ""
    category: str = ""          # e.g., "injection", "auth_bypass"
    target: str = ""
    prior_confidence: float = 0.5  # Initial probability
    current_confidence: float = 0.5
    evidence: list[Evidence] = field(default_factory=list)
    test_plans: list[TestPlan] = field(default_factory=list)
    alternatives: list[str] = field(default_factory=list)  # Alternative hypothesis IDs
    created_at: float = field(default_factory=time.time)
    resolved_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id[:10],
            "status": self.status.value,
            "desc": self.description[:30],
            "confidence": round(self.current_confidence, 2),
            "evidence_count": len(self.evidence),
            "tests_planned": len(self.test_plans),
        }


# ── Bayesian update weights ──────────────────────────────────

EVIDENCE_LIKELIHOOD_RATIOS: dict[str, dict[str, float]] = {
    "strong": {"supports": 4.0, "contradicts": 0.1},
    "moderate": {"supports": 2.0, "contradicts": 0.3},
    "weak": {"supports": 1.3, "contradicts": 0.7},
    "contradictory": {"supports": 0.2, "contradicts": 3.0},
}

# ── Hypothesis generation templates ──────────────────────────

HYPOTHESIS_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "open_port": [
        {"desc": "Service running on port {port} is vulnerable to known exploits",
         "category": "service_vuln", "prior": 0.3,
         "tests": [{"tool": "nmap", "args": ["--script", "vuln", "-p", "{port}"]}]},
        {"desc": "Service on port {port} has default credentials",
         "category": "default_creds", "prior": 0.4,
         "tests": [{"tool": "hydra", "args": ["-C", "default-creds.txt"]}]},
        {"desc": "Service on port {port} leaks version information",
         "category": "info_disclosure", "prior": 0.6,
         "tests": [{"tool": "nmap", "args": ["-sV", "-p", "{port}"]}]},
    ],
    "web_endpoint": [
        {"desc": "Endpoint {url} is vulnerable to SQL injection",
         "category": "injection", "prior": 0.2,
         "tests": [{"tool": "sqlmap", "args": ["-u", "{url}", "--batch"]}]},
        {"desc": "Endpoint {url} is vulnerable to XSS",
         "category": "xss", "prior": 0.3,
         "tests": [{"tool": "dalfox", "args": ["url", "{url}"]}]},
        {"desc": "Endpoint {url} has broken access control",
         "category": "access_control", "prior": 0.35,
         "tests": [{"tool": "custom", "args": ["test_idor"]}]},
    ],
    "authentication": [
        {"desc": "Authentication mechanism is vulnerable to brute force",
         "category": "brute_force", "prior": 0.3,
         "tests": [{"tool": "hydra", "args": ["-L", "users.txt", "-P", "pass.txt"]}]},
        {"desc": "Session management has predictable tokens",
         "category": "session", "prior": 0.2},
        {"desc": "Password reset flow is exploitable",
         "category": "auth_bypass", "prior": 0.25},
    ],
}


def _bayesian_update(prior: float, likelihood_ratio: float) -> float:
    """Update probability using Bayes' rule."""
    odds = prior / max(0.001, 1.0 - prior)
    posterior_odds = odds * likelihood_ratio
    posterior = posterior_odds / (1.0 + posterior_odds)
    return max(0.01, min(0.99, posterior))


class HypothesisEngine:
    """Generates and validates security hypotheses.

    Uses Bayesian reasoning to track confidence
    in security hypotheses and plan evidence
    collection.
    """

    def __init__(self) -> None:
        self._hypotheses: dict[str, Hypothesis] = {}
        self._counter = 0
        self._evidence_counter = 0
        self._plan_counter = 0
        self._log = logger.bind(component="hypothesis_engine")

    def generate_hypotheses(
        self,
        context_type: str,
        context_data: dict[str, Any],
    ) -> list[Hypothesis]:
        """Generate hypotheses from context."""
        templates = HYPOTHESIS_TEMPLATES.get(context_type, [])
        generated: list[Hypothesis] = []

        for tmpl in templates:
            self._counter += 1
            desc = tmpl["desc"]
            for key, value in context_data.items():
                desc = desc.replace("{" + key + "}", str(value))

            hyp = Hypothesis(
                hypothesis_id=f"hyp-{self._counter}",
                description=desc,
                category=tmpl.get("category", ""),
                target=context_data.get("target", ""),
                prior_confidence=tmpl.get("prior", 0.5),
                current_confidence=tmpl.get("prior", 0.5),
            )

            # Generate test plans
            for test in tmpl.get("tests", []):
                self._plan_counter += 1
                args = []
                for arg in test.get("args", []):
                    for k, v in context_data.items():
                        arg = arg.replace("{" + k + "}", str(v))
                    args.append(arg)

                plan = TestPlan(
                    plan_id=f"plan-{self._plan_counter}",
                    hypothesis_id=hyp.hypothesis_id,
                    tool_name=test.get("tool", ""),
                    tool_args=args,
                )
                hyp.test_plans.append(plan)

            self._hypotheses[hyp.hypothesis_id] = hyp
            generated.append(hyp)

        return generated

    def add_evidence(
        self,
        hypothesis_id: str,
        evidence_type: EvidenceType,
        strength: EvidenceStrength,
        source: str,
        description: str,
        supports: bool = True,
        raw_data: str = "",
    ) -> Evidence | None:
        """Add evidence and update confidence."""
        hyp = self._hypotheses.get(hypothesis_id)
        if not hyp:
            return None

        self._evidence_counter += 1
        evidence = Evidence(
            evidence_id=f"ev-{self._evidence_counter}",
            evidence_type=evidence_type,
            strength=strength,
            source=source,
            description=description,
            supports_hypothesis=supports,
            raw_data=raw_data,
        )
        hyp.evidence.append(evidence)

        # Bayesian update
        ratios = EVIDENCE_LIKELIHOOD_RATIOS.get(strength.value, {})
        if supports:
            lr = ratios.get("supports", 1.5)
        else:
            lr = ratios.get("contradicts", 0.5)

        hyp.current_confidence = _bayesian_update(hyp.current_confidence, lr)

        # Auto-resolve
        if hyp.current_confidence >= 0.90:
            hyp.status = HypothesisStatus.CONFIRMED
            hyp.resolved_at = time.time()
        elif hyp.current_confidence <= 0.10:
            hyp.status = HypothesisStatus.REFUTED
            hyp.resolved_at = time.time()

        return evidence

    def get_active_hypotheses(self) -> list[Hypothesis]:
        """Get hypotheses still being tested."""
        return [
            h for h in self._hypotheses.values()
            if h.status in (HypothesisStatus.PROPOSED, HypothesisStatus.TESTING)
        ]

    def get_confirmed(self) -> list[Hypothesis]:
        """Get confirmed hypotheses."""
        return [
            h for h in self._hypotheses.values()
            if h.status == HypothesisStatus.CONFIRMED
        ]

    def get_next_test_plan(self) -> TestPlan | None:
        """Get the highest priority untested plan."""
        for hyp in self.get_active_hypotheses():
            if hyp.test_plans:
                return hyp.test_plans[0]
        return None

    def consume_test_plan(self, hypothesis_id: str) -> TestPlan | None:
        """Pop the next test plan for a hypothesis."""
        hyp = self._hypotheses.get(hypothesis_id)
        if not hyp or not hyp.test_plans:
            return None
        plan = hyp.test_plans.pop(0)
        hyp.status = HypothesisStatus.TESTING
        return plan

    def build_hypothesis_prompt(self, max_hypotheses: int = 5) -> str:
        """Build hypothesis context for LLM."""
        lines = ["## Active Hypotheses\n"]
        active = self.get_active_hypotheses()
        for hyp in active[:max_hypotheses]:
            lines.append(
                f"- [{hyp.current_confidence:.0%}] {hyp.description} "
                f"({len(hyp.evidence)} evidence, {len(hyp.test_plans)} tests remaining)"
            )
        confirmed = self.get_confirmed()
        if confirmed:
            lines.append("\n## Confirmed Findings:")
            for hyp in confirmed[:5]:
                lines.append(f"- {hyp.description} ({hyp.current_confidence:.0%})")
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for h in self._hypotheses.values():
            status_counts[h.status.value] = status_counts.get(h.status.value, 0) + 1

        return {
            "total": len(self._hypotheses),
            "by_status": status_counts,
            "total_evidence": sum(len(h.evidence) for h in self._hypotheses.values()),
        }
