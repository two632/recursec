"""Reasoning validator — validates and challenges agent reasoning.

Implements:
1. Logical consistency checking
2. Evidence sufficiency verification
3. Assumption identification and validation
4. Contradiction detection across reasoning chains
5. Argument strength scoring
6. Common fallacy detection
7. Counter-argument generation
8. Reasoning confidence assessment
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ValidationResult(str, Enum):
    VALID = "valid"
    WEAK = "weak"
    INVALID = "invalid"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CONTRADICTORY = "contradictory"
    FALLACIOUS = "fallacious"


class FallacyType(str, Enum):
    FALSE_POSITIVE_BIAS = "false_positive_bias"
    CONFIRMATION_BIAS = "confirmation_bias"
    ANCHORING = "anchoring"
    AVAILABILITY_HEURISTIC = "availability_heuristic"
    HASTY_GENERALIZATION = "hasty_generalization"
    FALSE_CAUSE = "false_cause"
    APPEAL_TO_AUTHORITY = "appeal_to_authority"
    CHERRY_PICKING = "cherry_picking"


@dataclass
class Assumption:
    """An identified assumption in reasoning."""
    assumption_id: str = ""
    statement: str = ""
    explicit: bool = False         # Explicitly stated vs implicit
    validated: bool = False
    validation_method: str = ""
    risk_if_wrong: str = "low"     # What happens if this assumption is wrong

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.assumption_id, "statement": self.statement[:80],
            "explicit": self.explicit, "validated": self.validated,
            "risk": self.risk_if_wrong,
        }


@dataclass
class ValidationReport:
    """Result of reasoning validation."""
    report_id: str = ""
    result: ValidationResult = ValidationResult.VALID
    overall_score: float = 0.5
    evidence_score: float = 0.5
    consistency_score: float = 0.5
    assumptions: list[Assumption] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    fallacies: list[str] = field(default_factory=list)
    counter_arguments: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.report_id, "result": self.result.value,
            "score": round(self.overall_score, 2),
            "evidence": round(self.evidence_score, 2),
            "consistency": round(self.consistency_score, 2),
            "assumptions": len(self.assumptions),
            "contradictions": len(self.contradictions),
            "fallacies": len(self.fallacies),
        }


# ── Common Security Reasoning Patterns ──────────────────────

VALID_REASONING_PATTERNS = [
    "port_open_implies_service",           # Open port → service running
    "service_version_implies_vulns",       # Known version → check CVEs
    "default_creds_on_admin_panel",        # Admin panel → try defaults
    "info_disclosure_leads_to_exploitation",  # Leaked info → exploit path
    "misconfiguration_enables_attack",     # Misconfig → attack vector
]

COMMON_FALSE_POSITIVES = [
    "waf_reflected_as_vuln",             # WAF response misidentified
    "cdn_ip_as_target",                  # CDN IP not actual target
    "honeypot_as_real_service",          # Honeypot detection
    "rate_limited_as_down",              # Rate limiting → false negative
    "version_string_spoofed",            # Fake version string
]


class ReasoningValidator:
    """Validates and challenges agent reasoning.

    Checks for logical consistency, evidence sufficiency,
    and common fallacies in security assessment reasoning.
    """

    def __init__(self) -> None:
        self._report_counter = 0
        self._assumption_counter = 0
        self._validation_history: list[ValidationReport] = []
        self._log = logger.bind(component="reasoning_validator")

    def validate(
        self,
        reasoning_steps: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        conclusion: str = "",
    ) -> ValidationReport:
        """Validate a reasoning chain."""
        self._report_counter += 1
        report = ValidationReport(
            report_id=f"val-{self._report_counter}",
        )

        # Check evidence sufficiency
        report.evidence_score = self._check_evidence(reasoning_steps, evidence)

        # Check logical consistency
        report.consistency_score = self._check_consistency(reasoning_steps)

        # Identify assumptions
        report.assumptions = self._identify_assumptions(reasoning_steps)

        # Detect contradictions
        report.contradictions = self._detect_contradictions(reasoning_steps)

        # Detect fallacies
        report.fallacies = self._detect_fallacies(reasoning_steps, conclusion)

        # Generate counter-arguments
        report.counter_arguments = self._generate_counters(reasoning_steps, conclusion)

        # Generate recommendations
        report.recommendations = self._generate_recommendations(report)

        # Overall score
        report.overall_score = (
            report.evidence_score * 0.4 +
            report.consistency_score * 0.3 +
            (1.0 - len(report.contradictions) * 0.15) * 0.15 +
            (1.0 - len(report.fallacies) * 0.1) * 0.15
        )
        report.overall_score = max(0.0, min(1.0, report.overall_score))

        # Determine result
        if report.overall_score >= 0.8 and not report.contradictions:
            report.result = ValidationResult.VALID
        elif report.overall_score >= 0.5:
            report.result = ValidationResult.WEAK
        elif report.contradictions:
            report.result = ValidationResult.CONTRADICTORY
        elif report.fallacies:
            report.result = ValidationResult.FALLACIOUS
        elif report.evidence_score < 0.3:
            report.result = ValidationResult.INSUFFICIENT_EVIDENCE
        else:
            report.result = ValidationResult.INVALID

        self._validation_history.append(report)
        if len(self._validation_history) > 200:
            self._validation_history = self._validation_history[-200:]

        return report

    def _check_evidence(
        self,
        steps: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
    ) -> float:
        """Check if evidence supports the reasoning."""
        if not steps:
            return 0.0

        supported_steps = 0
        for step in steps:
            step_text = str(step.get("inference", "")) + str(step.get("conclusion", ""))

            has_support = False
            for ev in evidence:
                ev_text = str(ev.get("description", "")) + str(ev.get("data", ""))
                # Simple keyword overlap check
                step_words = set(step_text.lower().split())
                ev_words = set(ev_text.lower().split())
                overlap = len(step_words & ev_words)
                if overlap >= 3:
                    has_support = True
                    break

            if has_support:
                supported_steps += 1

        return supported_steps / max(1, len(steps))

    def _check_consistency(self, steps: list[dict[str, Any]]) -> float:
        """Check logical consistency between steps."""
        if len(steps) <= 1:
            return 1.0

        inconsistencies = 0

        for i in range(len(steps) - 1):
            current = str(steps[i].get("conclusion", "")).lower()
            next_premise = str(steps[i + 1].get("premise", "")).lower()

            # Check if current conclusion feeds into next premise
            current_words = set(current.split())
            premise_words = set(next_premise.split())
            if not current_words & premise_words:
                inconsistencies += 1

        return max(0.0, 1.0 - inconsistencies / max(1, len(steps) - 1))

    def _identify_assumptions(self, steps: list[dict[str, Any]]) -> list[Assumption]:
        """Identify assumptions in reasoning."""
        assumptions = []

        assumption_indicators = [
            ("assumes", "explicit"), ("assuming", "explicit"),
            ("likely", "implicit"), ("probably", "implicit"),
            ("should", "implicit"), ("typically", "implicit"),
            ("usually", "implicit"), ("expected", "implicit"),
            ("default", "implicit"), ("standard", "implicit"),
        ]

        for step in steps:
            text = str(step.get("inference", "")) + " " + str(step.get("premise", ""))
            text_lower = text.lower()

            for indicator, kind in assumption_indicators:
                if indicator in text_lower:
                    self._assumption_counter += 1
                    assumptions.append(Assumption(
                        assumption_id=f"assumption-{self._assumption_counter}",
                        statement=f"Assumed: '{indicator}' in reasoning",
                        explicit=(kind == "explicit"),
                    ))

        return assumptions

    def _detect_contradictions(self, steps: list[dict[str, Any]]) -> list[str]:
        """Detect contradictions between reasoning steps."""
        contradictions = []
        conclusions = [str(s.get("conclusion", "")).lower() for s in steps]

        # Simple contradiction detection
        negation_pairs = [
            ("vulnerable", "not vulnerable"),
            ("open", "closed"),
            ("exposed", "protected"),
            ("valid", "invalid"),
            ("present", "absent"),
            ("confirmed", "denied"),
        ]

        for i, c1 in enumerate(conclusions):
            for j, c2 in enumerate(conclusions):
                if i >= j:
                    continue
                for pos, neg in negation_pairs:
                    if pos in c1 and neg in c2:
                        contradictions.append(
                            f"Step {i + 1} says '{pos}' but step {j + 1} says '{neg}'"
                        )
                    elif neg in c1 and pos in c2:
                        contradictions.append(
                            f"Step {i + 1} says '{neg}' but step {j + 1} says '{pos}'"
                        )

        return contradictions

    def _detect_fallacies(
        self,
        steps: list[dict[str, Any]],
        conclusion: str,
    ) -> list[str]:
        """Detect common reasoning fallacies."""
        fallacies = []
        all_text = " ".join(str(s.get("inference", "")) for s in steps).lower()

        # False positive bias
        if "must be" in all_text and "vulnerable" in all_text:
            if "evidence" not in all_text and "confirmed" not in all_text:
                fallacies.append("Potential false positive bias: concluding vulnerability without confirmation")

        # Hasty generalization
        if "all" in all_text or "every" in all_text or "always" in all_text:
            if len(steps) < 3:
                fallacies.append("Hasty generalization: broad claim with limited reasoning steps")

        # Appeal to tool authority
        if any(tool in all_text for tool in ["nmap says", "nuclei found", "scanner reported"]):
            if "verify" not in all_text and "confirm" not in all_text:
                fallacies.append("Appeal to tool authority: accepting tool output without verification")

        return fallacies

    def _generate_counters(
        self,
        steps: list[dict[str, Any]],
        conclusion: str,
    ) -> list[str]:
        """Generate counter-arguments."""
        counters = []
        conclusion_lower = conclusion.lower()

        if "vulnerable" in conclusion_lower:
            counters.append("Could be a false positive from scanner misconfiguration")
            counters.append("The vulnerability may be mitigated by WAF/IPS")
            counters.append("The affected version may have been patched without updating the banner")

        if "critical" in conclusion_lower:
            counters.append("The impact may be limited by network segmentation")
            counters.append("Exploitation may require additional prerequisites not considered")

        if "default" in conclusion_lower and "credential" in conclusion_lower:
            counters.append("The service may be using a different authentication method")
            counters.append("The default credentials may have been changed")

        return counters

    def _generate_recommendations(self, report: ValidationReport) -> list[str]:
        """Generate recommendations based on validation."""
        recs = []

        if report.evidence_score < 0.5:
            recs.append("Gather more evidence before concluding")

        if report.contradictions:
            recs.append("Resolve contradictions between reasoning steps")

        if report.fallacies:
            recs.append("Address identified reasoning fallacies")

        unvalidated = [a for a in report.assumptions if not a.validated]
        if unvalidated:
            recs.append(f"Validate {len(unvalidated)} unverified assumptions")

        return recs

    def get_stats(self) -> dict[str, Any]:
        return {
            "validations": len(self._validation_history),
            "avg_score": round(
                sum(r.overall_score for r in self._validation_history) /
                max(1, len(self._validation_history)),
                2,
            ),
        }
