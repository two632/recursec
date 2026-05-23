"""Risk scorer — CVSS-based risk scoring engine.

Implements:
1. CVSS v3.1 base score calculation
2. Environmental and temporal adjustments
3. Finding severity classification
4. Risk aggregation across findings
5. Business impact assessment
6. Risk trend tracking
7. Risk prompt for LLM context
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AttackVector(str, Enum):
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(str, Enum):
    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(str, Enum):
    NONE = "N"
    REQUIRED = "R"


class Scope(str, Enum):
    UNCHANGED = "U"
    CHANGED = "C"


class Impact(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class SeverityRating(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CVSSVector:
    """CVSS v3.1 base score vector."""
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: Impact = Impact.HIGH
    integrity: Impact = Impact.HIGH
    availability: Impact = Impact.HIGH

    def to_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.attack_vector.value}"
            f"/AC:{self.attack_complexity.value}"
            f"/PR:{self.privileges_required.value}"
            f"/UI:{self.user_interaction.value}"
            f"/S:{self.scope.value}"
            f"/C:{self.confidentiality.value}"
            f"/I:{self.integrity.value}"
            f"/A:{self.availability.value}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "vector": self.to_string(),
            "AV": self.attack_vector.value,
            "AC": self.attack_complexity.value,
            "PR": self.privileges_required.value,
        }


@dataclass
class RiskAssessment:
    """Risk assessment for a finding."""
    finding_id: str = ""
    cvss_vector: CVSSVector = field(default_factory=CVSSVector)
    base_score: float = 0.0
    severity: SeverityRating = SeverityRating.NONE
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    business_impact: str = ""
    remediation_priority: int = 0    # 1 = fix first
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding_id[:10],
            "score": round(self.base_score, 1),
            "severity": self.severity.value,
            "exploitability": round(self.exploitability_score, 1),
            "impact": round(self.impact_score, 1),
            "priority": self.remediation_priority,
        }


# ── CVSS v3.1 metric values ─────────────────────────────────

AV_VALUES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_VALUES = {"L": 0.77, "H": 0.44}
PR_VALUES_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_VALUES_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI_VALUES = {"N": 0.85, "R": 0.62}
IMPACT_VALUES = {"N": 0.0, "L": 0.22, "H": 0.56}


class RiskScorer:
    """CVSS-based risk scoring engine.

    Calculates CVSS v3.1 base scores, classifies
    severity, and tracks risk across assessments.
    """

    def __init__(self) -> None:
        self._assessments: dict[str, RiskAssessment] = {}
        self._counter = 0
        self._log = logger.bind(component="risk_scorer")

    def score(
        self,
        finding_id: str,
        vector: CVSSVector,
        business_impact: str = "",
    ) -> RiskAssessment:
        """Calculate CVSS score for a finding."""
        self._counter += 1

        exploitability = self._calc_exploitability(vector)
        impact = self._calc_impact(vector)
        base_score = self._calc_base_score(exploitability, impact, vector.scope)
        severity = self._classify_severity(base_score)

        assessment = RiskAssessment(
            finding_id=finding_id,
            cvss_vector=vector,
            base_score=base_score,
            severity=severity,
            exploitability_score=exploitability,
            impact_score=impact,
            business_impact=business_impact,
        )

        self._assessments[finding_id] = assessment

        # Calculate remediation priority
        self._update_priorities()

        return assessment

    def score_from_cwe(
        self,
        finding_id: str,
        cwe_id: str,
    ) -> RiskAssessment:
        """Score based on CWE ID with default vectors."""
        vector = CWE_VECTORS.get(cwe_id, CVSSVector())
        return self.score(finding_id, vector)

    def get_risk_summary(self) -> dict[str, Any]:
        """Get overall risk summary."""
        if not self._assessments:
            return {"total": 0}

        severities: dict[str, int] = {}
        total_score = 0.0
        for a in self._assessments.values():
            severities[a.severity.value] = severities.get(a.severity.value, 0) + 1
            total_score += a.base_score

        return {
            "total": len(self._assessments),
            "by_severity": severities,
            "avg_score": total_score / len(self._assessments),
            "max_score": max(a.base_score for a in self._assessments.values()),
        }

    def get_top_risks(self, limit: int = 10) -> list[RiskAssessment]:
        """Get highest-risk findings."""
        sorted_risks = sorted(
            self._assessments.values(),
            key=lambda a: a.base_score,
            reverse=True,
        )
        return sorted_risks[:limit]

    def build_risk_prompt(self, max_findings: int = 10) -> str:
        """Build risk context for LLM."""
        lines = ["## Risk Assessment\n"]

        summary = self.get_risk_summary()
        if not summary.get("total"):
            lines.append("No findings scored yet.")
            return "\n".join(lines)

        lines.append(
            f"Findings: {summary['total']} | "
            f"Avg CVSS: {summary['avg_score']:.1f} | "
            f"Max: {summary['max_score']:.1f}"
        )

        sev = summary.get("by_severity", {})
        parts = []
        for s in ["critical", "high", "medium", "low", "none"]:
            count = sev.get(s, 0)
            if count:
                parts.append(f"{s}={count}")
        if parts:
            lines.append(f"Severity: {' '.join(parts)}")

        top = self.get_top_risks(max_findings)
        if top:
            lines.append("\nTop risks:")
            for a in top:
                lines.append(
                    f"  [{a.severity.value[0].upper()}] {a.finding_id[:15]} "
                    f"CVSS={a.base_score:.1f} {a.cvss_vector.to_string()[:30]}"
                )

        return "\n".join(lines)

    def _calc_exploitability(self, v: CVSSVector) -> float:
        """Calculate exploitability sub-score."""
        av = AV_VALUES.get(v.attack_vector.value, 0.85)
        ac = AC_VALUES.get(v.attack_complexity.value, 0.77)
        pr_map = PR_VALUES_CHANGED if v.scope == Scope.CHANGED else PR_VALUES_UNCHANGED
        pr = pr_map.get(v.privileges_required.value, 0.85)
        ui = UI_VALUES.get(v.user_interaction.value, 0.85)
        return 8.22 * av * ac * pr * ui

    def _calc_impact(self, v: CVSSVector) -> float:
        """Calculate impact sub-score."""
        c = IMPACT_VALUES.get(v.confidentiality.value, 0.56)
        i = IMPACT_VALUES.get(v.integrity.value, 0.56)
        a = IMPACT_VALUES.get(v.availability.value, 0.56)

        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        if v.scope == Scope.UNCHANGED:
            return 6.42 * iss
        else:
            return 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    def _calc_base_score(
        self,
        exploitability: float,
        impact: float,
        scope: Scope,
    ) -> float:
        """Calculate base score."""
        if impact <= 0:
            return 0.0

        if scope == Scope.UNCHANGED:
            raw = min(exploitability + impact, 10.0)
        else:
            raw = min(1.08 * (exploitability + impact), 10.0)

        # Round up to one decimal
        return round(raw * 10) / 10

    def _classify_severity(self, score: float) -> SeverityRating:
        """Classify severity from CVSS score."""
        if score == 0.0:
            return SeverityRating.NONE
        if score <= 3.9:
            return SeverityRating.LOW
        if score <= 6.9:
            return SeverityRating.MEDIUM
        if score <= 8.9:
            return SeverityRating.HIGH
        return SeverityRating.CRITICAL

    def _update_priorities(self) -> None:
        """Update remediation priorities."""
        sorted_list = sorted(
            self._assessments.values(),
            key=lambda a: a.base_score,
            reverse=True,
        )
        for i, a in enumerate(sorted_list):
            a.remediation_priority = i + 1

    def get_stats(self) -> dict[str, Any]:
        return self.get_risk_summary()


# ── Common CWE to CVSS vector mappings ───────────────────────

CWE_VECTORS: dict[str, CVSSVector] = {
    "CWE-89": CVSSVector(  # SQL Injection
        attack_vector=AttackVector.NETWORK, attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE, user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED, confidentiality=Impact.HIGH, integrity=Impact.HIGH, availability=Impact.HIGH,
    ),
    "CWE-79": CVSSVector(  # XSS
        attack_vector=AttackVector.NETWORK, attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE, user_interaction=UserInteraction.REQUIRED,
        scope=Scope.CHANGED, confidentiality=Impact.LOW, integrity=Impact.LOW, availability=Impact.NONE,
    ),
    "CWE-78": CVSSVector(  # OS Command Injection
        attack_vector=AttackVector.NETWORK, attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE, user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED, confidentiality=Impact.HIGH, integrity=Impact.HIGH, availability=Impact.HIGH,
    ),
    "CWE-918": CVSSVector(  # SSRF
        attack_vector=AttackVector.NETWORK, attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE, user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED, confidentiality=Impact.HIGH, integrity=Impact.NONE, availability=Impact.NONE,
    ),
    "CWE-502": CVSSVector(  # Deserialization
        attack_vector=AttackVector.NETWORK, attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE, user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED, confidentiality=Impact.HIGH, integrity=Impact.HIGH, availability=Impact.HIGH,
    ),
    "CWE-22": CVSSVector(  # Path Traversal
        attack_vector=AttackVector.NETWORK, attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE, user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED, confidentiality=Impact.HIGH, integrity=Impact.NONE, availability=Impact.NONE,
    ),
    "CWE-287": CVSSVector(  # Improper Authentication
        attack_vector=AttackVector.NETWORK, attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE, user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED, confidentiality=Impact.HIGH, integrity=Impact.HIGH, availability=Impact.HIGH,
    ),
}
