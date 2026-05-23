"""Vulnerability classifier — severity and type classification engine.

Implements:
1. CWE-based vulnerability classification
2. CVSS v3.1 vector calculation
3. OWASP Top 10 mapping
4. Exploitability scoring
5. Business impact assessment
6. False positive scoring
7. Severity aggregation across findings
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class VulnSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnCategory(str, Enum):
    INJECTION = "injection"
    BROKEN_AUTH = "broken_auth"
    SENSITIVE_DATA = "sensitive_data"
    XXE = "xxe"
    BROKEN_ACCESS = "broken_access"
    MISCONFIG = "misconfig"
    XSS = "xss"
    INSECURE_DESER = "insecure_deser"
    VULN_COMPONENTS = "vuln_components"
    INSUFFICIENT_LOG = "insufficient_log"
    SSRF = "ssrf"
    CRYPTO = "crypto"
    BUSINESS_LOGIC = "business_logic"
    OTHER = "other"


class ExploitDifficulty(str, Enum):
    TRIVIAL = "trivial"        # Automated, no auth needed
    EASY = "easy"              # Known exploit available
    MODERATE = "moderate"      # Requires some customization
    HARD = "hard"              # Custom exploit needed
    VERY_HARD = "very_hard"    # Novel techniques required


@dataclass
class CVSSVector:
    """CVSS v3.1 base score components."""
    attack_vector: str = "N"       # N=Network, A=Adjacent, L=Local, P=Physical
    attack_complexity: str = "L"   # L=Low, H=High
    privileges_required: str = "N"  # N=None, L=Low, H=High
    user_interaction: str = "N"    # N=None, R=Required
    scope: str = "U"              # U=Unchanged, C=Changed
    confidentiality: str = "H"    # N=None, L=Low, H=High
    integrity: str = "H"          # N=None, L=Low, H=High
    availability: str = "H"       # N=None, L=Low, H=High

    @property
    def vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}"
            f"/PR:{self.privileges_required}/UI:{self.user_interaction}"
            f"/S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}"
            f"/A:{self.availability}"
        )

    @property
    def base_score(self) -> float:
        """Calculate CVSS v3.1 base score."""
        # Impact sub-score
        isc_base = 1 - (
            (1 - _impact_val(self.confidentiality))
            * (1 - _impact_val(self.integrity))
            * (1 - _impact_val(self.availability))
        )

        if self.scope == "U":
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

        if impact <= 0:
            return 0.0

        # Exploitability sub-score
        exploit = (
            8.22
            * _av_val(self.attack_vector)
            * _ac_val(self.attack_complexity)
            * _pr_val(self.privileges_required, self.scope)
            * _ui_val(self.user_interaction)
        )

        if self.scope == "U":
            raw = min(impact + exploit, 10.0)
        else:
            raw = min(1.08 * (impact + exploit), 10.0)

        return _roundup(raw)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vector": self.vector_string,
            "score": self.base_score,
        }


def _impact_val(metric: str) -> float:
    return {"N": 0.0, "L": 0.22, "H": 0.56}.get(metric, 0.0)


def _av_val(av: str) -> float:
    return {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(av, 0.85)


def _ac_val(ac: str) -> float:
    return {"L": 0.77, "H": 0.44}.get(ac, 0.77)


def _pr_val(pr: str, scope: str) -> float:
    if scope == "U":
        return {"N": 0.85, "L": 0.62, "H": 0.27}.get(pr, 0.85)
    return {"N": 0.85, "L": 0.68, "H": 0.50}.get(pr, 0.85)


def _ui_val(ui: str) -> float:
    return {"N": 0.85, "R": 0.62}.get(ui, 0.85)


def _roundup(x: float) -> float:
    """CVSS roundup function."""
    import math
    return math.ceil(x * 10) / 10


# ── CWE to Category mapping ─────────────────────────────────

CWE_CATEGORY_MAP: dict[int, VulnCategory] = {
    # Injection
    89: VulnCategory.INJECTION,    # SQL Injection
    78: VulnCategory.INJECTION,    # OS Command Injection
    79: VulnCategory.XSS,          # XSS
    94: VulnCategory.INJECTION,    # Code Injection
    917: VulnCategory.INJECTION,   # Expression Language Injection
    # Auth
    287: VulnCategory.BROKEN_AUTH,
    306: VulnCategory.BROKEN_AUTH,
    798: VulnCategory.BROKEN_AUTH,  # Hardcoded Credentials
    # Access Control
    284: VulnCategory.BROKEN_ACCESS,
    639: VulnCategory.BROKEN_ACCESS,  # IDOR
    862: VulnCategory.BROKEN_ACCESS,
    # Crypto
    327: VulnCategory.CRYPTO,
    328: VulnCategory.CRYPTO,
    330: VulnCategory.CRYPTO,
    # Misconfig
    16: VulnCategory.MISCONFIG,
    200: VulnCategory.SENSITIVE_DATA,
    209: VulnCategory.SENSITIVE_DATA,
    # Deserialization
    502: VulnCategory.INSECURE_DESER,
    # SSRF
    918: VulnCategory.SSRF,
    # XXE
    611: VulnCategory.XXE,
}

# ── OWASP Top 10 (2021) mapping ─────────────────────────────

OWASP_MAP: dict[str, str] = {
    "injection": "A03:2021-Injection",
    "broken_auth": "A07:2021-Identification and Authentication Failures",
    "sensitive_data": "A02:2021-Cryptographic Failures",
    "xxe": "A05:2021-Security Misconfiguration",
    "broken_access": "A01:2021-Broken Access Control",
    "misconfig": "A05:2021-Security Misconfiguration",
    "xss": "A03:2021-Injection",
    "insecure_deser": "A08:2021-Software and Data Integrity Failures",
    "vuln_components": "A06:2021-Vulnerable and Outdated Components",
    "insufficient_log": "A09:2021-Security Logging and Monitoring Failures",
    "ssrf": "A10:2021-Server-Side Request Forgery",
    "crypto": "A02:2021-Cryptographic Failures",
}


@dataclass
class ClassifiedVuln:
    """A classified vulnerability."""
    vuln_id: str = ""
    title: str = ""
    description: str = ""
    severity: VulnSeverity = VulnSeverity.MEDIUM
    category: VulnCategory = VulnCategory.OTHER
    owasp_id: str = ""
    cwe_id: int = 0
    cve_id: str = ""
    cvss: CVSSVector = field(default_factory=CVSSVector)
    exploit_difficulty: ExploitDifficulty = ExploitDifficulty.MODERATE
    false_positive_score: float = 0.0  # 0=definitely real, 1=definitely FP
    business_impact: str = ""
    target: str = ""
    evidence: str = ""
    classified_at: float = field(default_factory=time.time)

    @property
    def cvss_score(self) -> float:
        return self.cvss.base_score

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.vuln_id[:10],
            "title": self.title[:30],
            "severity": self.severity.value,
            "cvss": self.cvss_score,
            "category": self.category.value,
            "fp_score": round(self.false_positive_score, 2),
        }


class VulnClassifier:
    """Classifies vulnerabilities by type, severity, and impact.

    Maps findings to CWE, OWASP Top 10, calculates
    CVSS scores, and estimates false positive probability.
    """

    def __init__(self) -> None:
        self._classifications: dict[str, ClassifiedVuln] = {}
        self._counter = 0
        self._log = logger.bind(component="vuln_classifier")

    def classify(
        self,
        title: str,
        description: str = "",
        cwe_id: int = 0,
        cve_id: str = "",
        target: str = "",
        evidence: str = "",
        cvss_vector: CVSSVector | None = None,
    ) -> ClassifiedVuln:
        """Classify a vulnerability finding."""
        self._counter += 1

        # Determine category from CWE
        category = CWE_CATEGORY_MAP.get(cwe_id, VulnCategory.OTHER)
        if category == VulnCategory.OTHER:
            category = self._infer_category(title, description)

        # OWASP mapping
        owasp_id = OWASP_MAP.get(category.value, "")

        # Calculate CVSS if not provided
        cvss = cvss_vector or self._estimate_cvss(category, title, description)

        # Determine severity from CVSS
        score = cvss.base_score
        if score >= 9.0:
            severity = VulnSeverity.CRITICAL
        elif score >= 7.0:
            severity = VulnSeverity.HIGH
        elif score >= 4.0:
            severity = VulnSeverity.MEDIUM
        elif score > 0:
            severity = VulnSeverity.LOW
        else:
            severity = VulnSeverity.INFO

        # Estimate false positive score
        fp_score = self._estimate_fp_score(title, evidence)

        # Estimate exploit difficulty
        difficulty = self._estimate_difficulty(category, cvss)

        vuln = ClassifiedVuln(
            vuln_id=f"vuln-{self._counter}",
            title=title,
            description=description,
            severity=severity,
            category=category,
            owasp_id=owasp_id,
            cwe_id=cwe_id,
            cve_id=cve_id,
            cvss=cvss,
            exploit_difficulty=difficulty,
            false_positive_score=fp_score,
            target=target,
            evidence=evidence,
        )

        self._classifications[vuln.vuln_id] = vuln
        return vuln

    def _infer_category(self, title: str, desc: str) -> VulnCategory:
        """Infer category from title/description keywords."""
        text = (title + " " + desc).lower()
        keyword_map = {
            VulnCategory.INJECTION: ["sql injection", "sqli", "command injection", "code injection", "ldap injection"],
            VulnCategory.XSS: ["xss", "cross-site scripting", "script injection"],
            VulnCategory.SSRF: ["ssrf", "server-side request"],
            VulnCategory.BROKEN_AUTH: ["authentication", "login bypass", "credential", "session fixation"],
            VulnCategory.BROKEN_ACCESS: ["idor", "access control", "authorization", "privilege escalation"],
            VulnCategory.MISCONFIG: ["misconfiguration", "default password", "directory listing", "information disclosure"],
            VulnCategory.CRYPTO: ["weak cipher", "ssl", "tls", "certificate", "encryption"],
            VulnCategory.INSECURE_DESER: ["deserialization", "pickle", "java serial"],
            VulnCategory.XXE: ["xxe", "xml external"],
            VulnCategory.SENSITIVE_DATA: ["sensitive data", "pii", "password in", "api key exposed"],
        }

        for category, keywords in keyword_map.items():
            if any(kw in text for kw in keywords):
                return category

        return VulnCategory.OTHER

    def _estimate_cvss(
        self,
        category: VulnCategory,
        title: str,
        desc: str,
    ) -> CVSSVector:
        """Estimate CVSS vector from category."""
        # Common CVSS templates by category
        templates: dict[str, dict[str, str]] = {
            "injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
            "xss": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
            "ssrf": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "N", "A": "N"},
            "broken_auth": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
            "broken_access": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
            "misconfig": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
            "crypto": {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
            "insecure_deser": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        }

        tmpl = templates.get(category.value, {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N",
        })

        return CVSSVector(
            attack_vector=tmpl["AV"],
            attack_complexity=tmpl["AC"],
            privileges_required=tmpl["PR"],
            user_interaction=tmpl["UI"],
            scope=tmpl["S"],
            confidentiality=tmpl["C"],
            integrity=tmpl["I"],
            availability=tmpl["A"],
        )

    def _estimate_fp_score(self, title: str, evidence: str) -> float:
        """Estimate false positive probability."""
        fp_score = 0.3  # Base

        # Strong evidence reduces FP score
        evidence_lower = evidence.lower()
        if any(w in evidence_lower for w in ["confirmed", "verified", "reproduced", "poc"]):
            fp_score -= 0.2
        if any(w in evidence_lower for w in ["http/", "status:", "response"]):
            fp_score -= 0.1

        # Weak indicators increase FP score
        title_lower = title.lower()
        if any(w in title_lower for w in ["possible", "potential", "might"]):
            fp_score += 0.2
        if not evidence:
            fp_score += 0.3

        return max(0.0, min(1.0, fp_score))

    def _estimate_difficulty(
        self,
        category: VulnCategory,
        cvss: CVSSVector,
    ) -> ExploitDifficulty:
        """Estimate exploit difficulty."""
        score = cvss.base_score
        if score >= 9.0 and cvss.attack_complexity == "L":
            return ExploitDifficulty.TRIVIAL
        if score >= 7.0:
            return ExploitDifficulty.EASY
        if score >= 4.0:
            return ExploitDifficulty.MODERATE
        if score >= 2.0:
            return ExploitDifficulty.HARD
        return ExploitDifficulty.VERY_HARD

    def get_severity_summary(self) -> dict[str, int]:
        """Get count of vulns by severity."""
        counts: dict[str, int] = {}
        for v in self._classifications.values():
            counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
        return counts

    def build_classification_prompt(self, max_vulns: int = 10) -> str:
        """Build classification context for LLM."""
        lines = ["## Vulnerability Classifications\n"]

        summary = self.get_severity_summary()
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = summary.get(sev, 0)
            if count:
                lines.append(f"  {sev.upper()}: {count}")

        # Show top vulns
        sorted_vulns = sorted(
            self._classifications.values(),
            key=lambda v: v.cvss_score,
            reverse=True,
        )
        for v in sorted_vulns[:max_vulns]:
            fp_marker = " [possible FP]" if v.false_positive_score > 0.5 else ""
            lines.append(
                f"\n  [{v.severity.value.upper()}] {v.title[:40]}"
                f"\n    CVSS: {v.cvss_score} | {v.category.value} | {v.exploit_difficulty.value}{fp_marker}"
            )
            if v.owasp_id:
                lines.append(f"    OWASP: {v.owasp_id}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "total": len(self._classifications),
            "by_severity": self.get_severity_summary(),
            "avg_cvss": (
                sum(v.cvss_score for v in self._classifications.values()) / len(self._classifications)
                if self._classifications else 0
            ),
        }
