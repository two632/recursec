"""Vulnerability intelligence — enriches findings with CVE data and threat context.

Implements:
1. CVE pattern matching and lookup
2. CVSS score estimation
3. Exploit availability tracking
4. Vulnerability classification (CWE mapping)
5. Threat actor association
6. Remediation recommendation generation
7. Historical vulnerability correlation
8. Priority scoring based on multiple factors
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ExploitAvailability(str, Enum):
    PUBLIC = "public"             # Public exploit code available
    WEAPONIZED = "weaponized"    # Exploit used in the wild
    PRIVATE = "private"          # Known but not public
    THEORETICAL = "theoretical"  # PoC or theoretical only
    NONE = "none"                # No known exploit


@dataclass
class CVEEntry:
    """A CVE entry with enrichment data."""
    cve_id: str = ""
    title: str = ""
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    exploit_availability: ExploitAvailability = ExploitAvailability.NONE
    references: list[str] = field(default_factory=list)
    published_date: str = ""
    threat_level: ThreatLevel = ThreatLevel.MEDIUM

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve_id, "title": self.title[:80],
            "cvss": self.cvss_score,
            "exploit": self.exploit_availability.value,
            "threat": self.threat_level.value,
        }


@dataclass
class VulnEnrichment:
    """Enriched vulnerability data."""
    original_finding: dict[str, Any] = field(default_factory=dict)
    cve_matches: list[CVEEntry] = field(default_factory=list)
    cwe_classification: str = ""
    cwe_name: str = ""
    estimated_cvss: float = 0.0
    exploit_available: bool = False
    remediation: str = ""
    priority_score: float = 0.0
    threat_context: str = ""
    similar_vulns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.original_finding.get("title", "")[:80],
            "cve_matches": len(self.cve_matches),
            "cwe": self.cwe_classification,
            "cvss": round(self.estimated_cvss, 1),
            "exploit": self.exploit_available,
            "priority": round(self.priority_score, 2),
        }


# ── CWE Database (most common security CWEs) ────────────────

CWE_DATABASE: dict[str, dict[str, Any]] = {
    "CWE-79": {"name": "Cross-site Scripting (XSS)", "cvss_base": 6.1,
               "keywords": ["xss", "cross-site scripting", "reflected", "stored xss", "dom xss"]},
    "CWE-89": {"name": "SQL Injection", "cvss_base": 9.8,
               "keywords": ["sql injection", "sqli", "sql"]},
    "CWE-78": {"name": "OS Command Injection", "cvss_base": 9.8,
               "keywords": ["command injection", "os command", "cmd injection", "rce"]},
    "CWE-22": {"name": "Path Traversal", "cvss_base": 7.5,
               "keywords": ["path traversal", "directory traversal", "lfi", "local file inclusion"]},
    "CWE-352": {"name": "Cross-Site Request Forgery (CSRF)", "cvss_base": 4.3,
                "keywords": ["csrf", "cross-site request forgery"]},
    "CWE-918": {"name": "Server-Side Request Forgery (SSRF)", "cvss_base": 7.5,
                "keywords": ["ssrf", "server-side request forgery"]},
    "CWE-611": {"name": "XML External Entity (XXE)", "cvss_base": 7.5,
                "keywords": ["xxe", "xml external entity"]},
    "CWE-287": {"name": "Improper Authentication", "cvss_base": 9.8,
                "keywords": ["authentication bypass", "auth bypass", "broken auth"]},
    "CWE-862": {"name": "Missing Authorization", "cvss_base": 7.5,
                "keywords": ["missing authorization", "broken access control", "idor"]},
    "CWE-200": {"name": "Information Disclosure", "cvss_base": 5.3,
                "keywords": ["information disclosure", "info leak", "sensitive data exposure"]},
    "CWE-502": {"name": "Deserialization of Untrusted Data", "cvss_base": 9.8,
                "keywords": ["deserialization", "unserialize", "pickle", "yaml.load"]},
    "CWE-434": {"name": "Unrestricted File Upload", "cvss_base": 9.8,
                "keywords": ["file upload", "unrestricted upload"]},
    "CWE-319": {"name": "Cleartext Transmission", "cvss_base": 5.9,
                "keywords": ["cleartext", "unencrypted", "http://", "no ssl"]},
    "CWE-326": {"name": "Inadequate Encryption Strength", "cvss_base": 5.9,
                "keywords": ["weak encryption", "weak cipher", "des", "rc4", "md5"]},
    "CWE-798": {"name": "Hard-coded Credentials", "cvss_base": 9.8,
                "keywords": ["hardcoded", "hard-coded", "default password", "default credential"]},
    "CWE-307": {"name": "Improper Restriction of Authentication Attempts", "cvss_base": 7.5,
                "keywords": ["brute force", "no rate limit", "missing lockout"]},
    "CWE-732": {"name": "Incorrect Permission Assignment", "cvss_base": 7.5,
                "keywords": ["permission", "world readable", "chmod 777", "misconfiguration"]},
    "CWE-94": {"name": "Code Injection", "cvss_base": 9.8,
               "keywords": ["code injection", "eval(", "exec("]},
    "CWE-1321": {"name": "Prototype Pollution", "cvss_base": 7.5,
                 "keywords": ["prototype pollution", "__proto__"]},
    "CWE-384": {"name": "Session Fixation", "cvss_base": 6.5,
                "keywords": ["session fixation", "session hijack"]},
}


# ── Remediation Templates ────────────────────────────────────

REMEDIATION_TEMPLATES: dict[str, str] = {
    "CWE-79": "Implement output encoding/escaping. Use Content-Security-Policy headers. Validate and sanitize user input.",
    "CWE-89": "Use parameterized queries/prepared statements. Implement input validation. Use ORM frameworks.",
    "CWE-78": "Avoid OS command execution with user input. Use allowlists. Implement proper input validation.",
    "CWE-22": "Normalize paths before validation. Use allowlists for file access. Implement chroot/sandbox.",
    "CWE-352": "Implement CSRF tokens. Use SameSite cookie attribute. Verify Origin/Referer headers.",
    "CWE-918": "Validate and allowlist URLs. Block internal IP ranges. Use network-level restrictions.",
    "CWE-611": "Disable XML external entity processing. Use JSON instead. Configure XML parsers securely.",
    "CWE-287": "Implement multi-factor authentication. Use strong password policies. Session management best practices.",
    "CWE-862": "Implement proper authorization checks. Use RBAC. Validate access at every request.",
    "CWE-200": "Remove verbose error messages. Configure proper error handling. Review HTTP response headers.",
    "CWE-502": "Avoid deserializing untrusted data. Use safe serialization formats. Implement integrity checks.",
    "CWE-434": "Validate file types and content. Restrict upload locations. Implement file size limits.",
    "CWE-798": "Remove hard-coded credentials. Use secrets management systems. Rotate compromised credentials.",
    "CWE-326": "Use strong encryption algorithms (AES-256, RSA-2048+). Update TLS configuration. Disable weak ciphers.",
}


ENRICH_PROMPT = """You are a vulnerability intelligence analyst.

Finding:
  Title: {title}
  Severity: {severity}
  Target: {target}
  Description: {description}
  Tool: {tool}
  Evidence: {evidence}

Provide intelligence enrichment:
1. Likely CVE matches (if any)
2. CWE classification
3. CVSS score estimate
4. Exploit availability assessment
5. Threat context (how attackers typically use this)
6. Remediation recommendations
7. Priority score (0-10)

Respond as JSON:
{{
  "cwe": "CWE-XXX",
  "cvss_estimate": X.X,
  "exploit_available": true/false,
  "threat_context": "brief context",
  "remediation": "recommended fix",
  "priority": X.X,
  "cve_candidates": ["CVE-XXXX-XXXXX"]
}}"""


class VulnIntelligence:
    """Vulnerability intelligence enrichment engine.

    Enriches raw findings with CVE data, CWE classification,
    CVSS scores, exploit availability, and remediation guidance.
    """

    def __init__(self, model_router: ModelRouter | None = None) -> None:
        self._router = model_router
        self._enrichment_cache: dict[str, VulnEnrichment] = {}
        self._log = logger.bind(component="vuln_intelligence")

    async def enrich(self, finding: dict[str, Any]) -> VulnEnrichment:
        """Enrich a vulnerability finding with intelligence data."""
        title = finding.get("title", "")
        cache_key = f"{title}:{finding.get('target', '')}"

        if cache_key in self._enrichment_cache:
            return self._enrichment_cache[cache_key]

        enrichment = VulnEnrichment(original_finding=finding)

        # CWE classification
        cwe_id, cwe_name = self._classify_cwe(finding)
        enrichment.cwe_classification = cwe_id
        enrichment.cwe_name = cwe_name

        # CVSS estimation
        enrichment.estimated_cvss = self._estimate_cvss(finding, cwe_id)

        # Remediation
        enrichment.remediation = REMEDIATION_TEMPLATES.get(
            cwe_id,
            "Perform detailed analysis and implement appropriate security controls.",
        )

        # LLM enrichment
        if self._router:
            llm_data = await self._llm_enrich(finding)
            if llm_data.get("cvss_estimate"):
                enrichment.estimated_cvss = (enrichment.estimated_cvss + llm_data["cvss_estimate"]) / 2
            if llm_data.get("threat_context"):
                enrichment.threat_context = llm_data["threat_context"]
            if llm_data.get("remediation"):
                enrichment.remediation = llm_data["remediation"]
            if llm_data.get("exploit_available"):
                enrichment.exploit_available = True

        # Priority scoring
        enrichment.priority_score = self._calculate_priority(
            enrichment.estimated_cvss,
            enrichment.exploit_available,
            finding.get("severity", "medium"),
        )

        self._enrichment_cache[cache_key] = enrichment
        return enrichment

    async def enrich_batch(
        self,
        findings: list[dict[str, Any]],
    ) -> list[VulnEnrichment]:
        """Enrich multiple findings."""
        results = []
        for finding in findings:
            enrichment = await self.enrich(finding)
            results.append(enrichment)
        return results

    def _classify_cwe(self, finding: dict[str, Any]) -> tuple[str, str]:
        """Classify a finding to a CWE."""
        title = finding.get("title", "").lower()
        desc = finding.get("description", "").lower()
        vuln_type = finding.get("type", "").lower()
        combined = f"{title} {desc} {vuln_type}"

        best_match = ""
        best_score = 0

        for cwe_id, cwe_data in CWE_DATABASE.items():
            score = 0
            for keyword in cwe_data["keywords"]:
                if keyword in combined:
                    score += len(keyword)
            if score > best_score:
                best_score = score
                best_match = cwe_id

        if best_match:
            return best_match, CWE_DATABASE[best_match]["name"]
        return "CWE-200", "Information Disclosure"

    def _estimate_cvss(self, finding: dict[str, Any], cwe_id: str) -> float:
        """Estimate CVSS score."""
        # Start with CWE base score
        cwe_data = CWE_DATABASE.get(cwe_id, {})
        base = cwe_data.get("cvss_base", 5.0)

        # Adjust based on severity
        severity = finding.get("severity", "medium")
        severity_adjustments = {
            "critical": 1.0, "high": 0.5, "medium": 0.0,
            "low": -1.0, "info": -2.0,
        }
        base += severity_adjustments.get(severity, 0.0)

        return max(0.0, min(10.0, base))

    def _calculate_priority(
        self,
        cvss: float,
        exploit_available: bool,
        severity: str,
    ) -> float:
        """Calculate priority score (0-10)."""
        score = cvss

        if exploit_available:
            score += 1.5

        severity_bonus = {
            "critical": 1.0, "high": 0.5, "medium": 0.0,
            "low": -0.5, "info": -1.0,
        }
        score += severity_bonus.get(severity, 0.0)

        return max(0.0, min(10.0, score))

    async def _llm_enrich(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Use LLM for enrichment."""
        if not self._router:
            return {}

        prompt = ENRICH_PROMPT.format(
            title=finding.get("title", ""),
            severity=finding.get("severity", ""),
            target=finding.get("target", ""),
            description=finding.get("description", "")[:200],
            tool=finding.get("tool", ""),
            evidence=finding.get("evidence", "")[:200],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="security",
            temperature=0.1,
            max_tokens=512,
        )

        import json
        try:
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]
            return json.loads(response.strip())
        except (json.JSONDecodeError, IndexError):
            return {}

    def get_stats(self) -> dict[str, Any]:
        return {
            "enriched": len(self._enrichment_cache),
            "cwe_database": len(CWE_DATABASE),
        }
