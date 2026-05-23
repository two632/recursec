"""Compliance & standards knowledge base.

Maps findings to compliance frameworks:
1. OWASP Top 10 (2021)
2. SANS CWE Top 25
3. PCI-DSS requirements
4. NIST Cybersecurity Framework
5. MITRE ATT&CK techniques
6. CVSS scoring guidelines
7. CIS Benchmarks
8. SOC 2 controls
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ComplianceMapping:
    """Maps a finding to compliance requirements."""
    framework: str = ""           # OWASP, PCI-DSS, NIST, etc.
    requirement_id: str = ""      # A01:2021, Req 6.5.1, etc.
    requirement_name: str = ""
    description: str = ""
    severity: str = "medium"
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework[:10],
            "id": self.requirement_id[:12],
            "name": self.requirement_name[:30],
            "severity": self.severity,
        }


# ── OWASP Top 10 (2021) ─────────────────────────────────────

OWASP_TOP10: list[ComplianceMapping] = [
    ComplianceMapping(
        framework="OWASP", requirement_id="A01:2021",
        requirement_name="Broken Access Control",
        severity="critical",
        description=(
            "Access control enforces policy so users cannot act outside their intended permissions. "
            "Failures typically lead to unauthorized information disclosure, modification, or destruction of data."
        ),
        remediation=(
            "- Deny access by default (except public resources)\n"
            "- Implement access control mechanisms once and reuse\n"
            "- Model access controls should enforce record ownership\n"
            "- Disable web server directory listing\n"
            "- Log access control failures, alert admins\n"
            "- Rate limit API and controller access\n"
            "- Invalidate JWT tokens on server after logout"
        ),
    ),
    ComplianceMapping(
        framework="OWASP", requirement_id="A02:2021",
        requirement_name="Cryptographic Failures",
        severity="critical",
        description=(
            "Failures related to cryptography which often lead to sensitive data exposure. "
            "Previously known as Sensitive Data Exposure."
        ),
        remediation=(
            "- Classify data and identify sensitive data\n"
            "- Don't store sensitive data unnecessarily\n"
            "- Encrypt all sensitive data at rest\n"
            "- Use strong standard algorithms (AES-256, RSA-2048+)\n"
            "- Enforce HTTPS with HSTS\n"
            "- Disable caching for sensitive responses"
        ),
    ),
    ComplianceMapping(
        framework="OWASP", requirement_id="A03:2021",
        requirement_name="Injection",
        severity="critical",
        description=(
            "Injection flaws such as SQL, NoSQL, OS, and LDAP injection occur when "
            "untrusted data is sent to an interpreter as part of a command or query."
        ),
        remediation=(
            "- Use safe API with parameterized queries\n"
            "- Use positive server-side input validation\n"
            "- Escape special characters for residual dynamic queries\n"
            "- Use LIMIT and other SQL controls\n"
            "- Use ORMs but be aware of their limitations"
        ),
    ),
    ComplianceMapping(
        framework="OWASP", requirement_id="A04:2021",
        requirement_name="Insecure Design",
        severity="high",
        description=(
            "Insecure design is a broad category representing different weaknesses, "
            "expressed as missing or ineffective control design."
        ),
        remediation=(
            "- Establish secure development lifecycle\n"
            "- Use threat modeling for critical flows\n"
            "- Integrate security language into user stories\n"
            "- Implement plausibility checks at each tier"
        ),
    ),
    ComplianceMapping(
        framework="OWASP", requirement_id="A05:2021",
        requirement_name="Security Misconfiguration",
        severity="high",
        description=(
            "The application might be vulnerable if it is missing security hardening, "
            "has unnecessary features enabled, or has default accounts/passwords."
        ),
        remediation=(
            "- Repeatable hardening process\n"
            "- Minimal platform without unnecessary features\n"
            "- Review and update configurations regularly\n"
            "- Send security directives in headers\n"
            "- Automated verification of configurations"
        ),
    ),
    ComplianceMapping(
        framework="OWASP", requirement_id="A06:2021",
        requirement_name="Vulnerable and Outdated Components",
        severity="high",
        description=(
            "Components such as libraries, frameworks, and software modules run with "
            "the same privileges as the application."
        ),
        remediation=(
            "- Remove unused dependencies and features\n"
            "- Continuously inventory component versions\n"
            "- Monitor CVE databases for vulnerabilities\n"
            "- Only obtain components from official sources over secure links"
        ),
    ),
    ComplianceMapping(
        framework="OWASP", requirement_id="A07:2021",
        requirement_name="Identification and Authentication Failures",
        severity="critical",
        description=(
            "Confirmation of the user's identity, authentication, and session management "
            "is critical to protect against authentication-related attacks."
        ),
        remediation=(
            "- Implement multi-factor authentication\n"
            "- Don't ship with default credentials\n"
            "- Implement weak password checks\n"
            "- Limit failed login attempts (account lockout)\n"
            "- Use server-side session manager with random session IDs"
        ),
    ),
    ComplianceMapping(
        framework="OWASP", requirement_id="A08:2021",
        requirement_name="Software and Data Integrity Failures",
        severity="high",
        description=(
            "Software and data integrity failures relate to code and infrastructure "
            "that does not protect against integrity violations."
        ),
        remediation=(
            "- Use digital signatures to verify software\n"
            "- Ensure libraries are from trusted repositories\n"
            "- Use a software supply chain security tool\n"
            "- Review code and configuration changes"
        ),
    ),
    ComplianceMapping(
        framework="OWASP", requirement_id="A09:2021",
        requirement_name="Security Logging and Monitoring Failures",
        severity="medium",
        description=(
            "Without logging and monitoring, breaches cannot be detected. "
            "Insufficient logging, detection, monitoring, and active response."
        ),
        remediation=(
            "- Log all login, access control, and server-side input validation failures\n"
            "- Ensure logs are in format easily consumed by log management\n"
            "- Establish effective monitoring and alerting\n"
            "- Establish incident response and recovery plan"
        ),
    ),
    ComplianceMapping(
        framework="OWASP", requirement_id="A10:2021",
        requirement_name="Server-Side Request Forgery (SSRF)",
        severity="critical",
        description=(
            "SSRF flaws occur when a web application fetches a remote resource "
            "without validating the user-supplied URL."
        ),
        remediation=(
            "- Sanitize and validate all client-supplied input data\n"
            "- Enforce URL schema, port, and destination with allowlist\n"
            "- Disable HTTP redirections\n"
            "- Don't send raw responses to clients"
        ),
    ),
]


# ── CWE/CVSS mapping ────────────────────────────────────────

CWE_SEVERITY_MAP: dict[str, dict[str, Any]] = {
    "CWE-79": {"name": "Cross-site Scripting (XSS)", "cvss_base": 6.1, "owasp": "A03:2021"},
    "CWE-89": {"name": "SQL Injection", "cvss_base": 9.8, "owasp": "A03:2021"},
    "CWE-78": {"name": "OS Command Injection", "cvss_base": 9.8, "owasp": "A03:2021"},
    "CWE-22": {"name": "Path Traversal", "cvss_base": 7.5, "owasp": "A01:2021"},
    "CWE-352": {"name": "Cross-Site Request Forgery", "cvss_base": 8.8, "owasp": "A01:2021"},
    "CWE-287": {"name": "Improper Authentication", "cvss_base": 9.8, "owasp": "A07:2021"},
    "CWE-862": {"name": "Missing Authorization", "cvss_base": 9.8, "owasp": "A01:2021"},
    "CWE-918": {"name": "Server-Side Request Forgery", "cvss_base": 9.1, "owasp": "A10:2021"},
    "CWE-502": {"name": "Deserialization of Untrusted Data", "cvss_base": 9.8, "owasp": "A08:2021"},
    "CWE-611": {"name": "XXE", "cvss_base": 7.5, "owasp": "A05:2021"},
    "CWE-94": {"name": "Code Injection", "cvss_base": 9.8, "owasp": "A03:2021"},
    "CWE-434": {"name": "Unrestricted File Upload", "cvss_base": 9.8, "owasp": "A04:2021"},
    "CWE-269": {"name": "Improper Privilege Management", "cvss_base": 8.8, "owasp": "A01:2021"},
    "CWE-306": {"name": "Missing Authentication for Critical Function", "cvss_base": 9.8, "owasp": "A07:2021"},
    "CWE-798": {"name": "Hardcoded Credentials", "cvss_base": 9.8, "owasp": "A07:2021"},
    "CWE-200": {"name": "Information Exposure", "cvss_base": 5.3, "owasp": "A01:2021"},
    "CWE-319": {"name": "Cleartext Transmission", "cvss_base": 5.9, "owasp": "A02:2021"},
    "CWE-327": {"name": "Broken Crypto Algorithm", "cvss_base": 7.5, "owasp": "A02:2021"},
    "CWE-732": {"name": "Incorrect Permission Assignment", "cvss_base": 7.5, "owasp": "A01:2021"},
    "CWE-1321": {"name": "Prototype Pollution", "cvss_base": 9.8, "owasp": "A03:2021"},
}


# ── PCI-DSS requirements ────────────────────────────────────

PCI_DSS_REQUIREMENTS: dict[str, str] = {
    "1.1": "Install and maintain network security controls",
    "2.1": "Apply secure configurations to all system components",
    "3.1": "Protect stored account data",
    "4.1": "Protect cardholder data with strong cryptography during transmission",
    "5.1": "Protect all systems and networks from malicious software",
    "6.1": "Develop and maintain secure systems and software",
    "6.2": "Develop software securely (secure coding practices)",
    "6.3": "Security vulnerabilities are identified and addressed",
    "6.4": "Public-facing web applications are protected against attacks",
    "7.1": "Access to system components and cardholder data is restricted",
    "8.1": "User identification and authentication to system components",
    "9.1": "Restrict physical access to cardholder data",
    "10.1": "Log and monitor all access to system components and cardholder data",
    "11.1": "Test security of systems and networks regularly",
    "12.1": "Support information security with organizational policies and programs",
}


class ComplianceKB:
    """Compliance and standards knowledge base.

    Maps findings to compliance frameworks and generates
    compliance-focused prompts for the agent.
    """

    def __init__(self) -> None:
        self._owasp_mappings: dict[str, ComplianceMapping] = {}
        self._cwe_map = CWE_SEVERITY_MAP
        self._pci_dss = PCI_DSS_REQUIREMENTS
        self._log = logger.bind(component="compliance_kb")
        self._load_owasp()

    def _load_owasp(self) -> None:
        """Load OWASP Top 10 mappings."""
        for mapping in OWASP_TOP10:
            self._owasp_mappings[mapping.requirement_id] = mapping

    def map_finding_to_compliance(
        self,
        cwe: str = "",
        vuln_type: str = "",
    ) -> list[ComplianceMapping]:
        """Map a finding to compliance requirements."""
        results = []

        # CWE mapping
        if cwe and cwe in self._cwe_map:
            cwe_info = self._cwe_map[cwe]
            owasp_id = cwe_info.get("owasp", "")
            if owasp_id and owasp_id in self._owasp_mappings:
                results.append(self._owasp_mappings[owasp_id])

        # Vuln type mapping
        type_to_owasp = {
            "xss": "A03:2021",
            "sqli": "A03:2021",
            "injection": "A03:2021",
            "auth_bypass": "A07:2021",
            "idor": "A01:2021",
            "ssrf": "A10:2021",
            "misconfig": "A05:2021",
            "outdated": "A06:2021",
            "crypto": "A02:2021",
        }

        if vuln_type:
            owasp_id = type_to_owasp.get(vuln_type.lower(), "")
            if owasp_id and owasp_id in self._owasp_mappings:
                mapping = self._owasp_mappings[owasp_id]
                if mapping not in results:
                    results.append(mapping)

        return results

    def get_cvss_estimate(self, cwe: str) -> float:
        """Get estimated CVSS score for a CWE."""
        if cwe in self._cwe_map:
            return self._cwe_map[cwe].get("cvss_base", 5.0)
        return 5.0

    def build_compliance_prompt(
        self,
        frameworks: list[str] | None = None,
        max_items: int = 5,
    ) -> str:
        """Build compliance-aware prompt for the agent."""
        lines = ["## Compliance Requirements\n"]

        if not frameworks or "owasp" in [f.lower() for f in (frameworks or [])]:
            lines.append("### OWASP Top 10 (2021)")
            for mapping in list(self._owasp_mappings.values())[:max_items]:
                lines.append(f"- {mapping.requirement_id}: {mapping.requirement_name} [{mapping.severity}]")
            lines.append("")

        if not frameworks or "pci" in [f.lower() for f in (frameworks or [])]:
            lines.append("### PCI-DSS v4.0")
            for req_id, req_name in list(self._pci_dss.items())[:max_items]:
                lines.append(f"- Req {req_id}: {req_name}")
            lines.append("")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "owasp_mappings": len(self._owasp_mappings),
            "cwe_mappings": len(self._cwe_map),
            "pci_dss_requirements": len(self._pci_dss),
        }
