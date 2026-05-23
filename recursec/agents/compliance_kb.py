"""Compliance and standards knowledge base.

Maps findings to compliance frameworks:
1. OWASP Top 10 (2021)
2. CWE Top 25
3. NIST 800-53
4. PCI-DSS 4.0
5. MITRE ATT&CK
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ComplianceMapping:
    """Maps a finding to compliance requirements."""
    mapping_id: str = ""
    framework: str = ""
    control_id: str = ""
    control_name: str = ""
    description: str = ""
    related_cwes: list[str] = field(default_factory=list)
    severity_impact: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.mapping_id,
            "framework": self.framework[:10],
            "control": self.control_id[:15],
        }


# ── OWASP Top 10 (2021) ──────────────────────────────────────

OWASP_TOP_10: list[dict[str, Any]] = [
    {
        "id": "A01:2021", "name": "Broken Access Control",
        "desc": "Failures enforcing proper access controls, IDOR, privilege escalation.",
        "cwes": ["CWE-200", "CWE-201", "CWE-352", "CWE-566", "CWE-639", "CWE-862", "CWE-863"],
        "testing": (
            "BROKEN ACCESS CONTROL TESTING:\n"
            "  - Test IDOR: Change object IDs in requests\n"
            "  - Test privilege escalation: Access admin functions as regular user\n"
            "  - Test directory traversal: ../../etc/passwd\n"
            "  - Test CORS: Check Access-Control-Allow-Origin\n"
            "  - Test JWT: Modify claims, test none algorithm\n"
            "  - Test CSRF: Submit state-changing requests without CSRF token\n"
            "  - Test forced browsing: Access /admin, /debug, /api/internal"
        ),
    },
    {
        "id": "A02:2021", "name": "Cryptographic Failures",
        "desc": "Weak crypto, plaintext data, insecure protocols.",
        "cwes": ["CWE-259", "CWE-327", "CWE-328", "CWE-330", "CWE-331", "CWE-798"],
        "testing": (
            "CRYPTOGRAPHIC FAILURES TESTING:\n"
            "  - Check TLS: testssl.sh <target>\n"
            "  - Check for weak ciphers: nmap --script ssl-enum-ciphers\n"
            "  - Check certificate: openssl s_client -connect <host>:443\n"
            "  - Check password storage: Look for MD5/SHA1 without salt\n"
            "  - Check data in transit: Look for HTTP (non-HTTPS) endpoints\n"
            "  - Check data at rest: Database encryption, file encryption"
        ),
    },
    {
        "id": "A03:2021", "name": "Injection",
        "desc": "SQL, NoSQL, OS command, LDAP, XPath, SSTI injection.",
        "cwes": ["CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-89"],
        "testing": (
            "INJECTION TESTING:\n"
            "  - SQL: ' OR 1=1-- , UNION SELECT, time-based blind\n"
            "  - XSS: <script>alert(1)</script>, onerror=, onload=\n"
            "  - Command: ; id, | id, && id, `id`\n"
            "  - SSTI: {{7*7}}, ${7*7}, #{7*7}\n"
            "  - LDAP: *)(uid=*))(|(uid=*\n"
            "  - XPath: ' or '1'='1\n"
            "  - NoSQL: {\"$gt\": \"\"}, {\"$ne\": null}"
        ),
    },
    {
        "id": "A04:2021", "name": "Insecure Design",
        "desc": "Design and architecture flaws, missing threat modeling.",
        "cwes": ["CWE-209", "CWE-256", "CWE-501", "CWE-522"],
        "testing": (
            "INSECURE DESIGN TESTING:\n"
            "  - Threat modeling: STRIDE analysis\n"
            "  - Business logic: Test workflow bypass\n"
            "  - Rate limiting: Test brute force on login\n"
            "  - Data flow: Trace sensitive data through application\n"
            "  - Trust boundaries: Test between user/admin/service tiers"
        ),
    },
    {
        "id": "A05:2021", "name": "Security Misconfiguration",
        "desc": "Default configs, unnecessary features, missing hardening.",
        "cwes": ["CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-388"],
        "testing": (
            "SECURITY MISCONFIGURATION TESTING:\n"
            "  - Default credentials: admin:admin, test:test\n"
            "  - Unnecessary services: Scan all ports\n"
            "  - Stack traces in errors: Trigger application errors\n"
            "  - Directory listing: Browse directories\n"
            "  - Debug endpoints: /debug, /phpinfo, /.env\n"
            "  - HTTP headers: X-Frame-Options, CSP, HSTS\n"
            "  - Cloud storage: Public S3 buckets, Azure blobs"
        ),
    },
    {
        "id": "A06:2021", "name": "Vulnerable and Outdated Components",
        "desc": "Using components with known vulnerabilities.",
        "cwes": ["CWE-1035", "CWE-1104"],
        "testing": (
            "COMPONENT VULNERABILITY TESTING:\n"
            "  - Dependency scanning: trivy fs, grype, npm audit\n"
            "  - Version detection: whatweb, nmap -sV\n"
            "  - CVE search: searchsploit, vulners.com\n"
            "  - Container scanning: trivy image\n"
            "  - SBOM generation: syft, cyclonedx"
        ),
    },
    {
        "id": "A07:2021", "name": "Identification and Authentication Failures",
        "desc": "Weak authentication, credential stuffing, session issues.",
        "cwes": ["CWE-255", "CWE-259", "CWE-287", "CWE-384"],
        "testing": (
            "AUTHENTICATION TESTING:\n"
            "  - Brute force: hydra, medusa on login endpoints\n"
            "  - Password policy: Test weak passwords\n"
            "  - Session management: Cookie flags, timeout, fixation\n"
            "  - Multi-factor: Test bypass techniques\n"
            "  - Password reset: Token predictability, flow bypass"
        ),
    },
    {
        "id": "A08:2021", "name": "Software and Data Integrity Failures",
        "desc": "CI/CD pipeline issues, insecure deserialization, unsigned updates.",
        "cwes": ["CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-829"],
        "testing": (
            "INTEGRITY TESTING:\n"
            "  - Deserialization: Test for Java/Python/PHP deserialization\n"
            "  - Dependency integrity: Check for dependency confusion\n"
            "  - CI/CD: Review pipeline configs for injection\n"
            "  - Update mechanism: Check for signed updates\n"
            "  - Subresource Integrity: Check SRI tags in HTML"
        ),
    },
    {
        "id": "A09:2021", "name": "Security Logging and Monitoring Failures",
        "desc": "Insufficient logging, detection, and incident response.",
        "cwes": ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        "testing": (
            "LOGGING AND MONITORING TESTING:\n"
            "  - Login failures: Check if they are logged\n"
            "  - Log injection: Test for log forging\n"
            "  - Sensitive data in logs: Check for PII, tokens\n"
            "  - Alerting: Test if suspicious activity triggers alerts"
        ),
    },
    {
        "id": "A10:2021", "name": "Server-Side Request Forgery (SSRF)",
        "desc": "Making the server send requests to unintended locations.",
        "cwes": ["CWE-918"],
        "testing": (
            "SSRF TESTING:\n"
            "  - Internal: http://127.0.0.1, http://169.254.169.254\n"
            "  - Protocols: file://, gopher://, dict://\n"
            "  - Bypass: IP encoding, DNS rebinding\n"
            "  - Blind: OOB detection with collaborator/interactsh\n"
            "  - Cloud metadata: AWS, GCP, Azure metadata endpoints"
        ),
    },
]


class ComplianceKB:
    """Compliance and standards knowledge base.

    Maps vulnerabilities to compliance frameworks
    for reporting and prioritization.
    """

    def __init__(self) -> None:
        self._owasp: list[dict[str, Any]] = OWASP_TOP_10
        self._cwe_to_owasp: dict[str, str] = {}
        self._log = logger.bind(component="compliance_kb")
        self._build_indices()

    def _build_indices(self) -> None:
        """Build CWE to OWASP mapping."""
        for entry in self._owasp:
            for cwe in entry.get("cwes", []):
                self._cwe_to_owasp[cwe] = entry["id"]

    def map_cwe_to_owasp(self, cwe: str) -> str:
        """Map a CWE to OWASP Top 10 category."""
        return self._cwe_to_owasp.get(cwe, "")

    def get_owasp_entry(self, owasp_id: str) -> dict[str, Any] | None:
        """Get OWASP Top 10 entry."""
        for entry in self._owasp:
            if entry["id"] == owasp_id:
                return entry
        return None

    def build_compliance_prompt(
        self,
        cwes: list[str] | None = None,
        max_entries: int = 5,
    ) -> str:
        """Build compliance mapping prompt."""
        lines = ["## Compliance Mapping\n"]

        if cwes:
            mapped_owasp = set()
            for cwe in cwes:
                owasp_id = self.map_cwe_to_owasp(cwe)
                if owasp_id:
                    mapped_owasp.add(owasp_id)
            lines.append(f"CWEs mapped to OWASP: {', '.join(sorted(mapped_owasp))}")

        lines.append("\n### OWASP Top 10 (2021)")
        for idx, entry in enumerate(self._owasp):
            if idx >= max_entries:
                break
            lines.append(f"\n**{entry['id']} — {entry['name']}**")
            lines.append(entry.get("testing", ""))

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "owasp_entries": len(self._owasp),
            "cwe_mappings": len(self._cwe_to_owasp),
        }
