"""Compliance and reporting knowledge base.

Knowledge about security compliance frameworks:
1. OWASP Top 10 mapping
2. CWE classification
3. CVSS scoring guidance
4. MITRE ATT&CK mapping
5. Remediation templates
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ComplianceMapping:
    """A compliance framework mapping."""
    mapping_id: str = ""
    framework: str = ""
    category: str = ""
    description: str = ""
    mapping_data: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.mapping_id,
            "framework": self.framework[:12],
            "category": self.category[:15],
        }


COMPLIANCE_MAPPINGS: list[dict[str, Any]] = [
    {
        "id": "comp-001", "framework": "owasp_top10",
        "category": "classification",
        "desc": "OWASP Top 10 2021 vulnerability classification.",
        "data": (
            "OWASP TOP 10 (2021):\n"
            "A01 Broken Access Control:\n"
            "  - IDOR, privilege escalation, CORS misconfig\n"
            "  - Missing function-level access control\n"
            "  - CWEs: 200, 201, 352, 284, 285, 862, 863, 22\n"
            "A02 Cryptographic Failures:\n"
            "  - Weak encryption, plaintext data, expired certs\n"
            "  - CWEs: 259, 327, 331, 261\n"
            "A03 Injection:\n"
            "  - SQL, NoSQL, OS, LDAP, XSS, SSTI\n"
            "  - CWEs: 79, 89, 73, 77, 78, 917\n"
            "A04 Insecure Design:\n"
            "  - Missing security controls, threat modeling gaps\n"
            "  - CWEs: 209, 256, 501, 522\n"
            "A05 Security Misconfiguration:\n"
            "  - Default configs, unnecessary features, missing patches\n"
            "  - CWEs: 16, 611, 614\n"
            "A06 Vulnerable Components:\n"
            "  - Known CVEs, unmaintained libraries\n"
            "  - No specific CWEs\n"
            "A07 Authentication Failures:\n"
            "  - Weak passwords, credential stuffing, session flaws\n"
            "  - CWEs: 255, 259, 287, 288, 307, 384\n"
            "A08 Data Integrity Failures:\n"
            "  - Insecure deserialization, CI/CD compromise\n"
            "  - CWEs: 502, 829\n"
            "A09 Logging/Monitoring Failures:\n"
            "  - Missing logs, no alerting, insufficient monitoring\n"
            "  - CWEs: 117, 223, 532, 778\n"
            "A10 SSRF:\n"
            "  - Server-Side Request Forgery\n"
            "  - CWEs: 918"
        ),
    },
    {
        "id": "comp-002", "framework": "cvss",
        "category": "scoring",
        "desc": "CVSS v3.1 scoring guidance for findings.",
        "data": (
            "CVSS v3.1 SCORING:\n"
            "ATTACK VECTOR (AV):\n"
            "  Network (N): Remotely exploitable = 0.85\n"
            "  Adjacent (A): Adjacent network = 0.62\n"
            "  Local (L): Local access required = 0.55\n"
            "  Physical (P): Physical access = 0.20\n"
            "ATTACK COMPLEXITY (AC):\n"
            "  Low (L): No special conditions = 0.77\n"
            "  High (H): Special conditions needed = 0.44\n"
            "PRIVILEGES REQUIRED (PR):\n"
            "  None (N): No auth needed = 0.85\n"
            "  Low (L): Basic user = 0.62 (0.68 if scope changed)\n"
            "  High (H): Admin/privileged = 0.27 (0.50 if scope changed)\n"
            "USER INTERACTION (UI):\n"
            "  None (N): No user action = 0.85\n"
            "  Required (R): User must act = 0.62\n"
            "SCOPE (S):\n"
            "  Unchanged (U): Same security authority\n"
            "  Changed (C): Different security authority\n"
            "IMPACT (C/I/A):\n"
            "  High (H) = 0.56   Medium = N/A   Low (L) = 0.22   None (N) = 0\n"
            "SEVERITY RANGES:\n"
            "  0.0: None  |  0.1-3.9: Low  |  4.0-6.9: Medium\n"
            "  7.0-8.9: High  |  9.0-10.0: Critical"
        ),
    },
    {
        "id": "comp-003", "framework": "mitre_attack",
        "category": "mapping",
        "desc": "MITRE ATT&CK framework tactic and technique mapping.",
        "data": (
            "MITRE ATT&CK MAPPING:\n"
            "TACTICS (kill chain order):\n"
            "  TA0043 Reconnaissance: OSINT, scanning, social engineering\n"
            "  TA0042 Resource Development: Infrastructure, accounts, tools\n"
            "  TA0001 Initial Access: Phishing, exploit public-facing app\n"
            "  TA0002 Execution: Command line, scripting, exploitation\n"
            "  TA0003 Persistence: Accounts, scheduled tasks, implants\n"
            "  TA0004 Privilege Escalation: Exploit vuln, access token manip\n"
            "  TA0005 Defense Evasion: Obfuscation, indicator removal\n"
            "  TA0006 Credential Access: Brute force, credential dumping\n"
            "  TA0007 Discovery: Network scan, system info discovery\n"
            "  TA0008 Lateral Movement: Remote services, pass-the-hash\n"
            "  TA0009 Collection: Data from local system, clipboard\n"
            "  TA0011 Command and Control: Protocol tunneling, proxy\n"
            "  TA0010 Exfiltration: Automated, over C2, over web service\n"
            "  TA0040 Impact: Data destruction, defacement, ransomware\n"
            "COMMON TECHNIQUE MAPPINGS:\n"
            "  SQL Injection → T1190 (Exploit Public-Facing App)\n"
            "  XSS → T1189 (Drive-by Compromise)\n"
            "  SSRF → T1190\n"
            "  Pass-the-Hash → T1550.002\n"
            "  Kerberoasting → T1558.003\n"
            "  Container Escape → T1611"
        ),
    },
    {
        "id": "comp-004", "framework": "cwe",
        "category": "classification",
        "desc": "Common Weakness Enumeration for vulnerability classification.",
        "data": (
            "CWE CLASSIFICATION:\n"
            "TOP 25 MOST DANGEROUS (2024):\n"
            "  CWE-79: Cross-Site Scripting (XSS)\n"
            "  CWE-89: SQL Injection\n"
            "  CWE-78: OS Command Injection\n"
            "  CWE-20: Improper Input Validation\n"
            "  CWE-22: Path Traversal\n"
            "  CWE-352: Cross-Site Request Forgery (CSRF)\n"
            "  CWE-434: Unrestricted File Upload\n"
            "  CWE-862: Missing Authorization\n"
            "  CWE-476: NULL Pointer Dereference\n"
            "  CWE-287: Improper Authentication\n"
            "  CWE-190: Integer Overflow\n"
            "  CWE-502: Insecure Deserialization\n"
            "  CWE-77: Command Injection\n"
            "  CWE-119: Buffer Overflow\n"
            "  CWE-798: Hardcoded Credentials\n"
            "  CWE-918: SSRF\n"
            "  CWE-306: Missing Authentication\n"
            "  CWE-362: Race Condition\n"
            "  CWE-269: Improper Privilege Management\n"
            "  CWE-94: Code Injection\n"
            "  CWE-863: Incorrect Authorization\n"
            "  CWE-416: Use After Free\n"
            "  CWE-611: XXE\n"
            "  CWE-125: Out-of-Bounds Read\n"
            "  CWE-787: Out-of-Bounds Write"
        ),
    },
    {
        "id": "comp-005", "framework": "remediation",
        "category": "remediation",
        "desc": "Standard remediation templates for common findings.",
        "data": (
            "REMEDIATION TEMPLATES:\n"
            "SQL INJECTION:\n"
            "  - Use parameterized queries / prepared statements\n"
            "  - Apply input validation (allowlist)\n"
            "  - Use ORM for database operations\n"
            "  - Apply least privilege to DB accounts\n"
            "XSS:\n"
            "  - Output encode all user data (context-aware)\n"
            "  - Implement Content-Security-Policy header\n"
            "  - Use HttpOnly and Secure flags on cookies\n"
            "  - Use modern framework auto-escaping (React, Vue)\n"
            "SSRF:\n"
            "  - Validate and sanitize all URLs\n"
            "  - Use allowlist for permitted domains/IPs\n"
            "  - Block internal IP ranges (10.x, 172.16-31.x, 192.168.x)\n"
            "  - Disable unnecessary URL schemes (file://, gopher://)\n"
            "IDOR:\n"
            "  - Implement server-side authorization checks\n"
            "  - Use indirect references (map to internal IDs)\n"
            "  - Validate user ownership of requested resources\n"
            "AUTHENTICATION:\n"
            "  - Implement MFA\n"
            "  - Use strong password policy\n"
            "  - Rate limit login attempts\n"
            "  - Use bcrypt/scrypt/Argon2 for password hashing\n"
            "  - Implement account lockout"
        ),
    },
]


class ComplianceKB:
    """Compliance knowledge base.

    Provides compliance framework mappings
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._mappings: dict[str, ComplianceMapping] = {}
        self._log = logger.bind(component="compliance_kb")
        self._load_mappings()

    def _load_mappings(self) -> None:
        """Load compliance mappings."""
        for data in COMPLIANCE_MAPPINGS:
            mapping = ComplianceMapping(
                mapping_id=data["id"],
                framework=data["framework"],
                category=data.get("category", ""),
                description=data.get("desc", ""),
                mapping_data=data.get("data", ""),
            )
            self._mappings[mapping.mapping_id] = mapping

    def get_by_framework(self, framework: str) -> list[ComplianceMapping]:
        """Get mappings by framework."""
        return [
            m for m in self._mappings.values()
            if m.framework.lower() == framework.lower()
        ]

    def build_compliance_prompt(
        self,
        frameworks: list[str] | None = None,
        max_mappings: int = 3,
    ) -> str:
        """Build compliance prompt."""
        lines = ["## Compliance Framework Reference\n"]
        count = 0
        for mapping in self._mappings.values():
            if frameworks and mapping.framework.lower() not in [f.lower() for f in frameworks]:
                continue
            if count >= max_mappings:
                break
            lines.append(f"### {mapping.framework.upper()}")
            lines.append(mapping.mapping_data)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        fw_counts: dict[str, int] = {}
        for m in self._mappings.values():
            fw_counts[m.framework] = fw_counts.get(m.framework, 0) + 1
        return {
            "mappings": len(self._mappings),
            "by_framework": fw_counts,
        }
