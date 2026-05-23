"""Compliance and audit knowledge base.

Deep knowledge about security compliance frameworks:
1. OWASP Top 10 mapping
2. PCI-DSS requirements
3. NIST CSF controls
4. CIS benchmarks
5. MITRE ATT&CK mapping
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ComplianceCheck:
    """A compliance check pattern."""
    check_id: str = ""
    name: str = ""
    framework: str = ""
    requirement: str = ""
    severity: str = "medium"
    description: str = ""
    testing_methodology: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.check_id,
            "name": self.name[:25],
            "framework": self.framework[:10],
        }


COMPLIANCE_CHECKS: list[dict[str, Any]] = [
    {
        "id": "comp-001", "name": "OWASP Top 10 - 2021",
        "framework": "OWASP", "req": "A01-A10",
        "severity": "high",
        "desc": "OWASP Top 10 Web Application Security Risks 2021.",
        "testing": (
            "OWASP TOP 10 - 2021:\n"
            "A01:2021 BROKEN ACCESS CONTROL (94% apps):\n"
            "  - IDOR testing: Modify IDs in URLs/body\n"
            "  - BFLA: Access admin endpoints as regular user\n"
            "  - CORS misconfiguration: Check Access-Control-Allow-Origin\n"
            "  - Directory traversal: ../../../etc/passwd\n"
            "  - Missing function-level access control\n"
            "A02:2021 CRYPTOGRAPHIC FAILURES:\n"
            "  - Check TLS: testssl.sh / sslyze\n"
            "  - Sensitive data in transit (HTTP vs HTTPS)\n"
            "  - Weak algorithms: MD5, SHA1, DES, RC4\n"
            "  - Hardcoded secrets in source\n"
            "  - Password storage: bcrypt/scrypt/argon2 vs MD5/SHA1\n"
            "A03:2021 INJECTION:\n"
            "  - SQL injection: sqlmap --batch\n"
            "  - XSS: dalfox / XSStrike\n"
            "  - Command injection: ; | ` $() in params\n"
            "  - LDAP injection: )(cn=*)\n"
            "  - NoSQL injection: {\"$gt\": \"\"}\n"
            "A04:2021 INSECURE DESIGN:\n"
            "  - Business logic flaws\n"
            "  - Missing rate limiting\n"
            "  - Credential recovery weakness\n"
            "A05:2021 SECURITY MISCONFIGURATION:\n"
            "  - Default credentials\n"
            "  - Unnecessary features enabled\n"
            "  - Missing security headers\n"
            "  - Verbose error messages\n"
            "  - nuclei -t misconfiguration/\n"
            "A06:2021 VULNERABLE COMPONENTS:\n"
            "  - trivy / grype / npm audit / pip audit\n"
            "  - Check CVE databases for versions\n"
            "A07:2021 AUTH FAILURES:\n"
            "  - Brute force testing: hydra\n"
            "  - Session management flaws\n"
            "  - JWT vulnerabilities\n"
            "A08:2021 SOFTWARE/DATA INTEGRITY:\n"
            "  - Deserialization attacks\n"
            "  - CI/CD pipeline security\n"
            "  - SRI (Subresource Integrity) checks\n"
            "A09:2021 LOGGING FAILURES:\n"
            "  - Check for security event logging\n"
            "  - Log injection testing\n"
            "A10:2021 SSRF:\n"
            "  - Internal service access via URL params\n"
            "  - Cloud metadata endpoint access"
        ),
        "tools": ["nuclei", "sqlmap", "dalfox", "testssl", "trivy"],
    },
    {
        "id": "comp-002", "name": "PCI-DSS v4.0",
        "framework": "PCI-DSS", "req": "Requirements 1-12",
        "severity": "critical",
        "desc": "Payment Card Industry Data Security Standard.",
        "testing": (
            "PCI-DSS v4.0 KEY REQUIREMENTS:\n"
            "REQ 1 - NETWORK SECURITY:\n"
            "  - Firewall rules review\n"
            "  - Network segmentation testing\n"
            "  - DMZ validation\n"
            "  - nmap -sS -sV -O {cardholder_network}\n"
            "REQ 2 - SECURE CONFIGURATIONS:\n"
            "  - Default password testing\n"
            "  - CIS benchmark compliance\n"
            "  - Unnecessary service identification\n"
            "REQ 3 - PROTECT STORED DATA:\n"
            "  - PAN storage location identification\n"
            "  - Encryption algorithm validation\n"
            "  - Key management review\n"
            "REQ 4 - ENCRYPT TRANSMISSION:\n"
            "  - TLS configuration: testssl.sh\n"
            "  - Weak cipher identification\n"
            "  - Certificate validation\n"
            "REQ 5 - MALWARE PROTECTION:\n"
            "  - Antivirus/EDR presence\n"
            "  - Signature update verification\n"
            "REQ 6 - SECURE DEVELOPMENT:\n"
            "  - Code review findings\n"
            "  - SAST/DAST results\n"
            "  - Change management process\n"
            "REQ 7-8 - ACCESS CONTROL:\n"
            "  - Least privilege validation\n"
            "  - MFA implementation\n"
            "  - Password policy compliance\n"
            "REQ 9 - PHYSICAL SECURITY:\n"
            "  - Physical access controls\n"
            "  - Media destruction procedures\n"
            "REQ 10 - LOGGING & MONITORING:\n"
            "  - Audit trail completeness\n"
            "  - Log integrity verification\n"
            "  - Alerting mechanism testing\n"
            "REQ 11 - SECURITY TESTING:\n"
            "  - Quarterly vulnerability scans\n"
            "  - Annual penetration test\n"
            "  - Wireless scanning\n"
            "  - File integrity monitoring\n"
            "REQ 12 - SECURITY POLICY:\n"
            "  - Policy documentation review\n"
            "  - Incident response plan testing"
        ),
        "tools": ["nmap", "testssl", "nuclei", "semgrep"],
    },
    {
        "id": "comp-003", "name": "NIST CSF 2.0",
        "framework": "NIST", "req": "Identify-Protect-Detect-Respond-Recover",
        "severity": "high",
        "desc": "NIST Cybersecurity Framework.",
        "testing": (
            "NIST CSF 2.0 FUNCTIONS:\n"
            "IDENTIFY (ID):\n"
            "  - Asset inventory: nmap network scan\n"
            "  - Business environment mapping\n"
            "  - Risk assessment\n"
            "  - Supply chain risk management\n"
            "PROTECT (PR):\n"
            "  - Identity management: AD audit\n"
            "  - Access control testing\n"
            "  - Data security: encryption validation\n"
            "  - Security awareness (phishing simulations)\n"
            "  - Protective technology: WAF, IDS/IPS, EDR\n"
            "DETECT (DE):\n"
            "  - Anomaly detection capabilities\n"
            "  - Security monitoring coverage\n"
            "  - Detection process maturity\n"
            "  - SIEM rule effectiveness\n"
            "RESPOND (RS):\n"
            "  - Incident response plan testing\n"
            "  - Communication procedures\n"
            "  - Analysis capabilities\n"
            "  - Mitigation effectiveness\n"
            "RECOVER (RC):\n"
            "  - Recovery plan testing\n"
            "  - Backup validation\n"
            "  - Communication during recovery"
        ),
        "tools": ["nmap", "nuclei", "testssl"],
    },
    {
        "id": "comp-004", "name": "MITRE ATT&CK Mapping",
        "framework": "MITRE", "req": "Tactics TA0001-TA0011",
        "severity": "high",
        "desc": "MITRE ATT&CK framework mapping.",
        "testing": (
            "MITRE ATT&CK TACTICS:\n"
            "TA0001 INITIAL ACCESS:\n"
            "  - T1190: Exploit Public-Facing Application\n"
            "  - T1133: External Remote Services\n"
            "  - T1566: Phishing (if in scope)\n"
            "  - T1078: Valid Accounts (default/stolen)\n"
            "TA0002 EXECUTION:\n"
            "  - T1059: Command & Scripting (bash, powershell, python)\n"
            "  - T1203: Exploitation for Client Execution\n"
            "TA0003 PERSISTENCE:\n"
            "  - T1136: Create Account\n"
            "  - T1053: Scheduled Task/Job\n"
            "  - T1505: Server Software Component (webshell)\n"
            "TA0004 PRIVILEGE ESCALATION:\n"
            "  - T1068: Exploitation for Privilege Escalation\n"
            "  - T1548: Abuse Elevation Control (sudo, UAC)\n"
            "  - T1134: Access Token Manipulation\n"
            "TA0005 DEFENSE EVASION:\n"
            "  - T1070: Indicator Removal (log clearing)\n"
            "  - T1027: Obfuscated Files or Information\n"
            "TA0006 CREDENTIAL ACCESS:\n"
            "  - T1110: Brute Force\n"
            "  - T1003: OS Credential Dumping\n"
            "  - T1558: Steal or Forge Kerberos Tickets\n"
            "TA0007 DISCOVERY:\n"
            "  - T1046: Network Service Discovery\n"
            "  - T1087: Account Discovery\n"
            "  - T1082: System Information Discovery\n"
            "TA0008 LATERAL MOVEMENT:\n"
            "  - T1021: Remote Services (SSH, RDP, SMB)\n"
            "  - T1550: Use Alternate Authentication (PtH, PtT)\n"
            "TA0009 COLLECTION:\n"
            "  - T1005: Data from Local System\n"
            "  - T1039: Data from Network Shared Drive\n"
            "TA0010 EXFILTRATION:\n"
            "  - T1041: Exfiltration Over C2\n"
            "  - T1048: Exfiltration Over Alternative Protocol\n"
            "TA0011 IMPACT:\n"
            "  - T1486: Data Encrypted for Impact (ransomware)\n"
            "  - T1489: Service Stop"
        ),
        "tools": ["nmap", "crackmapexec", "hydra", "bloodhound"],
    },
]


class ComplianceKB:
    """Compliance and audit knowledge base.

    Provides compliance framework testing methodology
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._checks: dict[str, ComplianceCheck] = {}
        self._log = logger.bind(component="compliance_kb")
        self._load_checks()

    def _load_checks(self) -> None:
        """Load compliance checks."""
        for data in COMPLIANCE_CHECKS:
            check = ComplianceCheck(
                check_id=data["id"],
                name=data["name"],
                framework=data.get("framework", ""),
                requirement=data.get("req", ""),
                severity=data.get("severity", "medium"),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
            )
            self._checks[check.check_id] = check

    def get_checks_for_framework(
        self,
        framework: str,
    ) -> list[ComplianceCheck]:
        """Get checks by framework."""
        return [
            c for c in self._checks.values()
            if c.framework.lower() == framework.lower()
        ]

    def build_compliance_prompt(
        self,
        frameworks: list[str] | None = None,
        max_checks: int = 3,
    ) -> str:
        """Build compliance testing prompt."""
        lines = ["## Compliance Testing\n"]
        count = 0
        for check in self._checks.values():
            if frameworks and check.framework.lower() not in [f.lower() for f in frameworks]:
                continue
            if count >= max_checks:
                break
            lines.append(f"### {check.name} [{check.framework}]")
            lines.append(check.testing_methodology)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        fw_counts: dict[str, int] = defaultdict(int)
        for c in self._checks.values():
            fw_counts[c.framework] += 1
        return {
            "checks": len(self._checks),
            "by_framework": dict(fw_counts),
        }
