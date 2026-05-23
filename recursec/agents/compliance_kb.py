"""Compliance and audit knowledge base.

Deep knowledge about security compliance:
1. PCI DSS requirements
2. HIPAA technical safeguards
3. SOC 2 controls
4. NIST cybersecurity framework
5. GDPR technical requirements
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CompliancePattern:
    """A compliance requirement pattern."""
    pattern_id: str = ""
    name: str = ""
    framework: str = ""
    category: str = ""
    description: str = ""
    test_procedures: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "framework": self.framework[:10],
        }


COMPLIANCE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "comp-001", "name": "PCI DSS Network Security",
        "framework": "PCI_DSS", "category": "network",
        "desc": "PCI DSS requirements for network security.",
        "procedures": (
            "PCI DSS NETWORK SECURITY:\n"
            "REQ 1: Install and maintain network security controls\n"
            "  TESTS:\n"
            "  - Verify firewall between DMZ and internal network\n"
            "  - Check firewall rules deny all by default\n"
            "  - Verify no direct public access to cardholder data env\n"
            "  - Review firewall/router configurations\n"
            "  nmap -sS -p- <cardholder_env>  # Check open ports\n"
            "  nmap --script firewall-bypass <target>\n"
            "REQ 2: Secure system configurations\n"
            "  TESTS:\n"
            "  - Check no default passwords on systems\n"
            "  - Verify unnecessary services disabled\n"
            "  - Review system hardening standards\n"
            "  nmap -sV --script default <target>  # Service versions\n"
            "  # Check default credentials\n"
            "  hydra -L defaults.txt -P defaults.txt <target> ssh\n"
            "REQ 4: Encrypt cardholder data in transit\n"
            "  TESTS:\n"
            "  - Verify TLS 1.2+ on all external connections\n"
            "  - Check for weak ciphers\n"
            "  testssl.sh <target>  # Full TLS analysis\n"
            "  nmap --script ssl-enum-ciphers <target>"
        ),
        "tools": ["nmap", "testssl", "hydra"],
    },
    {
        "id": "comp-002", "name": "HIPAA Technical Safeguards",
        "framework": "HIPAA", "category": "healthcare",
        "desc": "HIPAA technical safeguard requirements.",
        "procedures": (
            "HIPAA TECHNICAL SAFEGUARDS:\n"
            "ACCESS CONTROL (164.312(a)):\n"
            "  - Unique user identification\n"
            "  - Emergency access procedures\n"
            "  - Automatic logoff\n"
            "  - Encryption and decryption of ePHI\n"
            "  TESTS:\n"
            "  - Verify unique user IDs for all users\n"
            "  - Check session timeout settings\n"
            "  - Test encryption of data at rest\n"
            "  - Verify role-based access controls\n"
            "AUDIT CONTROLS (164.312(b)):\n"
            "  - Hardware, software, procedural logging\n"
            "  - Record and examine system activity\n"
            "  TESTS:\n"
            "  - Verify logging enabled on all systems\n"
            "  - Check log retention (minimum 6 years)\n"
            "  - Review log monitoring processes\n"
            "TRANSMISSION SECURITY (164.312(e)):\n"
            "  - Integrity controls\n"
            "  - Encryption of ePHI in transit\n"
            "  TESTS:\n"
            "  testssl.sh <target>  # Verify TLS\n"
            "  - Check all ePHI transmissions encrypted\n"
            "  - Verify VPN for remote access"
        ),
        "tools": ["testssl", "nmap"],
    },
    {
        "id": "comp-003", "name": "NIST Cybersecurity Framework",
        "framework": "NIST_CSF", "category": "general",
        "desc": "NIST CSF assessment areas.",
        "procedures": (
            "NIST CYBERSECURITY FRAMEWORK:\n"
            "IDENTIFY (ID):\n"
            "  - Asset management (ID.AM)\n"
            "  - Business environment (ID.BE)\n"
            "  - Risk assessment (ID.RA)\n"
            "  TESTS:\n"
            "  - Verify asset inventory completeness\n"
            "  nmap -sn <network>/24  # Discover unknown devices\n"
            "  - Review risk assessment documentation\n"
            "PROTECT (PR):\n"
            "  - Access control (PR.AC)\n"
            "  - Awareness and training (PR.AT)\n"
            "  - Data security (PR.DS)\n"
            "  TESTS:\n"
            "  - Verify MFA on all critical systems\n"
            "  - Check patch management process\n"
            "  - Test backup and recovery\n"
            "DETECT (DE):\n"
            "  - Anomalies and events (DE.AE)\n"
            "  - Continuous monitoring (DE.CM)\n"
            "  TESTS:\n"
            "  - Verify IDS/IPS deployment\n"
            "  - Check SIEM coverage\n"
            "  - Test alerting with simulated attacks\n"
            "RESPOND (RS):\n"
            "  - Response planning (RS.RP)\n"
            "  - Communications (RS.CO)\n"
            "  - Analysis (RS.AN)\n"
            "RECOVER (RC):\n"
            "  - Recovery planning (RC.RP)\n"
            "  - Verify RTO/RPO compliance"
        ),
        "tools": ["nmap", "nuclei"],
    },
    {
        "id": "comp-004", "name": "SOC 2 Trust Services",
        "framework": "SOC2", "category": "cloud",
        "desc": "SOC 2 trust service criteria testing.",
        "procedures": (
            "SOC 2 TRUST SERVICES:\n"
            "SECURITY (CC):\n"
            "  CC6.1: Logical and physical access controls\n"
            "  TESTS:\n"
            "  - Verify access reviews performed quarterly\n"
            "  - Check least privilege enforcement\n"
            "  - Test account provisioning/deprovisioning\n"
            "  - Verify MFA on all admin accounts\n"
            "  CC6.6: Restriction of network traffic\n"
            "  TESTS:\n"
            "  - Verify firewall rules\n"
            "  - Check network segmentation\n"
            "  - Test egress filtering\n"
            "  nmap -sS <target>  # Verify exposed ports\n"
            "  CC7.2: Monitoring of system components\n"
            "  TESTS:\n"
            "  - Verify logging coverage\n"
            "  - Check SIEM alerts configured\n"
            "AVAILABILITY (A):\n"
            "  A1.1: Processing capacity\n"
            "  - Verify auto-scaling configured\n"
            "  - Test failover mechanisms\n"
            "  - Check SLA compliance\n"
            "CONFIDENTIALITY (C):\n"
            "  C1.1: Confidential information protection\n"
            "  - Verify encryption at rest and in transit\n"
            "  - Check data classification\n"
            "  - Test DLP controls"
        ),
        "tools": ["nmap", "nuclei", "testssl"],
    },
    {
        "id": "comp-005", "name": "GDPR Technical Controls",
        "framework": "GDPR", "category": "privacy",
        "desc": "GDPR technical requirement testing.",
        "procedures": (
            "GDPR TECHNICAL CONTROLS:\n"
            "ART 25: Data protection by design\n"
            "  TESTS:\n"
            "  - Verify data minimization in applications\n"
            "  - Check privacy settings default to most protective\n"
            "  - Test pseudonymization/anonymization\n"
            "  - Review data retention automation\n"
            "ART 32: Security of processing\n"
            "  TESTS:\n"
            "  - Verify encryption of personal data\n"
            "  testssl.sh <target>  # TLS assessment\n"
            "  - Check access controls on personal data stores\n"
            "  - Verify regular security testing\n"
            "  nuclei -u <target> -t cves/  # Vulnerability scan\n"
            "ART 33: Data breach notification\n"
            "  TESTS:\n"
            "  - Verify breach detection capability\n"
            "  - Check notification process (<72 hours)\n"
            "  - Test incident response plan\n"
            "ART 17: Right to erasure\n"
            "  TESTS:\n"
            "  - Verify data deletion mechanisms\n"
            "  - Check deletion from backups\n"
            "  - Test API for data deletion requests\n"
            "ART 20: Data portability\n"
            "  TESTS:\n"
            "  - Verify data export in machine-readable format\n"
            "  - Test API for data export"
        ),
        "tools": ["testssl", "nuclei", "nmap"],
    },
]


class ComplianceKB:
    """Compliance and audit knowledge base.

    Provides compliance framework patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, CompliancePattern] = {}
        self._log = logger.bind(component="compliance_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load compliance patterns."""
        for data in COMPLIANCE_PATTERNS:
            pattern = CompliancePattern(
                pattern_id=data["id"],
                name=data["name"],
                framework=data.get("framework", ""),
                category=data.get("category", ""),
                description=data.get("desc", ""),
                test_procedures=data.get("procedures", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_framework(self, framework: str) -> list[CompliancePattern]:
        """Get patterns by framework."""
        return [
            p for p in self._patterns.values()
            if p.framework.lower() == framework.lower()
        ]

    def build_compliance_prompt(
        self,
        frameworks: list[str] | None = None,
        max_patterns: int = 3,
    ) -> str:
        """Build compliance prompt."""
        lines = ["## Compliance Requirements\n"]
        count = 0
        for pattern in self._patterns.values():
            if frameworks and pattern.framework.lower() not in [f.lower() for f in frameworks]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.framework}]")
            lines.append(pattern.test_procedures)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        fw_counts: dict[str, int] = {}
        for p in self._patterns.values():
            fw_counts[p.framework] = fw_counts.get(p.framework, 0) + 1
        return {
            "patterns": len(self._patterns),
            "by_framework": fw_counts,
        }
