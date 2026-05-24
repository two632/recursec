"""Compliance and regulatory knowledge base.

Deep knowledge about compliance testing:
1. PCI DSS assessment
2. HIPAA security assessment
3. SOC 2 controls testing
4. GDPR technical assessment
5. NIST framework mapping
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CompliancePattern:
    """A compliance pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:12],
        }


COMPLIANCE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "comp-001", "name": "PCI DSS Assessment",
        "category": "pci", "severity": "high",
        "desc": "PCI DSS security testing.",
        "detection": (
            "PCI DSS ASSESSMENT:\n"
            "REQ 1: FIREWALL CONFIGURATION:\n"
            "  - Network segmentation validation\n"
            "  - Firewall rule review\n"
            "  - DMZ configuration\n"
            "  - Inbound/outbound rules\n"
            "REQ 2: VENDOR DEFAULTS:\n"
            "  - Default passwords changed\n"
            "  - Unnecessary services disabled\n"
            "  - System configuration standards\n"
            "REQ 3: STORED CARDHOLDER DATA:\n"
            "  - PAN storage locations\n"
            "  - Encryption at rest (AES-256)\n"
            "  - Key management procedures\n"
            "  - Data retention policies\n"
            "REQ 4: ENCRYPTION IN TRANSIT:\n"
            "  - TLS 1.2+ enforcement\n"
            "  - Certificate management\n"
            "  - Weak cipher suites\n"
            "REQ 6: SECURE DEVELOPMENT:\n"
            "  - Code review practices\n"
            "  - OWASP Top 10 testing\n"
            "  - Web application firewall\n"
            "  - Change management\n"
            "REQ 8: AUTHENTICATION:\n"
            "  - MFA for admin access\n"
            "  - Password policy (12+ chars)\n"
            "  - Account lockout\n"
            "  - Unique user IDs\n"
            "REQ 10: LOGGING & MONITORING:\n"
            "  - Audit trail implementation\n"
            "  - Log integrity (tamper-proof)\n"
            "  - Log review procedures\n"
            "  - Alert thresholds\n"
            "REQ 11: REGULAR TESTING:\n"
            "  - Quarterly ASV scans\n"
            "  - Annual penetration test\n"
            "  - IDS/IPS monitoring\n"
            "  - File integrity monitoring\n"
            "TOOLS:\n"
            "  Nessus (PCI scan profile), QSA tools"
        ),
        "tools": [],
    },
    {
        "id": "comp-002", "name": "HIPAA Security Assessment",
        "category": "hipaa", "severity": "critical",
        "desc": "HIPAA security rule testing.",
        "detection": (
            "HIPAA SECURITY ASSESSMENT:\n"
            "ADMINISTRATIVE:\n"
            "  - Risk analysis (required)\n"
            "  - Risk management plan\n"
            "  - Sanction policy\n"
            "  - Information system activity review\n"
            "  - Workforce training\n"
            "  - Business associate agreements\n"
            "  - Contingency planning\n"
            "PHYSICAL:\n"
            "  - Facility access controls\n"
            "  - Workstation security\n"
            "  - Device and media controls\n"
            "  - Disposal procedures\n"
            "TECHNICAL:\n"
            "  - Access control\n"
            "    # Unique user identification\n"
            "    # Emergency access procedures\n"
            "    # Automatic logoff\n"
            "    # Encryption/decryption\n"
            "  - Audit controls\n"
            "    # Hardware, software, procedural\n"
            "    # Record and examine activity\n"
            "  - Integrity controls\n"
            "    # Mechanism to authenticate ePHI\n"
            "  - Transmission security\n"
            "    # Integrity controls\n"
            "    # Encryption (TLS 1.2+)\n"
            "ePHI LOCATIONS:\n"
            "  - Databases (SQL, NoSQL)\n"
            "  - File servers\n"
            "  - Email systems\n"
            "  - Cloud services (BAA required)\n"
            "  - Mobile devices\n"
            "  - Medical devices\n"
            "  - Backup systems\n"
            "TOOLS:\n"
            "  Nessus, OpenSCAP, CIS-CAT"
        ),
        "tools": [],
    },
    {
        "id": "comp-003", "name": "SOC 2 Controls Testing",
        "category": "soc2", "severity": "high",
        "desc": "SOC 2 trust services criteria.",
        "detection": (
            "SOC 2 CONTROLS TESTING:\n"
            "CC1: CONTROL ENVIRONMENT:\n"
            "  - Organizational structure\n"
            "  - Management philosophy\n"
            "  - HR policies and practices\n"
            "  - Board oversight\n"
            "CC2: COMMUNICATION:\n"
            "  - Internal communication\n"
            "  - External communication\n"
            "  - System description accuracy\n"
            "CC3: RISK ASSESSMENT:\n"
            "  - Risk identification process\n"
            "  - Fraud risk assessment\n"
            "  - Change management impact\n"
            "CC5: CONTROL ACTIVITIES:\n"
            "  - Logical access controls\n"
            "  - Change management\n"
            "  - Infrastructure security\n"
            "CC6: LOGICAL ACCESS:\n"
            "  - User provisioning/deprovisioning\n"
            "  - Authentication mechanisms\n"
            "  - Access review (quarterly)\n"
            "  - Network access restrictions\n"
            "  - Encryption controls\n"
            "CC7: SYSTEM OPERATIONS:\n"
            "  - Monitoring tools and processes\n"
            "  - Incident detection\n"
            "  - Incident response plan\n"
            "  - Vulnerability management\n"
            "CC8: CHANGE MANAGEMENT:\n"
            "  - Change approval process\n"
            "  - Testing requirements\n"
            "  - Rollback procedures\n"
            "CC9: RISK MITIGATION:\n"
            "  - Vendor management\n"
            "  - Business continuity\n"
            "TESTING:\n"
            "  - Control design effectiveness\n"
            "  - Operating effectiveness\n"
            "  - Evidence collection\n"
            "TOOLS:\n"
            "  Vanta, Drata, Secureframe, AuditBoard"
        ),
        "tools": [],
    },
    {
        "id": "comp-004", "name": "GDPR Technical Assessment",
        "category": "gdpr", "severity": "high",
        "desc": "GDPR technical controls testing.",
        "detection": (
            "GDPR TECHNICAL ASSESSMENT:\n"
            "ART 25: DATA PROTECTION BY DESIGN:\n"
            "  - Pseudonymization\n"
            "  - Data minimization\n"
            "  - Purpose limitation\n"
            "  - Default privacy settings\n"
            "ART 32: SECURITY OF PROCESSING:\n"
            "  - Encryption of personal data\n"
            "  - Confidentiality assurance\n"
            "  - Integrity assurance\n"
            "  - Availability assurance\n"
            "  - Regular testing/assessment\n"
            "ART 33/34: BREACH NOTIFICATION:\n"
            "  - 72-hour notification capability\n"
            "  - Breach detection mechanisms\n"
            "  - Incident response procedures\n"
            "  - Communication templates\n"
            "DATA MAPPING:\n"
            "  - Personal data inventory\n"
            "  - Processing activities register\n"
            "  - Cross-border data flows\n"
            "  - Third-party data sharing\n"
            "  - Retention schedules\n"
            "RIGHTS:\n"
            "  - Right to access (Art 15)\n"
            "  - Right to erasure (Art 17)\n"
            "  - Right to portability (Art 20)\n"
            "  - Right to rectification (Art 16)\n"
            "  - Consent management\n"
            "TESTING:\n"
            "  - Test data subject request fulfillment\n"
            "  - Verify encryption implementation\n"
            "  - Audit consent mechanisms\n"
            "  - Test breach notification workflow\n"
            "  - Verify data retention enforcement\n"
            "TOOLS:\n"
            "  OneTrust, BigID, TrustArc"
        ),
        "tools": [],
    },
    {
        "id": "comp-005", "name": "NIST Framework Mapping",
        "category": "nist", "severity": "medium",
        "desc": "NIST Cybersecurity Framework mapping.",
        "detection": (
            "NIST CYBERSECURITY FRAMEWORK:\n"
            "IDENTIFY (ID):\n"
            "  - Asset management (ID.AM)\n"
            "  - Business environment (ID.BE)\n"
            "  - Governance (ID.GV)\n"
            "  - Risk assessment (ID.RA)\n"
            "  - Supply chain (ID.SC)\n"
            "PROTECT (PR):\n"
            "  - Access control (PR.AC)\n"
            "  - Awareness training (PR.AT)\n"
            "  - Data security (PR.DS)\n"
            "  - Info protection (PR.IP)\n"
            "  - Maintenance (PR.MA)\n"
            "  - Protective technology (PR.PT)\n"
            "DETECT (DE):\n"
            "  - Anomalies and events (DE.AE)\n"
            "  - Security monitoring (DE.CM)\n"
            "  - Detection processes (DE.DP)\n"
            "RESPOND (RS):\n"
            "  - Response planning (RS.RP)\n"
            "  - Communications (RS.CO)\n"
            "  - Analysis (RS.AN)\n"
            "  - Mitigation (RS.MI)\n"
            "  - Improvements (RS.IM)\n"
            "RECOVER (RC):\n"
            "  - Recovery planning (RC.RP)\n"
            "  - Improvements (RC.IM)\n"
            "  - Communications (RC.CO)\n"
            "MATURITY LEVELS:\n"
            "  1 - Partial (ad hoc)\n"
            "  2 - Risk Informed (policy exists)\n"
            "  3 - Repeatable (documented)\n"
            "  4 - Adaptive (metrics-driven)\n"
            "TOOLS:\n"
            "  NIST CSF Tool, CIS Controls, OpenSCAP"
        ),
        "tools": [],
    },
]


class ComplianceKB:
    """Compliance and regulatory knowledge base.

    Provides compliance patterns injected
    into agent prompts.
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
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[CompliancePattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_compliance_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build compliance prompt."""
        lines = ["## Compliance\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category.lower() not in [c.lower() for c in categories]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.category.upper()}]")
            lines.append(pattern.detection_strategy)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = {}
        for p in self._patterns.values():
            cat_counts[p.category] = cat_counts.get(p.category, 0) + 1
        return {
            "patterns": len(self._patterns),
            "by_category": cat_counts,
        }
