"""Compliance and audit knowledge base.

Deep knowledge about compliance frameworks:
1. PCI DSS (Payment Card Industry)
2. HIPAA (Healthcare)
3. SOC 2 (Service Organizations)
4. ISO 27001 (Information Security)
5. NIST Cybersecurity Framework
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
    severity: str = "medium"
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
        "id": "comp-001", "name": "PCI DSS",
        "category": "pci", "severity": "high",
        "desc": "PCI DSS compliance assessment.",
        "detection": (
            "PCI DSS COMPLIANCE:\n"
            "KEY REQUIREMENTS:\n"
            "  Req 1: Firewall/network security\n"
            "  Req 2: No vendor defaults (passwords)\n"
            "  Req 3: Protect stored cardholder data\n"
            "  Req 4: Encrypt transmission\n"
            "  Req 5: Anti-malware\n"
            "  Req 6: Secure development\n"
            "  Req 7: Restrict access (need-to-know)\n"
            "  Req 8: Identify users (authentication)\n"
            "  Req 9: Physical access controls\n"
            "  Req 10: Log and monitor access\n"
            "  Req 11: Regular testing\n"
            "  Req 12: Security policy\n"
            "TESTING:\n"
            "  - Network segmentation verification\n"
            "  - ASV (Approved Scanning Vendor) scans\n"
            "  - Penetration testing (internal/external)\n"
            "  - Wireless scanning\n"
            "  - File integrity monitoring\n"
            "  - IDS/IPS testing\n"
            "CARDHOLDER DATA:\n"
            "  - PAN (Primary Account Number)\n"
            "  - Track data (magnetic stripe)\n"
            "  - CVV2/CVC2\n"
            "  - PIN/PIN block\n"
            "  - Where is data stored/processed/transmitted?\n"
            "TOOLS:\n"
            "  Nessus (PCI plugin), Qualys PCI, OpenSCAP"
        ),
        "tools": ["nessus", "openscap"],
    },
    {
        "id": "comp-002", "name": "HIPAA Security",
        "category": "hipaa", "severity": "high",
        "desc": "HIPAA compliance for healthcare.",
        "detection": (
            "HIPAA SECURITY:\n"
            "SAFEGUARDS:\n"
            "  ADMINISTRATIVE:\n"
            "    - Risk analysis (164.308(a)(1))\n"
            "    - Security management\n"
            "    - Workforce security\n"
            "    - Information access management\n"
            "    - Security awareness training\n"
            "    - Incident procedures\n"
            "    - Contingency plan\n"
            "    - Business associate agreements\n"
            "  PHYSICAL:\n"
            "    - Facility access controls\n"
            "    - Workstation use\n"
            "    - Device and media controls\n"
            "  TECHNICAL:\n"
            "    - Access control\n"
            "    - Audit controls (logging)\n"
            "    - Integrity (ePHI modification)\n"
            "    - Person/entity authentication\n"
            "    - Transmission security (encryption)\n"
            "PHI/ePHI:\n"
            "  - Protected Health Information\n"
            "  - 18 HIPAA identifiers\n"
            "  - Names, dates, SSN, medical records\n"
            "  - Biometric data, photos, device IDs\n"
            "TESTING:\n"
            "  - PHI data flow mapping\n"
            "  - Encryption audit (at rest + in transit)\n"
            "  - Access control review\n"
            "  - Audit log analysis\n"
            "TOOLS:\n"
            "  HIPAA compliance scanners, Nessus"
        ),
        "tools": ["nessus"],
    },
    {
        "id": "comp-003", "name": "SOC 2",
        "category": "soc2", "severity": "medium",
        "desc": "SOC 2 compliance assessment.",
        "detection": (
            "SOC 2 COMPLIANCE:\n"
            "TRUST SERVICE CRITERIA:\n"
            "  SECURITY (Common Criteria):\n"
            "    - CC1: Control environment\n"
            "    - CC2: Communication and information\n"
            "    - CC3: Risk assessment\n"
            "    - CC4: Monitoring activities\n"
            "    - CC5: Control activities\n"
            "    - CC6: Logical/physical access\n"
            "    - CC7: System operations\n"
            "    - CC8: Change management\n"
            "    - CC9: Risk mitigation\n"
            "  AVAILABILITY:\n"
            "    - A1: Capacity planning\n"
            "    - Backup and recovery\n"
            "    - Business continuity\n"
            "  PROCESSING INTEGRITY:\n"
            "    - PI1: Processing completeness\n"
            "    - Data validation\n"
            "    - Error handling\n"
            "  CONFIDENTIALITY:\n"
            "    - C1: Identification of confidential info\n"
            "    - Encryption, access controls\n"
            "  PRIVACY:\n"
            "    - P1-P8: Notice, choice, access\n"
            "    - Data retention, disposal\n"
            "TESTING:\n"
            "  - Evidence collection (screenshots, logs)\n"
            "  - Policy review\n"
            "  - Technical control verification\n"
            "  - Pen testing (CC7.1)\n"
            "TOOLS:\n"
            "  Vanta, Drata, Secureframe, manual review"
        ),
        "tools": [],
    },
    {
        "id": "comp-004", "name": "ISO 27001",
        "category": "iso27001", "severity": "medium",
        "desc": "ISO 27001 compliance assessment.",
        "detection": (
            "ISO 27001 COMPLIANCE:\n"
            "ANNEX A CONTROLS (2022):\n"
            "  5. Organizational (37 controls)\n"
            "    - Policies, roles, segregation of duties\n"
            "    - Threat intelligence\n"
            "    - Information classification\n"
            "    - Identity management\n"
            "  6. People (8 controls)\n"
            "    - Screening, awareness, training\n"
            "    - Disciplinary process\n"
            "    - Post-employment\n"
            "  7. Physical (14 controls)\n"
            "    - Perimeters, entry controls\n"
            "    - Equipment protection\n"
            "    - Clear desk/screen\n"
            "  8. Technological (34 controls)\n"
            "    - User endpoint devices\n"
            "    - Access control (8.2-8.5)\n"
            "    - Malware protection\n"
            "    - Backup (8.13)\n"
            "    - Logging (8.15)\n"
            "    - Network security (8.20-8.23)\n"
            "    - Cryptography (8.24)\n"
            "    - Vulnerability management (8.8)\n"
            "    - Configuration management (8.9)\n"
            "    - Secure development (8.25-8.29)\n"
            "ASSESSMENT:\n"
            "  - Gap analysis against Annex A\n"
            "  - Risk treatment plan\n"
            "  - Statement of Applicability\n"
            "  - Technical control testing\n"
            "TOOLS:\n"
            "  OpenSCAP, Lynis, CIS Benchmark tools"
        ),
        "tools": ["openscap", "lynis"],
    },
    {
        "id": "comp-005", "name": "NIST CSF",
        "category": "nist", "severity": "medium",
        "desc": "NIST Cybersecurity Framework assessment.",
        "detection": (
            "NIST CYBERSECURITY FRAMEWORK:\n"
            "FUNCTIONS:\n"
            "  IDENTIFY (ID):\n"
            "    - Asset management (ID.AM)\n"
            "    - Business environment (ID.BE)\n"
            "    - Governance (ID.GV)\n"
            "    - Risk assessment (ID.RA)\n"
            "    - Risk management strategy (ID.RM)\n"
            "    - Supply chain risk (ID.SC)\n"
            "  PROTECT (PR):\n"
            "    - Access control (PR.AC)\n"
            "    - Awareness training (PR.AT)\n"
            "    - Data security (PR.DS)\n"
            "    - Information protection (PR.IP)\n"
            "    - Maintenance (PR.MA)\n"
            "    - Protective technology (PR.PT)\n"
            "  DETECT (DE):\n"
            "    - Anomalies and events (DE.AE)\n"
            "    - Continuous monitoring (DE.CM)\n"
            "    - Detection processes (DE.DP)\n"
            "  RESPOND (RS):\n"
            "    - Response planning (RS.RP)\n"
            "    - Communications (RS.CO)\n"
            "    - Analysis (RS.AN)\n"
            "    - Mitigation (RS.MI)\n"
            "    - Improvements (RS.IM)\n"
            "  RECOVER (RC):\n"
            "    - Recovery planning (RC.RP)\n"
            "    - Improvements (RC.IM)\n"
            "    - Communications (RC.CO)\n"
            "MATURITY:\n"
            "  Tier 1: Partial\n"
            "  Tier 2: Risk Informed\n"
            "  Tier 3: Repeatable\n"
            "  Tier 4: Adaptive\n"
            "TOOLS:\n"
            "  NIST CSF Assessment Tools, OpenSCAP"
        ),
        "tools": ["openscap"],
    },
]


class ComplianceKB:
    """Compliance knowledge base.

    Provides compliance patterns
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
                category=data.get("category", ""),
                severity=data.get("severity", "medium"),
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
        lines = ["## Compliance & Audit\n"]
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
