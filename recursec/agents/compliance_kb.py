"""Compliance and regulatory knowledge base.

Deep knowledge about security compliance frameworks:
1. PCI DSS compliance testing
2. HIPAA security assessment
3. SOC 2 controls
4. GDPR technical requirements
5. NIST CSF mapping
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
        "id": "comp-001", "name": "PCI DSS Testing",
        "category": "pci", "severity": "high",
        "desc": "PCI DSS compliance security testing.",
        "detection": (
            "PCI DSS COMPLIANCE TESTING:\n"
            "REQUIREMENT 1: Network Security Controls\n"
            "  - Firewall rules review\n"
            "  - Network segmentation testing\n"
            "  - CDE boundary verification\n"
            "  - DMZ configuration check\n"
            "REQUIREMENT 2: Secure Configurations\n"
            "  - Default credential check\n"
            "  - Unnecessary service removal\n"
            "  - Encryption standards (TLS 1.2+)\n"
            "  - System hardening benchmarks (CIS)\n"
            "REQUIREMENT 3: Stored Account Data\n"
            "  - PAN storage discovery\n"
            "  - Encryption verification (AES-256)\n"
            "  - Key management review\n"
            "  - Data retention policies\n"
            "REQUIREMENT 6: Secure Software\n"
            "  - OWASP Top 10 testing\n"
            "  - Secure SDLC review\n"
            "  - Public-facing web app scanning\n"
            "  - WAF deployment check\n"
            "REQUIREMENT 11: Regular Testing\n"
            "  - Quarterly ASV scans\n"
            "  - Annual penetration testing\n"
            "  - Internal vulnerability scans\n"
            "  - Wireless scanning\n"
            "  - IDS/IPS monitoring\n"
            "  - File integrity monitoring\n"
            "TOOLS:\n"
            "  Nessus, Qualys, nmap, nuclei"
        ),
        "tools": ["nessus", "qualys"],
    },
    {
        "id": "comp-002", "name": "HIPAA Security",
        "category": "hipaa", "severity": "high",
        "desc": "HIPAA security assessment.",
        "detection": (
            "HIPAA SECURITY ASSESSMENT:\n"
            "ADMINISTRATIVE (§164.308):\n"
            "  - Risk analysis conducted\n"
            "  - Risk management plan\n"
            "  - Workforce training\n"
            "  - Information access management\n"
            "  - Security incident procedures\n"
            "PHYSICAL (§164.310):\n"
            "  - Facility access controls\n"
            "  - Workstation security\n"
            "  - Device and media controls\n"
            "  - Disposal procedures\n"
            "TECHNICAL (§164.312):\n"
            "  - Access control (unique user ID, auto-logoff)\n"
            "  - Audit controls (logging, monitoring)\n"
            "  - Integrity controls (hashing, checksums)\n"
            "  - Transmission security (encryption in transit)\n"
            "  - Authentication mechanisms\n"
            "PHI DATA:\n"
            "  - PHI at rest encryption\n"
            "  - PHI in transit encryption (TLS 1.2+)\n"
            "  - Access logging for PHI access\n"
            "  - Minimum necessary principle\n"
            "  - Business associate agreements\n"
            "TESTING:\n"
            "  - Network segmentation of PHI systems\n"
            "  - PHI data discovery (DLP scanning)\n"
            "  - Access control testing\n"
            "  - Encryption verification"
        ),
        "tools": [],
    },
    {
        "id": "comp-003", "name": "SOC 2 Controls",
        "category": "soc2", "severity": "medium",
        "desc": "SOC 2 Trust Services Criteria.",
        "detection": (
            "SOC 2 CONTROLS:\n"
            "SECURITY (CC):\n"
            "  CC6.1: Access controls (RBAC, MFA)\n"
            "  CC6.2: Authentication mechanisms\n"
            "  CC6.3: Authorization management\n"
            "  CC6.6: External threat protection\n"
            "  CC6.7: Network security monitoring\n"
            "  CC6.8: Unauthorized access prevention\n"
            "AVAILABILITY (A):\n"
            "  A1.1: Capacity planning\n"
            "  A1.2: Environmental safeguards\n"
            "  A1.3: Recovery procedures\n"
            "CONFIDENTIALITY (C):\n"
            "  C1.1: Data classification\n"
            "  C1.2: Confidential data protection\n"
            "PROCESSING INTEGRITY (PI):\n"
            "  PI1.1: Processing accuracy\n"
            "  PI1.2: Input/output validation\n"
            "TESTING:\n"
            "  - Evidence collection automation\n"
            "  - Control effectiveness testing\n"
            "  - Gap analysis against criteria\n"
            "  - Continuous monitoring setup\n"
            "  - Policy and procedure review\n"
            "TOOLS:\n"
            "  Vanta, Drata, Secureframe (compliance automation)"
        ),
        "tools": [],
    },
    {
        "id": "comp-004", "name": "GDPR Technical",
        "category": "gdpr", "severity": "high",
        "desc": "GDPR technical security requirements.",
        "detection": (
            "GDPR TECHNICAL REQUIREMENTS:\n"
            "ARTICLE 32 (Security of Processing):\n"
            "  - Encryption of personal data\n"
            "  - Confidentiality, integrity, availability\n"
            "  - Resilience of processing systems\n"
            "  - Ability to restore data\n"
            "  - Regular testing of security\n"
            "DATA PROTECTION:\n"
            "  - Data at rest encryption (AES-256)\n"
            "  - Data in transit encryption (TLS 1.2+)\n"
            "  - Pseudonymization/anonymization\n"
            "  - Data minimization\n"
            "  - Storage limitation\n"
            "ACCESS CONTROL:\n"
            "  - Role-based access (RBAC)\n"
            "  - Multi-factor authentication\n"
            "  - Privileged access management\n"
            "  - Access reviews\n"
            "BREACH NOTIFICATION (Art. 33/34):\n"
            "  - 72-hour notification to authority\n"
            "  - Breach detection capabilities\n"
            "  - Incident response procedures\n"
            "  - Data subject notification\n"
            "DATA SUBJECT RIGHTS:\n"
            "  - Right to access (Art. 15)\n"
            "  - Right to erasure (Art. 17)\n"
            "  - Data portability (Art. 20)\n"
            "  - Technical implementation of rights"
        ),
        "tools": [],
    },
    {
        "id": "comp-005", "name": "NIST CSF Mapping",
        "category": "nist", "severity": "medium",
        "desc": "NIST Cybersecurity Framework mapping.",
        "detection": (
            "NIST CSF MAPPING:\n"
            "IDENTIFY (ID):\n"
            "  ID.AM: Asset management\n"
            "  ID.BE: Business environment\n"
            "  ID.GV: Governance\n"
            "  ID.RA: Risk assessment\n"
            "  ID.RM: Risk management strategy\n"
            "PROTECT (PR):\n"
            "  PR.AC: Access control\n"
            "  PR.AT: Awareness training\n"
            "  PR.DS: Data security\n"
            "  PR.IP: Information protection\n"
            "  PR.MA: Maintenance\n"
            "  PR.PT: Protective technology\n"
            "DETECT (DE):\n"
            "  DE.AE: Anomalies and events\n"
            "  DE.CM: Continuous monitoring\n"
            "  DE.DP: Detection processes\n"
            "RESPOND (RS):\n"
            "  RS.RP: Response planning\n"
            "  RS.CO: Communications\n"
            "  RS.AN: Analysis\n"
            "  RS.MI: Mitigation\n"
            "  RS.IM: Improvements\n"
            "RECOVER (RC):\n"
            "  RC.RP: Recovery planning\n"
            "  RC.IM: Improvements\n"
            "  RC.CO: Communications\n"
            "TESTING:\n"
            "  - Map existing controls to CSF\n"
            "  - Identify gaps per function\n"
            "  - Prioritize by risk/impact\n"
            "  - Implement maturity levels (1-4)"
        ),
        "tools": [],
    },
]


class ComplianceKB:
    """Compliance knowledge base.

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
        lines = ["## Compliance Frameworks\n"]
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
