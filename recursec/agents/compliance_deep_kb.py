"""Compliance frameworks knowledge base.

Deep knowledge about compliance:
1. PCI DSS assessment
2. SOC 2 controls
3. ISO 27001 audit
4. HIPAA security
5. NIST CSF assessment
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CompliancePattern:
    """A compliance assessment pattern."""
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
        "id": "comp-001", "name": "PCI DSS Assessment",
        "category": "pci", "severity": "high",
        "desc": "PCI DSS compliance assessment.",
        "detection": (
            "PCI DSS ASSESSMENT:\n"
            "REQUIREMENTS:\n"
            "  Req 1: Network segmentation / firewalls\n"
            "    # Verify CDE boundaries\n"
            "    # Test firewall rules\n"
            "    # Network segmentation testing\n"
            "  Req 2: Secure configurations\n"
            "    # Default credentials check\n"
            "    # Unnecessary services\n"
            "    # CIS benchmarks\n"
            "  Req 3: Protect stored cardholder data\n"
            "    # PAN discovery scans\n"
            "    # Encryption verification\n"
            "    # Key management audit\n"
            "  Req 4: Encrypt transmission\n"
            "    # TLS configuration\n"
            "    # Certificate validation\n"
            "    # Cipher suite analysis\n"
            "  Req 5: Anti-malware\n"
            "  Req 6: Secure development\n"
            "    # Code review\n"
            "    # OWASP Top 10 testing\n"
            "    # WAF deployment\n"
            "  Req 7-8: Access control / authentication\n"
            "    # MFA verification\n"
            "    # Privilege review\n"
            "    # Password policy\n"
            "  Req 9: Physical security\n"
            "  Req 10: Logging and monitoring\n"
            "    # Log review\n"
            "    # SIEM verification\n"
            "  Req 11: Regular testing\n"
            "    # Quarterly ASV scans\n"
            "    # Annual penetration test\n"
            "  Req 12: Security policies\n"
            "TOOLS:\n"
            "  Qualys, Nessus, testssl.sh, ScoutSuite"
        ),
        "tools": [],
    },
    {
        "id": "comp-002", "name": "SOC 2 Controls",
        "category": "soc2", "severity": "medium",
        "desc": "SOC 2 trust service criteria.",
        "detection": (
            "SOC 2 CONTROLS:\n"
            "TRUST SERVICE CRITERIA:\n"
            "  Security (Common Criteria CC):\n"
            "    CC1: Control environment\n"
            "    CC2: Communication and information\n"
            "    CC3: Risk assessment\n"
            "    CC4: Monitoring activities\n"
            "    CC5: Control activities\n"
            "    CC6: Logical and physical access\n"
            "    CC7: System operations\n"
            "    CC8: Change management\n"
            "    CC9: Risk mitigation\n"
            "  Availability:\n"
            "    A1: Infrastructure, software, procedures\n"
            "    A2: Environmental protections\n"
            "  Confidentiality:\n"
            "    C1: Identification and protection\n"
            "    C2: Disposal\n"
            "  Processing Integrity:\n"
            "    PI1: Completeness, accuracy, timeliness\n"
            "  Privacy:\n"
            "    P1-P8: Notice, choice, collection, use\n"
            "TESTING:\n"
            "  - Access control review\n"
            "  - Change management verification\n"
            "  - Encryption assessment\n"
            "  - Logging/monitoring review\n"
            "  - Incident response plan test\n"
            "  - Vendor management audit\n"
            "TOOLS:\n"
            "  Vanta, Drata, ScoutSuite, Prowler"
        ),
        "tools": [],
    },
    {
        "id": "comp-003", "name": "ISO 27001 Audit",
        "category": "iso27001", "severity": "medium",
        "desc": "ISO 27001 information security audit.",
        "detection": (
            "ISO 27001 AUDIT:\n"
            "ANNEX A CONTROLS:\n"
            "  A.5: Information security policies\n"
            "  A.6: Organization of information security\n"
            "  A.7: Human resource security\n"
            "  A.8: Asset management\n"
            "    # Asset inventory\n"
            "    # Classification\n"
            "    # Media handling\n"
            "  A.9: Access control\n"
            "    # Access policy\n"
            "    # User registration\n"
            "    # Privilege management\n"
            "    # MFA review\n"
            "  A.10: Cryptography\n"
            "    # Encryption policy\n"
            "    # Key management\n"
            "  A.11: Physical security\n"
            "  A.12: Operations security\n"
            "    # Change management\n"
            "    # Capacity management\n"
            "    # Malware protection\n"
            "    # Backup verification\n"
            "    # Logging/monitoring\n"
            "  A.13: Communications security\n"
            "    # Network controls\n"
            "    # Segmentation\n"
            "  A.14: System development\n"
            "    # Secure development lifecycle\n"
            "    # Test data protection\n"
            "  A.15: Supplier relationships\n"
            "  A.16: Incident management\n"
            "  A.17: Business continuity\n"
            "  A.18: Compliance\n"
            "TOOLS:\n"
            "  ScoutSuite, Prowler, custom checklists"
        ),
        "tools": [],
    },
    {
        "id": "comp-004", "name": "HIPAA Security",
        "category": "hipaa", "severity": "high",
        "desc": "HIPAA security rule assessment.",
        "detection": (
            "HIPAA SECURITY:\n"
            "ADMINISTRATIVE SAFEGUARDS:\n"
            "  §164.308:\n"
            "  - Risk analysis (required)\n"
            "  - Risk management (required)\n"
            "  - Sanction policy (required)\n"
            "  - Information system activity review\n"
            "  - Workforce security\n"
            "  - Security awareness training\n"
            "  - Incident response (required)\n"
            "  - Contingency plan (required)\n"
            "  - Evaluation (required)\n"
            "  - BAA with business associates\n"
            "PHYSICAL SAFEGUARDS:\n"
            "  §164.310:\n"
            "  - Facility access controls\n"
            "  - Workstation security\n"
            "  - Device/media controls\n"
            "TECHNICAL SAFEGUARDS:\n"
            "  §164.312:\n"
            "  - Access control\n"
            "    # Unique user identification\n"
            "    # Emergency access procedure\n"
            "    # Automatic logoff\n"
            "    # Encryption and decryption\n"
            "  - Audit controls\n"
            "    # Activity logging\n"
            "    # Log review\n"
            "  - Integrity controls\n"
            "    # PHI integrity mechanisms\n"
            "  - Transmission security\n"
            "    # Encryption in transit\n"
            "    # Integrity controls\n"
            "  - Authentication\n"
            "TOOLS:\n"
            "  Nessus, ScoutSuite, custom scripts"
        ),
        "tools": [],
    },
    {
        "id": "comp-005", "name": "NIST CSF Assessment",
        "category": "nist", "severity": "medium",
        "desc": "NIST Cybersecurity Framework assessment.",
        "detection": (
            "NIST CSF ASSESSMENT:\n"
            "IDENTIFY:\n"
            "  ID.AM: Asset management\n"
            "  ID.BE: Business environment\n"
            "  ID.GV: Governance\n"
            "  ID.RA: Risk assessment\n"
            "  ID.RM: Risk management strategy\n"
            "  ID.SC: Supply chain management\n"
            "PROTECT:\n"
            "  PR.AC: Access control\n"
            "  PR.AT: Awareness and training\n"
            "  PR.DS: Data security\n"
            "  PR.IP: Protective processes\n"
            "  PR.MA: Maintenance\n"
            "  PR.PT: Protective technology\n"
            "DETECT:\n"
            "  DE.AE: Anomalies and events\n"
            "  DE.CM: Security monitoring\n"
            "  DE.DP: Detection processes\n"
            "RESPOND:\n"
            "  RS.RP: Response planning\n"
            "  RS.CO: Communications\n"
            "  RS.AN: Analysis\n"
            "  RS.MI: Mitigation\n"
            "  RS.IM: Improvements\n"
            "RECOVER:\n"
            "  RC.RP: Recovery planning\n"
            "  RC.IM: Improvements\n"
            "  RC.CO: Communications\n"
            "MAPPING:\n"
            "  - NIST CSF → CIS Controls\n"
            "  - NIST CSF → ISO 27001\n"
            "  - NIST CSF → PCI DSS\n"
            "  - Implementation tiers (1-4)\n"
            "TOOLS:\n"
            "  NIST CSF tool, Prowler, ScoutSuite"
        ),
        "tools": [],
    },
]


class ComplianceDeepKB:
    """Compliance frameworks knowledge base.

    Provides compliance assessment patterns
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
