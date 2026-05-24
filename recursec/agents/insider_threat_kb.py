"""Insider threat knowledge base.

Deep knowledge about insider threats:
1. Insider threat indicators
2. Data loss prevention strategies
3. Privileged access abuse
4. Behavioral analytics
5. Insider threat response
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class InsiderPattern:
    """An insider threat pattern."""
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


INSIDER_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ins-001", "name": "Insider Threat Indicators",
        "category": "indicators", "severity": "high",
        "desc": "Insider threat detection indicators.",
        "detection": (
            "INSIDER THREAT INDICATORS:\n"
            "DIGITAL:\n"
            "  - Unusual data access patterns\n"
            "  - Large file downloads/copies\n"
            "  - Access outside normal hours\n"
            "  - Accessing data outside job scope\n"
            "  - USB device usage anomalies\n"
            "  - Excessive printing\n"
            "  - Personal email/cloud usage\n"
            "  - Network traffic to unusual destinations\n"
            "  - Privilege escalation attempts\n"
            "  - Account sharing indicators\n"
            "  - VPN from unusual locations\n"
            "  - Database query anomalies\n"
            "BEHAVIORAL:\n"
            "  - Sudden interest in other departments\n"
            "  - Accessing old/archived data\n"
            "  - Late night/weekend access spikes\n"
            "  - Data staging before departure\n"
            "  - Copying competitor information\n"
            "  - Bypassing security controls\n"
            "RISK FACTORS:\n"
            "  - Notice of resignation\n"
            "  - Performance issues\n"
            "  - Organizational changes\n"
            "  - Financial stress\n"
            "  - Passed over for promotion\n"
            "MONITORING:\n"
            "  - UEBA (User Entity Behavior Analytics)\n"
            "  - SIEM correlation rules\n"
            "  - DLP alerts\n"
            "  - IAM audit logs\n"
            "TOOLS:\n"
            "  UEBA (Exabeam, Securonix), SIEM, DLP"
        ),
        "tools": [],
    },
    {
        "id": "ins-002", "name": "Data Loss Prevention",
        "category": "dlp", "severity": "high",
        "desc": "Data loss prevention strategies.",
        "detection": (
            "DATA LOSS PREVENTION:\n"
            "CLASSIFICATION:\n"
            "  - Data discovery and inventory\n"
            "  - Sensitivity labeling\n"
            "  - PII/PHI/PCI detection\n"
            "  - IP/trade secret marking\n"
            "  - Automated classification (ML)\n"
            "ENDPOINT DLP:\n"
            "  - USB/removable media control\n"
            "  - Print monitoring\n"
            "  - Screen capture detection\n"
            "  - Clipboard monitoring\n"
            "  - Application whitelisting\n"
            "NETWORK DLP:\n"
            "  - Email inspection (attachments)\n"
            "  - Web upload monitoring\n"
            "  - Cloud storage controls\n"
            "  - Encrypted traffic inspection\n"
            "  - Protocol-level inspection\n"
            "CLOUD DLP:\n"
            "  - CASB (Cloud Access Security Broker)\n"
            "  - SaaS app monitoring\n"
            "  - Shadow IT detection\n"
            "  - OAuth token monitoring\n"
            "  - File sharing controls\n"
            "TESTING:\n"
            "  - Attempt USB copy of test data\n"
            "  - Email sensitive test documents\n"
            "  - Upload to personal cloud storage\n"
            "  - Print sensitive documents\n"
            "  - Test exfiltration channels\n"
            "TOOLS:\n"
            "  Symantec DLP, Microsoft Purview, CASB"
        ),
        "tools": [],
    },
    {
        "id": "ins-003", "name": "Privileged Access Abuse",
        "category": "priv_abuse", "severity": "critical",
        "desc": "Privileged access abuse detection.",
        "detection": (
            "PRIVILEGED ACCESS ABUSE:\n"
            "DATABASE ADMIN:\n"
            "  - Direct data access/export\n"
            "  - Query pattern anomalies\n"
            "  - Schema/permission changes\n"
            "  - Backup to unauthorized location\n"
            "  - Audit trail modification\n"
            "SYSTEM ADMIN:\n"
            "  - Service account creation\n"
            "  - Backdoor account creation\n"
            "  - Group policy modification\n"
            "  - Security tool disabling\n"
            "  - Log tampering\n"
            "  - Unauthorized software install\n"
            "DEVELOPER:\n"
            "  - Source code exfiltration\n"
            "  - Backdoor in application code\n"
            "  - CI/CD pipeline manipulation\n"
            "  - Secrets extraction from repos\n"
            "  - Unauthorized production access\n"
            "CLOUD ADMIN:\n"
            "  - IAM policy modifications\n"
            "  - Resource sharing external\n"
            "  - Storage bucket exposure\n"
            "  - Encryption key management\n"
            "  - Billing/cost manipulation\n"
            "MONITORING:\n"
            "  - PAM (Privileged Access Management)\n"
            "  - Session recording\n"
            "  - Command logging\n"
            "  - Change management correlation\n"
            "  - Least privilege auditing\n"
            "TOOLS:\n"
            "  CyberArk, BeyondTrust, HashiCorp Vault"
        ),
        "tools": [],
    },
    {
        "id": "ins-004", "name": "Behavioral Analytics",
        "category": "analytics", "severity": "medium",
        "desc": "User behavior analytics for insider detection.",
        "detection": (
            "BEHAVIORAL ANALYTICS:\n"
            "BASELINE:\n"
            "  - Normal working hours\n"
            "  - Typical data access volume\n"
            "  - Common access patterns\n"
            "  - Network traffic profiles\n"
            "  - Application usage patterns\n"
            "  - Peer group comparison\n"
            "ANOMALIES:\n"
            "  - Access time deviation (>2 std dev)\n"
            "  - Volume spike (>3x baseline)\n"
            "  - New resource access\n"
            "  - Geographic anomaly\n"
            "  - Device anomaly\n"
            "  - Velocity anomaly (impossible travel)\n"
            "RISK SCORING:\n"
            "  - Composite risk score per user\n"
            "  - Weight: severity × frequency × deviation\n"
            "  - Decay: recent events weighted higher\n"
            "  - Threshold alerts (high/critical)\n"
            "  - Peer comparison scoring\n"
            "ML MODELS:\n"
            "  - Isolation forest (anomaly detection)\n"
            "  - LSTM (sequence prediction)\n"
            "  - Autoencoder (reconstruction error)\n"
            "  - Graph neural network (relationship)\n"
            "  - Clustering (group behavior)\n"
            "CORRELATION:\n"
            "  - HR events + digital activity\n"
            "  - Travel + VPN access\n"
            "  - Project assignment + data access\n"
            "  - Badge swipe + login location\n"
            "TOOLS:\n"
            "  Exabeam, Securonix, Microsoft Sentinel"
        ),
        "tools": [],
    },
    {
        "id": "ins-005", "name": "Insider Threat Response",
        "category": "response", "severity": "high",
        "desc": "Insider threat incident response.",
        "detection": (
            "INSIDER THREAT RESPONSE:\n"
            "INVESTIGATION:\n"
            "  - Preserve evidence (forensic imaging)\n"
            "  - Timeline reconstruction\n"
            "  - Access log analysis\n"
            "  - Email/communication review\n"
            "  - Data flow mapping\n"
            "  - Interview planning\n"
            "CONTAINMENT:\n"
            "  - Account suspension/restriction\n"
            "  - Access privilege reduction\n"
            "  - Network segment isolation\n"
            "  - Device confiscation\n"
            "  - Enhanced monitoring\n"
            "  - Legal hold on data\n"
            "ERADICATION:\n"
            "  - Backdoor removal\n"
            "  - Credential rotation\n"
            "  - Policy updates\n"
            "  - Access review\n"
            "  - Third-party audit\n"
            "RECOVERY:\n"
            "  - Data integrity verification\n"
            "  - System restore from known-good\n"
            "  - Enhanced monitoring period\n"
            "  - Policy enforcement review\n"
            "LEGAL:\n"
            "  - Chain of custody for evidence\n"
            "  - Legal counsel coordination\n"
            "  - HR involvement\n"
            "  - Law enforcement (if warranted)\n"
            "  - Regulatory notification\n"
            "TOOLS:\n"
            "  Forensic suites, SIEM, legal toolkit"
        ),
        "tools": [],
    },
]


class InsiderThreatKB:
    """Insider threat knowledge base.

    Provides insider threat patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, InsiderPattern] = {}
        self._log = logger.bind(component="insider_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load insider threat patterns."""
        for data in INSIDER_PATTERNS:
            pattern = InsiderPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[InsiderPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_insider_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build insider threat prompt."""
        lines = ["## Insider Threats\n"]
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
