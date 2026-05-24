"""Insider threat knowledge base.

Deep knowledge about insider threats:
1. Insider threat detection
2. Data exfiltration techniques
3. Privilege abuse patterns
4. Social engineering from inside
5. Insider threat indicators
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class InsiderThreatPattern:
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
        "id": "ins-001", "name": "Insider Threat Detection",
        "category": "detection", "severity": "high",
        "desc": "Detecting insider threats.",
        "detection": (
            "INSIDER THREAT DETECTION:\n"
            "BEHAVIORAL INDICATORS:\n"
            "  - Unusual access patterns\n"
            "    # Access outside normal hours\n"
            "    # Accessing resources not needed for role\n"
            "    # Large data downloads\n"
            "    # Bulk file operations\n"
            "  - Authentication anomalies\n"
            "    # Failed login spikes\n"
            "    # Login from unusual locations\n"
            "    # Simultaneous sessions\n"
            "    # Credential sharing indicators\n"
            "  - Communication changes\n"
            "    # External email volume increase\n"
            "    # Use of personal email for work\n"
            "    # Encrypted file transfers\n"
            "    # USB device usage\n"
            "TECHNICAL INDICATORS:\n"
            "  - Privilege escalation attempts\n"
            "  - Security tool tampering\n"
            "  - Log deletion or modification\n"
            "  - Network scanning from internal\n"
            "  - Unauthorized software installation\n"
            "  - Database query volume changes\n"
            "  - Cloud storage uploads\n"
            "MONITORING:\n"
            "  - UEBA (User Entity Behavior Analytics)\n"
            "  - DLP (Data Loss Prevention)\n"
            "  - SIEM correlation rules\n"
            "  - Endpoint detection\n"
            "TOOLS:\n"
            "  Splunk UBA, Exabeam, Varonis, CrowdStrike"
        ),
        "tools": [],
    },
    {
        "id": "ins-002", "name": "Data Exfiltration Techniques",
        "category": "exfiltration", "severity": "critical",
        "desc": "How insiders exfiltrate data.",
        "detection": (
            "DATA EXFILTRATION:\n"
            "NETWORK:\n"
            "  - DNS tunneling\n"
            "    # Encode data in DNS queries\n"
            "    # iodine, dnscat2\n"
            "  - HTTPS exfiltration\n"
            "    # Blend with normal traffic\n"
            "    # Encrypted payloads\n"
            "  - Cloud storage upload\n"
            "    # Personal Dropbox, Google Drive\n"
            "    # Shadow IT detection\n"
            "  - Email attachments\n"
            "    # Personal email\n"
            "    # Encoded/encrypted attachments\n"
            "  - Steganography\n"
            "    # Hide data in images\n"
            "    # OpenStego, Steghide\n"
            "PHYSICAL:\n"
            "  - USB/external drives\n"
            "    # Rubber ducky devices\n"
            "    # Modified cables (OMG Cable)\n"
            "  - Mobile phone camera\n"
            "  - Printed documents\n"
            "  - Bluetooth transfer\n"
            "COVERT CHANNELS:\n"
            "  - ICMP tunneling\n"
            "  - HTTP header hiding\n"
            "  - Timing-based channels\n"
            "  - Protocol abuse\n"
            "DETECTION:\n"
            "  - DLP monitoring\n"
            "  - Network anomaly detection\n"
            "  - Endpoint monitoring\n"
            "  - USB device control\n"
            "TOOLS:\n"
            "  DLP solutions, NetFlow analysis, Wireshark"
        ),
        "tools": [],
    },
    {
        "id": "ins-003", "name": "Privilege Abuse Patterns",
        "category": "privilege_abuse", "severity": "high",
        "desc": "How insiders abuse privileges.",
        "detection": (
            "PRIVILEGE ABUSE:\n"
            "ADMIN ABUSE:\n"
            "  - Creating backdoor accounts\n"
            "  - Modifying security controls\n"
            "  - Disabling logging/monitoring\n"
            "  - Installing rootkits\n"
            "  - Modifying firewall rules\n"
            "  - Accessing other users' data\n"
            "DATABASE:\n"
            "  - Direct database queries\n"
            "    # Bypassing application layer\n"
            "  - Schema modification\n"
            "  - Data tampering\n"
            "  - Export/dump operations\n"
            "  - Privilege grants to other accounts\n"
            "CLOUD:\n"
            "  - IAM policy modifications\n"
            "  - Resource sharing changes\n"
            "  - Storage bucket permissions\n"
            "  - Service account key creation\n"
            "  - Cross-account access setup\n"
            "APPLICATION:\n"
            "  - Bypassing approval workflows\n"
            "  - Manipulating business logic\n"
            "  - Creating test/debug modes\n"
            "  - API key creation\n"
            "DETECTION:\n"
            "  - Least privilege auditing\n"
            "  - Privileged access monitoring\n"
            "  - Change management verification\n"
            "  - Segregation of duties checks\n"
            "TOOLS:\n"
            "  PAM solutions, SIEM, IAM auditing"
        ),
        "tools": [],
    },
    {
        "id": "ins-004", "name": "Social Engineering from Inside",
        "category": "social_internal", "severity": "medium",
        "desc": "Internal social engineering.",
        "detection": (
            "INTERNAL SOCIAL ENGINEERING:\n"
            "TECHNIQUES:\n"
            "  - Pretexting as IT support\n"
            "    # Calling employees for passwords\n"
            "    # Fake help desk tickets\n"
            "  - Impersonation\n"
            "    # Posing as management\n"
            "    # Using authority pressure\n"
            "  - Tailgating/Piggybacking\n"
            "    # Following authorized person\n"
            "    # Propping doors open\n"
            "  - Shoulder surfing\n"
            "    # Observing passwords/PINs\n"
            "    # Screen recording\n"
            "  - Dumpster diving\n"
            "    # Paper documents\n"
            "    # Disposed hardware\n"
            "CREDENTIAL HARVESTING:\n"
            "  - Internal phishing\n"
            "    # Fake internal portals\n"
            "    # Credential capture pages\n"
            "  - Shared credential discovery\n"
            "    # Post-it notes\n"
            "    # Shared spreadsheets\n"
            "    # Internal wikis\n"
            "  - Session hijacking\n"
            "    # Shared workstations\n"
            "    # Session tokens\n"
            "PHYSICAL:\n"
            "  - Badge cloning (RFID)\n"
            "  - Lock picking\n"
            "  - Unauthorized area access\n"
            "TOOLS:\n"
            "  KnowBe4 (training), GoPhish (testing)"
        ),
        "tools": [],
    },
    {
        "id": "ins-005", "name": "Insider Threat Indicators",
        "category": "indicators", "severity": "medium",
        "desc": "Warning signs of insider threats.",
        "detection": (
            "INSIDER THREAT INDICATORS:\n"
            "HR INDICATORS:\n"
            "  - Notice period / resignation\n"
            "  - Performance issues\n"
            "  - Disciplinary actions\n"
            "  - Passed over for promotion\n"
            "  - Organizational changes\n"
            "  - Financial stress indicators\n"
            "  - Unusual travel patterns\n"
            "DIGITAL INDICATORS:\n"
            "  - Accessing files outside scope\n"
            "  - Large data transfers\n"
            "  - Working unusual hours\n"
            "  - Using unauthorized tools\n"
            "  - Disabling security software\n"
            "  - Searching for sensitive keywords\n"
            "  - Multiple login failures\n"
            "  - VPN from unusual locations\n"
            "RISK SCORING:\n"
            "  - Combine HR + digital indicators\n"
            "  - Weighted risk score per user\n"
            "  - Threshold-based alerting\n"
            "  - Peer group comparison\n"
            "  - Historical baseline deviation\n"
            "PROGRAM:\n"
            "  - Insider threat program (ITP)\n"
            "  - Cross-functional team (HR+IT+Legal)\n"
            "  - Clear policies and consequences\n"
            "  - Anonymous reporting mechanism\n"
            "  - Regular security awareness training\n"
            "TOOLS:\n"
            "  UEBA platforms, DLP, SIEM, HR systems"
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
        self._patterns: dict[str, InsiderThreatPattern] = {}
        self._log = logger.bind(component="insider_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load insider threat patterns."""
        for data in INSIDER_PATTERNS:
            pattern = InsiderThreatPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[InsiderThreatPattern]:
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
