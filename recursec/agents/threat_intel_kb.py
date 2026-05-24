"""Threat intelligence knowledge base.

Deep knowledge about threat intelligence:
1. CTI collection and analysis
2. IOC management and enrichment
3. Threat actor profiling
4. Threat landscape monitoring
5. Intelligence-driven defense
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ThreatIntelPattern:
    """A threat intelligence pattern."""
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


THREATINTEL_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ti-001", "name": "CTI Collection",
        "category": "collection", "severity": "medium",
        "desc": "Cyber threat intelligence collection.",
        "detection": (
            "CTI COLLECTION:\n"
            "OSINT SOURCES:\n"
            "  - VirusTotal (file/URL/IP analysis)\n"
            "  - Shodan (internet-facing devices)\n"
            "  - Censys (internet scan data)\n"
            "  - GreyNoise (internet noise vs targeted)\n"
            "  - AlienVault OTX (threat indicators)\n"
            "  - MISP (threat sharing platform)\n"
            "  - Abuse.ch (malware/botnet tracking)\n"
            "  - URLhaus, MalwareBazaar, ThreatFox\n"
            "COMMERCIAL:\n"
            "  - Recorded Future\n"
            "  - Mandiant Advantage\n"
            "  - CrowdStrike Intel\n"
            "  - Intel 471\n"
            "DARK WEB:\n"
            "  - Forum monitoring\n"
            "  - Marketplace tracking\n"
            "  - Paste site monitoring\n"
            "  - Ransomware leak sites\n"
            "  - Credential dump monitoring\n"
            "FEEDS:\n"
            "  - STIX/TAXII feeds\n"
            "  - ISAC/ISAO sharing\n"
            "  - Government advisories\n"
            "  - Vendor security bulletins\n"
            "  - CVE/NVD monitoring\n"
            "TOOLS:\n"
            "  MISP, OpenCTI, TheHive, Cortex"
        ),
        "tools": [],
    },
    {
        "id": "ti-002", "name": "IOC Management",
        "category": "ioc", "severity": "medium",
        "desc": "Indicator of Compromise management.",
        "detection": (
            "IOC MANAGEMENT:\n"
            "IOC TYPES:\n"
            "  - IP addresses (C2, scanning)\n"
            "  - Domains (phishing, C2)\n"
            "  - URLs (malware delivery)\n"
            "  - File hashes (MD5, SHA256)\n"
            "  - Email addresses/subjects\n"
            "  - YARA rules (file patterns)\n"
            "  - Sigma rules (log patterns)\n"
            "  - Suricata rules (network)\n"
            "ENRICHMENT:\n"
            "  - Whois lookup\n"
            "  - Passive DNS\n"
            "  - Geolocation\n"
            "  - Reputation scoring\n"
            "  - Malware family classification\n"
            "  - MITRE ATT&CK mapping\n"
            "  - Related indicators\n"
            "LIFECYCLE:\n"
            "  1. Collection → raw indicators\n"
            "  2. Processing → normalize, deduplicate\n"
            "  3. Analysis → context, attribution\n"
            "  4. Dissemination → distribute to tools\n"
            "  5. Feedback → update confidence\n"
            "AUTOMATION:\n"
            "  - SOAR playbooks for IOC ingestion\n"
            "  - Auto-block on SIEM/firewall\n"
            "  - Threat hunting queries\n"
            "  - Alert enrichment\n"
            "TOOLS:\n"
            "  MISP, OpenCTI, TheHive, Cortex, YARA"
        ),
        "tools": [],
    },
    {
        "id": "ti-003", "name": "Threat Actor Profiling",
        "category": "actor", "severity": "high",
        "desc": "Threat actor profiling and attribution.",
        "detection": (
            "THREAT ACTOR PROFILING:\n"
            "ATTRIBUTION:\n"
            "  - TTPs (Tactics, Techniques, Procedures)\n"
            "  - Infrastructure patterns\n"
            "  - Malware families\n"
            "  - Victimology (target selection)\n"
            "  - Operating hours (timezone)\n"
            "  - Language artifacts\n"
            "  - Code reuse and shared tools\n"
            "MAJOR GROUPS:\n"
            "  STATE-SPONSORED:\n"
            "    - Russia: APT28, APT29, Sandworm\n"
            "    - China: APT1, APT41, Hafnium\n"
            "    - Iran: APT33, APT35, MuddyWater\n"
            "    - NK: Lazarus, Kimsuky, APT38\n"
            "  CYBERCRIME:\n"
            "    - FIN7, FIN11, Carbanak\n"
            "    - REvil, LockBit, BlackCat\n"
            "    - Wizard Spider (Conti/Ryuk)\n"
            "  HACKTIVISM:\n"
            "    - Anonymous\n"
            "    - IT Army of Ukraine\n"
            "DIAMOND MODEL:\n"
            "  - Adversary ↔ Capability\n"
            "  - Infrastructure ↔ Victim\n"
            "  - Metadata (timestamp, phase)\n"
            "TOOLS:\n"
            "  MITRE ATT&CK Groups, Malpedia, MISP"
        ),
        "tools": [],
    },
    {
        "id": "ti-004", "name": "Threat Landscape Monitoring",
        "category": "landscape", "severity": "medium",
        "desc": "Continuous threat landscape monitoring.",
        "detection": (
            "THREAT LANDSCAPE:\n"
            "VULNERABILITY:\n"
            "  - Zero-day tracking\n"
            "  - Exploit availability monitoring\n"
            "  - CVE trend analysis\n"
            "  - Technology-specific vulnerabilities\n"
            "  - Patch gap analysis\n"
            "MALWARE:\n"
            "  - New malware families\n"
            "  - Ransomware evolution\n"
            "  - Infostealer trends\n"
            "  - Botnet activity\n"
            "  - Wiper malware\n"
            "CAMPAIGNS:\n"
            "  - Active exploitation campaigns\n"
            "  - Phishing campaign tracking\n"
            "  - Supply chain incidents\n"
            "  - Critical infrastructure targeting\n"
            "EMERGING:\n"
            "  - AI-powered attacks\n"
            "  - Quantum computing threats\n"
            "  - IoT/OT convergence\n"
            "  - 5G security implications\n"
            "  - Deepfake-enabled attacks\n"
            "SOURCES:\n"
            "  - CISA KEV (Known Exploited)\n"
            "  - FIRST EPSS (Exploit Prediction)\n"
            "  - Vendor advisories\n"
            "  - Bug bounty disclosures\n"
            "TOOLS:\n"
            "  CISA KEV, EPSS, CVE, Vulncheck"
        ),
        "tools": [],
    },
    {
        "id": "ti-005", "name": "Intelligence-Driven Defense",
        "category": "defense", "severity": "high",
        "desc": "Intelligence-driven defensive operations.",
        "detection": (
            "INTELLIGENCE-DRIVEN DEFENSE:\n"
            "THREAT HUNTING:\n"
            "  - Hypothesis-driven hunting\n"
            "  - IOC-based hunting\n"
            "  - Anomaly-based hunting\n"
            "  - TTP-based hunting\n"
            "  # Hunting loop:\n"
            "  # 1. Form hypothesis\n"
            "  # 2. Investigate data\n"
            "  # 3. Identify patterns\n"
            "  # 4. Develop detections\n"
            "  # 5. Repeat\n"
            "DETECTION ENGINEERING:\n"
            "  - Sigma rules from CTI\n"
            "  - YARA rules from malware analysis\n"
            "  - Suricata rules from network IOCs\n"
            "  - Behavioral detections from TTPs\n"
            "  - Machine learning models\n"
            "PRIORITIZATION:\n"
            "  - Threat-informed patching\n"
            "  - Risk-based vulnerability management\n"
            "  - Attack surface reduction\n"
            "  - Crown jewel protection\n"
            "MATURITY:\n"
            "  Level 0: No CTI program\n"
            "  Level 1: Ad-hoc, reactive\n"
            "  Level 2: Tactical IOC focus\n"
            "  Level 3: Operational TTP focus\n"
            "  Level 4: Strategic, proactive\n"
            "TOOLS:\n"
            "  OpenCTI, MISP, ELK/Splunk, Sigma"
        ),
        "tools": [],
    },
]


class ThreatIntelKB:
    """Threat intelligence knowledge base.

    Provides threat intel patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, ThreatIntelPattern] = {}
        self._log = logger.bind(component="threatintel_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load threat intelligence patterns."""
        for data in THREATINTEL_PATTERNS:
            pattern = ThreatIntelPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "medium"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[ThreatIntelPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_threatintel_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build threat intelligence prompt."""
        lines = ["## Threat Intelligence\n"]
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
