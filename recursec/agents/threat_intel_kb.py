"""Threat intelligence knowledge base.

Deep knowledge about threat intelligence:
1. MITRE ATT&CK framework
2. Indicators of compromise (IoC)
3. Threat actor profiles
4. Kill chain analysis
5. Threat intelligence platforms
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


THREAT_INTEL_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ti-001", "name": "MITRE ATT&CK Framework",
        "category": "mitre", "severity": "high",
        "desc": "MITRE ATT&CK mapping.",
        "detection": (
            "MITRE ATT&CK:\n"
            "TACTICS (Kill Chain Phases):\n"
            "  TA0043: Reconnaissance\n"
            "  TA0042: Resource Development\n"
            "  TA0001: Initial Access\n"
            "  TA0002: Execution\n"
            "  TA0003: Persistence\n"
            "  TA0004: Privilege Escalation\n"
            "  TA0005: Defense Evasion\n"
            "  TA0006: Credential Access\n"
            "  TA0007: Discovery\n"
            "  TA0008: Lateral Movement\n"
            "  TA0009: Collection\n"
            "  TA0011: Command and Control\n"
            "  TA0010: Exfiltration\n"
            "  TA0040: Impact\n"
            "COMMON TECHNIQUES:\n"
            "  T1190: Exploit Public-Facing Application\n"
            "  T1566: Phishing\n"
            "  T1059: Command and Scripting Interpreter\n"
            "  T1053: Scheduled Task/Job\n"
            "  T1078: Valid Accounts\n"
            "  T1098: Account Manipulation\n"
            "  T1110: Brute Force\n"
            "  T1021: Remote Services\n"
            "  T1071: Application Layer Protocol\n"
            "  T1048: Exfiltration Over Alternative Protocol\n"
            "MAPPING:\n"
            "  - Map findings to ATT&CK techniques\n"
            "  - Identify tactic coverage gaps\n"
            "  - Assess detection capabilities\n"
            "TOOLS:\n"
            "  ATT&CK Navigator, CALDERA, Atomic Red Team"
        ),
        "tools": [],
    },
    {
        "id": "ti-002", "name": "Indicators of Compromise",
        "category": "ioc", "severity": "high",
        "desc": "IoC collection and analysis.",
        "detection": (
            "INDICATORS OF COMPROMISE:\n"
            "TYPES:\n"
            "  Network:\n"
            "    - IP addresses (C2 servers)\n"
            "    - Domain names (malicious)\n"
            "    - URLs (phishing, malware)\n"
            "    - JA3/JA3S fingerprints\n"
            "    - User agents\n"
            "  Host:\n"
            "    - File hashes (MD5, SHA256)\n"
            "    - File paths\n"
            "    - Registry keys\n"
            "    - Mutex names\n"
            "    - Named pipes\n"
            "  Email:\n"
            "    - Sender addresses\n"
            "    - Subject patterns\n"
            "    - Attachment hashes\n"
            "    - Header anomalies\n"
            "FEEDS:\n"
            "  - AlienVault OTX (free)\n"
            "  - Abuse.ch (malware, botnets)\n"
            "  - CIRCL MISP (sharing)\n"
            "  - VirusTotal (hash lookup)\n"
            "  - Shodan (infrastructure)\n"
            "STANDARDS:\n"
            "  - STIX/TAXII (structured sharing)\n"
            "  - OpenIOC (Mandiant format)\n"
            "  - YARA rules (pattern matching)\n"
            "  - Sigma rules (log detection)\n"
            "TOOLS:\n"
            "  MISP, OpenCTI, TheHive, Yeti"
        ),
        "tools": [],
    },
    {
        "id": "ti-003", "name": "Threat Actor Profiles",
        "category": "actor", "severity": "critical",
        "desc": "Known threat actor TTPs.",
        "detection": (
            "THREAT ACTOR PROFILES:\n"
            "APT GROUPS:\n"
            "  APT28 (Fancy Bear / Russia):\n"
            "    - Spear phishing with exploits\n"
            "    - OAuth token theft\n"
            "    - Credential harvesting\n"
            "  APT29 (Cozy Bear / Russia):\n"
            "    - Supply chain compromise\n"
            "    - Cloud exploitation\n"
            "    - Token theft\n"
            "  APT41 (China):\n"
            "    - Supply chain + financial\n"
            "    - Custom malware families\n"
            "    - Zero-days\n"
            "  Lazarus (North Korea):\n"
            "    - Cryptocurrency theft\n"
            "    - Supply chain attacks\n"
            "    - Social engineering\n"
            "RANSOMWARE:\n"
            "  - LockBit: RaaS, fast encryption\n"
            "  - BlackCat/ALPHV: Rust-based\n"
            "  - Cl0p: MOVEit exploitation\n"
            "  - Play: Double extortion\n"
            "PROFILING:\n"
            "  - Motivation (financial, espionage, hacktivism)\n"
            "  - Capabilities (zero-day, custom malware)\n"
            "  - Infrastructure (C2, bulletproof hosting)\n"
            "  - Victimology (targets, sectors)\n"
            "TOOLS:\n"
            "  MISP, MITRE ATT&CK, Threat Intelligence Platforms"
        ),
        "tools": [],
    },
    {
        "id": "ti-004", "name": "Kill Chain Analysis",
        "category": "kill_chain", "severity": "high",
        "desc": "Kill chain and attack lifecycle.",
        "detection": (
            "KILL CHAIN ANALYSIS:\n"
            "LOCKHEED MARTIN KILL CHAIN:\n"
            "  1. Reconnaissance\n"
            "     - OSINT, scanning, social media\n"
            "     - Detection: DNS anomalies, web logs\n"
            "  2. Weaponization\n"
            "     - Malware creation, exploit dev\n"
            "     - Detection: N/A (attacker side)\n"
            "  3. Delivery\n"
            "     - Phishing, drive-by, USB\n"
            "     - Detection: Email gateway, web proxy\n"
            "  4. Exploitation\n"
            "     - Vulnerability exploit, social eng\n"
            "     - Detection: EDR, application logs\n"
            "  5. Installation\n"
            "     - Backdoor, implant, persistence\n"
            "     - Detection: File monitoring, registry\n"
            "  6. Command & Control\n"
            "     - HTTP/HTTPS, DNS, custom protocol\n"
            "     - Detection: Network monitoring, DNS\n"
            "  7. Actions on Objectives\n"
            "     - Data theft, destruction, ransom\n"
            "     - Detection: DLP, UEBA, integrity\n"
            "DIAMOND MODEL:\n"
            "  - Adversary ↔ Capability\n"
            "  - Infrastructure ↔ Victim\n"
            "  - Meta-features (timestamp, phase, result)\n"
            "TOOLS:\n"
            "  ATT&CK Navigator, MISP, analyst notebooks"
        ),
        "tools": [],
    },
    {
        "id": "ti-005", "name": "Threat Intel Platforms",
        "category": "platform", "severity": "medium",
        "desc": "Threat intelligence platforms.",
        "detection": (
            "THREAT INTEL PLATFORMS:\n"
            "OPEN SOURCE:\n"
            "  MISP:\n"
            "    - Open-source threat sharing\n"
            "    - STIX/TAXII support\n"
            "    - Correlation engine\n"
            "    - Galaxy/cluster taxonomies\n"
            "  OpenCTI:\n"
            "    - Knowledge management\n"
            "    - STIX2 native\n"
            "    - Connector ecosystem\n"
            "    - Attack pattern mapping\n"
            "  TheHive:\n"
            "    - Case management\n"
            "    - Cortex analyzers\n"
            "    - Alert management\n"
            "    - Integration with MISP\n"
            "  Yeti:\n"
            "    - Observable management\n"
            "    - Feed aggregation\n"
            "    - API-first design\n"
            "FEEDS:\n"
            "  Free:\n"
            "    - AlienVault OTX\n"
            "    - Abuse.ch URLhaus/MalwareBazaar\n"
            "    - CIRCL\n"
            "    - CriticalStack\n"
            "  Commercial:\n"
            "    - Recorded Future\n"
            "    - Mandiant\n"
            "    - CrowdStrike\n"
            "    - Flashpoint\n"
            "ENRICHMENT:\n"
            "  - VirusTotal, Shodan, Censys\n"
            "  - PassiveTotal, DomainTools\n"
            "  - GreyNoise, BinaryEdge\n"
            "TOOLS:\n"
            "  MISP, OpenCTI, TheHive, Cortex"
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
        """Load threat intel patterns."""
        for data in THREAT_INTEL_PATTERNS:
            pattern = ThreatIntelPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
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

    def build_threat_intel_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build threat intel prompt."""
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
