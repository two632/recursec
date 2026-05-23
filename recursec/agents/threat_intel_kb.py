"""Threat intelligence knowledge base.

Deep knowledge about threat intelligence:
1. Threat intelligence platforms and feeds
2. IOC types and enrichment
3. APT group profiles and TTPs
4. Threat hunting methodologies
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
        "id": "ti-001", "name": "Threat Intel Platforms",
        "category": "platforms", "severity": "medium",
        "desc": "Threat intelligence platforms and feeds.",
        "detection": (
            "THREAT INTELLIGENCE PLATFORMS:\n"
            "OPEN SOURCE:\n"
            "  MISP (Malware Information Sharing Platform)\n"
            "  - Self-hosted threat sharing\n"
            "  - STIX/TAXII format\n"
            "  - Correlation engine\n"
            "  - Galaxy clusters (threat actors, tools)\n"
            "  OpenCTI (Open Cyber Threat Intelligence)\n"
            "  - Knowledge graph-based\n"
            "  - STIX 2.1 native\n"
            "  - Connector ecosystem\n"
            "FEEDS:\n"
            "  - abuse.ch (URLhaus, MalwareBazaar, ThreatFox)\n"
            "  - AlienVault OTX\n"
            "  - VirusTotal\n"
            "  - Shodan\n"
            "  - Censys\n"
            "  - GreyNoise\n"
            "  - PhishTank\n"
            "STANDARDS:\n"
            "  - STIX (Structured Threat Info Expression)\n"
            "  - TAXII (transport protocol)\n"
            "  - CybOX (observables)\n"
            "  - MITRE ATT&CK (TTPs)\n"
            "  - Diamond Model (intrusion analysis)\n"
            "  - Kill Chain (Lockheed Martin)\n"
            "TOOLS:\n"
            "  MISP, OpenCTI, TheHive"
        ),
        "tools": ["misp", "opencti"],
    },
    {
        "id": "ti-002", "name": "IOC Types and Enrichment",
        "category": "ioc", "severity": "high",
        "desc": "Indicator of Compromise types and enrichment.",
        "detection": (
            "IOC TYPES AND ENRICHMENT:\n"
            "NETWORK:\n"
            "  - IP addresses (IPv4, IPv6)\n"
            "  - Domain names\n"
            "  - URLs\n"
            "  - Email addresses\n"
            "  - SSL certificate hashes\n"
            "  - JA3/JA3S fingerprints\n"
            "HOST:\n"
            "  - File hashes (MD5, SHA1, SHA256)\n"
            "  - File names and paths\n"
            "  - Registry keys\n"
            "  - Mutex names\n"
            "  - Process names\n"
            "  - Scheduled tasks\n"
            "BEHAVIORAL:\n"
            "  - YARA rules\n"
            "  - Sigma rules\n"
            "  - Snort/Suricata rules\n"
            "  - MITRE ATT&CK technique IDs\n"
            "ENRICHMENT:\n"
            "  - VirusTotal lookup\n"
            "  - Shodan host info\n"
            "  - WHOIS data\n"
            "  - GeoIP location\n"
            "  - DNS history (PassiveTotal)\n"
            "  - Reputation scoring\n"
            "  - Malware family classification\n"
            "TOOLS:\n"
            "  IntelOwl, Cortex, MISP modules"
        ),
        "tools": ["intelowl", "cortex"],
    },
    {
        "id": "ti-003", "name": "APT Group Profiles",
        "category": "apt", "severity": "critical",
        "desc": "Advanced Persistent Threat group profiles.",
        "detection": (
            "APT GROUP PROFILES:\n"
            "NATION-STATE:\n"
            "  APT28 (Fancy Bear / Russia)\n"
            "  - Targets: NATO, governments, defense\n"
            "  - TTPs: Spearphishing, OAuth abuse, credential harvest\n"
            "  - Tools: X-Agent, Zebrocy, custom implants\n"
            "  APT29 (Cozy Bear / Russia)\n"
            "  - Targets: Government, healthcare, tech\n"
            "  - TTPs: Supply chain, cloud abuse, WellMess\n"
            "  APT41 (Winnti / China)\n"
            "  - Targets: Gaming, telecom, tech\n"
            "  - TTPs: Supply chain, rootkits, ShadowPad\n"
            "  Lazarus Group (North Korea)\n"
            "  - Targets: Financial, crypto, defense\n"
            "  - TTPs: Watering hole, social engineering\n"
            "  - Financially motivated + espionage\n"
            "CYBERCRIME:\n"
            "  - FIN7/Carbanak (financial fraud)\n"
            "  - REvil/Sodinokibi (ransomware)\n"
            "  - Conti/Royal/Black Basta (ransomware)\n"
            "  - LockBit (RaaS)\n"
            "TRACKING:\n"
            "  - MITRE ATT&CK Groups page\n"
            "  - Mandiant APT reports\n"
            "  - CrowdStrike adversary profiles\n"
            "  - Kaspersky APT tracker"
        ),
        "tools": [],
    },
    {
        "id": "ti-004", "name": "Threat Hunting",
        "category": "hunting", "severity": "high",
        "desc": "Threat hunting methodologies.",
        "detection": (
            "THREAT HUNTING:\n"
            "METHODOLOGY:\n"
            "  1. Hypothesis generation\n"
            "     - ATT&CK technique-based\n"
            "     - Intelligence-driven\n"
            "     - Anomaly-based\n"
            "  2. Data collection\n"
            "     - EDR telemetry\n"
            "     - Network flow data\n"
            "     - DNS logs\n"
            "     - Authentication logs\n"
            "  3. Investigation\n"
            "     - Pattern analysis\n"
            "     - Behavioral analysis\n"
            "     - Statistical analysis\n"
            "  4. Validation\n"
            "     - Confirm/deny hypothesis\n"
            "     - Document findings\n"
            "  5. Action\n"
            "     - Create detection rules\n"
            "     - Update IOCs\n"
            "     - Remediate findings\n"
            "HUNT TECHNIQUES:\n"
            "  - Stack counting (frequency analysis)\n"
            "  - Long tail analysis (rare events)\n"
            "  - Clustering (group similar events)\n"
            "  - Beaconing detection (regular intervals)\n"
            "  - DNS analysis (DGA, tunneling)\n"
            "  - Process tree analysis\n"
            "  - Lateral movement patterns\n"
            "TOOLS:\n"
            "  ELK Stack, Splunk, Velociraptor, RITA"
        ),
        "tools": ["velociraptor"],
    },
    {
        "id": "ti-005", "name": "Intelligence-Driven Defense",
        "category": "defense", "severity": "medium",
        "desc": "Intelligence-driven defense strategies.",
        "detection": (
            "INTELLIGENCE-DRIVEN DEFENSE:\n"
            "F3EAD CYCLE:\n"
            "  Find → Fix → Finish → Exploit → Analyze → Disseminate\n"
            "  - Find: Identify threats/adversaries\n"
            "  - Fix: Attribute to specific actors\n"
            "  - Finish: Contain/eradicate\n"
            "  - Exploit: Gather intelligence from incident\n"
            "  - Analyze: Process intelligence\n"
            "  - Disseminate: Share with stakeholders\n"
            "DIAMOND MODEL:\n"
            "  - Adversary ↔ Capability ↔ Infrastructure ↔ Victim\n"
            "  - Pivot analysis (one axis to discover others)\n"
            "  - Activity threading\n"
            "  - Activity-attack graph\n"
            "INTELLIGENCE LEVELS:\n"
            "  Strategic: Executive, risk-based decisions\n"
            "  Operational: Campaign-level, TTPs\n"
            "  Tactical: IOCs, signatures, rules\n"
            "  Technical: Raw data, artifacts\n"
            "AUTOMATION:\n"
            "  - Automated IOC ingestion\n"
            "  - SOAR playbooks\n"
            "  - Threat feed correlation\n"
            "  - Automated blocking (IP, domain, hash)\n"
            "  - Enrichment pipelines\n"
            "METRICS:\n"
            "  - Intel accuracy rate\n"
            "  - Time to detect (MTTD)\n"
            "  - Intelligence actionability score"
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
        self._log = logger.bind(component="threat_intel_kb")
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
