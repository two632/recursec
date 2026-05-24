"""Threat intelligence knowledge base.

Deep knowledge about threat intelligence:
1. Threat actor profiling (APT groups)
2. Indicator of Compromise (IoC) management
3. Threat feeds and sources
4. Threat modeling (STRIDE, PASTA)
5. Threat hunting techniques
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


TI_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ti-001", "name": "Threat Actor Profiling",
        "category": "actors", "severity": "high",
        "desc": "APT group and threat actor profiling.",
        "detection": (
            "THREAT ACTOR PROFILING:\n"
            "NOTABLE APT GROUPS:\n"
            "  APT28 (Fancy Bear/Russia):\n"
            "    - Targets: Gov, military, media\n"
            "    - TTPs: Phishing, zero-days, credential theft\n"
            "    - Tools: X-Agent, Zebrocy, LoJax\n"
            "  APT29 (Cozy Bear/Russia):\n"
            "    - Targets: Gov, think tanks, tech\n"
            "    - TTPs: Supply chain, cloud abuse\n"
            "    - Tools: SUNBURST, WellMess, EnvyScout\n"
            "  APT41 (China):\n"
            "    - Targets: Healthcare, tech, gaming\n"
            "    - TTPs: Supply chain, zero-days, dual-use\n"
            "    - Both espionage and financial\n"
            "  Lazarus (North Korea):\n"
            "    - Targets: Finance, crypto, defense\n"
            "    - TTPs: Social eng, custom malware\n"
            "    - Financial motivation + espionage\n"
            "  FIN7/FIN11 (Financially motivated):\n"
            "    - Targets: Retail, hospitality, finance\n"
            "    - TTPs: Phishing, PoS malware, ransomware\n"
            "PROFILING:\n"
            "  - MITRE ATT&CK Navigator (group overlay)\n"
            "  - TTP mapping\n"
            "  - Infrastructure analysis\n"
            "  - Malware family tracking\n"
            "TOOLS:\n"
            "  MITRE ATT&CK Navigator, OpenCTI, MISP"
        ),
        "tools": ["opencti", "misp"],
    },
    {
        "id": "ti-002", "name": "IoC Management",
        "category": "ioc", "severity": "medium",
        "desc": "Indicator of Compromise management.",
        "detection": (
            "IoC MANAGEMENT:\n"
            "IoC TYPES:\n"
            "  - Atomic: IP, domain, hash, email, URL\n"
            "  - Computed: YARA rules, regex patterns\n"
            "  - Behavioral: TTPs, attack patterns\n"
            "STANDARDS:\n"
            "  - STIX (Structured Threat Information eXpression)\n"
            "  - TAXII (transport protocol for STIX)\n"
            "  - OpenIOC (Mandiant format)\n"
            "  - CybOX (cyber observables)\n"
            "MANAGEMENT:\n"
            "  # MISP (open source TIP)\n"
            "  # OpenCTI (knowledge management)\n"
            "  # TheHive (incident response)\n"
            "  # Cortex (analysis)\n"
            "ENRICHMENT:\n"
            "  - VirusTotal (hash, IP, domain)\n"
            "  - Shodan (IP info)\n"
            "  - PassiveTotal (DNS history)\n"
            "  - AbuseIPDB (IP reputation)\n"
            "  - GreyNoise (Internet noise)\n"
            "  - URLhaus (malicious URLs)\n"
            "LIFECYCLE:\n"
            "  1. Collection (feeds, manual, tools)\n"
            "  2. Processing (parsing, normalization)\n"
            "  3. Analysis (enrichment, correlation)\n"
            "  4. Dissemination (alerts, reports)\n"
            "  5. Feedback (effectiveness tracking)\n"
            "TOOLS:\n"
            "  MISP, OpenCTI, TheHive, Cortex, YETI"
        ),
        "tools": ["misp", "opencti"],
    },
    {
        "id": "ti-003", "name": "Threat Feeds and Sources",
        "category": "feeds", "severity": "medium",
        "desc": "Threat intelligence feeds and data sources.",
        "detection": (
            "THREAT FEEDS AND SOURCES:\n"
            "FREE FEEDS:\n"
            "  - AlienVault OTX (community IoCs)\n"
            "  - Abuse.ch (URLhaus, MalwareBazaar, ThreatFox)\n"
            "  - Blocklist.de (attack IPs)\n"
            "  - Feodo Tracker (banking trojans)\n"
            "  - PhishTank (phishing URLs)\n"
            "  - Spamhaus (spam/botnet IPs)\n"
            "  - Emerging Threats (Suricata rules)\n"
            "  - CIRCL (Luxembourg CERT)\n"
            "COMMERCIAL:\n"
            "  - Recorded Future\n"
            "  - Mandiant (Google)\n"
            "  - CrowdStrike Falcon Intel\n"
            "  - Unit 42 (Palo Alto)\n"
            "  - Talos Intelligence (Cisco)\n"
            "GOVERNMENT:\n"
            "  - CISA (US-CERT advisories)\n"
            "  - NCSC (UK)\n"
            "  - BSI (Germany)\n"
            "  - ANSSI (France)\n"
            "  - JPCERT (Japan)\n"
            "  - CERT-In (India)\n"
            "  - KrCERT (Korea)\n"
            "INTEGRATION:\n"
            "  # Aggregate feeds\n"
            "  # Normalize to STIX format\n"
            "  # Score confidence\n"
            "  # Age out old IoCs\n"
            "TOOLS:\n"
            "  IntelOwl, MISP, OTX, ThreatConnect"
        ),
        "tools": ["misp"],
    },
    {
        "id": "ti-004", "name": "Threat Modeling",
        "category": "modeling", "severity": "medium",
        "desc": "Threat modeling methodologies.",
        "detection": (
            "THREAT MODELING:\n"
            "STRIDE:\n"
            "  S - Spoofing (authentication bypass)\n"
            "  T - Tampering (data modification)\n"
            "  R - Repudiation (deny actions)\n"
            "  I - Information Disclosure (data leak)\n"
            "  D - Denial of Service\n"
            "  E - Elevation of Privilege\n"
            "PASTA:\n"
            "  1. Define objectives\n"
            "  2. Define technical scope\n"
            "  3. Application decomposition\n"
            "  4. Threat analysis\n"
            "  5. Vulnerability analysis\n"
            "  6. Attack modeling\n"
            "  7. Risk/impact analysis\n"
            "ATTACK TREES:\n"
            "  - Root: attacker goal\n"
            "  - Branches: different paths\n"
            "  - Leaves: specific techniques\n"
            "  - AND/OR nodes\n"
            "  - Cost and probability annotations\n"
            "DATA FLOW DIAGRAMS:\n"
            "  - External entities\n"
            "  - Processes\n"
            "  - Data stores\n"
            "  - Data flows\n"
            "  - Trust boundaries\n"
            "TOOLS:\n"
            "  Microsoft Threat Modeling Tool, OWASP Threat Dragon,\n"
            "  IriusRisk, Threagile"
        ),
        "tools": [],
    },
    {
        "id": "ti-005", "name": "Threat Hunting",
        "category": "hunting", "severity": "high",
        "desc": "Proactive threat hunting techniques.",
        "detection": (
            "THREAT HUNTING:\n"
            "METHODOLOGY:\n"
            "  1. Hypothesis generation (intel-driven)\n"
            "  2. Data collection (logs, telemetry)\n"
            "  3. Investigation (search, correlate)\n"
            "  4. Findings (confirm/deny hypothesis)\n"
            "  5. Response (contain, remediate)\n"
            "  6. Document (new detections)\n"
            "TECHNIQUES:\n"
            "  STACK COUNTING:\n"
            "    - Count occurrences of values\n"
            "    - Outliers = suspicious\n"
            "    - Example: rare process names\n"
            "  CLUSTERING:\n"
            "    - Group similar events\n"
            "    - Identify anomalous clusters\n"
            "  LONG TAIL:\n"
            "    - Focus on rare events\n"
            "    - Unusual user agents\n"
            "    - Rare DNS queries\n"
            "    - Uncommon executables\n"
            "  TTP-BASED:\n"
            "    - Hunt for specific ATT&CK techniques\n"
            "    - T1059: Command and Scripting\n"
            "    - T1053: Scheduled Tasks\n"
            "    - T1003: Credential Dumping\n"
            "    - T1021: Remote Services\n"
            "DATA SOURCES:\n"
            "  - EDR telemetry (CrowdStrike, Defender)\n"
            "  - SIEM logs (Splunk, Elastic, Sentinel)\n"
            "  - Network (Zeek, Suricata)\n"
            "  - DNS logs\n"
            "  - Authentication logs\n"
            "TOOLS:\n"
            "  Splunk, Elastic SIEM, Sigma rules, YARA, osquery"
        ),
        "tools": ["sigma"],
    },
]


class ThreatIntelKB:
    """Threat intelligence knowledge base.

    Provides threat intelligence patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, ThreatIntelPattern] = {}
        self._log = logger.bind(component="threat_intel_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load threat intel patterns."""
        for data in TI_PATTERNS:
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
