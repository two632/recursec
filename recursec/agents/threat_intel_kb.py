"""Threat intelligence knowledge base.

Deep knowledge about threat intelligence:
1. IOC (Indicators of Compromise) types and sources
2. Threat actor profiling
3. MITRE ATT&CK integration
4. CVE/NVD correlation
5. Threat intelligence feeds and enrichment
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
        "id": "ti-001", "name": "IOC Collection and Enrichment",
        "category": "ioc", "severity": "high",
        "desc": "Collecting and enriching indicators of compromise.",
        "detection": (
            "IOC COLLECTION AND ENRICHMENT:\n"
            "IOC TYPES:\n"
            "  - IP addresses (C2 servers, scanners)\n"
            "  - Domain names (malware C2, phishing)\n"
            "  - File hashes (MD5, SHA1, SHA256)\n"
            "  - URLs (malware distribution, phishing)\n"
            "  - Email addresses (phishing campaigns)\n"
            "  - SSL certificate fingerprints\n"
            "  - YARA rules (malware signatures)\n"
            "FREE SOURCES:\n"
            "  - VirusTotal: File/URL/IP/domain analysis\n"
            "  - AbuseIPDB: Malicious IP reports\n"
            "  - URLhaus: Malware distribution URLs\n"
            "  - MalwareBazaar: Malware sample repository\n"
            "  - ThreatFox: IOC sharing platform\n"
            "  - OTX (AlienVault): Community threat intel\n"
            "  - MISP: Threat sharing platform\n"
            "ENRICHMENT:\n"
            "  # IP enrichment\n"
            "  whois <ip>\n"
            "  shodan host <ip>\n"
            "  # Domain enrichment\n"
            "  dig ANY <domain>\n"
            "  dnstwist <domain>  # Lookalike detection\n"
            "  # File enrichment\n"
            "  # Hash lookup on VirusTotal, Hybrid-Analysis\n"
            "  # YARA rule matching\n"
            "  yara rules.yar suspicious_file"
        ),
        "tools": ["yara", "shodan", "whois"],
    },
    {
        "id": "ti-002", "name": "MITRE ATT&CK Mapping",
        "category": "mitre", "severity": "medium",
        "desc": "Mapping findings to MITRE ATT&CK framework.",
        "detection": (
            "MITRE ATT&CK MAPPING:\n"
            "TACTICS (Kill Chain):\n"
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
            "  TA0010: Exfiltration\n"
            "  TA0011: Command and Control\n"
            "  TA0040: Impact\n"
            "COMMON TECHNIQUES:\n"
            "  T1190: Exploit Public-Facing Application\n"
            "  T1133: External Remote Services\n"
            "  T1078: Valid Accounts\n"
            "  T1059: Command and Scripting Interpreter\n"
            "  T1053: Scheduled Task/Job\n"
            "  T1055: Process Injection\n"
            "  T1003: OS Credential Dumping\n"
            "  T1021: Remote Services\n"
            "USAGE:\n"
            "  - Map each finding to technique ID\n"
            "  - Identify coverage gaps in detection\n"
            "  - Build threat models per actor\n"
            "  - navigator.attack.mitre.org for visualization"
        ),
        "tools": ["attack-navigator"],
    },
    {
        "id": "ti-003", "name": "CVE Intelligence and Prioritization",
        "category": "cve", "severity": "high",
        "desc": "CVE analysis, prioritization, and exploit availability.",
        "detection": (
            "CVE INTELLIGENCE:\n"
            "SOURCES:\n"
            "  - NVD (National Vulnerability Database)\n"
            "  - CVE.org (MITRE)\n"
            "  - CISA KEV (Known Exploited Vulnerabilities)\n"
            "  - Exploit-DB\n"
            "  - PacketStorm\n"
            "  - GitHub Security Advisories\n"
            "PRIORITIZATION:\n"
            "  EPSS (Exploit Prediction Scoring System):\n"
            "    - Probability of exploitation in next 30 days\n"
            "    - EPSS > 0.5 → high likelihood of exploitation\n"
            "    - EPSS > 0.9 → almost certain exploitation\n"
            "  CISA KEV:\n"
            "    - If in KEV → actively exploited in the wild\n"
            "    - Mandatory patching deadline for federal agencies\n"
            "  CVSS + EPSS COMBINED:\n"
            "    - CVSS ≥ 9.0 AND EPSS ≥ 0.5 → CRITICAL priority\n"
            "    - CVSS ≥ 7.0 AND EPSS ≥ 0.3 → HIGH priority\n"
            "    - CVSS ≥ 7.0 AND EPSS < 0.1 → MEDIUM (high impact but low exploit probability)\n"
            "EXPLOIT AVAILABILITY:\n"
            "  searchsploit <product> <version>  # Exploit-DB CLI\n"
            "  # Check GitHub for PoC\n"
            "  # Check Metasploit modules\n"
            "  msfconsole -q -x 'search cve:CVE-2024-XXXX'"
        ),
        "tools": ["searchsploit", "msfconsole"],
    },
    {
        "id": "ti-004", "name": "Threat Actor Profiling",
        "category": "actor", "severity": "medium",
        "desc": "Profiling and tracking threat actors.",
        "detection": (
            "THREAT ACTOR PROFILING:\n"
            "CLASSIFICATION:\n"
            "  - APT (Advanced Persistent Threat): Nation-state\n"
            "  - Cybercrime groups: Financial motivation\n"
            "  - Hacktivists: Ideological motivation\n"
            "  - Insider threats: Authorized access abuse\n"
            "  - Script kiddies: Low-skill opportunistic\n"
            "PROFILING ATTRIBUTES:\n"
            "  - TTPs (Tactics, Techniques, Procedures)\n"
            "  - Infrastructure (C2, domains, IPs)\n"
            "  - Malware families used\n"
            "  - Target sectors/geographies\n"
            "  - Motivation and capabilities\n"
            "  - Activity timeline\n"
            "TRACKING:\n"
            "  - MITRE ATT&CK Groups database\n"
            "  - Mandiant APT reports\n"
            "  - CrowdStrike adversary naming\n"
            "  - Microsoft threat actor naming (weather themed)\n"
            "RELEVANCE TO ASSESSMENT:\n"
            "  - Identify likely threat actors for target's industry\n"
            "  - Focus testing on their known TTPs\n"
            "  - Simulate realistic attack scenarios\n"
            "  - Prioritize defenses against likely attackers"
        ),
        "tools": ["misp", "attack-navigator"],
    },
    {
        "id": "ti-005", "name": "Dark Web Intelligence",
        "category": "darkweb", "severity": "high",
        "desc": "Monitoring dark web for threat intelligence.",
        "detection": (
            "DARK WEB INTELLIGENCE:\n"
            "MONITORING TARGETS:\n"
            "  - Paste sites: Leaked credentials, data dumps\n"
            "  - Forums: Exploit sales, target discussions\n"
            "  - Marketplaces: Stolen data, access selling\n"
            "  - Telegram channels: Real-time threat intel\n"
            "  - Ransomware leak sites: Victim data\n"
            "OSINT TOOLS:\n"
            "  - OnionScan: Scan .onion sites\n"
            "  - Ahmia: Tor search engine\n"
            "  - IntelOwl: Automated threat intel\n"
            "  - SpiderFoot: OSINT automation\n"
            "  spiderfoot -s <target_domain>\n"
            "CREDENTIAL MONITORING:\n"
            "  - HaveIBeenPwned: Breach database\n"
            "  - DeHashed: Paid credential search\n"
            "  - Dehashed API for bulk checking\n"
            "  - Monitor for employee credentials in leaks\n"
            "BRAND MONITORING:\n"
            "  - Lookalike domain registration\n"
            "  - Phishing kit sales targeting org\n"
            "  - Social media impersonation\n"
            "  - Mobile app impersonation\n"
            "  - Source code leaks on GitHub/paste sites"
        ),
        "tools": ["spiderfoot", "onionscan", "intelowl"],
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
        """Build threat intelligence prompt."""
        lines = ["## Threat Intelligence Patterns\n"]
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
