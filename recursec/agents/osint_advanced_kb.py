"""Advanced OSINT knowledge base.

Deep knowledge about OSINT techniques:
1. Passive reconnaissance
2. People and organization OSINT
3. Infrastructure and domain OSINT
4. Social media intelligence
5. Dark web and deep web OSINT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class OSINTPattern:
    """An OSINT pattern."""
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


OSINT_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "osint-001", "name": "Passive Reconnaissance",
        "category": "passive", "severity": "medium",
        "desc": "Passive information gathering.",
        "detection": (
            "PASSIVE RECONNAISSANCE:\n"
            "DNS:\n"
            "  # Subdomain enumeration\n"
            "  subfinder -d TARGET -all\n"
            "  amass enum -passive -d TARGET\n"
            "  # DNS history\n"
            "  # SecurityTrails, ViewDNS, DNSdumpster\n"
            "  # Reverse DNS\n"
            "  # Zone transfer attempt\n"
            "  dig axfr @ns.TARGET TARGET\n"
            "CERTIFICATES:\n"
            "  # Certificate Transparency logs\n"
            "  curl 'https://crt.sh/?q=TARGET&output=json'\n"
            "  # Reveals subdomains, internal names\n"
            "  # Historical certificates\n"
            "WHOIS:\n"
            "  whois TARGET\n"
            "  # Registrant info, dates, nameservers\n"
            "  # Historical WHOIS (DomainTools)\n"
            "  # Reverse WHOIS by org/email\n"
            "WEB ARCHIVES:\n"
            "  # Wayback Machine\n"
            "  # waybackurls (tool)\n"
            "  waybackurls TARGET\n"
            "  # Find old endpoints, APIs, files\n"
            "  # Removed but cached content\n"
            "GOOGLE DORKING:\n"
            "  site:TARGET filetype:pdf\n"
            "  site:TARGET inurl:admin\n"
            "  site:TARGET ext:sql | ext:db\n"
            "  site:TARGET intitle:\"index of\"\n"
            "  site:pastebin.com TARGET\n"
            "SHODAN/CENSYS:\n"
            "  # Internet-wide scan data\n"
            "  shodan search hostname:TARGET\n"
            "  # Ports, services, banners, vulns\n"
            "TOOLS:\n"
            "  subfinder, amass, waybackurls, Shodan"
        ),
        "tools": ["subfinder", "amass"],
    },
    {
        "id": "osint-002", "name": "People and Organization OSINT",
        "category": "people", "severity": "medium",
        "desc": "People and org intelligence.",
        "detection": (
            "PEOPLE & ORG OSINT:\n"
            "EMAIL:\n"
            "  # Email harvesting\n"
            "  theHarvester -d TARGET -b all\n"
            "  # Email format discovery\n"
            "  # first.last@, flast@, firstl@\n"
            "  # Hunter.io, Phonebook.cz\n"
            "  # Email verification\n"
            "  # Breach databases (HIBP)\n"
            "LINKEDIN:\n"
            "  - Employee enumeration\n"
            "  - Technology stack from job posts\n"
            "  - Organization structure\n"
            "  - Key personnel identification\n"
            "  - CrossLinked (LinkedIn scraping)\n"
            "DOCUMENT METADATA:\n"
            "  # FOCA, ExifTool\n"
            "  exiftool document.pdf\n"
            "  # Usernames, software, paths\n"
            "  # Internal IPs, printer names\n"
            "  # Author names → username format\n"
            "CODE REPOS:\n"
            "  - GitHub/GitLab/Bitbucket search\n"
            "  - Secrets in public repos\n"
            "  - Internal URLs and endpoints\n"
            "  - Employee personal repos\n"
            "  # gitrob, trufflehog, gitleaks\n"
            "BREACH DATA:\n"
            "  - HIBP (Have I Been Pwned)\n"
            "  - Credential dumps\n"
            "  - Combo lists\n"
            "  - Dehashed, LeakCheck\n"
            "TOOLS:\n"
            "  theHarvester, CrossLinked, FOCA, ExifTool"
        ),
        "tools": ["theHarvester"],
    },
    {
        "id": "osint-003", "name": "Infrastructure OSINT",
        "category": "infrastructure", "severity": "medium",
        "desc": "Infrastructure intelligence.",
        "detection": (
            "INFRASTRUCTURE OSINT:\n"
            "IP RANGES:\n"
            "  - ASN lookup (BGPView, RIPE, ARIN)\n"
            "  - IP ranges from ASN\n"
            "  - Reverse IP lookup\n"
            "  - IP geolocation\n"
            "  # whois -h whois.radb.net -- '-i origin AS12345'\n"
            "CLOUD:\n"
            "  - S3 bucket enumeration\n"
            "  - Azure blob discovery\n"
            "  - GCP storage enumeration\n"
            "  # cloud_enum\n"
            "  cloud_enum -k TARGET\n"
            "  # S3Scanner\n"
            "  # AzureHound\n"
            "  # GCPBucketBrute\n"
            "CDN/ORIGIN:\n"
            "  - Find origin IP behind CDN\n"
            "  - DNS history before CDN\n"
            "  - Censys certificate search\n"
            "  - Email headers (origin IP)\n"
            "  - Subdomain with direct IP\n"
            "NETWORK TOPOLOGY:\n"
            "  - Traceroute mapping\n"
            "  - BGP path analysis\n"
            "  - Network relationships\n"
            "  - Shared hosting detection\n"
            "TECHNOLOGY:\n"
            "  # Wappalyzer / WhatRuns\n"
            "  # httpx with tech detect\n"
            "  httpx -l targets.txt -tech-detect\n"
            "  # Built With\n"
            "  # Netcraft\n"
            "TOOLS:\n"
            "  cloud_enum, httpx, Censys, BGPView"
        ),
        "tools": ["httpx"],
    },
    {
        "id": "osint-004", "name": "Social Media Intelligence",
        "category": "socmint", "severity": "low",
        "desc": "Social media intelligence.",
        "detection": (
            "SOCIAL MEDIA INTELLIGENCE:\n"
            "ACCOUNT DISCOVERY:\n"
            "  # Sherlock (username across platforms)\n"
            "  sherlock username\n"
            "  # Maigret (extended Sherlock)\n"
            "  maigret username\n"
            "  # WhatsMyName\n"
            "  # Namechk\n"
            "CONTENT ANALYSIS:\n"
            "  - Location from photos (geolocation)\n"
            "  - Travel patterns\n"
            "  - Work schedule patterns\n"
            "  - Technology mentions\n"
            "  - Colleague/friend networks\n"
            "  - Sentiment analysis\n"
            "PHOTO OSINT:\n"
            "  - EXIF data extraction\n"
            "  - Reverse image search (Google, Yandex)\n"
            "  - Face recognition\n"
            "  - Background analysis\n"
            "  - Time estimation from shadows\n"
            "PLATFORM-SPECIFIC:\n"
            "  - Twitter: advanced search operators\n"
            "  - Instagram: location history\n"
            "  - Facebook: friends, groups, events\n"
            "  - Reddit: comment history, interests\n"
            "  - GitHub: repos, contributions\n"
            "  - LinkedIn: professional network\n"
            "TOOLS:\n"
            "  Sherlock, Maigret, ExifTool, twint"
        ),
        "tools": ["sherlock"],
    },
    {
        "id": "osint-005", "name": "Dark/Deep Web OSINT",
        "category": "darkweb", "severity": "medium",
        "desc": "Dark and deep web intelligence.",
        "detection": (
            "DARK/DEEP WEB OSINT:\n"
            "TOR:\n"
            "  - .onion site crawling\n"
            "  - OnionScan (analyze .onion sites)\n"
            "  - Tor2web gateways\n"
            "  - Hidden service enumeration\n"
            "  - Ahmia search engine\n"
            "MONITORING:\n"
            "  - Company name mentions\n"
            "  - Credential dumps\n"
            "  - Data breach marketplaces\n"
            "  - Ransomware leak sites\n"
            "  - Initial access brokers\n"
            "  - Zero-day markets\n"
            "PASTE SITES:\n"
            "  - Pastebin monitoring\n"
            "  - GitHub Gist search\n"
            "  - Ghostbin, IX.io\n"
            "  - Leaked credentials\n"
            "  - Leaked configurations\n"
            "FORUMS:\n"
            "  - Hacker forums (monitoring only)\n"
            "  - Vulnerability discussions\n"
            "  - Tool releases\n"
            "  - Target-specific threats\n"
            "THREAT INTEL:\n"
            "  - VirusTotal\n"
            "  - AbuseIPDB\n"
            "  - OTX AlienVault\n"
            "  - MISP threat feeds\n"
            "  - C2 infrastructure tracking\n"
            "TOOLS:\n"
            "  OnionScan, DarkSearch, Ahmia,\n"
            "  VirusTotal, OTX, MISP"
        ),
        "tools": [],
    },
]


class OSINTAdvancedKB:
    """Advanced OSINT knowledge base.

    Provides OSINT patterns injected
    into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, OSINTPattern] = {}
        self._log = logger.bind(component="osint_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load OSINT patterns."""
        for data in OSINT_PATTERNS:
            pattern = OSINTPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "medium"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[OSINTPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_osint_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build OSINT prompt."""
        lines = ["## OSINT Intelligence\n"]
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
