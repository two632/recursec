"""OSINT (Open Source Intelligence) knowledge base.

Deep knowledge about OSINT techniques:
1. Subdomain enumeration
2. Email and personnel OSINT
3. Social media intelligence
4. Infrastructure mapping
5. Dark web intelligence
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
        "id": "osint-001", "name": "Subdomain Enumeration",
        "category": "subdomain", "severity": "medium",
        "desc": "Subdomain discovery techniques.",
        "detection": (
            "SUBDOMAIN ENUMERATION:\n"
            "PASSIVE:\n"
            "  # Certificate Transparency\n"
            "  curl https://crt.sh/?q=%.target.com&output=json\n"
            "  # DNS aggregators\n"
            "  subfinder -d target.com -all\n"
            "  amass enum -passive -d target.com\n"
            "  # SecurityTrails, Censys, Shodan\n"
            "  # Archive.org (Wayback Machine)\n"
            "  # Google dorking: site:*.target.com\n"
            "  # VirusTotal passive DNS\n"
            "  # DNSDumpster, RapidDNS\n"
            "ACTIVE:\n"
            "  # Brute force\n"
            "  puredns bruteforce wordlist.txt target.com\n"
            "  # DNS zone transfer\n"
            "  dig axfr @ns1.target.com target.com\n"
            "  # Virtual host discovery\n"
            "  ffuf -w vhosts.txt -u http://TARGET -H 'Host: FUZZ.target.com'\n"
            "  # DNS recursion\n"
            "  dnsrecon -d target.com -t brt\n"
            "VALIDATION:\n"
            "  # Resolve all found subdomains\n"
            "  puredns resolve subdomains.txt\n"
            "  # HTTP probe\n"
            "  httpx -l subdomains.txt -status-code -title -tech\n"
            "  # Screenshot\n"
            "  gowitness file -f live-hosts.txt\n"
            "TOOLS:\n"
            "  subfinder, amass, puredns, httpx, gowitness"
        ),
        "tools": ["subfinder", "amass", "puredns", "httpx"],
    },
    {
        "id": "osint-002", "name": "Email & Personnel OSINT",
        "category": "email", "severity": "medium",
        "desc": "Email and personnel intelligence gathering.",
        "detection": (
            "EMAIL & PERSONNEL OSINT:\n"
            "EMAIL DISCOVERY:\n"
            "  # Pattern: first.last@target.com\n"
            "  theHarvester -d target.com -b all\n"
            "  # Hunter.io (email patterns)\n"
            "  # LinkedIn employee enumeration\n"
            "  # Google: @target.com email\n"
            "  # GitHub commits (author emails)\n"
            "  # Phonebook.cz\n"
            "  # Dehashed (breached credentials)\n"
            "VALIDATION:\n"
            "  # SMTP verification\n"
            "  # VRFY command\n"
            "  # RCPT TO validation\n"
            "  # MX record check\n"
            "BREACH DATA:\n"
            "  # HaveIBeenPwned (HIBP)\n"
            "  # Dehashed\n"
            "  # IntelX\n"
            "  # Snusbase\n"
            "  # Credential stuffing lists\n"
            "PERSONNEL:\n"
            "  # LinkedIn profiles\n"
            "  # Conference talks/papers\n"
            "  # Job postings (tech stack reveal)\n"
            "  # Social media accounts\n"
            "  # Domain registrant info (WHOIS)\n"
            "TOOLS:\n"
            "  theHarvester, holehe, h8mail, emailfinder"
        ),
        "tools": ["theharvester", "holehe"],
    },
    {
        "id": "osint-003", "name": "Social Media Intelligence",
        "category": "socmint", "severity": "low",
        "desc": "Social media intelligence techniques.",
        "detection": (
            "SOCIAL MEDIA INTELLIGENCE:\n"
            "USERNAME:\n"
            "  # Cross-platform username search\n"
            "  sherlock username\n"
            "  # Maigret (advanced)\n"
            "  maigret username --all-sites\n"
            "  # WhatsMyName\n"
            "PLATFORMS:\n"
            "  TWITTER/X:\n"
            "    - Advanced search operators\n"
            "    - Geolocation from tweets\n"
            "    - Follower/following analysis\n"
            "    - Deleted tweets (archive.org)\n"
            "  LINKEDIN:\n"
            "    - Employee enumeration\n"
            "    - Technology stack from jobs\n"
            "    - Org chart reconstruction\n"
            "    - Group memberships\n"
            "  GITHUB:\n"
            "    - Repository secrets scanning\n"
            "    - Commit author emails\n"
            "    - History search (trufflehog)\n"
            "    - Internal tool names\n"
            "    - Infrastructure hints\n"
            "  REDDIT/FORUMS:\n"
            "    - Employee discussions\n"
            "    - Technical details\n"
            "    - Frustration posts (security gaps)\n"
            "METADATA:\n"
            "  - EXIF data from images\n"
            "  - Document metadata (author, software)\n"
            "  - PDF properties\n"
            "  exiftool image.jpg\n"
            "TOOLS:\n"
            "  sherlock, maigret, trufflehog, exiftool"
        ),
        "tools": ["sherlock", "maigret", "trufflehog"],
    },
    {
        "id": "osint-004", "name": "Infrastructure Mapping",
        "category": "infra", "severity": "medium",
        "desc": "Infrastructure and network OSINT.",
        "detection": (
            "INFRASTRUCTURE MAPPING:\n"
            "IP/ASN:\n"
            "  # ASN lookup\n"
            "  whois -h whois.radb.net -- '-i origin AS12345'\n"
            "  # BGP prefixes\n"
            "  # IP range discovery\n"
            "  # Hurricane Electric BGP toolkit\n"
            "  # ARIN, RIPE, APNIC databases\n"
            "NETWORK:\n"
            "  # Shodan\n"
            "  shodan search 'org:\"Target Inc\"'\n"
            "  # Censys\n"
            "  censys search 'services.tls.certificates.leaf.subject.organization:\"Target\"'\n"
            "  # ZoomEye (Chinese Shodan)\n"
            "  # FOFA (Chinese)\n"
            "  # BinaryEdge\n"
            "TECH STACK:\n"
            "  # Wappalyzer/Whatweb\n"
            "  whatweb https://target.com\n"
            "  # BuiltWith\n"
            "  # HTTP headers analysis\n"
            "  # JavaScript framework detection\n"
            "  # Cloud provider detection\n"
            "DNS:\n"
            "  # MX records → email provider\n"
            "  # SPF/DMARC → email infrastructure\n"
            "  # NS records → DNS hosting\n"
            "  # TXT records (verification tokens)\n"
            "  # Historical DNS (SecurityTrails)\n"
            "TOOLS:\n"
            "  shodan, censys, whois, whatweb, dnsrecon"
        ),
        "tools": ["shodan", "whois", "whatweb"],
    },
    {
        "id": "osint-005", "name": "Dark Web Intelligence",
        "category": "darkweb", "severity": "high",
        "desc": "Dark web intelligence gathering.",
        "detection": (
            "DARK WEB INTELLIGENCE:\n"
            "SOURCES:\n"
            "  - Tor hidden services (.onion)\n"
            "  - I2P eepsites\n"
            "  - Paste sites (Pastebin, Ghostbin)\n"
            "  - Dark web forums\n"
            "  - Ransomware leak sites\n"
            "  - Criminal marketplaces\n"
            "MONITORING:\n"
            "  # Credential leaks\n"
            "  # Data breach dumps\n"
            "  # Ransomware victim announcements\n"
            "  # Zero-day sales\n"
            "  # Exploit marketplace\n"
            "  # Initial access broker listings\n"
            "ACCESS:\n"
            "  # Tor Browser\n"
            "  # OnionScan (discover hidden services)\n"
            "  # Dark web search engines:\n"
            "    Ahmia, Torch, DarkSearch\n"
            "  # Automated monitoring:\n"
            "    SpiderFoot, IntelX, DarkOwl\n"
            "OPSEC:\n"
            "  - Use dedicated browser (Tor)\n"
            "  - VPN + Tor (debate on ordering)\n"
            "  - Separate identity\n"
            "  - Clean VM\n"
            "  - No personal accounts\n"
            "TOOLS:\n"
            "  Tor, OnionScan, SpiderFoot, IntelX"
        ),
        "tools": ["tor", "spiderfoot"],
    },
]


class OSINTKB:
    """OSINT knowledge base.

    Provides OSINT patterns injected into agent prompts.
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
