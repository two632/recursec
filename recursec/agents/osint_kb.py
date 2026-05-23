"""OSINT (Open Source Intelligence) knowledge base.

Deep knowledge about OSINT techniques:
1. Passive reconnaissance
2. Social media intelligence
3. Domain/IP intelligence
4. Code and credential leaks
5. Dark web monitoring patterns
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class OSINTPattern:
    """An OSINT collection pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
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
        "id": "osint-001", "name": "Domain and Infrastructure Intelligence",
        "category": "infrastructure",
        "desc": "Mapping target infrastructure passively.",
        "detection": (
            "DOMAIN INTELLIGENCE:\n"
            "DNS ENUMERATION:\n"
            "  # Zone transfer attempt\n"
            "  dig axfr @<nameserver> <domain>\n"
            "  # Subdomain enumeration\n"
            "  subfinder -d <domain> -all\n"
            "  amass enum -passive -d <domain>\n"
            "  # Certificate transparency\n"
            "  curl 'https://crt.sh/?q=%25.<domain>&output=json'\n"
            "  # DNS records\n"
            "  dig ANY <domain>\n"
            "  dig TXT <domain>  # SPF, DKIM, DMARC\n"
            "  # Reverse DNS\n"
            "  dig -x <ip>\n"
            "IP INTELLIGENCE:\n"
            "  # ASN lookup\n"
            "  whois -h whois.cymru.com \" -v <ip>\"\n"
            "  # IP range from ASN\n"
            "  whois -h whois.radb.net '!gAS<asn>'\n"
            "  # Shodan (if available)\n"
            "  shodan host <ip>\n"
            "  shodan search 'org:\"Target Org\"'\n"
            "TECHNOLOGY DETECTION:\n"
            "  # HTTP headers analysis\n"
            "  curl -sI https://<target> | grep -i 'server\\|x-powered\\|x-aspnet'\n"
            "  # Wappalyzer/WhatWeb\n"
            "  whatweb <target>\n"
            "  # JavaScript libraries\n"
            "  Check /robots.txt, /sitemap.xml, /.well-known/"
        ),
        "tools": ["subfinder", "amass", "dig", "whois", "whatweb"],
    },
    {
        "id": "osint-002", "name": "Credential and Secret Leaks",
        "category": "leaks",
        "desc": "Finding leaked credentials and secrets.",
        "detection": (
            "CREDENTIAL LEAK DISCOVERY:\n"
            "CODE REPOSITORIES:\n"
            "  # GitHub/GitLab search\n"
            "  Search: 'org:target password' or 'org:target api_key'\n"
            "  Dorks:\n"
            "    - filename:.env DB_PASSWORD\n"
            "    - filename:wp-config.php\n"
            "    - filename:id_rsa\n"
            "    - filename:.npmrc _authToken\n"
            "    - filename:docker-compose.yml\n"
            "  Tools:\n"
            "    trufflehog git https://github.com/org/repo\n"
            "    gitleaks detect --source <repo>\n"
            "    gitrob (automated GitHub scanner)\n"
            "PASTE SITES:\n"
            "  - Pastebin, Ghostbin, PrivateBin monitoring\n"
            "  - Search for domain, emails, IP ranges\n"
            "  - Automated monitoring with paste-alert tools\n"
            "BREACH DATABASES:\n"
            "  - Check if corporate emails appear in breaches\n"
            "  - Tool: h8mail -t target@company.com\n"
            "  - Check dehashed, leakpeek, snusbase\n"
            "  - Password reuse across services\n"
            "CLOUD STORAGE:\n"
            "  - S3 bucket enumeration (company name variations)\n"
            "  - Azure blob storage\n"
            "  - GCS buckets\n"
            "  - Tool: cloud_enum -k <company_name>"
        ),
        "tools": ["trufflehog", "gitleaks", "h8mail"],
    },
    {
        "id": "osint-003", "name": "Social Engineering Intelligence",
        "category": "social",
        "desc": "Gathering social intelligence for assessments.",
        "detection": (
            "SOCIAL ENGINEERING INTELLIGENCE:\n"
            "EMPLOYEE ENUMERATION:\n"
            "  - LinkedIn company page → employees list\n"
            "  - Email pattern discovery (first.last@company.com)\n"
            "  - Tool: linkedin2username\n"
            "  - theHarvester -d <domain> -b linkedin\n"
            "  - Verify emails: emailfinder, hunter.io\n"
            "SOCIAL MEDIA:\n"
            "  - Twitter/X: Search company mentions, employee posts\n"
            "  - Look for: tech stack mentions, internal tools\n"
            "  - Job postings reveal technology and infrastructure\n"
            "  - Conference talks by employees (reveal architecture)\n"
            "EMAIL INFRASTRUCTURE:\n"
            "  # MX records\n"
            "  dig MX <domain>\n"
            "  # SPF record (shows email infrastructure)\n"
            "  dig TXT <domain> | grep spf\n"
            "  # DMARC record\n"
            "  dig TXT _dmarc.<domain>\n"
            "  # Email validation\n"
            "  smtp-user-enum -M VRFY -u <user> -t <mailserver>\n"
            "DOCUMENT METADATA:\n"
            "  - Download public PDFs, DOCs from target website\n"
            "  - Extract metadata with exiftool:\n"
            "    exiftool <document> → author, software, OS, dates\n"
            "  - FOCA: Automated metadata extraction"
        ),
        "tools": ["theharvester", "exiftool", "linkedin2username"],
    },
    {
        "id": "osint-004", "name": "Web Archive and Historical Data",
        "category": "historical",
        "desc": "Using historical data for intelligence gathering.",
        "detection": (
            "HISTORICAL INTELLIGENCE:\n"
            "WEB ARCHIVES:\n"
            "  - Wayback Machine: web.archive.org/web/*/<target>\n"
            "  - Find old pages, removed content, config files\n"
            "  - Tool: waybackurls <domain>\n"
            "  - Tool: gau <domain> (GetAllUrls)\n"
            "  - Look for: old admin panels, API endpoints, js files\n"
            "HISTORICAL DNS:\n"
            "  - SecurityTrails: Past DNS records\n"
            "  - Old IP addresses may still be active\n"
            "  - Track infrastructure changes over time\n"
            "  - Find origin IP behind CDN/WAF\n"
            "GOOGLE DORKS:\n"
            "  - site:target.com filetype:pdf\n"
            "  - site:target.com inurl:admin\n"
            "  - site:target.com intitle:\"index of\"\n"
            "  - site:target.com ext:sql | ext:bak | ext:log\n"
            "  - site:target.com inurl:login\n"
            "  - \"target.com\" password | secret | credentials\n"
            "  - cache:target.com/sensitive-page\n"
            "JAVASCRIPT ANALYSIS:\n"
            "  - Download all JS files from target\n"
            "  - Search for: API keys, endpoints, debug info\n"
            "  - Tool: LinkFinder, SecretFinder\n"
            "  - Beautify and analyze with JSNice/Prettier"
        ),
        "tools": ["waybackurls", "gau", "linkfinder"],
    },
    {
        "id": "osint-005", "name": "Network and Physical Intelligence",
        "category": "network_phys",
        "desc": "Network mapping and physical site intelligence.",
        "detection": (
            "NETWORK INTELLIGENCE:\n"
            "ASN AND NETWORK BLOCKS:\n"
            "  # Find all IP ranges owned by organization\n"
            "  whois -h whois.radb.net '!gAS<asn>'\n"
            "  # BGP routing information\n"
            "  bgp.he.net lookup for ASN\n"
            "  # IPv4/IPv6 ranges\n"
            "  Scan all owned ranges for services\n"
            "CERTIFICATE TRANSPARENCY:\n"
            "  # All certificates issued for domain\n"
            "  crt.sh → wildcard and specific subdomain certs\n"
            "  certspotter.com → certificate monitoring\n"
            "  # Reveals: internal hostnames, service names\n"
            "CDN/WAF DETECTION:\n"
            "  # Detect CDN\n"
            "  Check DNS CNAME records\n"
            "  Check HTTP headers (cf-ray for Cloudflare)\n"
            "  # Find origin IP\n"
            "  Historical DNS records\n"
            "  Direct IP scanning of ASN ranges\n"
            "  Censys.io search for certificate\n"
            "  Outbound connections from target (SSRF)\n"
            "PHYSICAL LOCATION:\n"
            "  - IP geolocation (maxmind, ipinfo.io)\n"
            "  - Office locations from LinkedIn, Google Maps\n"
            "  - WiFi network names (wardriving/wigle.net)\n"
            "  - Satellite imagery for physical security assessment"
        ),
        "tools": ["whois", "nmap", "censys"],
    },
]


class OSINTKB:
    """OSINT knowledge base.

    Provides open source intelligence patterns
    injected into agent prompts.
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
        lines = ["## OSINT Collection Patterns\n"]
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
