"""OSINT knowledge base.

Deep knowledge about OSINT techniques:
1. Domain and infrastructure reconnaissance
2. People and organization research
3. Social media intelligence
4. Code and leak analysis
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
        "id": "osint-001", "name": "Domain Reconnaissance",
        "category": "domain", "severity": "medium",
        "desc": "Domain and infrastructure enumeration.",
        "detection": (
            "DOMAIN RECONNAISSANCE:\n"
            "DNS ENUMERATION:\n"
            "  # Subdomain enumeration\n"
            "  subfinder -d target.com -all -o subs.txt\n"
            "  amass enum -d target.com -o amass.txt\n"
            "  assetfinder target.com\n"
            "  # DNS records\n"
            "  dig target.com ANY +noall +answer\n"
            "  dig target.com MX +short\n"
            "  dig target.com TXT +short\n"
            "  dig target.com NS +short\n"
            "  # Zone transfer attempt\n"
            "  dig axfr target.com @ns1.target.com\n"
            "WHOIS:\n"
            "  whois target.com\n"
            "  # Registrant info, dates, nameservers\n"
            "  # Reverse WHOIS by email/org\n"
            "CERTIFICATE TRANSPARENCY:\n"
            "  # crt.sh query\n"
            "  curl 'https://crt.sh/?q=%.target.com&output=json' | jq '.[].name_value'\n"
            "  # Censys certificate search\n"
            "INFRASTRUCTURE:\n"
            "  # Shodan\n"
            "  shodan search hostname:target.com\n"
            "  # Censys\n"
            "  censys search target.com\n"
            "  # IP history\n"
            "  # SecurityTrails, ViewDNS, PassiveTotal\n"
            "TOOLS:\n"
            "  subfinder, amass, assetfinder  # Subdomain enum\n"
            "  httpx  # HTTP probing\n"
            "  dnsx  # DNS resolution"
        ),
        "tools": ["subfinder", "amass", "httpx", "dnsx"],
    },
    {
        "id": "osint-002", "name": "People and Organization",
        "category": "people", "severity": "medium",
        "desc": "People and organization research techniques.",
        "detection": (
            "PEOPLE AND ORGANIZATION OSINT:\n"
            "EMAIL ENUMERATION:\n"
            "  # theHarvester\n"
            "  theHarvester -d target.com -b all\n"
            "  # Email format discovery\n"
            "  # Common: first.last@, f.last@, first@\n"
            "  # Verify with SMTP VRFY or RCPT TO\n"
            "LINKEDIN:\n"
            "  - Employee enumeration\n"
            "  - Technology stack from job postings\n"
            "  - Organizational structure\n"
            "  - Key personnel identification\n"
            "CREDENTIAL LEAKS:\n"
            "  # Check breach databases\n"
            "  # Have I Been Pwned API\n"
            "  # DeHashed, IntelX, LeakCheck\n"
            "  # Credential stuffing lists\n"
            "GOOGLE DORKS:\n"
            "  site:target.com filetype:pdf\n"
            "  site:target.com inurl:admin\n"
            "  site:target.com intitle:\"index of\"\n"
            "  site:target.com ext:sql | ext:db | ext:bak\n"
            "  site:target.com intext:password\n"
            "  \"target.com\" filetype:env\n"
            "GITHUB:\n"
            "  # Search for secrets in repos\n"
            "  trufflehog github --org=target-org\n"
            "  gitleaks detect --source .\n"
            "  # Search: org:target password OR secret OR api_key"
        ),
        "tools": ["theHarvester", "trufflehog", "gitleaks"],
    },
    {
        "id": "osint-003", "name": "Web Application Recon",
        "category": "webapp", "severity": "medium",
        "desc": "Web application reconnaissance techniques.",
        "detection": (
            "WEB APPLICATION RECON:\n"
            "TECHNOLOGY FINGERPRINTING:\n"
            "  # Wappalyzer / WhatWeb\n"
            "  whatweb target.com\n"
            "  # Response headers\n"
            "  curl -sI https://target.com | grep -i 'server\\|x-powered\\|x-aspnet'\n"
            "  # HTML source analysis\n"
            "  # JavaScript library detection\n"
            "DIRECTORY/FILE DISCOVERY:\n"
            "  ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302\n"
            "  gobuster dir -u https://target.com -w wordlist.txt\n"
            "  # Interesting files\n"
            "  /robots.txt, /sitemap.xml, /.git/HEAD\n"
            "  /.env, /wp-config.php.bak, /web.config\n"
            "  /api, /swagger.json, /graphql\n"
            "WAYBACK MACHINE:\n"
            "  # Historical snapshots\n"
            "  waybackurls target.com | sort -u\n"
            "  gau target.com  # GetAllUrls\n"
            "  # Find old endpoints, removed pages\n"
            "  # JavaScript file analysis for endpoints\n"
            "JAVASCRIPT ANALYSIS:\n"
            "  # Extract URLs from JS files\n"
            "  # Find API endpoints, secrets\n"
            "  # LinkFinder, JSParser\n"
            "  katana -u https://target.com -jc  # JS crawling"
        ),
        "tools": ["ffuf", "gobuster", "katana", "whatweb"],
    },
    {
        "id": "osint-004", "name": "Network Infrastructure",
        "category": "network", "severity": "medium",
        "desc": "Network infrastructure intelligence.",
        "detection": (
            "NETWORK INFRASTRUCTURE OSINT:\n"
            "ASN/BGP:\n"
            "  # Find ASN\n"
            "  whois -h whois.cymru.com \" -v <ip>\"\n"
            "  # Find IP ranges for ASN\n"
            "  whois -h whois.radb.net -- '-i origin AS12345'\n"
            "  # BGP Looking Glass\n"
            "PORT SCANNING:\n"
            "  # Fast discovery\n"
            "  masscan -p0-65535 <target> --rate=10000\n"
            "  # Service detection\n"
            "  nmap -sV -sC -p<ports> <target>\n"
            "  # UDP scan\n"
            "  nmap -sU --top-ports 100 <target>\n"
            "CDN/WAF DETECTION:\n"
            "  # Detect CDN\n"
            "  # Cloudflare: cf-ray header\n"
            "  # AWS CloudFront: x-amz-cf-id header\n"
            "  # Akamai: x-akamai-* headers\n"
            "  # Bypass: Find origin IP behind CDN\n"
            "  # Check DNS history, certificate SAN\n"
            "  # SecurityTrails, Censys for historical IPs\n"
            "CLOUD ENUMERATION:\n"
            "  # AWS S3 buckets\n"
            "  aws s3 ls s3://target-name --no-sign-request\n"
            "  # Azure blobs\n"
            "  # target.blob.core.windows.net\n"
            "  # GCP storage\n"
            "  # storage.googleapis.com/target-name"
        ),
        "tools": ["nmap", "masscan"],
    },
    {
        "id": "osint-005", "name": "Leaked Credentials",
        "category": "leaks", "severity": "critical",
        "desc": "Credential and data leak intelligence.",
        "detection": (
            "LEAKED CREDENTIALS OSINT:\n"
            "BREACH DATABASES:\n"
            "  - Have I Been Pwned (HIBP)\n"
            "  - DeHashed (paid, comprehensive)\n"
            "  - IntelX (intelligence search)\n"
            "  - LeakCheck\n"
            "  - Snusbase\n"
            "CODE REPOSITORIES:\n"
            "  # GitHub/GitLab secret scanning\n"
            "  trufflehog github --org=target\n"
            "  gitleaks detect --source .\n"
            "  # Common secrets:\n"
            "  - AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY\n"
            "  - GITHUB_TOKEN, npm_token\n"
            "  - Database connection strings\n"
            "  - Private keys (RSA, SSH)\n"
            "  - .env files committed\n"
            "PASTE SITES:\n"
            "  - Pastebin, GitHub Gists\n"
            "  - Ghostbin, 0bin\n"
            "  - Search: \"target.com\" + \"password\"\n"
            "DOCKER IMAGES:\n"
            "  # Secrets in Docker layers\n"
            "  dive <image>  # Explore layers\n"
            "  # Check for .env, config files in layers\n"
            "TOOLS:\n"
            "  trufflehog  # Secret scanning\n"
            "  gitleaks  # Git secret detection\n"
            "  h8mail  # Email breach hunting\n"
            "  porch-pirate  # Postman workspace leaks"
        ),
        "tools": ["trufflehog", "gitleaks", "h8mail"],
    },
]


class OSINTKB:
    """OSINT knowledge base.

    Provides OSINT techniques and patterns
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
        lines = ["## OSINT Techniques\n"]
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
