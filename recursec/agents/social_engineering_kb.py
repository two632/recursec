"""Social engineering knowledge base.

Knowledge about social engineering attacks:
1. Phishing campaign analysis
2. Pretexting frameworks
3. Vishing (voice phishing)
4. Physical security assessment
5. Social media intelligence
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class SocialEngPattern:
    """A social engineering pattern."""
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


SOCIAL_ENG_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "se-001", "name": "Phishing Campaign Analysis",
        "category": "phishing", "severity": "high",
        "desc": "Analyzing and detecting phishing infrastructure.",
        "detection": (
            "PHISHING ANALYSIS:\n"
            "INFRASTRUCTURE DETECTION:\n"
            "  - Check newly registered domains (< 30 days)\n"
            "  - Lookalike domain detection:\n"
            "    dnstwist <domain>  # Generate and check permutations\n"
            "    urlcrazy <domain>  # Alternative domain fuzzer\n"
            "  - Check certificate transparency logs:\n"
            "    crt.sh/?q=%.<domain>\n"
            "  - Analyze DNS records:\n"
            "    dig <suspicious_domain> +short\n"
            "    whois <suspicious_domain>\n"
            "EMAIL ANALYSIS:\n"
            "  - Check SPF, DKIM, DMARC records:\n"
            "    dig TXT <domain> | grep spf\n"
            "    dig TXT _dmarc.<domain>\n"
            "  - Analyze email headers for forging\n"
            "  - Check Received headers chain\n"
            "  - Verify Return-Path matches From\n"
            "LANDING PAGE ANALYSIS:\n"
            "  - Screenshot with httpx -screenshot\n"
            "  - Compare visual similarity to legitimate\n"
            "  - Check for credential harvesting forms\n"
            "  - Analyze JavaScript for data exfiltration\n"
            "  - Check embedded links and redirects"
        ),
        "tools": ["dnstwist", "urlcrazy", "theharvester"],
    },
    {
        "id": "se-002", "name": "OSINT for Social Engineering",
        "category": "osint_se", "severity": "medium",
        "desc": "Gathering intelligence for social engineering attacks.",
        "detection": (
            "SOCIAL ENGINEERING OSINT:\n"
            "PEOPLE INTELLIGENCE:\n"
            "  - LinkedIn: org chart, roles, technologies\n"
            "  - GitHub: employee repos, email addresses, code\n"
            "  - Social media: personal info, interests, routines\n"
            "  - Breach databases: compromised credentials\n"
            "  - Job postings: technology stack, tools used\n"
            "EMAIL HARVESTING:\n"
            "  theHarvester -d <domain> -b all\n"
            "  hunter.io (email pattern detection)\n"
            "  # Verify emails\n"
            "  smtp-user-enum -M VRFY -D <domain> -U users.txt\n"
            "ORGANIZATIONAL MAPPING:\n"
            "  - Identify IT admins (highest value targets)\n"
            "  - Map reporting structure\n"
            "  - Identify new employees (less security-aware)\n"
            "  - Find contractors (weaker security controls)\n"
            "TECHNOLOGY PROFILING:\n"
            "  - Wappalyzer: Detect web technologies\n"
            "  - BuiltWith: Historical technology usage\n"
            "  - Shodan: Exposed services and versions\n"
            "  - Security job postings reveal tools in use"
        ),
        "tools": ["theharvester", "sherlock", "maltego"],
    },
    {
        "id": "se-003", "name": "Credential Stuffing and Spraying",
        "category": "credential", "severity": "high",
        "desc": "Automated credential attacks using leaked data.",
        "detection": (
            "CREDENTIAL ATTACKS:\n"
            "CREDENTIAL STUFFING:\n"
            "  - Use leaked credentials from breaches\n"
            "  - Test across multiple services\n"
            "  - Tools:\n"
            "    sentry-mba  # Multi-threaded credential checker\n"
            "    storm-breaker  # Credential stuffing framework\n"
            "  - Proxy rotation to avoid blocking\n"
            "  - Respect rate limits to stay under radar\n"
            "PASSWORD SPRAYING:\n"
            "  - Use common passwords across many accounts\n"
            "  - Low and slow to avoid lockout\n"
            "  - Tools:\n"
            "    sprayhound  # AD password spraying\n"
            "    trevorspray  # O365/Azure spraying\n"
            "    o365spray -d <domain> --spray -u users.txt -p <password>\n"
            "  - Common passwords to try:\n"
            "    Season+Year: Winter2026!, Summer2026!\n"
            "    Company+number: CompanyName1!\n"
            "    Welcome1!, Password123!\n"
            "DEFAULT CREDENTIALS:\n"
            "  - Check default-creds-cheat-sheet on GitHub\n"
            "  - Common: admin/admin, root/toor, admin/password\n"
            "  - Device-specific defaults (routers, printers, SCADA)\n"
            "BREACH CHECKING:\n"
            "  - HaveIBeenPwned API\n"
            "  - DeHashed (paid, more comprehensive)\n"
            "  - Check paste sites for dumps"
        ),
        "tools": ["hydra", "sprayhound", "trevorspray"],
    },
    {
        "id": "se-004", "name": "Physical Security Assessment",
        "category": "physical", "severity": "high",
        "desc": "Physical security testing methodology.",
        "detection": (
            "PHYSICAL SECURITY:\n"
            "RECONNAISSANCE:\n"
            "  - Google Maps/Earth: Building layout, entrances\n"
            "  - Social media: Office photos showing layouts\n"
            "  - Job site visits during business hours\n"
            "  - Dumpster diving for documents/devices\n"
            "ACCESS CONTROL TESTING:\n"
            "  - Tailgating: Follow authorized person through door\n"
            "  - Badge cloning (Proxmark3 + RFID cloner)\n"
            "  - Lock picking/bypassing\n"
            "  - Smoke detector exit button exploitation\n"
            "  - Under-door tool for lever handles\n"
            "NETWORK ACCESS:\n"
            "  - Unattended Ethernet ports in lobbies\n"
            "  - Rogue wireless access points\n"
            "  - Bash Bunny / Rubber Ducky USB drops\n"
            "  - LAN Turtle (stealth network implant)\n"
            "  - WiFi Pineapple (rogue AP)\n"
            "DOCUMENT TESTING:\n"
            "  - Sensitive documents in trash/recycling\n"
            "  - Visible on desks/monitors\n"
            "  - Clean desk policy compliance\n"
            "  - Printer/copier memory extraction"
        ),
        "tools": ["proxmark3", "wifi-pineapple"],
    },
    {
        "id": "se-005", "name": "Awareness and Training Metrics",
        "category": "metrics", "severity": "medium",
        "desc": "Measuring social engineering resilience.",
        "detection": (
            "SE METRICS AND MEASUREMENT:\n"
            "PHISHING SIMULATION:\n"
            "  - GoPhish: Open-source phishing framework\n"
            "    gophish  # Start server\n"
            "    # Create campaign with templates\n"
            "    # Track: opened, clicked, submitted\n"
            "  - King Phisher: Advanced phishing toolkit\n"
            "  - Metrics to track:\n"
            "    Click rate: % who clicked link\n"
            "    Submit rate: % who entered credentials\n"
            "    Report rate: % who reported to IT\n"
            "    Time to click: How quickly users fell for it\n"
            "RISK SCORING:\n"
            "  - Department-level vulnerability scores\n"
            "  - Individual repeat offender tracking\n"
            "  - Correlation with job role\n"
            "  - Improvement over time (training effectiveness)\n"
            "REPORTING:\n"
            "  - Executive summary with risk metrics\n"
            "  - Department breakdown\n"
            "  - Trend analysis over multiple campaigns\n"
            "  - Comparison with industry benchmarks\n"
            "  - Specific recommendations per finding"
        ),
        "tools": ["gophish", "king-phisher"],
    },
]


class SocialEngineeringKB:
    """Social engineering knowledge base.

    Provides social engineering patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, SocialEngPattern] = {}
        self._log = logger.bind(component="social_engineering_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load social engineering patterns."""
        for data in SOCIAL_ENG_PATTERNS:
            pattern = SocialEngPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[SocialEngPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_social_eng_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build social engineering prompt."""
        lines = ["## Social Engineering Patterns\n"]
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
