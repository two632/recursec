"""Social engineering knowledge base.

Deep knowledge about social engineering:
1. Phishing campaign techniques
2. Pretexting and impersonation
3. Physical social engineering
4. Credential harvesting
5. Social media reconnaissance
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
        "id": "se-001", "name": "Phishing Infrastructure",
        "category": "phishing", "severity": "high",
        "desc": "Building and detecting phishing infrastructure.",
        "detection": (
            "PHISHING INFRASTRUCTURE:\n"
            "RECONNAISSANCE:\n"
            "  - Identify target email format (first.last@company.com)\n"
            "  - Harvest emails: theHarvester, Hunter.io, LinkedIn\n"
            "  theHarvester -d company.com -b all\n"
            "  - Identify email protection (SPF, DKIM, DMARC)\n"
            "  dig TXT company.com  # SPF record\n"
            "  dig TXT _dmarc.company.com  # DMARC policy\n"
            "  dig TXT selector._domainkey.company.com  # DKIM\n"
            "DOMAIN ANALYSIS:\n"
            "  - Lookalike domain detection\n"
            "  dnstwist company.com  # Generate lookalikes\n"
            "  - Check registered lookalikes\n"
            "  - Monitor certificate transparency logs\n"
            "  - Check domain age and registration info\n"
            "DETECTION:\n"
            "  - SPF alignment check (envelope from vs header from)\n"
            "  - DKIM signature validation\n"
            "  - DMARC policy enforcement\n"
            "  - Header analysis (X-Originating-IP, Received chain)\n"
            "  - URL analysis in email body\n"
            "  - Attachment analysis (macro, exploit docs)\n"
            "TOOLS:\n"
            "  - GoPhish: Phishing simulation framework\n"
            "  - King Phisher: Campaign management\n"
            "  - Evilginx2: Transparent reverse proxy for MFA bypass\n"
            "  - Modlishka: Reverse proxy phishing"
        ),
        "tools": ["gophish", "evilginx2", "theharvester"],
    },
    {
        "id": "se-002", "name": "Credential Harvesting Techniques",
        "category": "credential", "severity": "critical",
        "desc": "Techniques for harvesting credentials.",
        "detection": (
            "CREDENTIAL HARVESTING:\n"
            "WEB-BASED:\n"
            "  - Clone target login page\n"
            "  - Transparent proxy (evilginx2, modlishka)\n"
            "  - Captures credentials AND session cookies\n"
            "  - Bypasses MFA (real-time proxy)\n"
            "  evilginx2:\n"
            "    phishlets hostname <site> <domain>\n"
            "    phishlets enable <site>\n"
            "    lures create <site>\n"
            "WIFI-BASED:\n"
            "  - Evil twin with captive portal\n"
            "  - WiFi Pineapple\n"
            "  - Capture WPA handshake + credential page\n"
            "DOCUMENT-BASED:\n"
            "  - Macro-enabled documents\n"
            "  - HTA files via email\n"
            "  - SVG files with embedded scripts\n"
            "  - PDF with JavaScript actions\n"
            "BROWSER-BASED:\n"
            "  - Browser-in-the-Browser (BITB) attack\n"
            "  - Fake OAuth consent screens\n"
            "  - JavaScript keylogger injection\n"
            "  - Clipboard hijacking\n"
            "DETECTION INDICATORS:\n"
            "  - URL mismatch with claimed sender\n"
            "  - Recently registered domains\n"
            "  - Self-signed or suspicious certificates\n"
            "  - Unusual redirect chains"
        ),
        "tools": ["evilginx2", "gophish"],
    },
    {
        "id": "se-003", "name": "OSINT for Social Engineering",
        "category": "osint", "severity": "medium",
        "desc": "Open-source intelligence gathering for SE attacks.",
        "detection": (
            "OSINT FOR SOCIAL ENGINEERING:\n"
            "PEOPLE INTELLIGENCE:\n"
            "  - LinkedIn: Employees, roles, technologies\n"
            "  - GitHub: Developer emails, code patterns\n"
            "  - Social media: Personal info, relationships\n"
            "  - Job postings: Internal technologies used\n"
            "TOOLS:\n"
            "  # Email discovery\n"
            "  theHarvester -d company.com -b all\n"
            "  # Username enumeration\n"
            "  sherlock <username>  # Check 300+ sites\n"
            "  # Full OSINT\n"
            "  maltego  # Visual link analysis\n"
            "  recon-ng  # OSINT framework\n"
            "  spiderfoot -s company.com  # Automated\n"
            "INFRASTRUCTURE OSINT:\n"
            "  - DNS records (subdomains, mail servers)\n"
            "  - Certificate transparency (crt.sh)\n"
            "  - Shodan/Censys for exposed services\n"
            "  - Wayback Machine for old content\n"
            "  - Google dorking for sensitive docs\n"
            "    site:company.com filetype:pdf\n"
            "    site:company.com inurl:admin\n"
            "    site:company.com 'password' filetype:xlsx\n"
            "BREACH DATA:\n"
            "  - HaveIBeenPwned (API for programmatic check)\n"
            "  - DeHashed for credential lookup\n"
            "  - IntelX for historical data"
        ),
        "tools": ["theharvester", "sherlock", "spiderfoot"],
    },
    {
        "id": "se-004", "name": "Vishing and Voice Attacks",
        "category": "vishing", "severity": "high",
        "desc": "Voice-based social engineering techniques.",
        "detection": (
            "VISHING (Voice Phishing):\n"
            "TECHNIQUES:\n"
            "  - IT helpdesk impersonation\n"
            "  - VPN/password reset pretext\n"
            "  - Vendor/supplier impersonation\n"
            "  - Executive impersonation (CEO fraud)\n"
            "  - Technical support scam\n"
            "CALLER ID SPOOFING:\n"
            "  - SIP-based VoIP spoofing\n"
            "  - Display company's own number\n"
            "  - Use local area codes\n"
            "AI-ENHANCED:\n"
            "  - Voice cloning (deepfake audio)\n"
            "  - Real-time voice modification\n"
            "  - AI-generated conversation scripts\n"
            "  - Automated call campaigns\n"
            "DETECTION:\n"
            "  - Callback verification to known numbers\n"
            "  - Caller ID verification policies\n"
            "  - Voice biometric analysis\n"
            "  - Call recording and review\n"
            "  - Out-of-band verification for sensitive requests\n"
            "ASSESSMENT:\n"
            "  - Test helpdesk procedures\n"
            "  - Attempt password resets via phone\n"
            "  - Test out-of-band verification compliance\n"
            "  - Document policy violations"
        ),
        "tools": ["asterisk", "sipvicious"],
    },
    {
        "id": "se-005", "name": "Physical Security Testing",
        "category": "physical", "severity": "high",
        "desc": "Physical security assessment techniques.",
        "detection": (
            "PHYSICAL SECURITY TESTING:\n"
            "ACCESS CONTROL:\n"
            "  - Tailgating/piggybacking test\n"
            "  - Badge cloning (Proxmark3)\n"
            "  - Lock picking assessment\n"
            "  - Window/door security check\n"
            "  - After-hours access test\n"
            "BADGE CLONING:\n"
            "  - Proxmark3 for RFID/NFC\n"
            "  - Read and clone access cards\n"
            "  - Supports HID, MIFARE, EM4100\n"
            "  - Long-range readers for covert cloning\n"
            "SURVEILLANCE:\n"
            "  - Camera coverage mapping\n"
            "  - Blind spot identification\n"
            "  - Guard patrol patterns\n"
            "  - Alarm system testing\n"
            "ASSESSMENT AREAS:\n"
            "  - Lobby/reception security\n"
            "  - Server room access controls\n"
            "  - Document disposal (dumpster diving)\n"
            "  - Clean desk policy compliance\n"
            "  - USB drop test (baiting)\n"
            "  - WiFi from parking lot\n"
            "  - Visible screens from outside\n"
            "  - Unlocked workstations"
        ),
        "tools": ["proxmark3", "flipper-zero"],
    },
]


class SocialEngineeringKB:
    """Social engineering knowledge base.

    Provides social engineering patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, SocialEngPattern] = {}
        self._log = logger.bind(component="social_eng_kb")
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
