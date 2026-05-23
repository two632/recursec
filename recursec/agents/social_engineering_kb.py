"""Social engineering knowledge base.

Deep knowledge about social engineering assessment:
1. Phishing simulation
2. Pretexting scenarios
3. Vishing (voice phishing)
4. Physical security assessment
5. OSINT for social engineering
"""

from __future__ import annotations

from collections import defaultdict
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
    mitre_tactic: str = ""
    description: str = ""
    testing_methodology: str = ""
    tools: list[str] = field(default_factory=list)
    ethical_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "category": self.category[:12],
        }


SE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "se-001", "name": "Phishing Simulation",
        "category": "phishing", "severity": "high",
        "mitre_tactic": "T1566",
        "desc": "Email-based social engineering assessment.",
        "testing": (
            "PHISHING SIMULATION:\n"
            "1. RECONNAISSANCE:\n"
            "   - Gather employee information:\n"
            "     * LinkedIn: Job titles, departments, reporting structure\n"
            "     * theHarvester -d company.com -b linkedin,google,bing\n"
            "     * hunter.io: Email format discovery\n"
            "     * phonebook.cz: Email and phone enumeration\n"
            "   - Identify email format:\n"
            "     firstname.lastname@company.com, flastname@company.com, etc.\n"
            "   - Map organization structure\n"
            "2. INFRASTRUCTURE SETUP:\n"
            "   - Domain registration: Typosquatting or lookalike domain\n"
            "     * company.com → companny.com, c0mpany.com, company-portal.com\n"
            "   - Email sending:\n"
            "     * GoPhish: Full campaign management with tracking\n"
            "     * SPF/DKIM/DMARC configuration for deliverability\n"
            "   - Landing page:\n"
            "     * Clone legitimate login page (evilginx2 for real-time proxy)\n"
            "     * Track clicks, credential submissions, 2FA tokens\n"
            "3. CAMPAIGN TYPES:\n"
            "   - Credential harvesting: Fake login page\n"
            "   - Payload delivery: Macro-enabled document\n"
            "   - Link click tracking: Measure click rate\n"
            "   - Internal phishing: From compromised internal account\n"
            "4. METRICS:\n"
            "   - Open rate: % who opened the email\n"
            "   - Click rate: % who clicked the link\n"
            "   - Submit rate: % who entered credentials\n"
            "   - Report rate: % who reported as suspicious\n"
            "   - Time to first click\n"
            "5. ADVANCED:\n"
            "   - Spear-phishing: Targeted, personalized content\n"
            "   - Whaling: Target C-suite executives\n"
            "   - Business Email Compromise (BEC): Impersonate authority\n"
            "   - QR code phishing (Quishing): QR code to malicious URL"
        ),
        "tools": ["GoPhish", "evilginx2", "Modlishka", "King Phisher"],
        "ethics": "Always have written authorization. Coordinate with HR. Provide training after.",
    },
    {
        "id": "se-002", "name": "OSINT for Social Engineering",
        "category": "osint", "severity": "medium",
        "mitre_tactic": "T1589,T1591",
        "desc": "Open-source intelligence gathering for social engineering.",
        "testing": (
            "OSINT FOR SOCIAL ENGINEERING:\n"
            "1. PEOPLE SEARCH:\n"
            "   - LinkedIn: Full profile scraping (titles, connections, skills)\n"
            "   - Social media: Twitter, Facebook, Instagram\n"
            "   - Breached credentials: haveibeenpwned.com, dehashed.com\n"
            "   - Google dorking: site:linkedin.com 'company name'\n"
            "2. ORGANIZATION INTEL:\n"
            "   - Corporate structure: SEC filings (EDGAR), Crunchbase\n"
            "   - Technology stack: BuiltWith, Wappalyzer, LinkedIn jobs\n"
            "   - Public documents: PDF metadata (exiftool), FOCA\n"
            "   - DNS: MX records → email provider, TXT records → SPF/DMARC\n"
            "3. EMAIL INTELLIGENCE:\n"
            "   - Email format enumeration: hunter.io, phonebook.cz\n"
            "   - Verify emails: smtp-user-enum, EmailHippo\n"
            "   - Email header analysis: Received headers, X-Mailer\n"
            "4. CREDENTIAL INTELLIGENCE:\n"
            "   - Breach databases: Search for target domain\n"
            "   - Password patterns: Common patterns per organization\n"
            "   - Credential stuffing: Cross-reference breached passwords\n"
            "5. INFRASTRUCTURE MAPPING:\n"
            "   - Shodan: Search for company's public assets\n"
            "   - Censys: Certificate search for domains\n"
            "   - GitHub: Search for leaked secrets in repos\n"
            "     github.com/search?q=org:company+password&type=code\n"
            "6. TOOLS:\n"
            "   - SpiderFoot: Automated OSINT collection\n"
            "   - Maltego: Visual OSINT analysis\n"
            "   - Recon-ng: Modular OSINT framework\n"
            "   - Sherlock: Username enumeration across platforms"
        ),
        "tools": ["SpiderFoot", "Maltego", "Recon-ng", "Sherlock"],
        "ethics": "Stay within public data. Do not access private accounts.",
    },
    {
        "id": "se-003", "name": "Pretexting & Vishing",
        "category": "pretexting", "severity": "high",
        "mitre_tactic": "T1598",
        "desc": "Voice and scenario-based social engineering.",
        "testing": (
            "PRETEXTING & VISHING:\n"
            "1. PRETEXT DEVELOPMENT:\n"
            "   - IT support: 'Hi, this is IT. We're migrating accounts...'\n"
            "   - Vendor: 'This is the payment portal team from [vendor]...'\n"
            "   - Executive: 'This is [CEO name]. I need you to process...'\n"
            "   - New employee: 'Hi, I just started and need access to...'\n"
            "   - Survey: 'We're conducting a security awareness survey...'\n"
            "2. VISHING (VOICE PHISHING):\n"
            "   - Caller ID spoofing: Show internal company number\n"
            "   - AI voice synthesis: Clone executive's voice\n"
            "   - IVR exploitation: Navigate phone trees to reach targets\n"
            "   - Multi-stage: Email first, then follow-up call\n"
            "3. INFORMATION GATHERING:\n"
            "   - Password reset questions\n"
            "   - System/software versions in use\n"
            "   - Network topology information\n"
            "   - VPN/remote access procedures\n"
            "   - Physical access procedures\n"
            "4. SUCCESS METRICS:\n"
            "   - % of targets who disclosed information\n"
            "   - Types of information disclosed\n"
            "   - Resistance behaviors observed\n"
            "   - Average call duration\n"
            "   - Target verification attempts\n"
            "5. LEGAL & ETHICAL:\n"
            "   - Written authorization required\n"
            "   - Record calls only if legally permitted\n"
            "   - Stop immediately if target becomes distressed\n"
            "   - Provide post-assessment training"
        ),
        "tools": ["SpoofCard", "AI voice tools"],
        "ethics": "Written authorization mandatory. Never record without consent.",
    },
    {
        "id": "se-004", "name": "Physical Security Assessment",
        "category": "physical", "severity": "high",
        "mitre_tactic": "T1200",
        "desc": "Physical access and security testing.",
        "testing": (
            "PHYSICAL SECURITY ASSESSMENT:\n"
            "1. PERIMETER ASSESSMENT:\n"
            "   - Access points: Doors, gates, loading docks\n"
            "   - Lock assessment: Pick resistance, bypass methods\n"
            "   - Badge systems: RFID/NFC cloning\n"
            "     * Proxmark3: Clone HID iClass, MIFARE cards\n"
            "     * Flipper Zero: Read/emulate access cards\n"
            "   - Surveillance: Camera coverage, blind spots\n"
            "   - Tailgating opportunities\n"
            "2. BADGE CLONING:\n"
            "   - Long-range RFID reader to capture badge data\n"
            "   - Proxmark3 rdv4: Read and clone most RFID cards\n"
            "   - NFC phone: Read MIFARE Classic cards\n"
            "   - Create clone on blank card\n"
            "3. SOCIAL ENGINEERING ENTRY:\n"
            "   - Delivery person pretext (uniform + clipboard)\n"
            "   - Vendor/contractor pretext (hard hat + safety vest)\n"
            "   - IT maintenance pretext (laptop bag + badge)\n"
            "   - Tailgating: Follow authorized employee through door\n"
            "4. INSIDE ASSESSMENT:\n"
            "   - Unlocked workstations\n"
            "   - Visible credentials (Post-it notes, whiteboard)\n"
            "   - USB drop attack: Leave malicious USB drives\n"
            "   - Network jack access: Plug in rogue device\n"
            "   - Dumpster diving: Sensitive documents in trash\n"
            "5. DEVICE DROPS:\n"
            "   - Raspberry Pi with reverse shell\n"
            "   - Bash Bunny / Rubber Ducky\n"
            "   - WiFi Pineapple for rogue AP\n"
            "   - LAN Turtle for network access"
        ),
        "tools": ["Proxmark3", "Flipper Zero", "WiFi Pineapple", "Bash Bunny"],
        "ethics": "Written authorization for physical access. Carry authorization letter at all times.",
    },
]


class SocialEngineeringKB:
    """Social engineering knowledge base.

    Provides social engineering testing methodology
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, SocialEngPattern] = {}
        self._log = logger.bind(component="social_engineering_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load SE patterns."""
        for data in SE_PATTERNS:
            pattern = SocialEngPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                mitre_tactic=data.get("mitre_tactic", ""),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
                ethical_notes=data.get("ethics", ""),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_category(
        self,
        category: str,
    ) -> list[SocialEngPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category == category
        ]

    def build_se_prompt(
        self,
        categories: list[str] | None = None,
        include_ethics: bool = True,
        max_patterns: int = 3,
    ) -> str:
        """Build social engineering prompt."""
        lines = ["## Social Engineering Assessment\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category not in categories:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            if pattern.mitre_tactic:
                lines.append(f"MITRE: {pattern.mitre_tactic}")
            lines.append(pattern.testing_methodology)
            if include_ethics and pattern.ethical_notes:
                lines.append(f"ETHICS: {pattern.ethical_notes}")
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            cat_counts[p.category] += 1
        return {
            "patterns": len(self._patterns),
            "by_category": dict(cat_counts),
        }
