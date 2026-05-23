"""Social engineering knowledge base.

Deep knowledge about social engineering techniques:
1. Phishing and spear-phishing
2. Pretexting and impersonation
3. Physical security testing
4. Voice phishing (vishing)
5. Social media exploitation
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
        "id": "se-001", "name": "Phishing Campaigns",
        "category": "phishing", "severity": "high",
        "desc": "Phishing and spear-phishing techniques.",
        "detection": (
            "PHISHING CAMPAIGNS:\n"
            "EMAIL PHISHING:\n"
            "  - Credential harvesting (fake login pages)\n"
            "  - Malicious attachments (macro docs, HTA, ISO)\n"
            "  - Link manipulation (homograph, URL shortening)\n"
            "  - HTML smuggling (encode payload in HTML)\n"
            "INFRASTRUCTURE:\n"
            "  # GoPhish — phishing campaign framework\n"
            "  gophish  # Web UI for campaigns\n"
            "  # Evilginx2 — MFA phishing proxy\n"
            "  evilginx2  # Transparent reverse proxy\n"
            "  # Captures session cookies after MFA\n"
            "  # King Phisher — phishing campaign toolkit\n"
            "PAYLOAD DELIVERY:\n"
            "  - Office macros (VBA, XLSB)\n"
            "  - ISO/IMG containers (bypass MOTW)\n"
            "  - LNK shortcut files\n"
            "  - OneNote with embedded scripts\n"
            "  - CHM help files\n"
            "  - HTML applications (.hta)\n"
            "DETECTION EVASION:\n"
            "  - SPF/DKIM/DMARC bypass\n"
            "  - Domain aging (register weeks before)\n"
            "  - Lookalike domains (homoglyphs)\n"
            "  - Compromised legitimate accounts\n"
            "  - Thread hijacking (reply to real email)"
        ),
        "tools": ["gophish", "evilginx2"],
    },
    {
        "id": "se-002", "name": "Pretexting and Impersonation",
        "category": "pretexting", "severity": "high",
        "desc": "Pretexting and impersonation techniques.",
        "detection": (
            "PRETEXTING AND IMPERSONATION:\n"
            "COMMON PRETEXTS:\n"
            "  - IT support: 'We need to verify your account'\n"
            "  - Executive: 'I need this done urgently' (BEC)\n"
            "  - Vendor: 'Updated payment information'\n"
            "  - New employee: 'I cannot access the system'\n"
            "  - Delivery person: 'I have a package'\n"
            "  - Auditor: 'I need access for compliance'\n"
            "BUSINESS EMAIL COMPROMISE (BEC):\n"
            "  - CEO fraud (impersonate executive)\n"
            "  - Invoice fraud (modified bank details)\n"
            "  - Account compromise (use real account)\n"
            "  - Attorney impersonation\n"
            "  - Data theft (HR/finance targets)\n"
            "TECHNIQUES:\n"
            "  - Authority: Impersonate someone with power\n"
            "  - Urgency: Create time pressure\n"
            "  - Scarcity: Limited time offer\n"
            "  - Social proof: Everyone else has done this\n"
            "  - Reciprocity: I did something for you\n"
            "  - Likability: Build rapport first\n"
            "DEFENSE TESTING:\n"
            "  - Test employee awareness\n"
            "  - Verify escalation procedures\n"
            "  - Check identity verification processes"
        ),
        "tools": [],
    },
    {
        "id": "se-003", "name": "Physical Security Testing",
        "category": "physical", "severity": "high",
        "desc": "Physical security assessment techniques.",
        "detection": (
            "PHYSICAL SECURITY TESTING:\n"
            "ACCESS CONTROL:\n"
            "  - Tailgating/piggybacking\n"
            "  - Badge cloning (Proxmark3, Flipper Zero)\n"
            "  - Lock picking (standard, bypass)\n"
            "  - Door propping (wedge, tape)\n"
            "  - Emergency exit bar manipulation\n"
            "RECONNAISSANCE:\n"
            "  - Building layout mapping\n"
            "  - Camera placement identification\n"
            "  - Guard rotation patterns\n"
            "  - Delivery schedule observation\n"
            "  - Dumpster diving\n"
            "  - WiFi signal analysis from outside\n"
            "TECHNIQUES:\n"
            "  - Delivery impersonation\n"
            "  - Maintenance worker pretext\n"
            "  - Visitor badge abuse\n"
            "  - USB drop attack\n"
            "  - Rogue device placement\n"
            "    * Network implant (LAN turtle)\n"
            "    * WiFi pineapple (rogue AP)\n"
            "    * Keylogger (hardware)\n"
            "    * Rubber Ducky (USB HID)\n"
            "TOOLS:\n"
            "  Proxmark3  # RFID/NFC cloning\n"
            "  Flipper Zero  # Multi-tool\n"
            "  WiFi Pineapple  # Rogue AP\n"
            "  LAN Turtle  # Network implant"
        ),
        "tools": ["proxmark3", "flipper"],
    },
    {
        "id": "se-004", "name": "Voice Phishing (Vishing)",
        "category": "vishing", "severity": "medium",
        "desc": "Voice-based social engineering techniques.",
        "detection": (
            "VOICE PHISHING (VISHING):\n"
            "TECHNIQUES:\n"
            "  - Caller ID spoofing\n"
            "  - IVR (Interactive Voice Response) phishing\n"
            "  - Callback phishing (BazarCall)\n"
            "  - AI voice cloning (deepfake audio)\n"
            "  - VoIP for untraceable calls\n"
            "COMMON SCENARIOS:\n"
            "  - Bank: 'Suspicious activity on your account'\n"
            "  - IT help desk: 'Your account is locked'\n"
            "  - Government: 'Tax issue requires immediate attention'\n"
            "  - Tech support: 'Your computer is infected'\n"
            "INFORMATION GATHERING:\n"
            "  - Full name and employee ID\n"
            "  - Manager's name\n"
            "  - Internal system names\n"
            "  - Help desk procedures\n"
            "  - VPN/remote access details\n"
            "  - Password reset procedures\n"
            "AI DEEPFAKE:\n"
            "  - Real-time voice cloning\n"
            "  - Impersonate CEO/manager voice\n"
            "  - Combined with video deepfake\n"
            "DEFENSE TESTING:\n"
            "  - Call back verification\n"
            "  - Out-of-band confirmation\n"
            "  - Code word verification"
        ),
        "tools": [],
    },
    {
        "id": "se-005", "name": "Social Media Intelligence",
        "category": "socmint", "severity": "medium",
        "desc": "Social media exploitation for social engineering.",
        "detection": (
            "SOCIAL MEDIA INTELLIGENCE (SOCMINT):\n"
            "RECONNAISSANCE:\n"
            "  - Employee identification (LinkedIn)\n"
            "  - Organizational structure mapping\n"
            "  - Technology stack from job postings\n"
            "  - Personal interests and hobbies\n"
            "  - Travel schedules\n"
            "  - Personal email addresses\n"
            "  - Family and relationships\n"
            "LINKEDIN:\n"
            "  - Employee enumeration\n"
            "  - Email format discovery\n"
            "  - Connection mapping\n"
            "  - Skills and technologies used\n"
            "  - Former employees (may still have access)\n"
            "FACEBOOK/INSTAGRAM:\n"
            "  - Personal details for pretexting\n"
            "  - Security question answers\n"
            "  - Workplace photos (badges, screens)\n"
            "  - Check-ins (physical location)\n"
            "TWITTER/X:\n"
            "  - Technical discussions (leak info)\n"
            "  - Vendor relationships\n"
            "  - Complaint threads (frustration = vulnerability)\n"
            "GITHUB:\n"
            "  - Committed secrets/credentials\n"
            "  - Internal tool names\n"
            "  - Infrastructure details in configs\n"
            "  - Employee personal accounts\n"
            "TOOLS:\n"
            "  sherlock  # Username search across platforms\n"
            "  theHarvester  # Email/subdomain OSINT\n"
            "  maltego  # Link analysis/visualization"
        ),
        "tools": ["sherlock", "theHarvester", "maltego"],
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
        lines = ["## Social Engineering Techniques\n"]
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
