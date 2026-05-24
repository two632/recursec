"""Social engineering knowledge base.

Deep knowledge about social engineering:
1. Phishing campaigns
2. Pretexting and impersonation
3. Physical social engineering
4. Vishing and smishing
5. Influence and manipulation
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


SE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "se-001", "name": "Phishing Campaigns",
        "category": "phishing", "severity": "high",
        "desc": "Phishing attack techniques for security testing.",
        "detection": (
            "PHISHING CAMPAIGNS:\n"
            "EMAIL PHISHING:\n"
            "  - Credential harvesting (cloned login pages)\n"
            "  - Payload delivery (macro documents, HTA)\n"
            "  - URL shorteners and redirectors\n"
            "  - Lookalike domains (homoglyph)\n"
            "  - Typosquatted domains\n"
            "SPEAR PHISHING:\n"
            "  - OSINT-driven personalization\n"
            "  - Impersonate known contacts\n"
            "  - Reference recent events/projects\n"
            "  - Embed in existing email threads\n"
            "TECHNICAL:\n"
            "  # GoPhish setup\n"
            "  gophish  # Web UI on :3333\n"
            "  # Create campaign → template → landing page\n"
            "  # Track opens, clicks, submissions\n"
            "  # Evilginx (real-time phishing proxy)\n"
            "  evilginx2  # Captures session tokens\n"
            "  # Bypasses 2FA (real-time relay)\n"
            "DELIVERY:\n"
            "  - SPF/DKIM/DMARC bypass techniques\n"
            "  - Authenticated SMTP relay\n"
            "  - Cloud email services (sendgrid, SES)\n"
            "  - Attachment alternatives:\n"
            "    .html (offline credential form)\n"
            "    .iso/.img (mark-of-web bypass)\n"
            "    .lnk (shortcut with payload)\n"
            "    OneNote (.one) with embedded files\n"
            "TOOLS:\n"
            "  GoPhish, Evilginx2, SET, King Phisher"
        ),
        "tools": ["gophish", "evilginx2"],
    },
    {
        "id": "se-002", "name": "Pretexting and Impersonation",
        "category": "pretexting", "severity": "high",
        "desc": "Pretexting techniques for engagements.",
        "detection": (
            "PRETEXTING AND IMPERSONATION:\n"
            "COMMON PRETEXTS:\n"
            "  - IT support / helpdesk\n"
            "  - Vendor / contractor\n"
            "  - New employee\n"
            "  - Executive / management\n"
            "  - Delivery person\n"
            "  - Building maintenance\n"
            "  - Fire marshal / inspector\n"
            "  - Auditor / compliance\n"
            "BEC (Business Email Compromise):\n"
            "  - CEO fraud (wire transfer request)\n"
            "  - Invoice manipulation\n"
            "  - Attorney impersonation\n"
            "  - W-2/tax form request\n"
            "  - Account changes (bank details)\n"
            "PREPARATION:\n"
            "  - OSINT on target personnel\n"
            "  - Org chart reconstruction\n"
            "  - Communication style analysis\n"
            "  - Industry terminology\n"
            "  - Timing (payroll, quarter-end)\n"
            "AI-ENHANCED:\n"
            "  - Voice cloning (deepfake calls)\n"
            "  - AI-generated emails (style matching)\n"
            "  - Video deepfakes for video calls\n"
            "  - Automated persona management\n"
            "DEFENSE:\n"
            "  - Callback verification\n"
            "  - Multi-person approval for transfers\n"
            "  - Security awareness training\n"
            "  - Out-of-band verification"
        ),
        "tools": [],
    },
    {
        "id": "se-003", "name": "Physical Social Engineering",
        "category": "physical", "severity": "high",
        "desc": "Physical social engineering techniques.",
        "detection": (
            "PHYSICAL SOCIAL ENGINEERING:\n"
            "TECHNIQUES:\n"
            "  - Tailgating / piggybacking\n"
            "  - Badge cloning (RFID/Prox)\n"
            "  - Dumpster diving\n"
            "  - Shoulder surfing\n"
            "  - USB drop (BadUSB, Rubber Ducky)\n"
            "  - Unauthorized photography\n"
            "BUILDING ACCESS:\n"
            "  - Delivery pretext (UPS, FedEx)\n"
            "  - Smoking area access\n"
            "  - Loading dock entry\n"
            "  - Emergency door propping\n"
            "  - Visitor sign-in bypass\n"
            "  - Elevator surfing\n"
            "DROP DEVICES:\n"
            "  - USB Rubber Ducky (HID injection)\n"
            "  - Bash Bunny (multi-payload)\n"
            "  - LAN Turtle (network implant)\n"
            "  - WiFi Pineapple (rogue AP)\n"
            "  - Raspberry Pi (persistent access)\n"
            "  - Keylogger (hardware)\n"
            "ASSESSMENT:\n"
            "  - Document all entry methods used\n"
            "  - Photograph security gaps\n"
            "  - Test badge readers and locks\n"
            "  - Map camera blind spots\n"
            "  - Test alarm response times\n"
            "TOOLS:\n"
            "  Proxmark3, Flipper Zero, Rubber Ducky, WiFi Pineapple"
        ),
        "tools": ["proxmark3", "flipper-zero"],
    },
    {
        "id": "se-004", "name": "Vishing and Smishing",
        "category": "vishing", "severity": "medium",
        "desc": "Voice and SMS phishing techniques.",
        "detection": (
            "VISHING AND SMISHING:\n"
            "VISHING (Voice):\n"
            "  - Call employees as IT support\n"
            "  - Request credentials for 'emergency'\n"
            "  - Caller ID spoofing\n"
            "  - IVR (Interactive Voice Response) phishing\n"
            "  - Voicemail social engineering\n"
            "PREPARATION:\n"
            "  - OSINT target phone numbers\n"
            "  - Record professional greetings\n"
            "  - Prepare rebuttals for common objections\n"
            "  - Background noise (call center sounds)\n"
            "  - VoIP with spoofed caller ID\n"
            "SMISHING (SMS):\n"
            "  - Shortened URLs to credential pages\n"
            "  - 'Your account has been locked' messages\n"
            "  - Package delivery notifications\n"
            "  - MFA fatigue via SMS\n"
            "  - SMS interception (SIM swap)\n"
            "AI VOICE:\n"
            "  - Real-time voice cloning\n"
            "  - Language translation\n"
            "  - Accent modification\n"
            "  - Emotional tone adjustment\n"
            "DEFENSE:\n"
            "  - Callback to known number\n"
            "  - Never share credentials by phone\n"
            "  - Verify through official channels\n"
            "  - Report suspicious calls"
        ),
        "tools": [],
    },
    {
        "id": "se-005", "name": "Influence and Manipulation",
        "category": "influence", "severity": "medium",
        "desc": "Psychological influence techniques.",
        "detection": (
            "INFLUENCE AND MANIPULATION:\n"
            "CIALDINI PRINCIPLES:\n"
            "  1. Reciprocity: Give first, then ask\n"
            "  2. Commitment: Get small yes, then big yes\n"
            "  3. Social Proof: 'Everyone in IT already did this'\n"
            "  4. Authority: Impersonate authority figure\n"
            "  5. Liking: Build rapport first\n"
            "  6. Scarcity: 'Only 10 minutes before lockout'\n"
            "  7. Unity: 'We're in this together'\n"
            "APPLICATION:\n"
            "  URGENCY:\n"
            "    - 'CEO needs this before the board meeting'\n"
            "    - 'Security breach detected, verify now'\n"
            "    - 'Your account will be deleted'\n"
            "  AUTHORITY:\n"
            "    - 'This is from the CTO's office'\n"
            "    - 'Legal requires immediate compliance'\n"
            "    - 'Auditor needs access today'\n"
            "  HELPFULNESS:\n"
            "    - 'I'm from IT, I can fix that for you'\n"
            "    - 'Let me help you update your password'\n"
            "    - 'I'll need your credentials to troubleshoot'\n"
            "COGNITIVE BIASES:\n"
            "  - Anchoring (first impression dominates)\n"
            "  - Confirmation bias (believe what fits)\n"
            "  - Authority bias (obey authority)\n"
            "  - Halo effect (attractive = trustworthy)\n"
            "  - Dunning-Kruger (overconfidence)\n"
            "DEFENSE:\n"
            "  - Security awareness training\n"
            "  - Simulated attacks (regular testing)\n"
            "  - Clear reporting procedures"
        ),
        "tools": [],
    },
]


class SocialEngineeringKB:
    """Social engineering knowledge base.

    Provides SE patterns injected into agent prompts.
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

    def build_social_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build social engineering prompt."""
        lines = ["## Social Engineering\n"]
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
