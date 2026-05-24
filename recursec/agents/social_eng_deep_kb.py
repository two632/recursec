"""Social engineering deep-dive knowledge base.

Deep knowledge about social engineering:
1. Phishing campaign analysis
2. Pretexting and impersonation
3. Vishing and smishing
4. Physical social engineering
5. Social engineering defense testing
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


SOCIALENG_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "se-001", "name": "Phishing Campaign Analysis",
        "category": "phishing", "severity": "high",
        "desc": "Phishing campaign techniques.",
        "detection": (
            "PHISHING CAMPAIGN ANALYSIS:\n"
            "EMAIL PHISHING:\n"
            "  - Spoofed sender (DMARC/DKIM bypass)\n"
            "  - Lookalike domains (homograph)\n"
            "  - Urgency/authority framing\n"
            "  - Credential harvesting pages\n"
            "  - Malicious attachments (macro, ISO, LNK)\n"
            "  - HTML smuggling\n"
            "  - QR code phishing (quishing)\n"
            "SPEAR PHISHING:\n"
            "  - OSINT-based personalization\n"
            "  - Organization-specific lures\n"
            "  - Role-based targeting (C-suite, IT, HR)\n"
            "  - Business email compromise (BEC)\n"
            "  - Supply chain phishing\n"
            "INFRASTRUCTURE:\n"
            "  - Domain setup (typosquatting)\n"
            "  - SSL certificates (Let's Encrypt)\n"
            "  - Hosting on legitimate services\n"
            "  - Redirectors and proxies\n"
            "  - URL shorteners for obfuscation\n"
            "EMAIL SECURITY:\n"
            "  - SPF record check\n"
            "  - DKIM verification\n"
            "  - DMARC policy analysis\n"
            "  - Header analysis (X-Originating-IP)\n"
            "  - MX record enumeration\n"
            "TOOLS:\n"
            "  GoPhish, King Phisher, Evilginx2, SET"
        ),
        "tools": ["gophish"],
    },
    {
        "id": "se-002", "name": "Pretexting and Impersonation",
        "category": "pretexting", "severity": "high",
        "desc": "Pretexting and impersonation techniques.",
        "detection": (
            "PRETEXTING & IMPERSONATION:\n"
            "RESEARCH:\n"
            "  - Target organization structure\n"
            "  - Key personnel identification\n"
            "  - Communication patterns\n"
            "  - Internal terminology/jargon\n"
            "  - Recent events/projects\n"
            "  - Vendor relationships\n"
            "PRETEXTS:\n"
            "  - IT support/helpdesk\n"
            "  - New employee onboarding\n"
            "  - Executive assistant\n"
            "  - Vendor/contractor\n"
            "  - Auditor/compliance\n"
            "  - Law enforcement\n"
            "  - Building maintenance\n"
            "  - Delivery service\n"
            "EXECUTION:\n"
            "  - Authority establishment\n"
            "  - Rapport building\n"
            "  - Urgency creation\n"
            "  - Information elicitation\n"
            "  - Credential/access request\n"
            "  - Call-back verification bypass\n"
            "DEFENSE TESTING:\n"
            "  - Test employee response to:\n"
            "    # Unknown callers requesting access\n"
            "    # Email from spoofed executives\n"
            "    # Requests to bypass procedure\n"
            "    # Tailgating attempts\n"
            "TOOLS:\n"
            "  SET, Social Media OSINT tools"
        ),
        "tools": [],
    },
    {
        "id": "se-003", "name": "Vishing and Smishing",
        "category": "vishing", "severity": "medium",
        "desc": "Voice and SMS social engineering.",
        "detection": (
            "VISHING & SMISHING:\n"
            "VISHING:\n"
            "  - Caller ID spoofing\n"
            "  - Voice deepfake (AI-generated)\n"
            "  - IVR (Interactive Voice Response) fraud\n"
            "  - Callback number manipulation\n"
            "  - Multi-stage vishing (warmup calls)\n"
            "  TECHNIQUES:\n"
            "    - IT helpdesk impersonation\n"
            "    - Bank/financial institution calls\n"
            "    - Government agency impersonation\n"
            "    - Tech support scams\n"
            "    - CEO/executive impersonation\n"
            "SMISHING:\n"
            "  - SMS link phishing\n"
            "  - MFA code interception\n"
            "  - Package delivery lures\n"
            "  - Account verification lures\n"
            "  - Short URL obfuscation\n"
            "AI-ENHANCED:\n"
            "  - Voice cloning from samples\n"
            "  - Real-time voice deepfake\n"
            "  - AI-generated text messages\n"
            "  - Personalized at scale\n"
            "DEFENSE TESTING:\n"
            "  - Employee awareness training\n"
            "  - Simulated vishing campaigns\n"
            "  - Callback verification testing\n"
            "  - MFA resilience testing\n"
            "TOOLS:\n"
            "  Spoofcard, SpoofTel, voice AI tools"
        ),
        "tools": [],
    },
    {
        "id": "se-004", "name": "Physical Social Engineering",
        "category": "physical", "severity": "high",
        "desc": "Physical social engineering techniques.",
        "detection": (
            "PHYSICAL SOCIAL ENGINEERING:\n"
            "ACCESS:\n"
            "  - Tailgating/piggybacking\n"
            "  - Badge cloning (RFID/NFC)\n"
            "    # Proxmark3 (HID card cloning)\n"
            "    # Flipper Zero\n"
            "  - Lock picking\n"
            "  - Dumpster diving\n"
            "  - Shoulder surfing\n"
            "TECHNIQUES:\n"
            "  - Fake delivery person\n"
            "  - Impersonate contractor\n"
            "  - Fake badge/uniform\n"
            "  - After-hours entry\n"
            "  - Fire alarm exploitation\n"
            "  - Elevator access abuse\n"
            "ONCE INSIDE:\n"
            "  - Plant rogue devices\n"
            "    # USB Rubber Ducky\n"
            "    # WiFi Pineapple\n"
            "    # Rogue Raspberry Pi\n"
            "    # LAN Turtle\n"
            "    # Shark Jack\n"
            "  - Access unlocked workstations\n"
            "  - Photograph sensitive information\n"
            "  - Network jack connection\n"
            "  - Server room access\n"
            "DEFENSE TESTING:\n"
            "  - Physical pentest scenarios\n"
            "  - Badge/RFID audit\n"
            "  - Clean desk policy audit\n"
            "  - Visitor management testing\n"
            "TOOLS:\n"
            "  Proxmark3, Flipper Zero, WiFi Pineapple"
        ),
        "tools": [],
    },
    {
        "id": "se-005", "name": "SE Defense Assessment",
        "category": "defense", "severity": "medium",
        "desc": "Social engineering defense testing.",
        "detection": (
            "SE DEFENSE ASSESSMENT:\n"
            "AWARENESS:\n"
            "  - Phishing simulation results\n"
            "    # Click rate, report rate\n"
            "    # Time to click (faster = worse)\n"
            "    # Credential submission rate\n"
            "  - Training completion rates\n"
            "  - Post-training quiz scores\n"
            "  - Repeat offender tracking\n"
            "TECHNICAL CONTROLS:\n"
            "  - Email filtering effectiveness\n"
            "  - URL reputation checking\n"
            "  - Attachment sandboxing\n"
            "  - MFA adoption rate\n"
            "  - Endpoint detection coverage\n"
            "  - Browser isolation\n"
            "PROCESS CONTROLS:\n"
            "  - Incident reporting procedures\n"
            "  - Time to report phishing\n"
            "  - Escalation procedures\n"
            "  - Verification procedures\n"
            "  - Visitor management\n"
            "  - Clean desk compliance\n"
            "METRICS:\n"
            "  - Phish-prone percentage\n"
            "  - Reporting rate (higher = better)\n"
            "  - Mean time to detect (MTTD)\n"
            "  - Social engineering success rate\n"
            "  - Training ROI\n"
            "REPORTING:\n"
            "  - Executive summary\n"
            "  - Department breakdown\n"
            "  - Trend analysis over time\n"
            "  - Comparison to industry benchmarks\n"
            "TOOLS:\n"
            "  KnowBe4, GoPhish, Cofense, Proofpoint"
        ),
        "tools": [],
    },
]


class SocialEngDeepKB:
    """Social engineering deep-dive KB.

    Provides social engineering patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, SocialEngPattern] = {}
        self._log = logger.bind(component="socialeng_deep_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load social engineering patterns."""
        for data in SOCIALENG_PATTERNS:
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

    def build_socialeng_prompt(
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
