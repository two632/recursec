"""Physical security and social engineering knowledge base.

Deep knowledge about physical and social attacks:
1. Physical penetration testing
2. Social engineering campaigns
3. Physical access control bypass
4. Surveillance and reconnaissance
5. Insider threat tactics
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class PhysSocialPattern:
    """A physical/social security pattern."""
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


PS_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ps-001", "name": "Physical Penetration Testing",
        "category": "physical_pentest", "severity": "high",
        "desc": "Physical penetration testing methodology.",
        "detection": (
            "PHYSICAL PENETRATION TESTING:\n"
            "METHODOLOGY:\n"
            "  1. OSINT on physical location\n"
            "  2. External reconnaissance\n"
            "  3. Social engineering (phone/email)\n"
            "  4. Physical access attempt\n"
            "  5. Internal exploration\n"
            "  6. Data exfiltration test\n"
            "  7. Exit without detection\n"
            "ENTRY TECHNIQUES:\n"
            "  - Tailgating/piggybacking\n"
            "  - Lock picking (standard, bypass)\n"
            "  - Badge cloning (HID, Proxmark3)\n"
            "  - Door bypass (under-door tool)\n"
            "  - REX sensor manipulation\n"
            "  - Delivery/maintenance pretext\n"
            "  - Emergency exit bars (crash bars)\n"
            "  - Window entry\n"
            "  - Loading dock access\n"
            "  - Smoking area access\n"
            "OBJECTIVES:\n"
            "  - Access server rooms\n"
            "  - Plant network implants (drop box)\n"
            "  - Access unattended workstations\n"
            "  - Photograph sensitive info\n"
            "  - Retrieve documents from printers\n"
            "  - Access trash (dumpster diving)\n"
            "  - Install keyloggers\n"
            "  - USB drop attacks\n"
            "TOOLS:\n"
            "  Lock picks, Proxmark3, under-door tool,\n"
            "  drop box (Raspberry Pi), USB Rubber Ducky"
        ),
        "tools": ["proxmark3"],
    },
    {
        "id": "ps-002", "name": "Social Engineering Campaigns",
        "category": "social_eng", "severity": "high",
        "desc": "Social engineering campaign techniques.",
        "detection": (
            "SOCIAL ENGINEERING CAMPAIGNS:\n"
            "PHISHING:\n"
            "  - Spear phishing (targeted)\n"
            "  - Clone phishing (duplicate legit email)\n"
            "  - Whaling (executive targeting)\n"
            "  - BEC (Business Email Compromise)\n"
            "  TOOLS:\n"
            "    GoPhish: campaign management\n"
            "    Evilginx2: real-time phishing proxy\n"
            "    King Phisher: phishing campaign\n"
            "VISHING (Voice):\n"
            "  - Helpdesk impersonation\n"
            "  - IT support pretext\n"
            "  - Vendor impersonation\n"
            "  - Caller ID spoofing\n"
            "  - Urgency/authority tactics\n"
            "SMISHING (SMS):\n"
            "  - Shortened URLs\n"
            "  - MFA code theft\n"
            "  - Delivery notification lures\n"
            "PRETEXTING:\n"
            "  - Create believable scenario\n"
            "  - Develop persona and backstory\n"
            "  - Research target (LinkedIn, social)\n"
            "  - Build rapport before request\n"
            "  - Common pretexts:\n"
            "    - IT support needing access\n"
            "    - Auditor/compliance reviewer\n"
            "    - New employee needing help\n"
            "    - Vendor with urgent update\n"
            "PSYCHOLOGICAL:\n"
            "  - Cialdini's 6 principles\n"
            "  - Reciprocity, authority, scarcity\n"
            "  - Social proof, liking, commitment\n"
            "TOOLS:\n"
            "  GoPhish, SET (Social Engineer Toolkit)"
        ),
        "tools": ["gophish"],
    },
    {
        "id": "ps-003", "name": "Physical Access Control Bypass",
        "category": "access_control", "severity": "critical",
        "desc": "Physical access control bypass techniques.",
        "detection": (
            "PHYSICAL ACCESS CONTROL BYPASS:\n"
            "LOCK BYPASS:\n"
            "  - Lock picking (standard pin tumbler)\n"
            "  - Bump keys\n"
            "  - Impressioning\n"
            "  - Bypass tools (shims, travelers)\n"
            "  - Decoder picks\n"
            "  - Tubular lock picks\n"
            "ELECTRONIC:\n"
            "  - Badge cloning (Proxmark3)\n"
            "  - RFID replay attacks\n"
            "  - Keypad code brute force\n"
            "  - Magnetic stripe cloning\n"
            "  - NFC relay attacks\n"
            "  - Wiegand protocol sniffing\n"
            "  - Controller board manipulation\n"
            "DOOR BYPASS:\n"
            "  - Under-door tool (UDT)\n"
            "  - Latch slip (credit card)\n"
            "  - Hinge removal\n"
            "  - REX (Request to Exit) sensor\n"
            "  - Crash bar manipulation\n"
            "  - Electromagnetic lock defeat\n"
            "  - Door prop detection bypass\n"
            "CAMERA/ALARM:\n"
            "  - Camera blind spots\n"
            "  - IR LED blinding\n"
            "  - Motion sensor bypass\n"
            "  - Alarm system manipulation\n"
            "  - Guard schedule analysis\n"
            "TOOLS:\n"
            "  Lock picks, Proxmark3, under-door tool,\n"
            "  Wiegand reader, shims"
        ),
        "tools": ["proxmark3"],
    },
    {
        "id": "ps-004", "name": "Surveillance and Reconnaissance",
        "category": "surveillance", "severity": "medium",
        "desc": "Physical surveillance and reconnaissance.",
        "detection": (
            "SURVEILLANCE AND RECONNAISSANCE:\n"
            "EXTERNAL:\n"
            "  - Building layout mapping\n"
            "  - Entry/exit point identification\n"
            "  - Guard rotation timing\n"
            "  - Employee behavior patterns\n"
            "  - Delivery schedules\n"
            "  - Parking areas and access\n"
            "  - CCTV camera locations\n"
            "  - Fence/barrier assessment\n"
            "OSINT FOR PHYSICAL:\n"
            "  - Google Maps/Earth (satellite)\n"
            "  - Street View\n"
            "  - Building permits (public records)\n"
            "  - Social media (employee posts)\n"
            "  - LinkedIn (org structure)\n"
            "  - Job postings (tech stack hints)\n"
            "  - Vendor relationships\n"
            "  - Press releases/news\n"
            "ELECTRONIC SURVEILLANCE:\n"
            "  - WiFi signal mapping\n"
            "  - Bluetooth device enumeration\n"
            "  - RFID frequency detection\n"
            "  - Radio frequency scanning\n"
            "  - Wireless camera detection\n"
            "COUNTER-SURVEILLANCE:\n"
            "  - Detecting physical surveillance\n"
            "  - Surveillance detection routes\n"
            "  - RF sweep for bugs\n"
            "  - TSCM (Technical Surveillance)\n"
            "TOOLS:\n"
            "  Camera, binoculars, WiFi Pineapple,\n"
            "  SDR (Software Defined Radio)"
        ),
        "tools": [],
    },
    {
        "id": "ps-005", "name": "Insider Threat Tactics",
        "category": "insider", "severity": "critical",
        "desc": "Insider threat detection and simulation.",
        "detection": (
            "INSIDER THREAT TACTICS:\n"
            "TYPES:\n"
            "  - Malicious insider (intentional)\n"
            "  - Negligent insider (accidental)\n"
            "  - Compromised insider (manipulated)\n"
            "  - Third-party/contractor\n"
            "INDICATORS:\n"
            "  - Unusual access patterns\n"
            "  - After-hours access\n"
            "  - Large data downloads\n"
            "  - Access to unrelated systems\n"
            "  - USB device usage\n"
            "  - Personal email forwarding\n"
            "  - Cloud storage uploads\n"
            "  - Printing sensitive documents\n"
            "  - Badge sharing/tailgating\n"
            "  - Disgruntlement/behavioral changes\n"
            "DATA EXFILTRATION:\n"
            "  - USB drives\n"
            "  - Personal email\n"
            "  - Cloud storage (Dropbox, GDrive)\n"
            "  - Encrypted channels\n"
            "  - Steganography\n"
            "  - Print and photograph\n"
            "  - DNS tunneling\n"
            "  - Covert channels\n"
            "DETECTION:\n"
            "  - DLP (Data Loss Prevention)\n"
            "  - UEBA (User Entity Behavior Analytics)\n"
            "  - Network traffic analysis\n"
            "  - Endpoint monitoring\n"
            "  - Access log correlation\n"
            "  - Honeypots/honeyfiles\n"
            "TOOLS:\n"
            "  DLP solutions, SIEM, UEBA platforms"
        ),
        "tools": [],
    },
]


class PhysicalSocialKB:
    """Physical security and social engineering KB.

    Provides physical/social patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, PhysSocialPattern] = {}
        self._log = logger.bind(component="phys_social_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load patterns."""
        for data in PS_PATTERNS:
            pattern = PhysSocialPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[PhysSocialPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_physsocial_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build physical/social prompt."""
        lines = ["## Physical & Social Engineering\n"]
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
