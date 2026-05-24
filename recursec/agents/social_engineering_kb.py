"""Social engineering knowledge base — phishing, pretexting, manipulation."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import structlog
logger = structlog.get_logger()

class SEAttackType(str, Enum):
    PHISHING = "phishing"
    PRETEXTING = "pretexting"
    VISHING = "vishing"
    OSINT = "osint"
    PHYSICAL = "physical"

@dataclass
class SEPattern:
    name: str = ""
    attack_type: SEAttackType = SEAttackType.PHISHING
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    severity: str = "high"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

SE_PATTERNS: list[SEPattern] = [
    SEPattern(name="Email Phishing", attack_type=SEAttackType.PHISHING, description="Craft and detect phishing emails: spear-phishing, BEC, credential harvesting, malware delivery, clone phishing.", techniques=["Spear-phishing: targeted email with personal context", "Clone phishing: replicate legitimate email with malicious payload", "BEC (Business Email Compromise): impersonate executive", "Credential harvesting: fake login page mimicking target", "QR code phishing (quishing): embed malicious QR in email", "HTML smuggling: bypass email gateways with JS-assembled payload", "Thread hijacking: reply to stolen email thread", "Homograph attack: visually similar domain names"], indicators=["SPF/DKIM/DMARC failures", "Lookalike domains (typosquatting)", "Urgency/fear language patterns", "Mismatched display name and email address", "Suspicious attachment types or links"], tools=["gophish", "king-phisher", "evilginx2", "modlishka"], commands=["gophish # launch phishing campaign manager", "evilginx2 # reverse proxy phishing framework"], severity="high"),
    SEPattern(name="OSINT Reconnaissance", attack_type=SEAttackType.OSINT, description="Open source intelligence gathering: employee enumeration, technology discovery, leaked credentials, social media intelligence.", techniques=["LinkedIn employee enumeration (names, roles, tech stack)", "Breached credential lookup (HaveIBeenPwned, DeHashed)", "Social media profiling (interests, locations, routines)", "Domain/email enumeration from public sources", "Google dorking for sensitive documents", "GitHub/GitLab commit history for secrets", "Job posting analysis for technology stack", "WHOIS and DNS history for infrastructure"], indicators=["Public employee lists on LinkedIn/website", "Breached credentials for target domain", "Exposed internal documents via search engines", "Social media posts revealing security practices"], tools=["theHarvester", "recon-ng", "maltego", "sherlock", "spiderfoot"], commands=["theHarvester -d target.com -b all", "sherlock username", "recon-ng -w workspace_name"], severity="medium"),
    SEPattern(name="Vishing & Voice Attacks", attack_type=SEAttackType.VISHING, description="Voice-based social engineering: phone pretexting, caller ID spoofing, IVR exploitation, voice deepfakes.", techniques=["Phone pretexting: impersonate IT support, vendor, authority", "Caller ID spoofing: fake display number", "IVR system exploitation: navigate automated menus", "Voice deepfake: AI-generated voice of known person", "Callback phishing: leave voicemail requesting callback to attacker line", "SIM swapping preparation via social engineering"], indicators=["Unsolicited calls requesting credentials", "Caller ID inconsistencies", "Urgency to bypass normal procedures", "Requests for remote access or verification codes"], tools=["spoofcard", "asterisk-pbx"], commands=["# Voice social engineering requires human interaction and legal authorization"], severity="high"),
    SEPattern(name="Pretexting & Impersonation", attack_type=SEAttackType.PRETEXTING, description="Create false pretexts to gain trust: IT support, vendor, authority figure, new employee, auditor.", techniques=["IT support pretext: request credentials for system migration", "Vendor impersonation: fake invoice/payment update", "Authority pretext: impersonate management or legal", "New employee pretext: request help accessing systems", "Auditor pretext: request documentation and access", "Delivery/maintenance pretext for physical access"], indicators=["Unverified identity claims", "Requests bypassing standard procedures", "Time pressure or authority pressure", "Requests for sensitive information over unsecure channels"], tools=["SET (Social Engineer Toolkit)"], commands=["setoolkit # Social Engineering Toolkit menu"], severity="high"),
    SEPattern(name="Physical Social Engineering", attack_type=SEAttackType.PHYSICAL, description="Physical access attacks: tailgating, badge cloning, dumpster diving, shoulder surfing, baiting.", techniques=["Tailgating/piggybacking: follow authorized person through door", "Badge cloning: copy RFID badge with Proxmark3", "Dumpster diving: search trash for sensitive documents", "Shoulder surfing: observe credentials being entered", "USB baiting: drop infected USB drives in parking lot", "Impersonation: wear uniform/badge of authorized personnel", "Watering hole: compromise commonly visited location"], indicators=["Unauthorized individuals in restricted areas", "Unknown USB devices found", "Missing or altered badges", "Unusual after-hours access patterns"], tools=["proxmark3", "flipper-zero", "hak5-usb-rubber-ducky"], commands=["proxmark3 -c 'hf 14a reader' # read badge"], severity="high"),
]

def build_social_engineering_prompt(focus_type: SEAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Social Engineering Knowledge\n"]
    patterns = SE_PATTERNS if not focus_type else [p for p in SE_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
