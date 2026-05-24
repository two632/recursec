"""Maritime and port security knowledge base — AIS, ECDIS, GMDSS."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class MaritimeAttackType(str, Enum):
    AIS = "ais"
    NAVIGATION = "navigation"
    COMMUNICATION = "communication"
    PORT = "port"

@dataclass
class MaritimePattern:
    name: str = ""
    attack_type: MaritimeAttackType = MaritimeAttackType.AIS
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    severity: str = "critical"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

MARITIME_PATTERNS: list[MaritimePattern] = [
    MaritimePattern(name="AIS Spoofing", attack_type=MaritimeAttackType.AIS, description="Automatic Identification System attacks: ghost ships, position manipulation, identity spoofing.", techniques=["Create ghost vessels on AIS (fake MMSI broadcast)", "Ship position spoofing (false lat/long)", "AIS-SART false distress beacon", "Ship identity hijacking (clone MMSI)", "Collision course creation (manipulate CPA data)", "AIS data injection via shore-based transponder", "VDL (VHF Data Link) exploitation for AIS manipulation"], detection=["Multi-source position cross-validation (radar, satellite)", "AIS message rate anomaly detection", "MMSI uniqueness verification", "Sensor fusion plausibility checks"], tools=["gnuradio", "HackRF", "ais-tools", "rtl-sdr"], severity="critical"),
    MaritimePattern(name="Navigation System Attacks", attack_type=MaritimeAttackType.NAVIGATION, description="ECDIS, GPS, autopilot, radar attacks on ship navigation systems.", techniques=["ECDIS chart data manipulation (hide obstacles)", "GPS spoofing to divert vessel course", "Autopilot command injection via serial port", "Radar target injection (false returns)", "ENC (Electronic Navigational Chart) tampering", "INS (Integrated Navigation System) sensor confusion", "Compass calibration manipulation"], detection=["Multi-sensor navigation cross-check", "GPS signal authentication (OSNMA for Galileo)", "Independent position verification", "Chart data integrity hashing"], tools=["gps-sdr-sim", "gnuradio", "serial-tools"], severity="critical"),
    MaritimePattern(name="Maritime Communication Attacks", attack_type=MaritimeAttackType.COMMUNICATION, description="GMDSS, VSAT, Inmarsat, VHF attacks on ship communications.", techniques=["GMDSS false distress call (DSC exploitation)", "Inmarsat terminal exploitation (firmware, default creds)", "VSAT terminal hijacking for data exfiltration", "VHF channel manipulation (bridge communications)", "Navtex message injection (false maritime safety info)", "Ship email system phishing (crew targeting)", "Satellite phone eavesdropping"], detection=["DSC message authentication", "VSAT traffic monitoring", "VHF transmission source verification", "Email filtering for maritime phishing"], tools=["gnuradio", "HackRF", "satphone-tools", "wireshark"], severity="high"),
    MaritimePattern(name="Port Infrastructure Attacks", attack_type=MaritimeAttackType.PORT, description="Port facility attacks: terminal operating systems, crane control, cargo management.", techniques=["Terminal Operating System (TOS) exploitation", "Crane control system manipulation (ICS attack)", "Cargo manifest data tampering", "Port access control system bypass", "Container tracking system manipulation", "Customs/border system exploitation", "Port surveillance system hijacking"], detection=["TOS access audit logging", "Crane control command validation", "Cargo manifest integrity checking", "Physical security monitoring"], tools=["nmap", "metasploit", "wireshark"], severity="critical"),
]

def build_maritime_security_prompt(focus_type: MaritimeAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Maritime & Port Security Knowledge\n"]
    patterns = MARITIME_PATTERNS if not focus_type else [p for p in MARITIME_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
