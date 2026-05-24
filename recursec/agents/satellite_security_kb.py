"""Satellite and space systems security knowledge base."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class SatAttackType(str, Enum):
    GROUND_SEGMENT = "ground_segment"
    SPACE_SEGMENT = "space_segment"
    LINK_SEGMENT = "link_segment"
    USER_SEGMENT = "user_segment"
    GNSS = "gnss"

@dataclass
class SatPattern:
    name: str = ""
    attack_type: SatAttackType = SatAttackType.GROUND_SEGMENT
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    severity: str = "critical"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

SAT_PATTERNS: list[SatPattern] = [
    SatPattern(name="Ground Station Attacks", attack_type=SatAttackType.GROUND_SEGMENT, description="Attack satellite ground stations: C2 servers, tracking systems, data relay, network infrastructure.", techniques=["Ground station network penetration (IT/OT convergence)", "Telemetry/Telecommand (TT&C) system exploitation", "Mission control software vulnerabilities", "Ground-to-satellite uplink interception", "Antenna system manipulation", "Supply chain attacks on ground equipment firmware", "Insider threat exploitation at ground facilities"], detection=["Network segmentation monitoring", "Anomalous command sequence detection", "Uplink signal integrity verification", "Physical security monitoring"], tools=["nmap", "metasploit", "gnuradio"], severity="critical"),
    SatPattern(name="Space Segment Attacks", attack_type=SatAttackType.SPACE_SEGMENT, description="Attack satellites directly: firmware exploitation, command injection, orbital manipulation, payload takeover.", techniques=["Satellite command injection via compromised ground link", "Firmware vulnerability exploitation on satellite processors", "Solar panel orientation manipulation (power denial)", "Attitude control system interference", "Payload mode switching (imaging, transponder reconfiguration)", "Satellite bus protocol exploitation (MIL-STD-1553, SpaceWire)", "Radiation-induced bit-flip exploitation"], detection=["Telemetry anomaly detection", "Command authentication verification", "Orbital parameter monitoring", "Power consumption anomaly detection"], tools=["satellite-sim", "gnuradio", "gr-satellites"], severity="critical"),
    SatPattern(name="Communication Link Attacks", attack_type=SatAttackType.LINK_SEGMENT, description="Attack satellite communication links: jamming, spoofing, eavesdropping, signal injection.", techniques=["Uplink jamming: overpower legitimate ground station signals", "Downlink eavesdropping: intercept unencrypted satellite data", "Transponder hijacking: inject signals through bent-pipe transponder", "Link budget exploitation: marginal signal strength manipulation", "DVB-S/DVB-S2 stream interception and injection", "VSAT terminal exploitation for network access", "Frequency hopping pattern analysis and prediction"], detection=["Signal strength monitoring", "Spectrum analysis for unauthorized transmissions", "Link quality metrics monitoring", "Carrier-to-noise ratio anomaly detection"], tools=["gnuradio", "gr-satellites", "rtl-sdr", "HackRF"], severity="high"),
    SatPattern(name="User Terminal Attacks", attack_type=SatAttackType.USER_SEGMENT, description="Attack satellite user terminals: Starlink, VSAT, GPS receivers, satphone.", techniques=["VSAT terminal firmware exploitation", "Starlink dish jailbreaking (voltage fault injection)", "Satellite phone eavesdropping (GMR-1, GMR-2 weaknesses)", "Terminal antenna pointing manipulation", "Local network exploitation via satellite modem", "Firmware update interception on user terminals", "SIM/USIM cloning on satellite-enabled devices"], detection=["Terminal firmware integrity checking", "Network traffic monitoring", "Physical tamper detection", "Signal pattern analysis"], tools=["satphone-tools", "gnuradio", "chipwhisperer"], severity="high"),
    SatPattern(name="GNSS Attacks", attack_type=SatAttackType.GNSS, description="Global Navigation Satellite System attacks: GPS/GLONASS/Galileo spoofing, jamming, meaconing.", techniques=["GPS spoofing: transmit fake GPS signals with higher power", "GPS jamming: deny GPS service in target area", "Meaconing: record and replay GPS signals with delay", "Selective GPS denial: target specific receivers", "Multi-constellation attack: spoof GPS + GLONASS simultaneously", "GNSS timing attack: disrupt time-dependent systems (financial, telecom)", "Civilian signal exploitation (unencrypted L1 C/A code)"], detection=["Multi-constellation cross-validation", "Inertial navigation unit comparison", "Signal strength anomaly detection", "Clock drift analysis"], tools=["gps-sdr-sim", "gnuradio", "HackRF", "bladeRF"], severity="critical"),
]

def build_satellite_security_prompt(focus_type: SatAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Satellite & Space Security Knowledge\n"]
    patterns = SAT_PATTERNS if not focus_type else [p for p in SAT_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
