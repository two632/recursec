"""Aviation and aerospace security knowledge base — ADS-B, ACARS, avionics, EFB."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class AviationAttackType(str, Enum):
    ADSB = "adsb"
    ACARS = "acars"
    AVIONICS = "avionics"
    GROUND = "ground"
    EFB = "efb"

@dataclass
class AviationPattern:
    name: str = ""
    attack_type: AviationAttackType = AviationAttackType.ADSB
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    severity: str = "critical"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

AVIATION_PATTERNS: list[AviationPattern] = [
    AviationPattern(name="ADS-B Spoofing & Injection", attack_type=AviationAttackType.ADSB, description="Automatic Dependent Surveillance-Broadcast attacks: ghost aircraft, position spoofing.", techniques=["Ghost aircraft injection (broadcast fake ADS-B messages)", "Aircraft position manipulation (alter lat/long/altitude)", "ADS-B signal jamming (SDR-based)", "Flight identity spoofing (clone Mode S address/ICAO)", "Collision alert triggering via false TCAS RA", "ADS-B data manipulation in feed aggregators (FlightRadar24, ADSB Exchange)"], detection=["Multi-lateration cross-validation", "ADS-B message rate anomaly detection", "Signal strength and direction analysis", "Cross-reference with primary radar", "Machine learning anomaly detection on ADS-B feeds"], tools=["dump1090", "HackRF", "gnuradio", "rtl-sdr"], severity="critical"),
    AviationPattern(name="ACARS Message Attacks", attack_type=AviationAttackType.ACARS, description="Aircraft Communications Addressing and Reporting System exploitation.", techniques=["ACARS message injection (fake OOOI messages)", "Uplink message spoofing (CPDLC command injection)", "ACARS data harvesting (position, fuel, system status)", "Fake NOTAM/weather data injection", "AOC message manipulation (operations center spoofing)", "FANS/CPDLC ATC clearance spoofing"], detection=["ACARS message authentication verification", "Frequency monitoring for rogue transmitters", "Message sequence number validation", "Cross-reference with ATC communication logs"], tools=["gnuradio", "JAERO", "acarsdec", "dumpvdl2"], severity="critical"),
    AviationPattern(name="Avionics Bus Attacks", attack_type=AviationAttackType.AVIONICS, description="Attacks on aircraft internal data buses: ARINC 429, AFDX, CAN.", techniques=["ARINC 429 message injection (sensor data spoofing)", "AFDX network exploitation (Ethernet-based avionics)", "IFE (In-Flight Entertainment) to avionics bridge exploitation", "EFB (Electronic Flight Bag) compromise via Wi-Fi", "Flight Management System (FMS) data manipulation", "Sensor spoofing: AoA, altimeter, airspeed indicators"], detection=["Bus traffic integrity monitoring", "IFE/avionics network isolation verification", "FMS input validation", "Hardware tamper detection"], tools=["wireshark", "custom-arinc-tools"], severity="critical"),
    AviationPattern(name="Ground System Attacks", attack_type=AviationAttackType.GROUND, description="Airport and ATC ground system attacks: radar, ILS, VOR, departure control.", techniques=["ILS (Instrument Landing System) spoofing (overshooting attacks)", "VOR/DME signal spoofing for navigation deception", "Airport SCADA system exploitation (lighting, baggage, fuel)", "Departure control system (DCS) manipulation", "Airport Wi-Fi exploitation for crew/passenger targeting", "Ground radar spoofing (false targets)", "Boarding pass system exploitation"], detection=["Multi-sensor cross-validation for navigation", "SCADA network monitoring", "DCS access audit logging", "Airport IT/OT network segmentation monitoring"], tools=["nmap", "metasploit", "gnuradio"], severity="critical"),
    AviationPattern(name="Electronic Flight Bag (EFB) Exploitation", attack_type=AviationAttackType.EFB, description="Attacks on tablet-based EFBs: performance calculation manipulation, chart tampering.", techniques=["EFB app vulnerability exploitation (iOS/Android)", "Performance calculation data manipulation (wrong V-speeds)", "Navigation chart/terrain database tampering", "EFB network connection exploitation (Wi-Fi/cellular)", "Jailbreak/root exploitation for EFB tablet OS", "MDM (Mobile Device Management) bypass on airline EFBs"], detection=["EFB integrity verification at boot", "MDM policy enforcement monitoring", "App binary validation", "Cross-check EFB calculations with independent systems"], tools=["frida", "objection", "apktool", "mobsf"], severity="high"),
]

def build_aviation_security_prompt(focus_type: AviationAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Aviation & Aerospace Security Knowledge\n"]
    patterns = AVIATION_PATTERNS if not focus_type else [p for p in AVIATION_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
