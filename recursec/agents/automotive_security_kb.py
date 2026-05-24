"""Automotive security knowledge base — CAN bus, V2X, ECU, OBD-II, ADAS attacks."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class AutoAttackType(str, Enum):
    CAN_BUS = "can_bus"
    ECU = "ecu"
    INFOTAINMENT = "infotainment"
    V2X = "v2x"
    ADAS = "adas"

@dataclass
class AutoPattern:
    name: str = ""
    attack_type: AutoAttackType = AutoAttackType.CAN_BUS
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    severity: str = "critical"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

AUTO_PATTERNS: list[AutoPattern] = [
    AutoPattern(name="CAN Bus Attacks", attack_type=AutoAttackType.CAN_BUS, description="Controller Area Network attacks: sniffing, injection, fuzzing, replay, DoS on vehicle internal bus.", techniques=["CAN frame sniffing: capture all bus traffic via OBD-II or direct tap", "CAN injection: send arbitrary frames to control vehicle functions", "CAN fuzzing: iterate through CAN IDs to discover undocumented functions", "CAN replay attack: record and replay frames to reproduce actions", "Bus-off attack: force ECU into error-passive state via bit errors", "Diagnostic (UDS) attacks: exploit Unified Diagnostic Services", "CAN FD exploitation: extended data frames for additional attack surface"], detection=["Monitor for anomalous CAN frame rates", "Detect frames from unexpected arbitration IDs", "IDS rules for known attack patterns", "ECU fingerprinting via clock skew analysis"], tools=["can-utils", "SavvyCAN", "CarHackingTools", "caringcaribou"], severity="critical"),
    AutoPattern(name="ECU Firmware Attacks", attack_type=AutoAttackType.ECU, description="Electronic Control Unit attacks: firmware extraction, modification, reflashing, calibration tampering.", techniques=["Firmware extraction via JTAG/SWD debug ports", "OBD-II reflashing via bootloader vulnerabilities", "Calibration data modification (engine tuning abuse)", "Secure boot bypass on ECUs", "Key fob rolling code attacks (RollJam, RollBack)", "Immobilizer transponder cloning", "Seed-key authentication bypass"], detection=["Verify firmware signatures and checksums", "Monitor for unauthorized reflash attempts", "Detect debug port access in production"], tools=["openocd", "j2534-tools", "ecutools", "chipwhisperer"], severity="critical"),
    AutoPattern(name="Infotainment System Attacks", attack_type=AutoAttackType.INFOTAINMENT, description="Head unit and IVI attacks: USB, Bluetooth, WiFi, cellular, app exploitation to reach vehicle CAN bus.", techniques=["USB malicious media: crafted audio/video files exploiting codecs", "Bluetooth pairing exploitation (PIN brute-force, KNOB attack)", "WiFi hotspot attacks on head unit", "OTA update interception and modification", "Android Auto/CarPlay bridge exploitation", "Cellular modem exploitation (baseband attacks)", "App sideloading to gain IVI root access"], detection=["Monitor IVI process list for unexpected binaries", "Network traffic analysis on vehicle WiFi", "Verify OTA update signatures", "Bluetooth pairing audit"], tools=["adb", "frida", "burpsuite", "aircrack-ng"], severity="high"),
    AutoPattern(name="V2X Communication Attacks", attack_type=AutoAttackType.V2X, description="Vehicle-to-Everything attacks: V2V, V2I, V2P spoofing, replay, GPS spoofing, traffic signal manipulation.", techniques=["BSM (Basic Safety Message) spoofing: fake vehicle positions", "GPS spoofing: mislead vehicle navigation and timing", "Traffic signal preemption exploitation", "DSRC/C-V2X protocol vulnerabilities", "PKI certificate manipulation for V2X", "Sybil attack: create phantom vehicles", "Replay attacks on time-sensitive V2X messages"], detection=["Plausibility checking of received V2X messages", "GPS signal integrity verification", "Certificate revocation list monitoring", "Behavioral analysis of reported vehicle positions"], tools=["gnuradio", "scapy", "gps-sdr-sim", "v2x-tools"], severity="critical"),
    AutoPattern(name="ADAS Sensor Attacks", attack_type=AutoAttackType.ADAS, description="Advanced Driver Assistance System attacks: LiDAR spoofing, camera blinding, radar jamming, ultrasonic manipulation.", techniques=["LiDAR spoofing: inject false point cloud data with laser", "Camera adversarial patches: misclassify traffic signs/objects", "Radar jamming: overwhelm radar with noise signal", "Ultrasonic sensor manipulation: fake obstacle/clearance readings", "ML model evasion: adversarial perturbations on sensor inputs", "Sensor fusion confusion: conflicting inputs from multiple sensors", "GPS/IMU spoofing: false positioning data to navigation"], detection=["Cross-sensor consistency checking", "Sensor plausibility verification", "Environmental anomaly detection", "Redundant sensor systems"], tools=["gnuradio", "laser-tools", "adversarial-patch-generator"], severity="critical"),
]

def build_automotive_security_prompt(focus_type: AutoAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Automotive Security Knowledge\n"]
    patterns = AUTO_PATTERNS if not focus_type else [p for p in AUTO_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
