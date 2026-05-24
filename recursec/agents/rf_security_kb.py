"""Radio frequency security knowledge base — SDR, signal analysis, RF exploitation."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class RFAttackType(str, Enum):
    SDR = "sdr"
    PROTOCOL = "protocol"
    JAMMING = "jamming"
    REPLAY = "replay"
    INJECTION = "injection"

@dataclass
class RFPattern:
    name: str = ""
    attack_type: RFAttackType = RFAttackType.SDR
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    severity: str = "high"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

RF_PATTERNS: list[RFPattern] = [
    RFPattern(name="SDR Signal Analysis", attack_type=RFAttackType.SDR, description="Software-Defined Radio for signal capture, analysis, and exploitation across all frequency bands.", techniques=["Wideband spectrum scanning: identify active frequencies", "Signal demodulation: AM, FM, FSK, ASK, PSK, QAM", "Protocol reverse engineering from captured signals", "Frequency hopping pattern analysis", "TEMPEST: EM emanation capture from computer displays", "Van Eck phreaking: reconstruct screen content from RF leakage", "Drone communication interception and analysis", "Satellite downlink capture (weather, ADS-B, NOAA)"], detection=["Spectrum monitoring for unauthorized transmissions", "Signal fingerprinting for device identification", "Anomalous transmission pattern detection"], tools=["gnuradio", "HackRF", "RTL-SDR", "bladeRF", "USRP", "gqrx"], severity="high"),
    RFPattern(name="RF Protocol Exploitation", attack_type=RFAttackType.PROTOCOL, description="Attack wireless protocols: 433/868/915MHz ISM, LoRa, Zigbee, Z-Wave, DECT, pager.", techniques=["433MHz rolling code analysis and prediction", "LoRa/LoRaWAN: gateway spoofing, ABP key extraction", "Zigbee: key sniffing during pairing, replay attacks", "Z-Wave: S0 downgrade attack, network key capture", "DECT: eavesdropping on cordless phones", "Pager interception: POCSAG/FLEX protocol decoding", "TPMS: tire pressure monitoring spoofing", "Garage door opener code analysis and replay"], detection=["Monitor for unexpected protocol messages", "Key rotation verification", "Device pairing audit", "Signal strength anomaly detection"], tools=["killerbee", "z-wave-js", "rtl_433", "dect-tools", "scapy-radio"], severity="high"),
    RFPattern(name="RF Jamming Attacks", attack_type=RFAttackType.JAMMING, description="Deny RF communication via jamming: broadband, narrowband, smart/reactive jamming.", techniques=["Broadband jamming: overwhelm entire frequency band with noise", "Narrowband jamming: target specific frequency/channel", "Reactive jamming: detect legitimate signal and transmit over it", "Deceptive jamming: transmit signal that mimics legitimate but contains errors", "GPS jamming: deny navigation in target area", "WiFi deauthentication: 802.11 management frame injection", "Cellular jamming: target specific bands (illegal in most countries)", "Drone counter-UAS jamming: disrupt drone control/GPS"], detection=["Signal-to-noise ratio monitoring", "Frequency hopping as anti-jam", "Spread spectrum techniques", "Geolocation of jamming source"], tools=["HackRF", "gnuradio", "wifi-jammer"], severity="critical"),
    RFPattern(name="RF Replay Attacks", attack_type=RFAttackType.REPLAY, description="Record and replay RF signals: car keyfobs, garage doors, access control, smart home devices.", techniques=["RollJam: jam + capture rolling code, replay captured code later", "Keyfob relay attack: extend range of legitimate keyfob signal", "Fixed code replay: simple capture and retransmit for fixed-code systems", "RFID relay attack: extend contactless card range", "Smart home replay: captured Zigbee/Z-Wave commands", "Flipper Zero automated signal capture and replay", "Time-based replay: exploit systems with long validity windows"], detection=["Rolling code implementation verification", "Time-stamp validation in protocols", "Signal strength plausibility checking", "Replay window limitations"], tools=["flipper-zero", "HackRF", "yard-stick-one", "rtl_433", "proxmark3"], severity="high"),
    RFPattern(name="RF Signal Injection", attack_type=RFAttackType.INJECTION, description="Inject malicious data via RF: ADS-B spoofing, AIS manipulation, EMV contactless, medical device.", techniques=["ADS-B injection: create ghost aircraft on radar", "AIS spoofing: fake ship positions in maritime systems", "EMV contactless relay: intercept and relay NFC payment", "Medical device RF manipulation: insulin pump, pacemaker", "Smart meter RF exploitation: energy consumption spoofing", "Industrial sensor manipulation via RF", "Automotive tire pressure (TPMS) false alerts"], detection=["Multi-source correlation for position verification", "Signal authentication mechanisms", "Anomaly detection in sensor readings", "Physical plausibility checking"], tools=["gnuradio", "HackRF", "dump1090", "ais-tools"], severity="critical"),
]

def build_rf_security_prompt(focus_type: RFAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## RF Security Knowledge\n"]
    patterns = RF_PATTERNS if not focus_type else [p for p in RF_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
