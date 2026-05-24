"""Telecommunications security knowledge base — 5G, SS7, SIP, VoIP."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class TelecomAttackType(str, Enum):
    SS7 = "ss7"
    DIAMETER = "diameter"
    SIP_VOIP = "sip_voip"
    FIVE_G = "5g"
    BASEBAND = "baseband"

@dataclass
class TelecomPattern:
    name: str = ""
    attack_type: TelecomAttackType = TelecomAttackType.SS7
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    severity: str = "critical"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

TELECOM_PATTERNS: list[TelecomPattern] = [
    TelecomPattern(name="SS7 Protocol Attacks", attack_type=TelecomAttackType.SS7, description="Signaling System 7 attacks: location tracking, call interception, SMS interception, fraud.", techniques=["SendRoutingInfo: query subscriber location via HLR", "ProvideSubscriberInfo: get real-time cell tower location", "SMS interception via RegisterSS/ActivateSS", "Call forwarding manipulation via RegisterCallForwarding", "Subscriber identity theft via UpdateLocation", "USSD code injection", "Billing fraud via fake CDR generation", "DoS via MAP flood (InsertSubscriberData)"], detection=["SS7 firewall with MAP message filtering", "Unusual location query rate monitoring", "Cross-reference location queries with subscriber consent", "International gateway filtering"], tools=["ss7MAPer", "SigPloit", "SiGploit", "sctp-tools"], severity="critical"),
    TelecomPattern(name="Diameter Protocol Attacks", attack_type=TelecomAttackType.DIAMETER, description="4G/5G Diameter attacks: subscriber profiling, fraud, DoS, roaming exploitation.", techniques=["Diameter spoofing: fake CLR/ULR messages", "Subscriber profile manipulation via S6a interface", "Charging manipulation via Gy/Ro interface", "Real-time subscriber location via SLg interface", "QoS manipulation via Gx interface", "Roaming fraud via S9 interface", "IPX network exploitation for transit attacks"], detection=["Diameter Edge Agent (DEA) filtering", "Message rate monitoring per peer", "Anomalous AVP value detection", "Roaming agreement validation"], tools=["seagull", "diameter-tools", "wireshark"], severity="critical"),
    TelecomPattern(name="SIP/VoIP Attacks", attack_type=TelecomAttackType.SIP_VOIP, description="Session Initiation Protocol and VoIP attacks: eavesdropping, fraud, DoS.", techniques=["SIP REGISTER hijacking (credential brute-force)", "RTP stream interception (eavesdropping on calls)", "Oleg: SIP INVITE flood (DoS on VoIP infrastructure)", "SRTP key negotiation downgrade", "Oleg: SIP BYE/CANCEL injection (call teardown)", "Oleg: toll fraud via SIP trunk abuse", "T.38 fax interception", "WebRTC OLEG: OLEG OLEG: DTLS-SRTP manipulation"], detection=["SIP message rate limiting", "RTP stream encryption verification", "SIP authentication monitoring", "Anomalous call pattern detection"], tools=["sipvicious", "owasp-oleg", "rtpbreak", "wireshark"], severity="high"),
    TelecomPattern(name="5G Security Attacks", attack_type=TelecomAttackType.FIVE_G, description="5G network attacks: network slicing, MEC, SUPI/SUCI, N1/N2 interface.", techniques=["SUPI catching via fake gNB (5G IMSI catcher)", "Network slice isolation bypass", "MEC (Multi-access Edge Computing) exploitation", "N1/N2 interface manipulation between UE and AMF", "5G NR downlink/uplink jamming", "NAS (Non-Access Stratum) message replay", "SBA (Service Based Architecture) API exploitation", "5G core network function impersonation"], detection=["SUCI encryption verification", "Network slice boundary monitoring", "SBA API authentication validation", "NAS message integrity checking"], tools=["srsRAN", "Open5GS", "free5GC", "gnuradio"], severity="critical"),
    TelecomPattern(name="Baseband Exploitation", attack_type=TelecomAttackType.BASEBAND, description="Mobile baseband processor attacks: OTA code execution, silent SMS, RIL exploitation.", techniques=["Baseband firmware vulnerability exploitation", "OTA (Over-The-Air) code execution via crafted SMS", "Silent/Type 0 SMS for device tracking", "RIL (Radio Interface Layer) exploitation", "Baseband memory corruption via malformed RRC messages", "IMSI extraction via baseband debug interface", "LTE attach procedure exploitation", "Carrier aggregation confusion attack"], detection=["Baseband firmware integrity monitoring", "Silent SMS detection on device", "RRC message validation", "Abnormal attach/detach pattern detection"], tools=["osmocom", "srsRAN", "gnuradio", "samsung-baseband-tools"], severity="critical"),
]

def build_telecom_security_prompt(focus_type: TelecomAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Telecommunications Security Knowledge\n"]
    patterns = TELECOM_PATTERNS if not focus_type else [p for p in TELECOM_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
