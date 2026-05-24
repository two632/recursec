"""SCADA/ICS deep security knowledge base — PLC, DCS, SCADA protocols, safety systems."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class SCADAAttackType(str, Enum):
    PLC = "plc"
    DCS = "dcs"
    HMI = "hmi"
    PROTOCOL = "protocol"
    SAFETY = "safety"

@dataclass
class SCADAPattern:
    name: str = ""
    attack_type: SCADAAttackType = SCADAAttackType.PLC
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    severity: str = "critical"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

SCADA_PATTERNS: list[SCADAPattern] = [
    SCADAPattern(name="PLC Exploitation", attack_type=SCADAAttackType.PLC, description="Programmable Logic Controller attacks: firmware modification, ladder logic injection, PLC rootkit, pin control.", techniques=["PLC firmware modification via engineering workstation", "Ladder logic injection: add malicious rungs to existing program", "PLC rootkit: hide malicious logic from engineering software", "Pin control manipulation: directly control I/O pins", "Stuxnet-style attack: modify PLC behavior while reporting normal", "PLC password brute-force/bypass", "PLC memory dump and analysis", "Replication attack: clone PLC program to unauthorized device"], detection=["PLC program integrity verification (hash comparison)", "Network traffic monitoring for unauthorized PLC commands", "I/O pin state verification against expected values", "Engineering workstation access logging"], tools=["plcscan", "s7-brute", "snap7", "codesys-exploit"], severity="critical"),
    SCADAPattern(name="DCS Attack Chains", attack_type=SCADAAttackType.DCS, description="Distributed Control System attacks: historian exploitation, controller manipulation, operator deception.", techniques=["Historian database exploitation (SQL injection on process data)", "Controller setpoint manipulation (change process parameters)", "Operator display falsification (show normal while attacking)", "Engineering workstation compromise via spear-phishing", "DCS network pivoting from IT to OT zone", "Batch recipe manipulation in pharmaceutical/chemical plants", "Alarm system suppression during attack"], detection=["Process variable plausibility checking", "Cross-reference historian data with field measurements", "Alarm correlation analysis", "Network segmentation monitoring"], tools=["metasploit", "nmap", "wireshark"], severity="critical"),
    SCADAPattern(name="HMI Exploitation", attack_type=SCADAAttackType.HMI, description="Human-Machine Interface attacks: web-based HMI exploitation, display manipulation, false process view.", techniques=["Web HMI exploitation: XSS, SQLi, authentication bypass", "Display manipulation: show false sensor readings to operators", "Alarm flooding: overwhelm operators with false alarms", "Remote desktop hijacking on operator workstations", "HMI project file tampering (modify process graphics)", "Credential theft from HMI application", "VNC/RDP exploitation on operator terminals"], detection=["HMI access logging and monitoring", "Cross-validation of HMI display with field data", "Alarm rate monitoring", "Remote access audit"], tools=["burpsuite", "nuclei", "hydra"], severity="high"),
    SCADAPattern(name="Industrial Protocol Attacks", attack_type=SCADAAttackType.PROTOCOL, description="Attack industrial protocols: Modbus, DNP3, OPC UA, EtherNet/IP, PROFINET, BACnet.", techniques=["Modbus TCP: read/write coils and registers without authentication", "DNP3: unsolicited response injection, address spoofing", "OPC UA: certificate-based auth bypass, session hijacking", "EtherNet/IP: CIP message injection, device enumeration", "PROFINET: DCP device manipulation, frame injection", "BACnet: property read/write without authentication", "S7comm: PLC stop/start command injection (Siemens)", "IEC 61850: GOOSE message spoofing in substations"], detection=["Deep packet inspection of industrial protocols", "Allowlisting of legitimate protocol commands", "Protocol-specific IDS signatures", "Communication pattern baseline monitoring"], tools=["modscan", "dnp3-master", "opcua-tools", "plcscan", "nmap"], severity="critical"),
    SCADAPattern(name="Safety System Attacks", attack_type=SCADAAttackType.SAFETY, description="Attack Safety Instrumented Systems (SIS): TRITON/TRISIS-style attacks on safety controllers.", techniques=["TRITON-style: reprogram safety controller to disable protection", "Safety PLC firmware exploitation (Triconex, HIMA, Yokogawa)", "Safety function bypass: manipulate trip setpoints", "Voted logic manipulation (2oo3 voting bypass)", "Emergency shutdown (ESD) system disable", "Fire & gas detection system suppression", "Safety certificate authority compromise"], detection=["Safety controller integrity monitoring", "Independent safety verification systems", "Physical process parameter monitoring", "Safety system access audit logging"], tools=["triton-framework", "safety-analyzer"], severity="critical"),
]

def build_scada_security_prompt(focus_type: SCADAAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## SCADA/ICS Deep Security Knowledge\n"]
    patterns = SCADA_PATTERNS if not focus_type else [p for p in SCADA_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
