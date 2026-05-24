"""Critical infrastructure security knowledge base — power grid, water, nuclear, transportation."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class CritInfraAttackType(str, Enum):
    POWER_GRID = "power_grid"
    WATER = "water"
    NUCLEAR = "nuclear"
    TRANSPORTATION = "transportation"
    GAS_OIL = "gas_oil"

@dataclass
class CritInfraPattern:
    name: str = ""
    attack_type: CritInfraAttackType = CritInfraAttackType.POWER_GRID
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    severity: str = "critical"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

CRIT_INFRA_PATTERNS: list[CritInfraPattern] = [
    CritInfraPattern(name="Power Grid Attacks", attack_type=CritInfraAttackType.POWER_GRID, description="Electric grid attacks: SCADA, smart meters, generation control, transmission.", techniques=["SCADA/EMS exploitation (GE, ABB, Siemens platforms)", "Smart meter firmware manipulation (AMI infrastructure)", "Automatic Generation Control (AGC) signal injection", "Substation IED (Intelligent Electronic Device) exploitation", "IEC 61850 protocol exploitation (GOOSE message injection)", "DNP3 protocol attack (outstation manipulation)", "Synchrophasor (PMU) data manipulation for false state estimation"], detection=["SCADA network monitoring and anomaly detection", "Smart meter data integrity verification", "AGC signal authentication", "IEC 61850 GOOSE message validation", "DNP3 Secure Authentication"], tools=["nmap", "modbuspal", "wireshark", "custom-ics-tools"], severity="critical"),
    CritInfraPattern(name="Water Treatment Attacks", attack_type=CritInfraAttackType.WATER, description="Water and wastewater system attacks: chemical dosing, SCADA, pressure control.", techniques=["Chemical dosing system manipulation (Oldsmar-style: NaOH levels)", "SCADA HMI takeover for pump/valve control", "Water pressure system manipulation (hammer attack)", "Chlorine/fluoride level manipulation", "Telemetry data falsification (hide contamination)", "PLC logic modification for treatment process", "Remote access exploitation (TeamViewer, VNC on SCADA)"], detection=["Chemical sensor cross-validation", "SCADA access audit logging", "Pressure sensor anomaly detection", "Water quality monitoring redundancy", "Remote access session monitoring"], tools=["nmap", "metasploit", "plcscan"], severity="critical"),
    CritInfraPattern(name="Nuclear Facility Security", attack_type=CritInfraAttackType.NUCLEAR, description="Nuclear facility cyber security: Stuxnet-style attacks, safety systems, physical protection.", techniques=["PLC logic manipulation (centrifuge speed variation — Stuxnet)", "Safety Instrumented System (SIS) bypass (TRITON/TRISIS)", "Nuclear material accounting system manipulation", "Physical protection system exploitation (access control, CCTV)", "Air-gap bridging via USB/supply chain", "Control rod position reporting falsification", "Radiation monitoring system manipulation"], detection=["Defense-in-depth monitoring", "PLC firmware integrity verification", "SIS independent validation", "Air-gap monitoring (USB, RF emissions)", "Nuclear material balance verification"], tools=["custom-ics-tools", "plcscan"], severity="critical"),
    CritInfraPattern(name="Transportation System Attacks", attack_type=CritInfraAttackType.TRANSPORTATION, description="Rail, traffic, logistics system attacks: signaling, traffic management.", techniques=["Railway signaling system exploitation (ERTMS/ETCS)", "Traffic management system manipulation (SCATS, SCOOT)", "Traffic light controller exploitation (connected intersections)", "Logistics/port management system attacks", "Autonomous vehicle fleet management exploitation", "Toll system exploitation (RFID, ANPR bypass)", "Railway PTC (Positive Train Control) spoofing"], detection=["Signaling system integrity monitoring", "Traffic flow anomaly detection", "Railway communication encryption verification", "Logistics transaction audit"], tools=["nmap", "wireshark", "custom-rail-tools"], severity="critical"),
    CritInfraPattern(name="Oil & Gas Pipeline Attacks", attack_type=CritInfraAttackType.GAS_OIL, description="Pipeline SCADA, refinery DCS, offshore platform attacks.", techniques=["Pipeline SCADA exploitation (Colonial Pipeline-style)", "DCS manipulation for refinery process control", "Gas turbine control system attacks", "Offshore platform OT network exploitation", "Pipeline leak detection system manipulation", "Compressor station PLC exploitation", "Tank farm level sensor manipulation"], detection=["Pipeline SCADA network monitoring", "DCS process value validation", "Safety system independence verification", "OT network segmentation monitoring"], tools=["nmap", "modbuspal", "plcscan", "wireshark"], severity="critical"),
]

def build_critical_infra_prompt(focus_type: CritInfraAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Critical Infrastructure Security Knowledge\n"]
    patterns = CRIT_INFRA_PATTERNS if not focus_type else [p for p in CRIT_INFRA_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
