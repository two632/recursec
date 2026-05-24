"""Medical device and healthcare security knowledge base."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class MedAttackType(str, Enum):
    DEVICE = "device"
    NETWORK = "network"
    DATA = "data"
    PROTOCOL = "protocol"
    SUPPLY_CHAIN = "supply_chain"

@dataclass
class MedPattern:
    name: str = ""
    attack_type: MedAttackType = MedAttackType.DEVICE
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    severity: str = "critical"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

MED_PATTERNS: list[MedPattern] = [
    MedPattern(name="Medical Device Exploitation", attack_type=MedAttackType.DEVICE, description="Attack medical devices: infusion pumps, pacemakers, MRI, ventilators, patient monitors.", techniques=["Infusion pump firmware tampering (dosage manipulation)", "Pacemaker wireless protocol exploitation (Medtronic, Abbott)", "Patient monitor data falsification", "MRI system command injection via DICOM", "Ventilator control system exploitation", "Defibrillator shock timing manipulation", "Insulin pump relay attack (replay valid commands)"], detection=["Device firmware integrity monitoring", "Network traffic anomaly detection for medical protocols", "Physical tamper detection", "Telemetry data validation"], tools=["nmap", "wireshark", "binwalk", "ghidra"], severity="critical"),
    MedPattern(name="Healthcare Network Attacks", attack_type=MedAttackType.NETWORK, description="Attack hospital networks: segmentation bypass, lateral movement, ransomware deployment.", techniques=["VLAN hopping between clinical and admin networks", "Biomedical device as pivot point (flat network exploitation)", "HL7 message injection via unsegmented interfaces", "Medical IoT device enumeration and exploitation", "PACS server exploitation for lateral movement", "Printer/MFD as network entry point in clinical areas", "Nurse call system exploitation"], detection=["Network segmentation monitoring", "HL7/FHIR traffic anomaly detection", "Medical device communication baselining", "Lateral movement detection in clinical VLANs"], tools=["nmap", "metasploit", "wireshark", "responder"], severity="critical"),
    MedPattern(name="Patient Data Exfiltration", attack_type=MedAttackType.DATA, description="Extract PHI: EHR systems, PACS, lab systems, insurance databases.", techniques=["EHR system SQL injection (Epic, Cerner, Meditech)", "DICOM image exfiltration from PACS servers", "HL7 FHIR API abuse for bulk data export", "Lab information system credential stuffing", "Insurance claim database exploitation", "Prescription system data harvesting", "Genetic data exfiltration from genomics platforms"], detection=["DLP monitoring on PHI data flows", "FHIR API access logging and anomaly detection", "Database query auditing", "Bulk export monitoring"], tools=["sqlmap", "burpsuite", "nuclei"], severity="critical"),
    MedPattern(name="Medical Protocol Attacks", attack_type=MedAttackType.PROTOCOL, description="Attack healthcare protocols: HL7, FHIR, DICOM, IHE, ASTM.", techniques=["HL7v2 message injection (ADT, ORM, ORU manipulation)", "FHIR API authentication bypass", "DICOM C-STORE injection of malicious images", "IHE XDS.b document manipulation", "ASTM protocol message tampering", "HL7 MLLP (Minimal Lower Layer Protocol) exploitation", "FHIR SMART on FHIR OAuth token theft"], detection=["HL7 message validation and schema checking", "FHIR API rate limiting and anomaly detection", "DICOM Association validation", "Protocol-specific IDS signatures"], tools=["hl7apy", "fhir-tools", "dcm4che", "wireshark"], severity="high"),
    MedPattern(name="Medical Supply Chain", attack_type=MedAttackType.SUPPLY_CHAIN, description="Supply chain attacks on medical devices: firmware, updates, third-party components.", techniques=["Firmware update interception for medical devices", "Third-party component vulnerability exploitation (Log4j in medical software)", "Medical device certificate authority compromise", "SBOM analysis for vulnerable components in medical devices", "Counterfeit medical device component insertion", "Cloud-connected medical device API exploitation", "Mobile health app supply chain compromise"], detection=["SBOM monitoring for medical devices", "Firmware update integrity verification", "Third-party component vulnerability scanning", "Certificate pinning validation"], tools=["trivy", "grype", "syft", "binwalk"], severity="high"),
]

def build_medical_device_prompt(focus_type: MedAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Medical Device & Healthcare Security Knowledge\n"]
    patterns = MED_PATTERNS if not focus_type else [p for p in MED_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
