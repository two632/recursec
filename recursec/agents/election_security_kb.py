"""Election and voting system security knowledge base."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class ElectionAttackType(str, Enum):
    VOTING_MACHINE = "voting_machine"
    INFRASTRUCTURE = "infrastructure"
    INFORMATION = "information"
    SUPPLY_CHAIN = "supply_chain"

@dataclass
class ElectionPattern:
    name: str = ""
    attack_type: ElectionAttackType = ElectionAttackType.VOTING_MACHINE
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    severity: str = "critical"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

ELECTION_PATTERNS: list[ElectionPattern] = [
    ElectionPattern(name="Voting Machine Exploitation", attack_type=ElectionAttackType.VOTING_MACHINE, description="Direct manipulation of electronic voting machines: DRE, optical scan, BMD.", techniques=["DRE memory card tampering (swap pre-loaded cards)", "USB boot attack on voting machines (bypass BIOS)", "Touchscreen calibration manipulation", "Ballot definition file tampering", "VVPAT printer manipulation (mismatch screen vs paper)", "QR code ballot manipulation on BMD systems", "Firmware modification via maintenance port"], detection=["Hash verification of voting machine software", "Physical tamper-evident seals", "Pre-election logic and accuracy testing", "Parallel testing during election"], tools=["binwalk", "ghidra", "volatility"], severity="critical"),
    ElectionPattern(name="Election Infrastructure", attack_type=ElectionAttackType.INFRASTRUCTURE, description="Attack election backend: voter registration, results reporting, election management.", techniques=["Voter registration database SQL injection", "Election night reporting system manipulation", "EMS (Election Management System) compromise", "Poll book system exploitation", "Results transmission interception (modem/VPN)", "Election website DDoS during results reporting", "Certificate authority compromise for election PKI"], detection=["Database integrity monitoring", "Air-gapped results aggregation", "Multi-party audit of election systems", "Network monitoring during transmission"], tools=["nmap", "sqlmap", "burpsuite", "wireshark"], severity="critical"),
    ElectionPattern(name="Information Operations", attack_type=ElectionAttackType.INFORMATION, description="Information warfare targeting elections: disinformation, social media manipulation.", techniques=["Deepfake candidate video generation", "Social media bot networks for narrative amplification", "Micro-targeted disinformation campaigns", "Voter suppression via false election information", "Hack-and-leak operations (email/document dumps)", "Domain squatting of election-related websites", "AI-generated fake news articles at scale"], detection=["Content authenticity verification", "Bot network detection algorithms", "Cross-platform narrative tracking", "Deepfake detection models"], tools=["osint-tools", "social-analyzer"], severity="high"),
    ElectionPattern(name="Election Supply Chain", attack_type=ElectionAttackType.SUPPLY_CHAIN, description="Supply chain attacks on election technology vendors and components.", techniques=["Voting system vendor network compromise", "Backdoor in voting machine firmware at factory", "Compromised USB drives distributed to election officials", "Third-party software component vulnerability (COTS)", "Printer supply chain attack (ballot-on-demand printers)", "Cloud service provider compromise (election SaaS)", "Hardware implant in voting machine components"], detection=["Vendor security assessment and auditing", "Hardware integrity verification", "Software bill of materials analysis", "Secure supply chain certification"], tools=["trivy", "syft", "binwalk"], severity="critical"),
]

def build_election_security_prompt(focus_type: ElectionAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Election & Voting System Security Knowledge\n"]
    patterns = ELECTION_PATTERNS if not focus_type else [p for p in ELECTION_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
