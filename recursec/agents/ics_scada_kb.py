"""ICS/SCADA security knowledge base.

Deep knowledge about industrial control systems:
1. ICS protocols (Modbus, DNP3, OPC, EtherNet/IP)
2. SCADA system attacks
3. PLC security
4. ICS network segmentation
5. Safety Instrumented Systems (SIS)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ICSPattern:
    """An ICS/SCADA security pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "critical"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:12],
        }


ICS_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ics-001", "name": "ICS Protocols",
        "category": "protocols", "severity": "critical",
        "desc": "ICS protocol security assessment.",
        "detection": (
            "ICS PROTOCOLS:\n"
            "MODBUS:\n"
            "  - No authentication (by design)\n"
            "  - TCP/502\n"
            "  - Read/write registers directly\n"
            "  # Enumerate with nmap\n"
            "  nmap -p 502 --script modbus-discover <target>\n"
            "  # Read holding registers\n"
            "  modbus-cli read <host> 0 10  # Read 10 registers\n"
            "  # Write coils/registers (DANGEROUS)\n"
            "  # Replay attacks (no sequence numbers)\n"
            "DNP3:\n"
            "  - Distributed Network Protocol 3\n"
            "  - TCP/20000\n"
            "  - Secure Authentication (SA) optional\n"
            "  - Fuzzing with Aegis\n"
            "  nmap -p 20000 --script dnp3-info <target>\n"
            "OPC UA:\n"
            "  - TCP/4840\n"
            "  - More modern, has security modes\n"
            "  - Security Mode: None (vulnerable!)\n"
            "  - Certificate-based auth\n"
            "  # OPC UA client: UaExpert, opcua-client\n"
            "ETHERNET/IP:\n"
            "  - TCP/44818, UDP/2222\n"
            "  - CIP (Common Industrial Protocol)\n"
            "  - No encryption by default\n"
            "  nmap -p 44818 --script enip-info <target>\n"
            "BACNET:\n"
            "  - UDP/47808\n"
            "  - Building automation\n"
            "  - No authentication\n"
            "  nmap -p 47808 --script bacnet-info <target>\n"
            "TOOLS:\n"
            "  nmap (ICS scripts), mbtget, opcua-client"
        ),
        "tools": ["nmap"],
    },
    {
        "id": "ics-002", "name": "SCADA System Attacks",
        "category": "scada", "severity": "critical",
        "desc": "SCADA system attack vectors.",
        "detection": (
            "SCADA SYSTEM ATTACKS:\n"
            "HISTORICAL ATTACKS:\n"
            "  - Stuxnet (2010): Iranian centrifuges\n"
            "    Siemens S7-300 PLC manipulation\n"
            "    4 zero-days, USB propagation\n"
            "  - Ukraine Power Grid (2015/2016):\n"
            "    BlackEnergy malware → SCADA access\n"
            "    Industroyer/CrashOverride\n"
            "  - TRITON/TRISIS (2017):\n"
            "    Targeted SIS (Safety Instrumented System)\n"
            "    Could have caused physical damage\n"
            "  - Colonial Pipeline (2021):\n"
            "    IT/OT boundary breach\n"
            "    Ransomware → operational shutdown\n"
            "ATTACK VECTORS:\n"
            "  - IT/OT boundary breach\n"
            "  - VPN/remote access compromise\n"
            "  - Engineering workstation infection\n"
            "  - Supply chain (vendor update)\n"
            "  - USB drop (air-gapped networks)\n"
            "  - Historian server compromise\n"
            "  - HMI (Human-Machine Interface) exploit\n"
            "RECONNAISSANCE:\n"
            "  # Shodan for ICS\n"
            "  shodan search 'port:502'\n"
            "  shodan search 'port:44818'\n"
            "  # Censys for ICS protocols\n"
            "  # Google dorking: 'intitle:\"SCADA\" inurl:\"view\"'"
        ),
        "tools": ["shodan"],
    },
    {
        "id": "ics-003", "name": "PLC Security",
        "category": "plc", "severity": "critical",
        "desc": "PLC (Programmable Logic Controller) security.",
        "detection": (
            "PLC SECURITY:\n"
            "VENDORS:\n"
            "  - Siemens S7 (S7comm, S7comm-plus)\n"
            "  - Allen-Bradley/Rockwell (EtherNet/IP)\n"
            "  - Schneider Electric (Modbus)\n"
            "  - ABB, Honeywell, Emerson\n"
            "SIEMENS S7:\n"
            "  # S7comm protocol (TCP/102)\n"
            "  nmap -p 102 --script s7-info <target>\n"
            "  # Password protection bypass\n"
            "  # snap7 library for communication\n"
            "  # CPU start/stop commands\n"
            "  # Program upload/download\n"
            "ATTACKS:\n"
            "  - Firmware manipulation\n"
            "  - Logic bomb injection\n"
            "  - CPU stop command (DoS)\n"
            "  - Configuration change\n"
            "  - Ladder logic modification\n"
            "  - Bypass safety interlocks\n"
            "DEFENSES:\n"
            "  - Network segmentation (IEC 62443)\n"
            "  - Firmware integrity verification\n"
            "  - Change detection monitoring\n"
            "  - Access control lists\n"
            "  - Physical key switches\n"
            "TOOLS:\n"
            "  snap7, PLCscan, Redpoint (Nmap scripts)"
        ),
        "tools": ["nmap"],
    },
    {
        "id": "ics-004", "name": "ICS Network Segmentation",
        "category": "network", "severity": "high",
        "desc": "ICS network architecture and segmentation.",
        "detection": (
            "ICS NETWORK SEGMENTATION:\n"
            "PURDUE MODEL:\n"
            "  Level 5: Enterprise Network\n"
            "  Level 4: Business Planning/Logistics\n"
            "  --- DMZ (IT/OT boundary) ---\n"
            "  Level 3: Site Operations (Historian, SCADA)\n"
            "  Level 2: Area Control (HMI, Engineering WS)\n"
            "  Level 1: Basic Control (PLC, RTU, DCS)\n"
            "  Level 0: Process (Sensors, Actuators)\n"
            "ASSESSMENT:\n"
            "  - Map IT/OT boundary\n"
            "  - Identify cross-zone connections\n"
            "  - Check firewall rules between zones\n"
            "  - Verify DMZ configuration\n"
            "  - Audit remote access (VPN, RDP)\n"
            "  - Check for flat networks (no segmentation)\n"
            "COMMON ISSUES:\n"
            "  - No DMZ between IT and OT\n"
            "  - Direct internet exposure\n"
            "  - Shared credentials across zones\n"
            "  - Unpatched Windows systems in OT\n"
            "  - Dual-homed workstations\n"
            "  - Legacy protocols without encryption\n"
            "STANDARDS:\n"
            "  - IEC 62443 (industrial cybersecurity)\n"
            "  - NIST SP 800-82 (ICS security)\n"
            "  - NERC CIP (energy sector)\n"
            "TOOLS:\n"
            "  Grassmarlin, Claroty, Dragos, Nozomi"
        ),
        "tools": [],
    },
    {
        "id": "ics-005", "name": "Safety Instrumented Systems",
        "category": "sis", "severity": "critical",
        "desc": "SIS security (Safety Instrumented Systems).",
        "detection": (
            "SAFETY INSTRUMENTED SYSTEMS (SIS):\n"
            "CONCEPT:\n"
            "  - Last line of defense against physical harm\n"
            "  - Emergency shutdown systems (ESD)\n"
            "  - Fire & gas detection\n"
            "  - Pressure/temperature relief\n"
            "  - Should be INDEPENDENT from control system\n"
            "TRITON/TRISIS:\n"
            "  - First malware targeting SIS\n"
            "  - Targeted Schneider Triconex\n"
            "  - Could have disabled safety systems\n"
            "  - Discovery: accidental plant shutdown\n"
            "  - Attacker goal: cause physical damage\n"
            "ATTACK VECTORS:\n"
            "  - Engineering workstation compromise\n"
            "  - SIS network not isolated from DCS\n"
            "  - Firmware update manipulation\n"
            "  - Logic change via engineering software\n"
            "  - Disabling safety interlocks\n"
            "ASSESSMENT:\n"
            "  - Verify SIS independence from DCS\n"
            "  - Check physical separation of networks\n"
            "  - Review change management for SIS\n"
            "  - Verify key switch positions\n"
            "  - Test bypass procedures\n"
            "  - Review SIL (Safety Integrity Level)\n"
            "STANDARDS:\n"
            "  - IEC 61508 (functional safety)\n"
            "  - IEC 61511 (process industry SIS)\n"
            "  - ISA 84.00.01\n"
            "WARNING:\n"
            "  NEVER test SIS on live systems without authorization\n"
            "  Incorrect actions can cause loss of life"
        ),
        "tools": [],
    },
]


class ICSScadaKB:
    """ICS/SCADA security knowledge base.

    Provides ICS/SCADA patterns injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, ICSPattern] = {}
        self._log = logger.bind(component="ics_scada_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load ICS patterns."""
        for data in ICS_PATTERNS:
            pattern = ICSPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[ICSPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_ics_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build ICS/SCADA prompt."""
        lines = ["## ICS/SCADA Security\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category.lower() not in [c.lower() for c in categories]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.category.upper()}]")
            lines.append(pattern.detection_strategy)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = {}
        for p in self._patterns.values():
            cat_counts[p.category] = cat_counts.get(p.category, 0) + 1
        return {
            "patterns": len(self._patterns),
            "by_category": cat_counts,
        }
