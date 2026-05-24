"""ICS/SCADA security deep-dive knowledge base.

Deep knowledge about industrial control systems:
1. SCADA protocol attacks (Modbus, DNP3, OPC)
2. PLC exploitation
3. HMI vulnerabilities
4. Network architecture attacks
5. Safety system targeting
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
        "id": "ics-001", "name": "SCADA Protocol Attacks",
        "category": "protocol", "severity": "critical",
        "desc": "SCADA protocol attacks.",
        "detection": (
            "SCADA PROTOCOL ATTACKS:\n"
            "MODBUS (TCP/502):\n"
            "  - No authentication\n"
            "  - No encryption\n"
            "  - Function code abuse\n"
            "    # Read Coils (0x01)\n"
            "    # Read Holding Registers (0x03)\n"
            "    # Write Single Coil (0x05)\n"
            "    # Write Multiple Registers (0x10)\n"
            "  # nmap -sV -p 502 --script modbus-discover TARGET\n"
            "  # mbtget (read/write Modbus)\n"
            "  # pymodbus (Python library)\n"
            "DNP3 (TCP/20000):\n"
            "  - Broadcast storm attacks\n"
            "  - Unsolicited response injection\n"
            "  - Authentication bypass (older)\n"
            "  - Secure Authentication v5 attacks\n"
            "  # nmap --script dnp3-info TARGET\n"
            "OPC UA:\n"
            "  - Default credentials\n"
            "  - Certificate management\n"
            "  - Discovery endpoint abuse\n"
            "  - Method call exploitation\n"
            "  # python-opcua\n"
            "  # UaExpert client\n"
            "PROFINET / ETHERNET/IP:\n"
            "  - Service enumeration\n"
            "  - Device identification\n"
            "  - Configuration read/write\n"
            "  # nmap --script enip-info TARGET\n"
            "TOOLS:\n"
            "  nmap ICS scripts, mbtget, pymodbus, Wireshark"
        ),
        "tools": [],
    },
    {
        "id": "ics-002", "name": "PLC Exploitation",
        "category": "plc", "severity": "critical",
        "desc": "PLC exploitation techniques.",
        "detection": (
            "PLC EXPLOITATION:\n"
            "RECONNAISSANCE:\n"
            "  - Identify PLC vendor/model\n"
            "  - Firmware version detection\n"
            "  - Programming software identification\n"
            "  - Network topology mapping\n"
            "  # Shodan: port:102 siemens\n"
            "  # Shodan: port:44818 allen-bradley\n"
            "SIEMENS S7:\n"
            "  - S7comm protocol (port 102)\n"
            "  - CPU stop/start commands\n"
            "  - Memory read/write\n"
            "  - Program upload/download\n"
            "  - Password bypass (older models)\n"
            "  # snap7 (Python library)\n"
            "  # nmap --script s7-info TARGET\n"
            "ALLEN-BRADLEY:\n"
            "  - CIP protocol exploitation\n"
            "  - EtherNet/IP attacks\n"
            "  - Firmware manipulation\n"
            "  - Project file extraction\n"
            "FIRMWARE:\n"
            "  - Firmware extraction (JTAG/SWD)\n"
            "  - Binary analysis\n"
            "  - Backdoor insertion\n"
            "  - Logic bomb injection\n"
            "  - Rootkit development\n"
            "LOGIC ATTACKS:\n"
            "  - Ladder logic modification\n"
            "  - Setpoint manipulation\n"
            "  - Timer/counter abuse\n"
            "  - Safety bypass\n"
            "TOOLS:\n"
            "  snap7, plcscan, OpenPLC, Codesys"
        ),
        "tools": [],
    },
    {
        "id": "ics-003", "name": "HMI Vulnerabilities",
        "category": "hmi", "severity": "high",
        "desc": "HMI and SCADA software vulnerabilities.",
        "detection": (
            "HMI VULNERABILITIES:\n"
            "WEB-BASED HMI:\n"
            "  - Default credentials\n"
            "  - SQL injection\n"
            "  - Cross-site scripting (XSS)\n"
            "  - Insecure direct object reference\n"
            "  - Path traversal\n"
            "  - Remote code execution\n"
            "  # Standard web pentest techniques\n"
            "  # OWASP Top 10 applicable\n"
            "THICK CLIENT HMI:\n"
            "  - Insecure communications\n"
            "  - Hardcoded credentials\n"
            "  - DLL hijacking\n"
            "  - Buffer overflows\n"
            "  - Memory corruption\n"
            "  - Insecure update mechanism\n"
            "HISTORIAN:\n"
            "  - Database access (SQL injection)\n"
            "  - Data manipulation\n"
            "  - Credential extraction\n"
            "  - API exploitation\n"
            "  - OSIsoft PI vulnerabilities\n"
            "SCADA SOFTWARE:\n"
            "  - Vendor-specific CVEs\n"
            "    # Schneider (ClearSCADA, Citect)\n"
            "    # Siemens (WinCC, SIMATIC)\n"
            "    # GE (iFIX, CIMPLICITY)\n"
            "    # Wonderware (InTouch)\n"
            "  - Patch management challenges\n"
            "  - Legacy system exposure\n"
            "TOOLS:\n"
            "  Burp Suite, DLL hijack tools, ICS-CERT"
        ),
        "tools": [],
    },
    {
        "id": "ics-004", "name": "ICS Network Architecture",
        "category": "network", "severity": "high",
        "desc": "ICS network architecture attacks.",
        "detection": (
            "ICS NETWORK ARCHITECTURE:\n"
            "PURDUE MODEL:\n"
            "  Level 5: Enterprise (Internet)\n"
            "  Level 4: Business Planning (ERP)\n"
            "  Level 3: Operations (MES, Historian)\n"
            "  Level 2: Control (HMI, SCADA)\n"
            "  Level 1: Basic Control (PLC, RTU)\n"
            "  Level 0: Process (Sensors, Actuators)\n"
            "ATTACKS:\n"
            "  - DMZ bypass (Level 3.5)\n"
            "  - Firewall rule abuse\n"
            "  - Jump host compromise\n"
            "  - Historian as pivot point\n"
            "  - VPN/remote access exploitation\n"
            "  - Dual-homed workstation abuse\n"
            "SEGMENTATION:\n"
            "  - VLAN hopping\n"
            "  - Firewall bypass\n"
            "  - Serial-to-IP converter abuse\n"
            "  - Wireless bridge exploitation\n"
            "  - USB/removable media\n"
            "REMOTE ACCESS:\n"
            "  - RDP to ICS systems\n"
            "  - VPN credential theft\n"
            "  - TeamViewer/AnyDesk abuse\n"
            "  - Vendor remote access\n"
            "  - Cellular modem access\n"
            "TOOLS:\n"
            "  nmap, Wireshark, Grassmarlin, Redpoint"
        ),
        "tools": [],
    },
    {
        "id": "ics-005", "name": "Safety System Targeting",
        "category": "safety", "severity": "critical",
        "desc": "Safety Instrumented System (SIS) attacks.",
        "detection": (
            "SAFETY SYSTEM TARGETING:\n"
            "SIS OVERVIEW:\n"
            "  - Safety Instrumented Systems\n"
            "  - Independent from BPCS\n"
            "  - Emergency shutdown capability\n"
            "  - Examples: Triconex, HIMA, Yokogawa\n"
            "TRITON/TRISIS:\n"
            "  - Targeted Schneider Triconex SIS\n"
            "  - Replaced safety logic\n"
            "  - Could have caused physical harm\n"
            "  - Zero-day in firmware\n"
            "  - Nation-state attack (XENOTIME)\n"
            "ATTACK VECTORS:\n"
            "  - Engineering workstation compromise\n"
            "  - Direct network access to SIS\n"
            "  - Firmware manipulation\n"
            "  - Logic modification\n"
            "  - Communication protocol abuse\n"
            "IMPACT:\n"
            "  - Disable safety protections\n"
            "  - Allow unsafe process states\n"
            "  - Physical damage potential\n"
            "  - Environmental damage\n"
            "  - Loss of life risk\n"
            "DETECTION:\n"
            "  - SIS network monitoring\n"
            "  - Logic change detection\n"
            "  - Communication anomaly detection\n"
            "  - Engineering workstation monitoring\n"
            "  - Firmware integrity checking\n"
            "TOOLS:\n"
            "  Claroty, Nozomi, Dragos, SIS monitoring"
        ),
        "tools": [],
    },
]


class ICSScadaDeepKB:
    """ICS/SCADA security deep-dive KB.

    Provides ICS/SCADA security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, ICSPattern] = {}
        self._log = logger.bind(component="ics_scada_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load ICS/SCADA patterns."""
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
        """Build ICS/SCADA security prompt."""
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
