"""IoT and ICS/OT security knowledge base.

Deep knowledge about IoT/ICS security:
1. IoT device security
2. Industrial control systems (SCADA)
3. Firmware analysis
4. Protocol security (Modbus, DNP3, BACnet)
5. Smart home / connected device attacks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class IoTICSPattern:
    """An IoT/ICS security pattern."""
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


IOT_ICS_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "iot-001", "name": "IoT Device Security",
        "category": "iot_device", "severity": "high",
        "desc": "IoT device security assessment.",
        "detection": (
            "IOT DEVICE SECURITY:\n"
            "NETWORK DISCOVERY:\n"
            "  - Shodan/Censys IoT search\n"
            "  - nmap service fingerprinting\n"
            "    # nmap -sV -sC -p- TARGET\n"
            "  - UPnP/SSDP discovery\n"
            "    # gssdp-discover\n"
            "  - mDNS/Bonjour enumeration\n"
            "  - ZigBee/Z-Wave sniffing\n"
            "  - BLE scanning\n"
            "    # hcitool lescan\n"
            "    # bettercap ble.recon on\n"
            "COMMON VULNERABILITIES:\n"
            "  - Default credentials\n"
            "    # admin/admin, root/root\n"
            "    # Vendor-specific defaults\n"
            "  - Unencrypted protocols\n"
            "    # Telnet, HTTP, FTP, MQTT\n"
            "  - Open debug ports\n"
            "    # UART, JTAG, SWD\n"
            "  - Hardcoded keys/certificates\n"
            "  - Insecure OTA updates\n"
            "    # No signature verification\n"
            "    # HTTP (not HTTPS)\n"
            "  - MQTT without auth\n"
            "    # mosquitto_sub -h TARGET -t '#'\n"
            "  - CoAP without DTLS\n"
            "TOOLS:\n"
            "  Shodan, nmap, bettercap, firmwalker, mqtt-pwn"
        ),
        "tools": [],
    },
    {
        "id": "iot-002", "name": "SCADA/ICS Security",
        "category": "scada", "severity": "critical",
        "desc": "Industrial control system security.",
        "detection": (
            "SCADA/ICS SECURITY:\n"
            "PROTOCOL ASSESSMENT:\n"
            "  Modbus:\n"
            "    # Port 502 (TCP)\n"
            "    # No authentication by default\n"
            "    # Read/write registers\n"
            "    # nmap --script modbus-discover TARGET\n"
            "    # modbus-cli read TARGET 0 100\n"
            "  DNP3:\n"
            "    # Port 20000\n"
            "    # Secure Authentication v5\n"
            "    # Unsolicited responses\n"
            "  OPC UA:\n"
            "    # Discovery endpoint\n"
            "    # Certificate validation\n"
            "    # Anonymous auth check\n"
            "    # opc-ua-scanner\n"
            "  EtherNet/IP:\n"
            "    # Port 44818\n"
            "    # CIP protocol\n"
            "    # Device enumeration\n"
            "  BACnet:\n"
            "    # Port 47808 (UDP)\n"
            "    # Device discovery\n"
            "    # Property read/write\n"
            "NETWORK:\n"
            "  - IT/OT segmentation check\n"
            "  - Purdue model compliance\n"
            "  - DMZ between corporate and ICS\n"
            "  - Remote access audit\n"
            "  - Historian server security\n"
            "TOOLS:\n"
            "  nmap ICS scripts, PLCScan, Redpoint, GRFICSv2"
        ),
        "tools": [],
    },
    {
        "id": "iot-003", "name": "Firmware Analysis",
        "category": "firmware", "severity": "high",
        "desc": "Firmware extraction and analysis.",
        "detection": (
            "FIRMWARE ANALYSIS:\n"
            "EXTRACTION:\n"
            "  - Download from vendor site\n"
            "  - Extract from device (UART/JTAG)\n"
            "  - Capture OTA update\n"
            "  - SPI flash dump (flashrom)\n"
            "UNPACKING:\n"
            "  # binwalk -e firmware.bin\n"
            "  # binwalk -Me firmware.bin (recursive)\n"
            "  # Identify filesystem\n"
            "    # SquashFS, JFFS2, CramFS\n"
            "    # unsquashfs, jefferson\n"
            "STATIC ANALYSIS:\n"
            "  - Hardcoded credentials\n"
            "    # grep -rn 'password' filesystem/\n"
            "    # grep -rn 'api_key' filesystem/\n"
            "  - Private keys/certificates\n"
            "    # find . -name '*.pem' -o -name '*.key'\n"
            "  - Configuration files\n"
            "  - Known vulnerable binaries\n"
            "    # Check versions against CVEs\n"
            "  - Backdoor accounts\n"
            "    # cat etc/passwd etc/shadow\n"
            "  - Debug interfaces\n"
            "    # Telnet/SSH enabled\n"
            "    # Debug web interfaces\n"
            "EMULATION:\n"
            "  - QEMU user-mode\n"
            "  - QEMU system-mode (FirmAE)\n"
            "  - Firmware Analysis Toolkit (FAT)\n"
            "TOOLS:\n"
            "  binwalk, firmwalker, EMBA, FirmAE, Ghidra"
        ),
        "tools": [],
    },
    {
        "id": "iot-004", "name": "ICS Protocol Attacks",
        "category": "ics_protocol", "severity": "critical",
        "desc": "ICS protocol-specific attacks.",
        "detection": (
            "ICS PROTOCOL ATTACKS:\n"
            "MODBUS ATTACKS:\n"
            "  - Register read (function 3/4)\n"
            "  - Coil write (function 5/15)\n"
            "  - Register write (function 6/16)\n"
            "  - Diagnostic functions\n"
            "  - Device identification\n"
            "  # No auth → full read/write control\n"
            "  # Replay attacks\n"
            "  # MitM between HMI and PLC\n"
            "S7COMM:\n"
            "  - Siemens S7 protocol (port 102)\n"
            "  - CPU stop/start\n"
            "  - Program upload/download\n"
            "  - Memory read/write\n"
            "  # snap7 library\n"
            "  # nmap --script s7-info TARGET\n"
            "PROFINET:\n"
            "  - DCP discovery\n"
            "  - Name/IP manipulation\n"
            "  - Firmware upload\n"
            "IEC 61850:\n"
            "  - MMS protocol\n"
            "  - GOOSE message injection\n"
            "  - Sampled Values manipulation\n"
            "  # Power grid substations\n"
            "CODESYS:\n"
            "  - Port 2455 (V2) / 1217 (V3)\n"
            "  - PLC code upload without auth\n"
            "  - Runtime manipulation\n"
            "TOOLS:\n"
            "  snap7, pymodbus, Scapy, ISF (ICS-exploit)"
        ),
        "tools": [],
    },
    {
        "id": "iot-005", "name": "Smart Home Attacks",
        "category": "smart_home", "severity": "medium",
        "desc": "Smart home and connected device attacks.",
        "detection": (
            "SMART HOME ATTACKS:\n"
            "WIRELESS:\n"
            "  ZigBee:\n"
            "    - Sniff with KillerBee\n"
            "    - Default trust center key\n"
            "    - Network key extraction\n"
            "    - Replay attacks\n"
            "    - Device impersonation\n"
            "  Z-Wave:\n"
            "    - S0 security (known key)\n"
            "    - S2 downgrade attack\n"
            "    - Signal jamming\n"
            "    - EZ-Wave tool\n"
            "  BLE:\n"
            "    - Sniffing (Ubertooth)\n"
            "    - GATT enumeration\n"
            "    - Characteristic write\n"
            "    - Eavesdropping\n"
            "    - Relay attacks\n"
            "VOICE ASSISTANTS:\n"
            "  - Ultrasonic injection (DolphinAttack)\n"
            "  - Laser injection (LightCommands)\n"
            "  - Skill squatting (Alexa/Google)\n"
            "  - Voice command injection\n"
            "CAMERAS:\n"
            "  - RTSP without auth\n"
            "    # rtsp://TARGET:554/stream\n"
            "  - Default credentials\n"
            "  - Firmware vulnerabilities\n"
            "  - Cloud API exploitation\n"
            "TOOLS:\n"
            "  KillerBee, Ubertooth, bettercap, nmap"
        ),
        "tools": [],
    },
]


class IoTICSKB:
    """IoT and ICS/OT security knowledge base.

    Provides IoT/ICS patterns injected
    into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, IoTICSPattern] = {}
        self._log = logger.bind(component="iot_ics_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load IoT/ICS patterns."""
        for data in IOT_ICS_PATTERNS:
            pattern = IoTICSPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[IoTICSPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_iot_ics_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build IoT/ICS prompt."""
        lines = ["## IoT/ICS Security\n"]
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
