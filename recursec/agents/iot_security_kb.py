"""IoT security knowledge base.

Deep knowledge about IoT security:
1. Firmware analysis
2. Hardware hacking
3. IoT protocol attacks
4. Smart device exploitation
5. Industrial IoT (IIoT) security
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class IoTPattern:
    """An IoT security pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:12],
        }


IOT_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "iot-001", "name": "Firmware Analysis",
        "category": "firmware", "severity": "high",
        "desc": "IoT firmware analysis.",
        "detection": (
            "FIRMWARE ANALYSIS:\n"
            "EXTRACTION:\n"
            "  # Binwalk (extract filesystem)\n"
            "  binwalk -e firmware.bin\n"
            "  # Firmware-mod-kit\n"
            "  extract-firmware.sh firmware.bin\n"
            "  # Jefferson (JFFS2)\n"
            "  jefferson firmware.bin -d output/\n"
            "  # ubi_reader (UBIFS)\n"
            "  ubireader_extract_images firmware.bin\n"
            "ANALYSIS:\n"
            "  - Hardcoded credentials\n"
            "  - Private keys (SSL/SSH)\n"
            "  - API keys and tokens\n"
            "  - Debug interfaces\n"
            "  - Backdoor accounts\n"
            "  - Known vulnerable libraries\n"
            "  - Insecure default configs\n"
            "  # Search patterns\n"
            "  grep -r 'password\\|passwd\\|secret\\|key' filesystem/\n"
            "  find . -name '*.pem' -o -name '*.key'\n"
            "  strings firmware.bin | grep -i 'admin\\|root\\|pass'\n"
            "EMULATION:\n"
            "  # QEMU (emulate firmware)\n"
            "  # Firmadyne (automated analysis)\n"
            "  # FAT (Firmware Analysis Toolkit)\n"
            "  # FirmAE (large-scale emulation)\n"
            "BINARY ANALYSIS:\n"
            "  - Ghidra/IDA for reverse engineering\n"
            "  - radare2 for quick analysis\n"
            "  - Angr for symbolic execution\n"
            "TOOLS:\n"
            "  Binwalk, Firmwalker, Ghidra, Firmadyne"
        ),
        "tools": ["binwalk"],
    },
    {
        "id": "iot-002", "name": "Hardware Hacking",
        "category": "hardware", "severity": "high",
        "desc": "Hardware-level attacks.",
        "detection": (
            "HARDWARE HACKING:\n"
            "INTERFACES:\n"
            "  UART:\n"
            "    - Find TX/RX/GND pins\n"
            "    - Logic analyzer to find baud rate\n"
            "    - minicom/screen for serial console\n"
            "    - Often gives root shell\n"
            "  JTAG:\n"
            "    - Boundary scan\n"
            "    - Flash reading/writing\n"
            "    - Debugging live systems\n"
            "    - OpenOCD for JTAG access\n"
            "  SPI/I2C:\n"
            "    - Flash chip reading\n"
            "    - EEPROM extraction\n"
            "    - flashrom for SPI flash\n"
            "    - Bus Pirate for interface\n"
            "CHIP-OFF:\n"
            "  - Desolder flash chips\n"
            "  - Read with programmer\n"
            "  - TSOP/BGA adapters\n"
            "  - Reconstruct filesystem\n"
            "SIDE CHANNEL:\n"
            "  - Power analysis (SPA/DPA)\n"
            "  - Electromagnetic analysis\n"
            "  - Timing attacks\n"
            "  - Fault injection (voltage glitching)\n"
            "PHYSICAL:\n"
            "  - PCB analysis\n"
            "  - Component identification\n"
            "  - Test point probing\n"
            "  - Decapping for chip analysis\n"
            "TOOLS:\n"
            "  Bus Pirate, logic analyzer, JTAGulator,\n"
            "  flashrom, OpenOCD, ChipWhisperer"
        ),
        "tools": [],
    },
    {
        "id": "iot-003", "name": "IoT Protocol Attacks",
        "category": "protocols", "severity": "high",
        "desc": "IoT protocol attacks.",
        "detection": (
            "IOT PROTOCOL ATTACKS:\n"
            "MQTT:\n"
            "  - Anonymous access (no auth)\n"
            "  - Subscribe to # (all topics)\n"
            "  - Inject messages to control devices\n"
            "  - Topic enumeration\n"
            "  # mosquitto_sub -h TARGET -t '#' -v\n"
            "  # mosquitto_pub -h TARGET -t 'cmd' -m 'payload'\n"
            "CoAP:\n"
            "  - No authentication by default\n"
            "  - Resource discovery (.well-known/core)\n"
            "  - Observe notification abuse\n"
            "  - UDP-based (amplification possible)\n"
            "ZIGBEE:\n"
            "  - Sniffing (KillerBee)\n"
            "  - Key extraction\n"
            "  - Replay attacks\n"
            "  - Network key interception\n"
            "  - Touchlink commissioning abuse\n"
            "Z-WAVE:\n"
            "  - S0 security (weak crypto)\n"
            "  - Network key brute force\n"
            "  - Node impersonation\n"
            "  - Downgrade attacks\n"
            "BLE:\n"
            "  - GATT enumeration\n"
            "  - Connection sniffing\n"
            "  - Legacy pairing attacks\n"
            "  - MITM (JustWorks pairing)\n"
            "UPnP:\n"
            "  - SSDP discovery\n"
            "  - Port mapping abuse\n"
            "  - XML injection\n"
            "TOOLS:\n"
            "  Mosquitto, KillerBee, HackRF, Ubertooth"
        ),
        "tools": [],
    },
    {
        "id": "iot-004", "name": "Smart Device Exploitation",
        "category": "smart_devices", "severity": "high",
        "desc": "Smart device exploitation.",
        "detection": (
            "SMART DEVICE EXPLOITATION:\n"
            "SMART HOME:\n"
            "  - Smart speakers (Alexa/Google)\n"
            "  - Smart locks (replay, bypass)\n"
            "  - Smart cameras (RTSP streams)\n"
            "  - Smart thermostats\n"
            "  - Smart plugs (firmware vuln)\n"
            "NETWORK DEVICES:\n"
            "  - Router admin (default creds)\n"
            "  - Router RCE (known CVEs)\n"
            "  - IP camera RTSP exposure\n"
            "  # rtsp://TARGET:554/live\n"
            "  - NAS device exploitation\n"
            "  - Printer exploitation (PJL/PRET)\n"
            "AUTOMOTIVE:\n"
            "  - CAN bus injection\n"
            "  - OBD-II exploitation\n"
            "  - Keyfob replay/relay\n"
            "  - Telematics exploitation\n"
            "MEDICAL DEVICES:\n"
            "  - Network-connected devices\n"
            "  - DICOM service exposure\n"
            "  - Default credentials\n"
            "  - Legacy OS (Windows XP)\n"
            "  - Wireless implant attacks\n"
            "ATTACK SURFACE:\n"
            "  - Shodan/Censys IoT search\n"
            "  - Default credential databases\n"
            "  - Firmware vulnerability databases\n"
            "  - CVE search by vendor/model\n"
            "TOOLS:\n"
            "  Shodan, PRET (printers), nmap, RTSP tools"
        ),
        "tools": ["shodan"],
    },
    {
        "id": "iot-005", "name": "Industrial IoT (IIoT) Security",
        "category": "iiot", "severity": "critical",
        "desc": "Industrial IoT security.",
        "detection": (
            "INDUSTRIAL IoT (IIoT):\n"
            "PROTOCOLS:\n"
            "  - Modbus TCP (port 502)\n"
            "  - OPC UA (port 4840)\n"
            "  - BACnet (port 47808)\n"
            "  - DNP3 (port 20000)\n"
            "  - EtherNet/IP (port 44818)\n"
            "  - PROFINET\n"
            "  - S7comm (Siemens, port 102)\n"
            "ATTACKS:\n"
            "  MODBUS:\n"
            "    # Read holding registers\n"
            "    modbus-cli read TARGET 0 10\n"
            "    # Write coils (DANGEROUS)\n"
            "    # No authentication by default\n"
            "  OPC UA:\n"
            "    - Anonymous authentication\n"
            "    - Weak security policies\n"
            "    - Certificate validation bypass\n"
            "  PLC/RTU:\n"
            "    - Firmware update abuse\n"
            "    - Logic modification\n"
            "    - Denial of service\n"
            "    - Ladder logic injection\n"
            "NETWORK:\n"
            "  - IT/OT network segmentation\n"
            "  - Purdue model assessment\n"
            "  - Air-gap bypass techniques\n"
            "  - SCADA protocol fuzzing\n"
            "STANDARDS:\n"
            "  - IEC 62443\n"
            "  - NIST SP 800-82\n"
            "  - NERC CIP\n"
            "TOOLS:\n"
            "  Metasploit SCADA modules, modbus-cli,\n"
            "  OPC UA tools, Redpoint (nmap scripts)"
        ),
        "tools": [],
    },
]


class IoTSecurityKB:
    """IoT security knowledge base.

    Provides IoT security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, IoTPattern] = {}
        self._log = logger.bind(component="iot_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load IoT patterns."""
        for data in IOT_PATTERNS:
            pattern = IoTPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[IoTPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_iot_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build IoT security prompt."""
        lines = ["## IoT Security\n"]
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
