"""IoT security knowledge base.

Deep knowledge about IoT vulnerabilities:
1. Firmware analysis and extraction
2. Hardware interface exploitation
3. MQTT/CoAP protocol attacks
4. SCADA/ICS security
5. Smart home device exploitation
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
        "id": "iot-001", "name": "Firmware Analysis and Extraction",
        "category": "firmware", "severity": "high",
        "desc": "Extracting and analyzing IoT device firmware.",
        "detection": (
            "FIRMWARE ANALYSIS:\n"
            "ACQUISITION:\n"
            "  - Download from vendor website (update packages)\n"
            "  - Extract from device via UART/JTAG/SWD\n"
            "  - Sniff OTA update traffic\n"
            "  - Read flash chip directly (SPI/I2C/NAND)\n"
            "    flashrom -p ft2232_spi:type=2232H -r firmware.bin\n"
            "EXTRACTION:\n"
            "  # binwalk — firmware extraction tool\n"
            "  binwalk -e firmware.bin  # Auto-extract\n"
            "  binwalk -Me firmware.bin  # Recursive extraction\n"
            "  # Entropy analysis (find encrypted/compressed sections)\n"
            "  binwalk -E firmware.bin\n"
            "  # Filesystem extraction\n"
            "  unsquashfs squashfs-root.img  # SquashFS\n"
            "  jefferson image.jffs2  # JFFS2\n"
            "  ubi_reader image.ubi  # UBIFS\n"
            "ANALYSIS:\n"
            "  # Search for secrets\n"
            "  grep -r 'password\\|secret\\|key\\|token' extracted/\n"
            "  # Find hardcoded credentials\n"
            "  strings firmware.bin | grep -i 'admin\\|root\\|pass'\n"
            "  # Analyze startup scripts\n"
            "  cat extracted/etc/init.d/*\n"
            "  cat extracted/etc/shadow  # Password hashes\n"
            "  # Emulate firmware\n"
            "  firmadyne  # Automated emulation framework\n"
            "  FAT (Firmware Analysis Toolkit)"
        ),
        "tools": ["binwalk", "firmadyne", "flashrom"],
    },
    {
        "id": "iot-002", "name": "Hardware Interface Exploitation",
        "category": "hardware", "severity": "critical",
        "desc": "Exploiting hardware debug interfaces.",
        "detection": (
            "HARDWARE INTERFACE EXPLOITATION:\n"
            "UART (Serial Console):\n"
            "  - Find UART pins on PCB (TX, RX, GND, VCC)\n"
            "  - Use multimeter to identify (3.3V typically)\n"
            "  - Connect with USB-to-UART adapter\n"
            "  screen /dev/ttyUSB0 115200\n"
            "  minicom -D /dev/ttyUSB0 -b 115200\n"
            "  # Often gives root shell or bootloader access\n"
            "  # Try common baud rates: 9600, 19200, 38400, 57600, 115200\n"
            "JTAG/SWD:\n"
            "  - Debug interface for ARM/MIPS processors\n"
            "  - Read/write flash memory\n"
            "  - Halt CPU and inspect registers\n"
            "  - Tools: OpenOCD, JLink, Bus Pirate\n"
            "  openocd -f interface/jlink.cfg -f target/stm32f1x.cfg\n"
            "  # Dump firmware\n"
            "  flash read_image firmware.bin 0x08000000 0x100000\n"
            "SPI FLASH:\n"
            "  - Direct flash chip read\n"
            "  - Use SOIC clip or desolder chip\n"
            "  flashrom -p buspirate_spi -r dump.bin\n"
            "  # Modify and reflash\n"
            "  flashrom -p buspirate_spi -w modified.bin\n"
            "I2C/EEPROM:\n"
            "  - Often stores configuration/credentials\n"
            "  i2cdetect -y 1  # Detect I2C devices\n"
            "  i2cdump -y 1 0x50  # Dump EEPROM contents"
        ),
        "tools": ["openocd", "flashrom", "buspirate"],
    },
    {
        "id": "iot-003", "name": "MQTT and CoAP Protocol Attacks",
        "category": "protocol", "severity": "high",
        "desc": "Attacking IoT messaging protocols.",
        "detection": (
            "MQTT AND CoAP ATTACKS:\n"
            "MQTT ENUMERATION:\n"
            "  # Default port: 1883 (plaintext), 8883 (TLS)\n"
            "  nmap -p 1883,8883 <target>\n"
            "  # Anonymous connection\n"
            "  mosquitto_sub -h <broker> -t '#' -v  # Subscribe to ALL topics\n"
            "  mosquitto_sub -h <broker> -t '$SYS/#' -v  # System info\n"
            "  # MQTT Explorer (GUI tool)\n"
            "MQTT ATTACKS:\n"
            "  - Anonymous access (no auth required)\n"
            "  - Wildcard subscription (# topic)\n"
            "  - Message injection\n"
            "  mosquitto_pub -h <broker> -t 'device/control' -m '{\"cmd\": \"unlock\"}'\n"
            "  - Topic enumeration\n"
            "  - Credential brute force\n"
            "  - TLS downgrade\n"
            "  - Retained message poisoning\n"
            "CoAP:\n"
            "  # Default port: 5683 (UDP)\n"
            "  coap-client -m get coap://<target>/.well-known/core\n"
            "  # Resource discovery\n"
            "  coap-client -m get coap://<target>/sensor/temp\n"
            "  # PUT/POST to modify\n"
            "  coap-client -m put coap://<target>/actuator -e '{\"state\":\"on\"}'\n"
            "  # No authentication by default"
        ),
        "tools": ["mosquitto", "coap-client", "nmap"],
    },
    {
        "id": "iot-004", "name": "SCADA/ICS Security",
        "category": "scada", "severity": "critical",
        "desc": "Attacking industrial control systems.",
        "detection": (
            "SCADA/ICS SECURITY:\n"
            "PROTOCOL SCANNING:\n"
            "  # Modbus (port 502)\n"
            "  nmap -p 502 --script modbus-discover <target>\n"
            "  # Read holding registers\n"
            "  modbus-cli read <target> 0 100\n"
            "  # Write registers (DANGEROUS in production!)\n"
            "  modbus-cli write <target> 0 0xFF\n"
            "  # DNP3 (port 20000)\n"
            "  nmap -p 20000 <target>\n"
            "  # BACnet (port 47808/UDP)\n"
            "  nmap -sU -p 47808 --script bacnet-info <target>\n"
            "  # EtherNet/IP (port 44818)\n"
            "  nmap -p 44818 --script enip-info <target>\n"
            "COMMON ISSUES:\n"
            "  - No authentication on industrial protocols\n"
            "  - Plaintext communication (no encryption)\n"
            "  - Default credentials on HMIs\n"
            "  - Windows XP/7 embedded (unpatched)\n"
            "  - Flat network (IT/OT not segmented)\n"
            "  - Remote access without VPN\n"
            "TOOLS:\n"
            "  - PLCScan: PLC discovery and fingerprinting\n"
            "  - s7scan: Siemens S7 scanner\n"
            "  - ISF (Industrial exploitation framework)\n"
            "  - GRFICSv2: ICS simulation for testing"
        ),
        "tools": ["nmap", "modbus-cli", "plcscan"],
    },
    {
        "id": "iot-005", "name": "UPnP and SSDP Exploitation",
        "category": "upnp", "severity": "high",
        "desc": "Exploiting Universal Plug and Play services.",
        "detection": (
            "UPnP/SSDP EXPLOITATION:\n"
            "DISCOVERY:\n"
            "  # SSDP discovery (port 1900/UDP)\n"
            "  gssdp-discover  # GNOME SSDP tool\n"
            "  upnp-inspector  # GUI UPnP browser\n"
            "  miranda  # UPnP pentesting tool\n"
            "  # Manual discovery\n"
            "  echo -e 'M-SEARCH * HTTP/1.1\\r\\nHOST:239.255.255.250:1900\\r\\n\"\n"
            "  \"ST:upnp:rootdevice\\r\\nMAN:\\\"ssdp:discover\\\"\\r\\nMX:2\\r\\n\\r\\n' |\n"
            "  socat - UDP4-DATAGRAM:239.255.255.250:1900\n"
            "ATTACKS:\n"
            "  - Port mapping injection\n"
            "    # Add port forwarding rule\n"
            "    # Forward internal services to internet\n"
            "  - SOAP command injection\n"
            "    # Inject commands via SOAP action parameters\n"
            "  - Information disclosure\n"
            "    # Device description XML reveals internals\n"
            "  - Firmware update manipulation\n"
            "    # If UPnP manages firmware → inject malicious update\n"
            "CallStranger (CVE-2020-12695):\n"
            "  - SUBSCRIBE callback to internal IP\n"
            "  - SSRF via UPnP\n"
            "  - Data exfiltration via callback\n"
            "  - DDoS amplification"
        ),
        "tools": ["miranda", "gssdp-discover", "nmap"],
    },
]


class IoTSecurityKB:
    """IoT security knowledge base.

    Provides IoT vulnerability patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, IoTPattern] = {}
        self._log = logger.bind(component="iot_security_kb")
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
        lines = ["## IoT Security Patterns\n"]
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
