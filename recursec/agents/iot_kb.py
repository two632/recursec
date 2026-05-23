"""IoT security knowledge base.

Deep knowledge about IoT device vulnerabilities:
1. Firmware analysis patterns
2. Protocol vulnerabilities (MQTT, CoAP, BLE, ZigBee)
3. Default credential databases
4. Hardware interface attacks
5. OTA update security
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class IoTPattern:
    """An IoT vulnerability pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    protocols: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:15],
        }


IOT_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "iot-001", "name": "Firmware Extraction and Analysis",
        "category": "firmware", "severity": "critical",
        "desc": "Extracting and analyzing IoT firmware for vulnerabilities.",
        "detection": (
            "FIRMWARE ANALYSIS:\n"
            "EXTRACTION METHODS:\n"
            "  1. Download from vendor website/update server\n"
            "  2. Capture OTA update traffic (MITM)\n"
            "  3. Read from flash chip (SPI, NAND) via hardware\n"
            "  4. UART/JTAG debug interface dump\n"
            "STATIC ANALYSIS:\n"
            "  binwalk -e <firmware.bin>  # Extract filesystem\n"
            "  binwalk -A <firmware.bin>  # Detect CPU architecture\n"
            "  strings <firmware.bin> | grep -i 'password\\|key\\|secret\\|token'\n"
            "  find ./extracted -name '*.conf' -o -name '*.cfg' -o -name 'passwd'\n"
            "COMMON FINDINGS:\n"
            "  - Hardcoded credentials in /etc/shadow, config files\n"
            "  - Private keys (SSL, SSH) embedded in firmware\n"
            "  - Debug interfaces left enabled (telnet, UART)\n"
            "  - Unencrypted sensitive data\n"
            "  - Known vulnerable libraries (busybox, openssl, etc.)\n"
            "  - Command injection in web interfaces (CGI scripts)\n"
            "TOOLS:\n"
            "  - binwalk: Firmware extraction and analysis\n"
            "  - firmware-mod-kit: Modify and repack firmware\n"
            "  - FACT (Firmware Analysis and Comparison Tool)\n"
            "  - Ghidra/radare2: Binary reverse engineering\n"
            "  - checksec: Binary hardening checks"
        ),
        "protocols": [],
        "tools": ["binwalk", "ghidra", "radare2", "strings"],
    },
    {
        "id": "iot-002", "name": "MQTT Protocol Vulnerabilities",
        "category": "protocol", "severity": "high",
        "desc": "MQTT broker and client security issues.",
        "detection": (
            "MQTT SECURITY:\n"
            "UNAUTHENTICATED ACCESS:\n"
            "  - Default: no authentication required\n"
            "  - Connect with mosquitto_sub -h <broker> -t '#' -v\n"
            "  - Subscribe to all topics: # (wildcard)\n"
            "  - Monitor for sensitive data: credentials, sensor data, commands\n"
            "INJECTION ATTACKS:\n"
            "  - Publish malicious payloads to control topics\n"
            "  - mosquitto_pub -h <broker> -t 'device/control' -m '{\"cmd\": \"reboot\"}'\n"
            "  - Topic traversal: ../admin/config\n"
            "PROTOCOL ISSUES:\n"
            "  - Unencrypted traffic (port 1883 vs 8883 TLS)\n"
            "  - Retained messages expose historical data\n"
            "  - Will messages for device enumeration\n"
            "  - $SYS/# topic exposes broker internals\n"
            "DETECTION:\n"
            "  nmap -p 1883,8883 <target>  # Detect MQTT brokers\n"
            "  mqtt-pwn: Interactive MQTT exploitation\n"
            "  mqttsa: MQTT security assessment tool\n"
            "TESTING CHECKLIST:\n"
            "  1. Check for anonymous access\n"
            "  2. Enumerate all topics\n"
            "  3. Test publish permissions\n"
            "  4. Check for TLS encryption\n"
            "  5. Look for sensitive data in messages"
        ),
        "protocols": ["mqtt"],
        "tools": ["mosquitto", "nmap", "wireshark"],
    },
    {
        "id": "iot-003", "name": "Default Credentials and Weak Auth",
        "category": "auth", "severity": "critical",
        "desc": "Default and weak credentials in IoT devices.",
        "detection": (
            "IoT DEFAULT CREDENTIALS:\n"
            "COMMON DEFAULTS:\n"
            "  Routers: admin:admin, admin:password, admin:1234\n"
            "  Cameras: admin:admin, root:root, admin:<blank>\n"
            "  Industrial: admin:admin, user:user, operator:operator\n"
            "  Printers: admin:admin, admin:<serial_number>\n"
            "  SCADA: system:manager, admin:admin\n"
            "DETECTION APPROACH:\n"
            "  1. Identify device model (Shodan, nmap -sV)\n"
            "  2. Search default credential databases\n"
            "     - https://cirt.net/passwords\n"
            "     - https://www.defaultpassword.com\n"
            "  3. Try vendor-specific defaults\n"
            "  4. Check for backdoor accounts\n"
            "  5. Test with hydra/medusa for brute force\n"
            "WEB INTERFACE TESTING:\n"
            "  - Test /admin, /login, /setup, /config endpoints\n"
            "  - Check for hardcoded API tokens\n"
            "  - Test serial number as password\n"
            "  - Check for firmware-embedded SSH keys\n"
            "TELNET/SSH TESTING:\n"
            "  hydra -l admin -P /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt <target> telnet\n"
            "  hydra -l root -P passwords.txt <target> ssh"
        ),
        "protocols": ["http", "telnet", "ssh"],
        "tools": ["hydra", "nmap", "medusa"],
    },
    {
        "id": "iot-004", "name": "BLE (Bluetooth Low Energy) Attacks",
        "category": "wireless", "severity": "high",
        "desc": "Bluetooth Low Energy protocol vulnerabilities.",
        "detection": (
            "BLE SECURITY:\n"
            "SCANNING AND ENUMERATION:\n"
            "  hcitool lescan  # Discover BLE devices\n"
            "  gatttool -b <mac> --primary  # List GATT services\n"
            "  gatttool -b <mac> --characteristics  # List characteristics\n"
            "  bettercap -eval 'ble.recon on'  # BLE reconnaissance\n"
            "COMMON VULNERABILITIES:\n"
            "  1. No authentication: Read/write without pairing\n"
            "  2. Just Works pairing: No MITM protection\n"
            "  3. Static keys: Reusable across sessions\n"
            "  4. Unencrypted characteristics: Sniffable data\n"
            "  5. GATT enumeration: Service/characteristic discovery\n"
            "ATTACK TECHNIQUES:\n"
            "  - Spoofing: Clone device MAC and characteristics\n"
            "  - Replay: Capture and replay BLE commands\n"
            "  - Fuzzing: Send malformed data to characteristics\n"
            "  - Downgrade: Force legacy pairing mode\n"
            "  - Passive eavesdropping: Ubertooth One\n"
            "TOOLS:\n"
            "  - GATTacker: BLE MITM framework\n"
            "  - BtleJuice: BLE MITM and replay\n"
            "  - Ubertooth: BLE packet capture\n"
            "  - nRF Connect: Mobile BLE explorer\n"
            "  - Bettercap: Multi-protocol attack framework"
        ),
        "protocols": ["ble"],
        "tools": ["bettercap", "gatttool", "hcitool"],
    },
    {
        "id": "iot-005", "name": "Hardware Interface Attacks",
        "category": "hardware", "severity": "critical",
        "desc": "Attacking exposed hardware debug interfaces.",
        "detection": (
            "HARDWARE INTERFACE ATTACKS:\n"
            "UART (Serial Console):\n"
            "  1. Identify UART pins: multimeter/logic analyzer\n"
            "  2. Common baud rates: 9600, 19200, 38400, 57600, 115200\n"
            "  3. Connect with USB-to-serial adapter\n"
            "  4. screen /dev/ttyUSB0 115200\n"
            "  5. Often provides root shell or bootloader access\n"
            "JTAG:\n"
            "  1. Identify JTAG pins (standard: TDI, TDO, TMS, TCK, TRST)\n"
            "  2. Use JTAGulator for automatic pin detection\n"
            "  3. Connect with OpenOCD or Bus Pirate\n"
            "  4. Dump firmware, set breakpoints, modify memory\n"
            "SPI/I2C:\n"
            "  1. Connect to flash chip directly\n"
            "  2. flashrom -p buspirate_spi -r firmware.bin\n"
            "  3. Read/write flash contents\n"
            "COMMON FINDINGS:\n"
            "  - Root shell access via UART\n"
            "  - Bootloader unlocked (U-Boot env modification)\n"
            "  - Firmware dump via JTAG/SPI\n"
            "  - Memory forensics via debug interfaces\n"
            "MITIGATION CHECKS:\n"
            "  - Are debug interfaces disabled in production?\n"
            "  - Is secure boot enabled?\n"
            "  - Are flash chips read-protected?\n"
            "  - Is the bootloader locked?"
        ),
        "protocols": ["uart", "jtag", "spi", "i2c"],
        "tools": ["openocd", "flashrom", "screen"],
    },
]


class IoTKB:
    """IoT security knowledge base.

    Provides IoT-specific vulnerability patterns
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
                protocols=data.get("protocols", []),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[IoTPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def get_by_protocol(self, protocol: str) -> list[IoTPattern]:
        """Get patterns by protocol."""
        return [
            p for p in self._patterns.values()
            if protocol.lower() in [pr.lower() for pr in p.protocols]
        ]

    def build_iot_prompt(
        self,
        category: str = "",
        max_patterns: int = 4,
    ) -> str:
        """Build IoT security prompt."""
        lines = ["## IoT Security Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if category and pattern.category.lower() != category.lower():
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
