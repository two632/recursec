"""IoT security knowledge base.

Deep knowledge about IoT device attacks:
1. Firmware extraction and analysis
2. UART/JTAG debug interface exploitation
3. Protocol fuzzing (MQTT, CoAP, AMQP)
4. Default credential attacks
5. OTA update hijacking
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
        "id": "iot-001", "name": "Firmware Extraction and Analysis",
        "category": "firmware", "severity": "high",
        "desc": "Extracting and analyzing IoT device firmware.",
        "detection": (
            "FIRMWARE ANALYSIS:\n"
            "EXTRACTION:\n"
            "  Physical:\n"
            "    - UART serial console: Find TX/RX pins, connect at common baud rates\n"
            "    - SPI flash dump: flashrom, Bus Pirate\n"
            "    - JTAG/SWD: OpenOCD, JLink\n"
            "    - Chip-off: Desolder flash, read with programmer\n"
            "  Software:\n"
            "    - Download from vendor update site\n"
            "    - Capture OTA update (MITM proxy)\n"
            "    - Extract from mobile app (APK/IPA)\n"
            "ANALYSIS:\n"
            "  binwalk -e <firmware.bin>  # Extract embedded filesystems\n"
            "  binwalk -A <firmware.bin>  # CPU architecture detection\n"
            "  firmware-mod-kit  # Unpack/repack firmware\n"
            "  jefferson  # JFFS2 filesystem extraction\n"
            "  ubi_reader  # UBI/UBIFS extraction\n"
            "TARGETS:\n"
            "  - /etc/passwd, /etc/shadow  # Credentials\n"
            "  - SSL certificates and private keys\n"
            "  - Configuration files with secrets\n"
            "  - Hardcoded API endpoints and keys\n"
            "  - Custom binaries (reverse engineer with Ghidra/radare2)\n"
            "  - Web server files (admin panels, hidden endpoints)\n"
            "  - Init scripts (startup services, debug modes)"
        ),
        "tools": ["binwalk", "firmware-mod-kit", "ghidra"],
    },
    {
        "id": "iot-002", "name": "UART/JTAG Debug Interface",
        "category": "hardware", "severity": "critical",
        "desc": "Exploiting hardware debug interfaces.",
        "detection": (
            "HARDWARE DEBUG INTERFACES:\n"
            "UART:\n"
            "  Finding pins:\n"
            "    - Visual inspection: 3-4 pin headers/test points\n"
            "    - Multimeter: Measure voltage (VCC=3.3V, GND=0V)\n"
            "    - JTAGulator / Bus Pirate for auto-detection\n"
            "    - Common baud rates: 9600, 19200, 38400, 57600, 115200\n"
            "  Connection:\n"
            "    screen /dev/ttyUSB0 115200\n"
            "    minicom -D /dev/ttyUSB0 -b 115200\n"
            "  Exploitation:\n"
            "    - Boot console → interrupt boot (press Enter during startup)\n"
            "    - U-Boot shell → modify boot args, enable debug\n"
            "    - Root shell (many devices drop to root UART shell)\n"
            "    - Dump flash from U-Boot: md.b <address> <length>\n"
            "JTAG/SWD:\n"
            "  Finding pins:\n"
            "    - 10/20 pin standard headers\n"
            "    - JTAGulator for auto-detection\n"
            "  Tools:\n"
            "    - OpenOCD: Open On-Chip Debugger\n"
            "    - JLink: Segger debug probe\n"
            "  Exploitation:\n"
            "    - Read/write memory\n"
            "    - Dump entire flash contents\n"
            "    - Bypass secure boot (halt CPU, modify registers)\n"
            "    - Debug running firmware (breakpoints, memory inspection)"
        ),
        "tools": ["jtagulator", "openocd", "bus-pirate"],
    },
    {
        "id": "iot-003", "name": "IoT Protocol Attacks",
        "category": "protocol", "severity": "high",
        "desc": "Attacking IoT-specific protocols.",
        "detection": (
            "IOT PROTOCOL ATTACKS:\n"
            "MQTT (Message Queuing Telemetry Transport):\n"
            "  - Default port: 1883 (plain), 8883 (TLS)\n"
            "  - Anonymous access: mosquitto_sub -h <host> -t '#' -v\n"
            "  - Subscribe to all topics: # wildcard\n"
            "  - Common topics: /home/+/temperature, /device/+/command\n"
            "  - Publish commands: mosquitto_pub -h <host> -t <topic> -m <payload>\n"
            "  - Credential brute force: ncrack mqtt://<host>\n"
            "CoAP (Constrained Application Protocol):\n"
            "  - Default port: 5683 (UDP)\n"
            "  - Discovery: coap-client -m get coap://<host>/.well-known/core\n"
            "  - No authentication by default\n"
            "  - Observe resources for data leakage\n"
            "UPnP/SSDP:\n"
            "  - Discovery: nmap --script upnp-info <subnet>\n"
            "  - SSDP amplification (DDoS)\n"
            "  - XML service descriptions may leak device info\n"
            "  - Unauthorized control: Send SOAP actions\n"
            "mDNS/DNS-SD:\n"
            "  - Discovery: avahi-browse -a\n"
            "  - Enumerate services on local network\n"
            "  - Find hidden management interfaces"
        ),
        "tools": ["mosquitto", "coap-client", "nmap"],
    },
    {
        "id": "iot-004", "name": "Default Credentials and Weak Auth",
        "category": "auth", "severity": "critical",
        "desc": "Default and weak authentication in IoT devices.",
        "detection": (
            "IOT DEFAULT CREDENTIALS:\n"
            "COMMON DEFAULTS:\n"
            "  Routers: admin/admin, admin/password, admin/<blank>\n"
            "  IP Cameras: admin/admin, root/root, admin/12345\n"
            "  Printers: admin/<blank>, admin/admin\n"
            "  Smart Home: often setup-dependent, check manufacturer\n"
            "DATABASES:\n"
            "  - https://cirt.net/passwords  # Default password DB\n"
            "  - https://default-password.info/\n"
            "  - datarecovery.com/rd/default-passwords/\n"
            "SCANNING:\n"
            "  # Scan for common IoT services\n"
            "  nmap -sV -p 80,443,8080,8443,1883,5683,23,22 <subnet>\n"
            "  # Brute force\n"
            "  hydra -L users.txt -P passwords.txt <host> http-get /\n"
            "  medusa -h <host> -U users.txt -P passwords.txt -M http\n"
            "TELNET (still common in IoT):\n"
            "  - Many IoT devices still expose Telnet\n"
            "  - Default credentials widely known (Mirai botnet used this)\n"
            "  - nmap -p 23 --script telnet-brute <subnet>\n"
            "WEB INTERFACES:\n"
            "  - Hidden admin pages (/admin, /management, /debug)\n"
            "  - API endpoints without authentication\n"
            "  - Firmware update without auth verification"
        ),
        "tools": ["hydra", "nmap", "medusa"],
    },
    {
        "id": "iot-005", "name": "OTA Update Hijacking",
        "category": "update", "severity": "critical",
        "desc": "Hijacking over-the-air firmware updates.",
        "detection": (
            "OTA UPDATE HIJACKING:\n"
            "INTERCEPTION:\n"
            "  - MITM the update channel:\n"
            "    bettercap + custom caplet for IoT protocols\n"
            "  - ARP spoofing to redirect device traffic\n"
            "  - DNS spoofing to redirect update server\n"
            "  - If HTTP (not HTTPS): Direct modification\n"
            "VULNERABILITIES:\n"
            "  No TLS:\n"
            "    - Update downloaded over HTTP → modify in transit\n"
            "    - Inject malicious firmware\n"
            "  No Signature Verification:\n"
            "    - Device accepts any firmware file\n"
            "    - Replace with backdoored firmware\n"
            "  Weak Signature:\n"
            "    - CRC32 or MD5 checksum only (not cryptographic)\n"
            "    - Collide or strip check\n"
            "  Rollback Attack:\n"
            "    - No anti-rollback protection\n"
            "    - Force update to older vulnerable version\n"
            "TESTING:\n"
            "  1. Trigger firmware update on device\n"
            "  2. Capture update traffic (Wireshark/tcpdump)\n"
            "  3. Analyze update protocol (HTTP? HTTPS? Custom?)\n"
            "  4. Check for certificate validation\n"
            "  5. Check for firmware signature verification\n"
            "  6. Attempt to serve modified firmware"
        ),
        "tools": ["bettercap", "wireshark", "mitmproxy"],
    },
]


class IoTSecurityKB:
    """IoT security knowledge base.

    Provides IoT attack patterns injected
    into agent prompts.
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
