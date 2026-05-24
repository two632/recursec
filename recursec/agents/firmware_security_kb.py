"""Firmware security knowledge base.

Deep knowledge about firmware security:
1. Firmware extraction and analysis
2. Embedded OS vulnerabilities
3. Hardware interface exploitation
4. Bootloader attacks
5. OTA update vulnerabilities
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class FirmwarePattern:
    """A firmware security pattern."""
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


FIRMWARE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "fw-001", "name": "Firmware Extraction",
        "category": "extraction", "severity": "high",
        "desc": "Firmware extraction and analysis.",
        "detection": (
            "FIRMWARE EXTRACTION:\n"
            "SOFTWARE:\n"
            "  - Vendor download page\n"
            "  - Device update mechanism capture\n"
            "  - MITM OTA update\n"
            "  - FCC ID database (photos/docs)\n"
            "BINWALK:\n"
            "  # binwalk firmware.bin\n"
            "  # binwalk -e firmware.bin  (extract)\n"
            "  # binwalk -Me firmware.bin (recursive extract)\n"
            "  # binwalk -A firmware.bin  (opcode scan)\n"
            "  # binwalk -E firmware.bin  (entropy)\n"
            "HARDWARE:\n"
            "  - UART (serial console)\n"
            "    # Pin identification (GND, TX, RX, VCC)\n"
            "    # Baud rate detection (usually 115200)\n"
            "    # Screen /dev/ttyUSB0 115200\n"
            "  - JTAG/SWD debug interface\n"
            "    # OpenOCD for flash dump\n"
            "    # JLink\n"
            "  - SPI flash (direct chip read)\n"
            "    # Flashrom\n"
            "    # Bus Pirate\n"
            "    # CH341A programmer\n"
            "  - eMMC (direct read)\n"
            "ANALYSIS:\n"
            "  - Filesystem identification\n"
            "  - String extraction\n"
            "  - Binary analysis (Ghidra, radare2)\n"
            "  - Certificate/key extraction\n"
            "  - Configuration file analysis\n"
            "TOOLS:\n"
            "  binwalk, FirmAE, Ghidra, OpenOCD"
        ),
        "tools": [],
    },
    {
        "id": "fw-002", "name": "Embedded OS Vulnerabilities",
        "category": "embedded_os", "severity": "critical",
        "desc": "Embedded operating system vulnerabilities.",
        "detection": (
            "EMBEDDED OS VULNERABILITIES:\n"
            "LINUX-BASED:\n"
            "  - Outdated kernel (known CVEs)\n"
            "  - Default credentials\n"
            "  - Unnecessary services running\n"
            "  - World-readable sensitive files\n"
            "  - SUID binaries\n"
            "  - Writable boot scripts\n"
            "  - BusyBox vulnerabilities\n"
            "  - Missing ASLR/NX/PIE\n"
            "RTOS:\n"
            "  - FreeRTOS vulnerabilities\n"
            "    # Memory corruption (heap)\n"
            "    # Task privilege escalation\n"
            "  - VxWorks\n"
            "    # Debug port exposure\n"
            "    # URGENT/11 TCP/IP stack\n"
            "  - ThreadX/Azure RTOS\n"
            "  - Zephyr\n"
            "BARE METAL:\n"
            "  - No memory protection\n"
            "  - No process isolation\n"
            "  - Stack overflow → RCE\n"
            "  - Format string bugs\n"
            "  - Integer overflow\n"
            "NETWORK STACK:\n"
            "  - lwIP vulnerabilities\n"
            "  - uIP vulnerabilities\n"
            "  - AMNESIA:33 (33 vulns in TCP/IP)\n"
            "  - Ripple20 (Treck TCP/IP)\n"
            "TOOLS:\n"
            "  FirmWalker, EMBA, firmadyne"
        ),
        "tools": [],
    },
    {
        "id": "fw-003", "name": "Hardware Interface Exploitation",
        "category": "hardware", "severity": "high",
        "desc": "Hardware interface exploitation.",
        "detection": (
            "HARDWARE INTERFACE EXPLOITATION:\n"
            "UART:\n"
            "  - Root shell access\n"
            "  - Boot log information leakage\n"
            "  - U-Boot console access\n"
            "  - Debug menu access\n"
            "  # Identify: multimeter, logic analyzer\n"
            "  # Connect: USB-UART adapter\n"
            "JTAG:\n"
            "  - Full chip debug access\n"
            "  - Memory read/write\n"
            "  - Firmware dump\n"
            "  - Breakpoint setting\n"
            "  # OpenOCD: open source debugger\n"
            "  # JTAGulator: pin identification\n"
            "SPI/I2C:\n"
            "  - Flash chip reading\n"
            "  - EEPROM extraction\n"
            "  - Sensor data manipulation\n"
            "  # Bus Pirate: universal interface\n"
            "  # Logic analyzer: Saleae\n"
            "USB:\n"
            "  - USB descriptors analysis\n"
            "  - USB fuzzing\n"
            "  - Rogue USB device (BadUSB)\n"
            "  - USB mass storage analysis\n"
            "  # Facedancer: USB emulation\n"
            "  # USBProxy\n"
            "SIDE CHANNELS:\n"
            "  - Power analysis (SPA/DPA)\n"
            "  - Electromagnetic analysis\n"
            "  - Timing analysis\n"
            "  - Fault injection (glitching)\n"
            "TOOLS:\n"
            "  Bus Pirate, Saleae, JTAGulator, OpenOCD"
        ),
        "tools": [],
    },
    {
        "id": "fw-004", "name": "Bootloader Attacks",
        "category": "bootloader", "severity": "critical",
        "desc": "Bootloader attack techniques.",
        "detection": (
            "BOOTLOADER ATTACKS:\n"
            "U-BOOT:\n"
            "  - Interrupt boot sequence\n"
            "    # Press key during autoboot delay\n"
            "    # Modify bootargs\n"
            "  - Environment variable manipulation\n"
            "    # setenv bootargs 'init=/bin/sh'\n"
            "    # setenv ipaddr / serverip\n"
            "    # tftpboot / nfs boot\n"
            "  - Memory read/write\n"
            "    # md (memory display)\n"
            "    # mw (memory write)\n"
            "  - Flash operations\n"
            "    # sf read/write (SPI flash)\n"
            "    # nand read/write\n"
            "  - Password bypass\n"
            "    # Environment variable overwrite\n"
            "    # UART pin modification\n"
            "SECURE BOOT:\n"
            "  - Chain of trust analysis\n"
            "  - Key extraction\n"
            "  - Signature bypass\n"
            "  - Fuse reading\n"
            "  - Rollback protection bypass\n"
            "  - Fault injection during verification\n"
            "UEFI (EMBEDDED):\n"
            "  - Capsule update manipulation\n"
            "  - Variable store exploitation\n"
            "  - SMM vulnerabilities\n"
            "  - TOCTOU in verification\n"
            "TOOLS:\n"
            "  OpenOCD, ChipWhisperer, U-Boot"
        ),
        "tools": [],
    },
    {
        "id": "fw-005", "name": "OTA Update Vulnerabilities",
        "category": "ota", "severity": "critical",
        "desc": "Over-the-air update vulnerabilities.",
        "detection": (
            "OTA UPDATE VULNERABILITIES:\n"
            "TRANSPORT:\n"
            "  - HTTP (no TLS)\n"
            "  - Expired/self-signed certificates\n"
            "  - Certificate validation disabled\n"
            "  - MITM downgrade to HTTP\n"
            "  - DNS hijacking for update server\n"
            "INTEGRITY:\n"
            "  - No signature verification\n"
            "  - Weak signature (MD5, SHA-1)\n"
            "  - Missing chain of trust\n"
            "  - CRC-only verification\n"
            "  - Hardcoded signing key\n"
            "DELIVERY:\n"
            "  - Unencrypted firmware image\n"
            "  - No rollback protection\n"
            "  - Race condition in update process\n"
            "  - Partial update vulnerability\n"
            "  - Update server compromise\n"
            "EXPLOITATION:\n"
            "  - Modify firmware in transit\n"
            "  - Serve malicious update\n"
            "  - Downgrade attack (old vuln version)\n"
            "  - Brick device (denial of service)\n"
            "  - Extract signing keys\n"
            "TESTING:\n"
            "  - MITM the update (mitmproxy)\n"
            "  - Capture and analyze update package\n"
            "  - Modify and re-serve firmware\n"
            "  - Test rollback protection\n"
            "  - Test update interruption\n"
            "TOOLS:\n"
            "  mitmproxy, binwalk, Wireshark"
        ),
        "tools": [],
    },
]


class FirmwareSecurityKB:
    """Firmware security knowledge base.

    Provides firmware security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, FirmwarePattern] = {}
        self._log = logger.bind(component="firmware_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load firmware patterns."""
        for data in FIRMWARE_PATTERNS:
            pattern = FirmwarePattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[FirmwarePattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_firmware_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build firmware security prompt."""
        lines = ["## Firmware Security\n"]
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
