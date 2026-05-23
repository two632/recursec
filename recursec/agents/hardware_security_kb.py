"""Hardware security knowledge base.

Deep knowledge about hardware and firmware security:
1. UEFI/BIOS attacks
2. Side-channel attacks
3. Hardware implants and tampering
4. Embedded device security
5. Physical security testing
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class HardwarePattern:
    """A hardware security pattern."""
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


HARDWARE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "hw-001", "name": "UEFI/BIOS Attacks",
        "category": "firmware", "severity": "critical",
        "desc": "UEFI/BIOS firmware attack techniques.",
        "detection": (
            "UEFI/BIOS ATTACKS:\n"
            "FIRMWARE EXTRACTION:\n"
            "  # SPI flash chip reading\n"
            "  flashrom -p ch341a_spi -r firmware.bin  # CH341A programmer\n"
            "  # Via Intel ME: MEAnalyzer, MECleaner\n"
            "  # CHIPSEC framework:\n"
            "  chipsec_main -m common.bios_wp  # BIOS write protection\n"
            "  chipsec_main -m common.spi_lock  # SPI flash lock\n"
            "  chipsec_main -m common.smm  # SMM protection\n"
            "UEFI ROOTKITS:\n"
            "  # DXE driver implants\n"
            "  # Boot-time persistence (survives OS reinstall)\n"
            "  # NVRAM variable manipulation\n"
            "  # Secure Boot bypass\n"
            "  # Known: LoJax, MosaicRegressor, CosmicStrand\n"
            "SECURE BOOT:\n"
            "  # Check Secure Boot status\n"
            "  mokutil --sb-state\n"
            "  # Key management (PK, KEK, db, dbx)\n"
            "  # Shim bootloader vulnerabilities\n"
            "  # BlackLotus UEFI bootkit\n"
            "INTEL ME/AMD PSP:\n"
            "  # Intel Management Engine\n"
            "  # Runs separate OS on CPU\n"
            "  # Full system access even when powered off\n"
            "  # AMT remote management exploitation\n"
            "  # AMD Platform Security Processor similar\n"
            "TOOLS:\n"
            "  CHIPSEC, UEFITool, flashrom, binwalk"
        ),
        "tools": ["chipsec", "flashrom"],
    },
    {
        "id": "hw-002", "name": "Side-Channel Attacks",
        "category": "side_channel", "severity": "critical",
        "desc": "Side-channel attack techniques.",
        "detection": (
            "SIDE-CHANNEL ATTACKS:\n"
            "TIMING ATTACKS:\n"
            "  # Measure execution time differences\n"
            "  # String comparison timing (password oracle)\n"
            "  # Cache timing: Flush+Reload, Prime+Probe\n"
            "  # Spectre/Meltdown variants\n"
            "POWER ANALYSIS:\n"
            "  # Simple Power Analysis (SPA)\n"
            "  # Differential Power Analysis (DPA)\n"
            "  # Measure power consumption during crypto ops\n"
            "  # Extract AES/RSA keys from power traces\n"
            "  # ChipWhisperer framework\n"
            "ELECTROMAGNETIC:\n"
            "  # EM emanation monitoring\n"
            "  # TEMPEST attacks (display reconstruction)\n"
            "  # EM fault injection\n"
            "  # Van Eck phreaking\n"
            "ACOUSTIC:\n"
            "  # CPU acoustic emanations\n"
            "  # RSA key extraction via sound\n"
            "  # Keyboard acoustic analysis\n"
            "SPECULATIVE EXECUTION:\n"
            "  # Spectre (Branch prediction)\n"
            "  # Meltdown (Out-of-order execution)\n"
            "  # Foreshadow (L1 Terminal Fault)\n"
            "  # MDS (Microarchitectural Data Sampling)\n"
            "  # Zenbleed, Downfall, Inception\n"
            "TOOLS:\n"
            "  ChipWhisperer, OpenSSL timing tests"
        ),
        "tools": ["chipwhisperer"],
    },
    {
        "id": "hw-003", "name": "Hardware Implants",
        "category": "implant", "severity": "critical",
        "desc": "Hardware implant and tampering detection.",
        "detection": (
            "HARDWARE IMPLANTS:\n"
            "SUPPLY CHAIN:\n"
            "  - Modified firmware in shipping\n"
            "  - Counterfeit components\n"
            "  - Extra chips soldered on board\n"
            "  - Modified PCB traces\n"
            "  - JTAG/SWD port exposure\n"
            "DETECTION:\n"
            "  - Visual inspection (X-ray, microscope)\n"
            "  - Weight comparison\n"
            "  - PCB layer analysis\n"
            "  - Unexpected RF emissions\n"
            "  - Firmware hash comparison\n"
            "  - Side-channel anomalies\n"
            "USB ATTACKS:\n"
            "  - BadUSB (reprogrammed firmware)\n"
            "  - USB Rubber Ducky (keystroke injection)\n"
            "  - USB Killer (power surge)\n"
            "  - O.MG Cable (WiFi-enabled HID)\n"
            "  - USB data exfiltration\n"
            "KEYLOGGERS:\n"
            "  - Hardware keylogger (inline, WiFi)\n"
            "  - BIOS-level keylogging\n"
            "  - Firmware-modified keyboard\n"
            "NETWORK IMPLANTS:\n"
            "  - Modified network equipment\n"
            "  - Rogue access points\n"
            "  - LAN tap (passive monitoring)\n"
            "  - Packet injection hardware"
        ),
        "tools": [],
    },
    {
        "id": "hw-004", "name": "Embedded Device Security",
        "category": "embedded", "severity": "high",
        "desc": "Embedded and IoT device security testing.",
        "detection": (
            "EMBEDDED DEVICE SECURITY:\n"
            "FIRMWARE ANALYSIS:\n"
            "  binwalk -e firmware.bin  # Extract filesystems\n"
            "  binwalk -E firmware.bin  # Entropy analysis\n"
            "  # Find crypto keys, hardcoded creds\n"
            "  strings firmware.bin | grep -i 'pass\\|key\\|secret'\n"
            "  # Identify compressed/encrypted sections\n"
            "UART/SERIAL:\n"
            "  # Find UART pins (TX, RX, GND, VCC)\n"
            "  # Use logic analyzer / Bus Pirate\n"
            "  # Baud rate detection: 9600, 115200 common\n"
            "  # Often provides root shell\n"
            "  screen /dev/ttyUSB0 115200\n"
            "JTAG/SWD:\n"
            "  # Identify JTAG pins\n"
            "  # JTAGulator for auto-detection\n"
            "  # OpenOCD for debug access\n"
            "  # Read/write flash memory\n"
            "  # Set hardware breakpoints\n"
            "  # Bypass secure boot\n"
            "SPI/I2C:\n"
            "  # Read SPI flash (firmware extraction)\n"
            "  # I2C EEPROM reading\n"
            "  # Bus Pirate, Saleae, Flashrom\n"
            "IoT PROTOCOLS:\n"
            "  # MQTT (often no auth)\n"
            "  # CoAP, Zigbee, Z-Wave\n"
            "  # BLE (see mobile_security_kb)\n"
            "  # LoRa/LoRaWAN\n"
            "TOOLS:\n"
            "  binwalk, firmwalker, EMBA, Bus Pirate, JTAGulator"
        ),
        "tools": ["binwalk", "emba"],
    },
    {
        "id": "hw-005", "name": "Physical Security Testing",
        "category": "physical", "severity": "high",
        "desc": "Physical security testing techniques.",
        "detection": (
            "PHYSICAL SECURITY TESTING:\n"
            "ACCESS CONTROL:\n"
            "  - Badge cloning (Proxmark3, Flipper Zero)\n"
            "  - RFID/NFC relay attacks\n"
            "  - Tailgating / piggybacking\n"
            "  - Lock picking (standard, electric picks)\n"
            "  - Key impression\n"
            "  - Bypass tools (shims, travelers hooks)\n"
            "SURVEILLANCE:\n"
            "  - Camera coverage gaps\n"
            "  - Blind spots analysis\n"
            "  - Motion sensor testing\n"
            "  - Guard patrol timing\n"
            "  - After-hours access testing\n"
            "SOCIAL:\n"
            "  - Impersonation (delivery, maintenance)\n"
            "  - Dumpster diving\n"
            "  - Shoulder surfing\n"
            "  - Phone pretexting\n"
            "NETWORK ACCESS:\n"
            "  - Exposed Ethernet ports\n"
            "  - Rogue AP deployment\n"
            "  - Network tap installation\n"
            "  - Server room access\n"
            "  - Printer exploitation\n"
            "DATA THEFT:\n"
            "  - USB drop attacks\n"
            "  - Document theft\n"
            "  - Screen capture\n"
            "  - Device theft testing\n"
            "TOOLS:\n"
            "  Proxmark3, Flipper Zero, WiFi Pineapple, LAN Turtle"
        ),
        "tools": ["proxmark3", "flipper-zero"],
    },
]


class HardwareSecurityKB:
    """Hardware security knowledge base.

    Provides hardware/firmware security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, HardwarePattern] = {}
        self._log = logger.bind(component="hardware_security_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load hardware patterns."""
        for data in HARDWARE_PATTERNS:
            pattern = HardwarePattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[HardwarePattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_hardware_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build hardware security prompt."""
        lines = ["## Hardware Security Patterns\n"]
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
