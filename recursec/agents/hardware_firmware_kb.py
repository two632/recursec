"""Hardware & firmware security knowledge base.

Deep knowledge about hardware/firmware vulnerabilities:
1. UEFI/BIOS attacks
2. TPM attacks
3. Side-channel attacks
4. Hardware implant detection
5. Firmware analysis methodology
6. JTAG/SWD debugging
7. PCIe/DMA attacks
8. Embedded device security
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class HardwareVulnPattern:
    """A hardware/firmware vulnerability pattern with methodology."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    description: str = ""
    testing_methodology: str = ""
    prerequisites: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "category": self.category[:15],
            "severity": self.severity,
        }


HARDWARE_VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "hw-001", "name": "UEFI/BIOS Vulnerability Analysis",
        "category": "firmware", "severity": "critical",
        "desc": "Firmware-level attacks that persist across OS reinstallation.",
        "testing": (
            "UEFI/BIOS SECURITY TESTING:\n"
            "1. FIRMWARE EXTRACTION:\n"
            "   - Software extraction: flashrom, chipsec (Intel), fwupd\n"
            "   - Hardware extraction: SPI flash programmer (CH341A)\n"
            "   - Dump UEFI variables: efivar, efitools\n"
            "2. FIRMWARE ANALYSIS:\n"
            "   - Extract firmware volumes: UEFITool, uefi-firmware-parser\n"
            "   - Identify DXE drivers, PEI modules, SMM handlers\n"
            "   - Check for known vulnerable modules (CVE database)\n"
            "   - Look for unsigned or improperly signed modules\n"
            "3. SECURE BOOT ANALYSIS:\n"
            "   - Check Secure Boot state: mokutil --sb-state\n"
            "   - Enumerate keys: mokutil --list-enrolled\n"
            "   - Check for known bypasses:\n"
            "     * shim vulnerability (CVE-2023-40547)\n"
            "     * GRUB bypass (CVE-2020-10713 BootHole)\n"
            "     * db/dbx gaps (missing revocations)\n"
            "4. SMM ATTACKS:\n"
            "   - System Management Mode runs at highest privilege\n"
            "   - chipsec modules: smm_dma, runtimescratch, smrr\n"
            "   - Check for SMM callout vulnerabilities\n"
            "5. PERSISTENCE:\n"
            "   - SPI flash write protection: chipsec bios_wp\n"
            "   - UEFI implant detection: compare firmware dump against known-good"
        ),
        "tools": ["chipsec", "flashrom", "uefi-firmware-parser", "UEFITool"],
    },
    {
        "id": "hw-002", "name": "TPM Security Assessment",
        "category": "hardware", "severity": "high",
        "desc": "Trusted Platform Module attacks and weaknesses.",
        "testing": (
            "TPM SECURITY TESTING:\n"
            "1. TPM ENUMERATION:\n"
            "   - Version check: tpm2_getcap properties-fixed\n"
            "   - PCR values: tpm2_pcrread\n"
            "   - Identify TPM type: discrete (more secure) vs firmware (fTPM)\n"
            "2. KNOWN ATTACKS:\n"
            "   - Bus sniffing (TPM 1.2 SPI): Logic analyzer on SPI bus\n"
            "     Extract BitLocker VMK from clear-text SPI traffic\n"
            "   - fTPM side-channel (CVE-2023-1017/1018): TPM.fail\n"
            "   - Reset attack: Cold boot with TPM PCR reset\n"
            "   - Dictionary attack bypass on lockout settings\n"
            "3. BITLOCKER/LUKS ANALYSIS:\n"
            "   - Check if TPM-only (no PIN): Most vulnerable\n"
            "   - Check PCR binding policy: Which PCRs are measured?\n"
            "   - Boot medium attack: Modify bootloader, TPM unseals anyway\n"
            "4. SEALED DATA RECOVERY:\n"
            "   - If PCR policy is weak, modify boot and unseal secrets\n"
            "   - Downgrade firmware to reset PCR measurements"
        ),
        "tools": ["tpm2-tools", "tpm2-tss", "logic_analyzer"],
    },
    {
        "id": "hw-003", "name": "Side-Channel Attack Methodology",
        "category": "side_channel", "severity": "critical",
        "desc": "Extracting secrets through timing, power, electromagnetic emanations.",
        "testing": (
            "SIDE-CHANNEL ATTACK METHODOLOGY:\n"
            "1. TIMING ATTACKS:\n"
            "   - Measure response time variations for different inputs\n"
            "   - String comparison timing: Leaks password character by character\n"
            "   - Cache timing (Spectre/Meltdown variants):\n"
            "     * Flush+Reload: Shared memory pages\n"
            "     * Prime+Probe: Cache set contention\n"
            "     * Check: cat /proc/cpuinfo (vulnerable CPU?)\n"
            "2. POWER ANALYSIS:\n"
            "   - Simple Power Analysis (SPA): Observe power traces\n"
            "   - Differential Power Analysis (DPA): Statistical correlation\n"
            "   - Targets: AES key extraction, RSA private key\n"
            "   - Tools: ChipWhisperer, oscilloscope\n"
            "3. ELECTROMAGNETIC:\n"
            "   - EM emanation capture near CPU/crypto chip\n"
            "   - TEMPEST-style attacks on displays\n"
            "4. MICROARCHITECTURAL:\n"
            "   - Spectre variants (v1 bounds check, v2 branch target)\n"
            "   - Meltdown (CVE-2017-5754)\n"
            "   - MDS (Microarchitectural Data Sampling)\n"
            "   - Detection: spectre-meltdown-checker script\n"
            "5. NETWORK TIMING:\n"
            "   - Remote timing attacks over network\n"
            "   - TLS oracle attacks via timing differences"
        ),
        "tools": ["ChipWhisperer", "spectre-meltdown-checker", "oscilloscope"],
    },
    {
        "id": "hw-004", "name": "Embedded Device Security",
        "category": "embedded", "severity": "high",
        "desc": "Security assessment of IoT and embedded devices.",
        "testing": (
            "EMBEDDED DEVICE SECURITY TESTING:\n"
            "1. PHYSICAL INSPECTION:\n"
            "   - Identify chips: CPU, flash, RAM, crypto\n"
            "   - Find debug ports: UART, JTAG, SWD headers\n"
            "   - Look for unpopulated pads (hidden debug)\n"
            "2. FIRMWARE EXTRACTION:\n"
            "   - Over-the-air (OTA) update interception\n"
            "   - SPI flash dump: flashrom, CH341A programmer\n"
            "   - JTAG/SWD: OpenOCD, J-Link\n"
            "   - EMMC dump: easy-JTAG, direct soldering\n"
            "3. FIRMWARE ANALYSIS:\n"
            "   - binwalk: Extract filesystem from firmware blob\n"
            "   - Identify OS: Linux (kernel version), RTOS, bare-metal\n"
            "   - Find hardcoded credentials: grep -r 'password\\|secret'\n"
            "   - Check for debug backdoors (telnet, SSH with default keys)\n"
            "   - Entropy analysis: binwalk -E (find encrypted/compressed sections)\n"
            "4. COMMUNICATION ANALYSIS:\n"
            "   - Network traffic: Wireshark, tcpdump\n"
            "   - Bluetooth: ubertooth, btlejack\n"
            "   - Zigbee: KillerBee, ApiMote\n"
            "   - RF: HackRF, RTL-SDR\n"
            "5. RUNTIME ANALYSIS:\n"
            "   - UART shell access (115200 baud common)\n"
            "   - GDB via JTAG/SWD\n"
            "   - Binary emulation: QEMU user mode"
        ),
        "tools": ["binwalk", "flashrom", "OpenOCD", "QEMU", "Wireshark"],
    },
    {
        "id": "hw-005", "name": "DMA/PCIe Attack Vectors",
        "category": "hardware", "severity": "critical",
        "desc": "Direct Memory Access attacks via PCIe/Thunderbolt.",
        "testing": (
            "DMA/PCIe ATTACK TESTING:\n"
            "1. ATTACK SURFACE:\n"
            "   - Thunderbolt 3/4 ports (PCIe tunneled)\n"
            "   - ExpressCard slots\n"
            "   - FireWire/1394 ports\n"
            "   - M.2 slots (accessible without opening case?)\n"
            "2. IOMMU CHECK:\n"
            "   - Linux: dmesg | grep -i iommu\n"
            "   - Should see: 'IOMMU enabled' or 'DMAR: Intel(R) Virtualization'\n"
            "   - If disabled → device can read/write ALL physical memory\n"
            "3. THUNDERBOLT SECURITY:\n"
            "   - Check security level: boltctl\n"
            "   - Levels: none, dponly, user, secure\n"
            "   - Thunderspy attack (CVE-2020-xxxx): Rewrites firmware to disable security\n"
            "4. DMA ATTACK TOOLS:\n"
            "   - PCILeech: FPGA-based DMA engine\n"
            "   - Inception: FireWire/Thunderbolt DMA over network\n"
            "   - Can: Dump memory, inject code, bypass login, extract keys\n"
            "5. MITIGATIONS:\n"
            "   - IOMMU (VT-d/AMD-Vi) enabled\n"
            "   - Thunderbolt security level = secure\n"
            "   - Kernel DMA protection"
        ),
        "tools": ["PCILeech", "inception", "boltctl"],
    },
    {
        "id": "hw-006", "name": "Wireless Protocol Security",
        "category": "wireless", "severity": "high",
        "desc": "Security assessment of wireless protocols (WiFi, BLE, Zigbee, RF).",
        "testing": (
            "WIRELESS PROTOCOL SECURITY TESTING:\n"
            "1. WiFi ASSESSMENT:\n"
            "   - aircrack-ng suite: airmon-ng, airodump-ng, aireplay-ng\n"
            "   - WPA2 handshake capture → offline brute force (hashcat)\n"
            "   - WPA3-SAE: Dragonblood attack (CVE-2019-9494/9495)\n"
            "   - Evil twin: hostapd + dnsmasq for credential capture\n"
            "   - PMKID attack: hcxdumptool + hashcat\n"
            "   - WPS PIN brute force: reaver, bully\n"
            "2. BLUETOOTH LOW ENERGY (BLE):\n"
            "   - Scanning: hcitool lescan, btlejack\n"
            "   - GATT enumeration: gatttool, bettercap\n"
            "   - Pairing attacks: Just Works bypass, MITM\n"
            "   - KNOB attack (CVE-2019-9506): Entropy reduction\n"
            "3. ZIGBEE:\n"
            "   - KillerBee: sniff, inject, replay\n"
            "   - Key extraction: Zigbee network key often sent in cleartext during join\n"
            "   - Touchlink commissioning attack\n"
            "4. RF/SDR:\n"
            "   - HackRF/RTL-SDR: Capture and analyze signals\n"
            "   - Replay attacks on garage doors, keyfobs\n"
            "   - Rolling code analysis\n"
            "5. NFC/RFID:\n"
            "   - Proxmark3: Read/clone/emulate cards\n"
            "   - MIFARE Classic: Nested attack, darkside attack\n"
            "   - Relay attack: wormhole card to terminal"
        ),
        "tools": ["aircrack-ng", "hashcat", "HackRF", "Proxmark3", "btlejack"],
    },
]


class HardwareFirmwareKB:
    """Hardware and firmware security knowledge base.

    Provides deep hardware/firmware attack methodology
    injected into agent prompts for physical security assessment.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, HardwareVulnPattern] = {}
        self._log = logger.bind(component="hardware_firmware_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load hardware vulnerability patterns."""
        for data in HARDWARE_VULN_PATTERNS:
            pattern = HardwareVulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_category(
        self,
        category: str,
    ) -> list[HardwareVulnPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category == category
        ]

    def get_testing_prompts(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 3,
    ) -> list[str]:
        """Get testing prompts for agent context injection."""
        prompts = []
        for pattern in self._patterns.values():
            if categories and pattern.category not in categories:
                continue
            if pattern.testing_methodology:
                prompts.append(pattern.testing_methodology)
            if len(prompts) >= max_patterns:
                break
        return prompts

    def build_hardware_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 3,
    ) -> str:
        """Build hardware testing prompt."""
        lines = ["## Hardware/Firmware Security Testing\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category not in categories:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            lines.append(pattern.testing_methodology)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            cat_counts[p.category] += 1
        return {
            "patterns": len(self._patterns),
            "by_category": dict(cat_counts),
        }
