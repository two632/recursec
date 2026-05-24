"""Firmware security knowledge base.

Attack patterns for firmware and embedded systems:
1. Firmware Extraction & Analysis — dumping, unpacking, filesystem analysis
2. Bootloader Attacks — secure boot bypass, U-Boot exploitation
3. Hardware Debug Interfaces — JTAG, SWD, UART, SPI flash
4. Firmware Update Mechanisms — OTA hijacking, downgrade attacks
5. Embedded OS Hardening — BusyBox, init scripts, kernel config
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class FirmwareAttackType(str, Enum):
    EXTRACTION = "extraction"
    BOOTLOADER = "bootloader"
    DEBUG_INTERFACE = "debug_interface"
    UPDATE_MECHANISM = "update_mechanism"
    EMBEDDED_OS = "embedded_os"


@dataclass
class FirmwarePattern:
    """A firmware attack pattern."""
    name: str = ""
    attack_type: FirmwareAttackType = FirmwareAttackType.EXTRACTION
    description: str = ""
    detection_strategies: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    hardware_required: list[str] = field(default_factory=list)
    severity: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.attack_type.value,
            "severity": self.severity,
            "detection_count": len(self.detection_strategies),
        }


FIRMWARE_PATTERNS: list[FirmwarePattern] = [
    FirmwarePattern(
        name="Firmware Extraction & Analysis",
        attack_type=FirmwareAttackType.EXTRACTION,
        description=(
            "Extracting firmware images from devices or update servers, "
            "unpacking filesystem layers, and analyzing for secrets, "
            "hardcoded credentials, and vulnerable components."
        ),
        detection_strategies=[
            "Download firmware from vendor update servers or FTP sites",
            "Use binwalk to identify and extract embedded filesystems",
            "Identify encryption/compression: gzip, LZMA, squashfs, JFFS2",
            "Extract filesystem and search for hardcoded credentials",
            "Analyze ELF binaries for known vulnerable library versions",
            "Check for debug symbols left in production firmware",
            "Identify custom protocols via string analysis",
            "Map the firmware memory layout (bootloader, kernel, rootfs)",
        ],
        indicators=[
            "Hardcoded passwords in /etc/shadow or config files",
            "Debug binaries (gdb, strace) present in production",
            "Unencrypted firmware update files on vendor servers",
            "Known vulnerable library versions (OpenSSL, BusyBox)",
            "Telnet/SSH backdoor services enabled",
            "Private keys or certificates in filesystem",
        ],
        tools=["binwalk", "firmware-mod-kit", "ubi_reader", "jefferson",
               "squashfs-tools", "sasquatch", "yaffshiv"],
        commands=[
            "binwalk -e firmware.bin",
            "binwalk --entropy firmware.bin",
            "strings firmware.bin | grep -i 'password\\|secret\\|key'",
            "unsquashfs -d extracted/ squashfs-root.img",
            "find extracted/ -name '*.conf' -exec grep -l 'pass' {} +",
            "readelf -d extracted/usr/bin/* | grep NEEDED",
        ],
        hardware_required=["SPI flash programmer", "Logic analyzer"],
        severity="high",
    ),
    FirmwarePattern(
        name="Bootloader Attacks",
        attack_type=FirmwareAttackType.BOOTLOADER,
        description=(
            "Bypassing secure boot chains, exploiting U-Boot/GRUB "
            "vulnerabilities, modifying boot arguments to gain root access."
        ),
        detection_strategies=[
            "Interrupt U-Boot during boot to access bootloader shell",
            "Modify kernel boot arguments (init=/bin/sh, single user)",
            "Check if secure boot chain is properly verified end-to-end",
            "Test for U-Boot environment variable injection",
            "Verify bootloader update signature verification",
            "Check for bootloader downgrade protection (rollback index)",
            "Analyze bootloader for debug/test commands left enabled",
            "Test boot from alternative media (SD, USB, TFTP)",
        ],
        indicators=[
            "U-Boot shell accessible via serial interrupt",
            "Boot arguments modifiable without authentication",
            "Secure boot can be disabled via hardware jumper",
            "Bootloader accepts unsigned kernel images",
            "TFTP/NFS boot enabled in production",
            "Bootloader version vulnerable to known CVEs",
        ],
        tools=["u-boot-tools", "flashrom", "openocd", "sigrok"],
        commands=[
            "strings bootloader.bin | grep -i 'u-boot\\|version'",
            "binwalk -A bootloader.bin",
            "fw_printenv",
            "fw_setenv bootargs 'init=/bin/sh'",
            "flashrom -p linux_spi:dev=/dev/spidev0.0 -r backup.bin",
        ],
        hardware_required=["UART adapter", "SPI flash clip"],
        severity="critical",
    ),
    FirmwarePattern(
        name="Hardware Debug Interfaces",
        attack_type=FirmwareAttackType.DEBUG_INTERFACE,
        description=(
            "Exploiting JTAG, SWD, UART, and other debug interfaces "
            "left accessible on production hardware for firmware extraction, "
            "memory dumping, and real-time debugging."
        ),
        detection_strategies=[
            "Visual inspection of PCB for debug headers (JTAG, SWD, UART)",
            "Use JTAGulator to automatically identify JTAG pinouts",
            "Probe test points with oscilloscope for UART TX activity",
            "Check if JTAG is disabled via fuse bits or software lock",
            "Test SWD interface on ARM-based devices",
            "Check for I2C/SPI EEPROM accessible via debug pads",
            "Verify debug interfaces require authentication",
            "Test for chip-level read protection (RDP, CRP)",
        ],
        indicators=[
            "Unpopulated debug headers on PCB",
            "JTAG/SWD responding to scan",
            "UART console accessible without authentication",
            "Debug chip read protection not enabled",
            "Test points on PCB near flash/RAM chips",
            "Silicon revision with known debug bypass",
        ],
        tools=["openocd", "jtagulator", "bus-pirate", "flashrom",
               "sigrok-cli", "urjtag"],
        commands=[
            "openocd -f interface/jlink.cfg -f target/stm32f1x.cfg",
            "openocd -c 'flash read_image firmware.bin 0x08000000 0x100000'",
            "screen /dev/ttyUSB0 115200",
            "sigrok-cli --driver fx2lafw --config samplerate=1M -o capture.sr",
            "flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r dump.bin",
        ],
        hardware_required=[
            "JTAGulator", "Bus Pirate", "J-Link", "UART adapter",
            "Logic analyzer", "SPI flash clip",
        ],
        severity="high",
    ),
    FirmwarePattern(
        name="Firmware Update Mechanisms",
        attack_type=FirmwareAttackType.UPDATE_MECHANISM,
        description=(
            "Attacking Over-The-Air (OTA) and local update mechanisms: "
            "man-in-the-middle updates, signature bypass, downgrade attacks, "
            "and malicious firmware injection."
        ),
        detection_strategies=[
            "Intercept firmware update traffic for TLS/signature checks",
            "Test if firmware updates are verified cryptographically",
            "Attempt firmware downgrade to older vulnerable versions",
            "Check update URL for HTTP (non-TLS) transport",
            "Analyze update client for certificate pinning bypass",
            "Test if update package format allows path traversal",
            "Check for rollback protection (anti-rollback counter)",
            "Verify update integrity check covers entire image not just header",
        ],
        indicators=[
            "Firmware updates over HTTP (not HTTPS)",
            "No signature verification on update packages",
            "Downgrade to older firmware version succeeds",
            "Update server accepts self-signed certificates",
            "Update package uses weak hash (MD5, SHA1) for integrity",
            "Update client does not verify server certificate",
        ],
        tools=["mitmproxy", "burpsuite", "frida", "binwalk", "openssl"],
        commands=[
            "mitmproxy --mode transparent -p 8080",
            "openssl dgst -sha256 firmware_update.bin",
            "openssl rsautl -verify -pubin -inkey pub.pem -in sig.bin",
            "binwalk --signature firmware_update.bin",
            "frida -U -l bypass_cert_pin.js com.vendor.updater",
        ],
        hardware_required=["WiFi adapter (monitor mode)"],
        severity="critical",
    ),
    FirmwarePattern(
        name="Embedded OS Hardening Analysis",
        attack_type=FirmwareAttackType.EMBEDDED_OS,
        description=(
            "Analyzing embedded Linux/RTOS configurations for security "
            "weaknesses: BusyBox misconfigurations, init script flaws, "
            "kernel hardening, and service exposure."
        ),
        detection_strategies=[
            "Check BusyBox applet list for dangerous utilities (telnetd, ftpd)",
            "Analyze init scripts for insecure service startup",
            "Verify kernel config (ASLR, stack canaries, SELinux/AppArmor)",
            "Check for world-writable files and SUID binaries",
            "Analyze iptables/nftables rules for exposed services",
            "Check for default credentials in /etc/passwd /etc/shadow",
            "Verify filesystem permissions on sensitive directories",
            "Check for unnecessary kernel modules loaded",
        ],
        indicators=[
            "Root shell accessible via serial console",
            "BusyBox compiled with telnetd, ftpd applets",
            "Kernel compiled without ASLR, stack protector",
            "World-writable /etc or /tmp directories",
            "No firewall rules (all ports accessible)",
            "Default root password or empty password",
        ],
        tools=["busybox", "checksec", "lynis", "chkrootkit"],
        commands=[
            "busybox --list | grep -i 'telnet\\|ftp\\|tftp'",
            "cat /proc/sys/kernel/randomize_va_space",
            "find / -perm -4000 -type f 2>/dev/null",
            "find / -perm -0002 -type f 2>/dev/null",
            "cat /etc/passwd | grep ':0:'",
            "iptables -L -n",
        ],
        hardware_required=[],
        severity="high",
    ),
]


def build_firmware_prompt(
    focus_type: FirmwareAttackType | None = None,
    max_patterns: int = 5,
) -> str:
    """Build LLM prompt with firmware security knowledge."""
    lines = ["## Firmware Security Knowledge\n"]

    patterns = FIRMWARE_PATTERNS
    if focus_type:
        patterns = [p for p in patterns if p.attack_type == focus_type]

    for pattern in patterns[:max_patterns]:
        lines.append(f"### {pattern.name} [{pattern.severity}]")
        lines.append(pattern.description)
        lines.append("\nDetection:")
        for strategy in pattern.detection_strategies[:4]:
            lines.append(f"  - {strategy}")
        lines.append("\nIndicators:")
        for indicator in pattern.indicators[:3]:
            lines.append(f"  - {indicator}")
        lines.append("\nCommands:")
        for cmd in pattern.commands[:3]:
            lines.append(f"  $ {cmd}")
        if pattern.hardware_required:
            lines.append("\nHardware:")
            for hw in pattern.hardware_required[:3]:
                lines.append(f"  - {hw}")
        lines.append("")

    return "\n".join(lines)
