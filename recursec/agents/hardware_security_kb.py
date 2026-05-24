"""Hardware security knowledge base — side-channels, fault injection, chip-level attacks."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import structlog
logger = structlog.get_logger()

class HWAttackType(str, Enum):
    SIDE_CHANNEL = "side_channel"
    FAULT_INJECTION = "fault_injection"
    DEBUG_INTERFACE = "debug_interface"
    CHIP_LEVEL = "chip_level"
    SUPPLY_CHAIN = "supply_chain"

@dataclass
class HWPattern:
    name: str = ""
    attack_type: HWAttackType = HWAttackType.SIDE_CHANNEL
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    severity: str = "high"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

HW_PATTERNS: list[HWPattern] = [
    HWPattern(name="Side-Channel Attacks", attack_type=HWAttackType.SIDE_CHANNEL, description="Extract secrets via physical side-channels: power analysis, electromagnetic emanations, timing, cache attacks, acoustic.", techniques=["SPA (Simple Power Analysis): visual inspection of power trace", "DPA (Differential Power Analysis): statistical correlation", "CPA (Correlation Power Analysis): Hamming weight model", "EM emanation analysis: near-field probe captures", "Cache timing attacks: Flush+Reload, Prime+Probe, Evict+Time", "Spectre/Meltdown: speculative execution side-channels", "PLATYPUS: power side-channel via Intel RAPL", "Hertzbleed: frequency side-channel on x86 CPUs"], indicators=["Timing-variable cryptographic operations", "Non-constant-time comparisons", "Shared cache between processes", "Power consumption correlated with secret data"], tools=["chipwhisperer", "riscure-inspector", "cachegrind"], commands=["# ChipWhisperer capture power traces during crypto operation"], severity="critical"),
    HWPattern(name="Fault Injection", attack_type=HWAttackType.FAULT_INJECTION, description="Induce faults to bypass security: voltage glitching, clock glitching, laser fault injection, electromagnetic fault.", techniques=["Voltage glitching: brief power supply manipulation", "Clock glitching: inject extra clock edges or skip cycles", "Laser fault injection: precise bit-flip in silicon", "EM fault injection: localized electromagnetic pulse", "Rowhammer: DRAM disturbance error causing bit-flips", "Differential Fault Analysis (DFA): recover AES key from faulty ciphertext", "Bootloader bypass via voltage glitch during secure boot", "Read-out protection bypass on microcontrollers"], indicators=["Single point of failure in security checks", "No fault detection/correction mechanisms", "Exposed power/clock pins on PCB", "Lack of secure boot integrity verification"], tools=["chipwhisperer", "newae-cw1200", "riscure-fi"], commands=["# Voltage glitch during boot to bypass secure boot check"], severity="critical"),
    HWPattern(name="Debug Interface Exploitation", attack_type=HWAttackType.DEBUG_INTERFACE, description="Exploit debug interfaces: JTAG, SWD, UART, SPI flash read, I2C, debug headers left on production boards.", techniques=["JTAG: boundary scan, memory read/write, CPU halt", "SWD (Serial Wire Debug): ARM debug access", "UART: serial console access, bootloader interaction", "SPI flash dump: read firmware from flash chip", "I2C EEPROM: read/write configuration data", "Debug header identification on PCB", "Chip-off: desolder flash and read externally", "ISP (In-System Programming): reprogram microcontroller"], indicators=["Exposed debug headers on PCB", "JTAG/SWD not disabled in production", "UART console accessible without authentication", "Flash read protection not enabled"], tools=["openocd", "jlink", "bus-pirate", "flashrom"], commands=["openocd -f interface/jlink.cfg -f target/stm32f4x.cfg", "flashrom -p buspirate_spi -r firmware.bin"], severity="high"),
    HWPattern(name="Chip-Level Attacks", attack_type=HWAttackType.CHIP_LEVEL, description="Physical attacks on silicon: decapsulation, FIB modification, microprobing, ROM extraction.", techniques=["Decapsulation: chemical or mechanical chip opening", "Optical microscopy: image die layers", "FIB (Focused Ion Beam): modify metal layers on chip", "Microprobing: attach probes to internal signals", "ROM extraction: read mask ROM via optical imaging", "Fuse reading: determine security fuse state", "Backside analysis: thin wafer for backside imaging"], indicators=["High-value target justifying cost", "No tamper-evident packaging", "Standard commercial microcontrollers without security features"], tools=["microscope", "fib-system", "probestation"], commands=["# Physical lab equipment required for chip-level attacks"], severity="critical"),
    HWPattern(name="Hardware Supply Chain", attack_type=HWAttackType.SUPPLY_CHAIN, description="Supply chain attacks on hardware: counterfeit components, implanted backdoors, modified firmware, interception.", techniques=["Hardware trojan insertion during manufacturing", "Counterfeit component detection (x-ray, electrical test)", "Firmware modification during shipping/storage", "Component substitution with vulnerable versions", "Bill of Materials (BOM) analysis for vulnerable parts", "PCB modification: added components for backdoor"], indicators=["Components from untrusted suppliers", "Unexpected firmware differences between batches", "PCB layout differences from reference design", "Unusual power consumption or emissions"], tools=["x-ray-inspection", "jtag-scanner", "binwalk"], commands=["binwalk -e firmware.bin # extract firmware for comparison"], severity="critical"),
]

def build_hardware_security_prompt(focus_type: HWAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Hardware Security Knowledge\n"]
    patterns = HW_PATTERNS if not focus_type else [p for p in HW_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
