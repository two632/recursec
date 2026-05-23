"""Hardware vulnerability analyzer — reasons about hardware-level attack surfaces.

Knowledge that gets injected into agent prompts for:
1. Spectre/Meltdown speculative execution analysis
2. Cache timing side channels
3. Rowhammer memory corruption patterns
4. Power analysis side channels
5. JTAG/debug interface exposure
6. Firmware vulnerability patterns
7. TPM and secure boot weaknesses
8. Hardware-specific CVE awareness
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class HardwareVulnCategory(str, Enum):
    SPECULATIVE_EXECUTION = "speculative_execution"
    CACHE_SIDE_CHANNEL = "cache_side_channel"
    MEMORY_CORRUPTION = "memory_corruption"
    POWER_ANALYSIS = "power_analysis"
    DEBUG_INTERFACE = "debug_interface"
    FIRMWARE = "firmware"
    SECURE_BOOT = "secure_boot"
    TPM = "tpm"
    MICROARCHITECTURE = "microarchitecture"


class HardwareTarget(str, Enum):
    X86_INTEL = "x86_intel"
    X86_AMD = "x86_amd"
    ARM = "arm"
    RISC_V = "risc_v"
    IOT_MCU = "iot_mcu"
    GPU = "gpu"
    FPGA = "fpga"
    NETWORK_ASIC = "network_asic"


@dataclass
class HardwareVulnPattern:
    """A hardware vulnerability pattern for agent reasoning."""
    pattern_id: str = ""
    name: str = ""
    category: HardwareVulnCategory = HardwareVulnCategory.SPECULATIVE_EXECUTION
    affected_targets: list[HardwareTarget] = field(default_factory=list)
    description: str = ""
    detection_approach: str = ""
    prompt_fragment: str = ""
    real_world_cves: list[str] = field(default_factory=list)
    severity: str = "high"
    difficulty: str = "advanced"
    prerequisites: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "category": self.category.value,
            "severity": self.severity,
            "cves": len(self.real_world_cves),
        }


@dataclass
class HardwareProfile:
    """Profile of a target's hardware characteristics."""
    profile_id: str = ""
    cpu_vendor: str = ""
    cpu_model: str = ""
    architecture: HardwareTarget = HardwareTarget.X86_INTEL
    has_smt: bool = True
    has_tpm: bool = False
    secure_boot_enabled: bool = False
    firmware_version: str = ""
    debug_ports_exposed: list[str] = field(default_factory=list)
    applicable_vulns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.profile_id,
            "arch": self.architecture.value,
            "cpu": self.cpu_model[:20],
            "smt": self.has_smt,
            "tpm": self.has_tpm,
            "vulns": len(self.applicable_vulns),
        }


# ── Hardware Vulnerability Patterns ───────────────────────────

HW_VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "hw-001",
        "name": "Spectre V1 (Bounds Check Bypass)",
        "category": "speculative_execution",
        "targets": ["x86_intel", "x86_amd", "arm"],
        "desc": "CPU speculatively executes past array bounds checks, leaking data through cache timing.",
        "detection": "Check for code patterns: if(x < array_len) use(array[x]) where x is attacker-controlled. Measure cache line timing differences after speculative execution.",
        "prompt": (
            "When analyzing code running on modern CPUs, check for SPECTRE V1 patterns: "
            "if(user_controlled_index < array_length) value = array[user_controlled_index]; "
            "The CPU may speculatively execute the array access BEFORE the bounds check completes, "
            "leaking the value through cache timing. Look for: (1) Bounds checks followed by "
            "array accesses with user-controlled indices, (2) Missing speculation barriers "
            "(lfence on x86, csdb on ARM), (3) JIT-compiled code that doesn't insert barriers."
        ),
        "cves": ["CVE-2017-5753"],
        "severity": "high",
    },
    {
        "id": "hw-002",
        "name": "Spectre V2 (Branch Target Injection)",
        "category": "speculative_execution",
        "targets": ["x86_intel", "x86_amd"],
        "desc": "Attacker poisons branch prediction to redirect speculative execution to gadgets that leak data.",
        "detection": "Check for indirect branches (call [rax], jmp [rbx]) that could be redirected. Check if retpoline or IBRS mitigations are enabled.",
        "prompt": (
            "Check for SPECTRE V2 vulnerability: indirect branches (call/jmp through registers or memory) "
            "can be redirected by training the Branch Target Buffer (BTB). Mitigations: retpoline "
            "(replaces indirect branches with return-based sequences), IBRS (hardware mitigation), "
            "STIBP (for SMT). Check: cat /sys/devices/system/cpu/vulnerabilities/spectre_v2"
        ),
        "cves": ["CVE-2017-5715"],
        "severity": "high",
    },
    {
        "id": "hw-003",
        "name": "Meltdown (Rogue Data Cache Load)",
        "category": "speculative_execution",
        "targets": ["x86_intel"],
        "desc": "CPU speculatively reads kernel memory from user space before permission check completes.",
        "detection": "Check if KPTI (Kernel Page Table Isolation) is enabled. On Intel pre-2018 CPUs without microcode updates, kernel memory may be readable from userspace.",
        "prompt": (
            "Check for MELTDOWN vulnerability: on affected Intel CPUs, user-space code can "
            "speculatively read kernel memory before the permission check halts execution. "
            "The data leaks through cache timing side channels. "
            "Mitigation: KPTI (Kernel Page Table Isolation). "
            "Check: cat /sys/devices/system/cpu/vulnerabilities/meltdown "
            "If 'Vulnerable', the system needs kernel update or microcode patch."
        ),
        "cves": ["CVE-2017-5754"],
        "severity": "critical",
    },
    {
        "id": "hw-004",
        "name": "Rowhammer (Memory Bit Flip)",
        "category": "memory_corruption",
        "targets": ["x86_intel", "x86_amd", "arm"],
        "desc": "Rapidly accessing DRAM rows causes bit flips in adjacent rows due to electrical interference.",
        "detection": "Run memory stress tests (rowhammer_test). Check if ECC memory is used. Test with TRRespass for modern TRR-equipped DRAM.",
        "prompt": (
            "Check for ROWHAMMER vulnerability: rapidly reading the same DRAM row causes "
            "electrical interference that flips bits in adjacent rows. Exploitable to: "
            "(1) Escape VM/sandbox by flipping page table bits, "
            "(2) Escalate privileges by flipping permission bits, "
            "(3) Bypass authentication by flipping comparison results. "
            "Mitigations: ECC memory, TRR (Target Row Refresh), memory isolation. "
            "Modern attack: TRRespass bypasses TRR on many DRAM chips."
        ),
        "cves": ["CVE-2015-0565", "CVE-2021-42114"],
        "severity": "high",
    },
    {
        "id": "hw-005",
        "name": "Cache Timing Side Channel",
        "category": "cache_side_channel",
        "targets": ["x86_intel", "x86_amd", "arm"],
        "desc": "Measure timing differences between cache hits and misses to extract secret data (e.g., AES key extraction).",
        "detection": "Measure access times to shared cache lines. If timing differences exceed threshold (~50 cycles), cache-based side channels are feasible.",
        "prompt": (
            "Analyze for CACHE TIMING SIDE CHANNELS: in shared-resource environments "
            "(cloud VMs, containers, multi-tenant), attackers can measure cache access times "
            "to extract secrets from co-located processes. Techniques: "
            "Flush+Reload (shared pages), Prime+Probe (L1/L2/LLC), "
            "Evict+Time (eviction-based). "
            "Applications: AES key extraction, RSA key recovery, keystroke timing. "
            "Mitigations: cache partitioning (CAT), constant-time implementations, "
            "noise injection."
        ),
        "cves": ["CVE-2018-3615"],
        "severity": "high",
    },
    {
        "id": "hw-006",
        "name": "JTAG/Debug Interface Exposure",
        "category": "debug_interface",
        "targets": ["iot_mcu", "arm", "network_asic"],
        "desc": "Exposed JTAG/SWD debug ports allow full memory read/write and code execution on embedded devices.",
        "detection": "Physical inspection for debug headers. Scan for exposed debug pins using JTAGulator. Check if debug fuses are blown.",
        "prompt": (
            "For IoT/embedded targets, check for EXPOSED DEBUG INTERFACES: "
            "JTAG, SWD (Serial Wire Debug), UART. These provide: "
            "(1) Full memory read/write access, "
            "(2) CPU register inspection, "
            "(3) Firmware extraction, "
            "(4) Arbitrary code execution. "
            "Even if physical access is required, many devices have debug ports "
            "enabled in production. Check firmware for debug strings, "
            "test for open UART (baud rates: 9600, 115200)."
        ),
        "cves": [],
        "severity": "critical",
    },
    {
        "id": "hw-007",
        "name": "Firmware Update Integrity",
        "category": "firmware",
        "targets": ["iot_mcu", "arm", "network_asic"],
        "desc": "Firmware update mechanism without signature verification allows malicious firmware installation.",
        "detection": "Analyze firmware update protocol. Check for signature verification, encrypted transport, rollback protection.",
        "prompt": (
            "Analyze FIRMWARE UPDATE MECHANISM for weaknesses: "
            "(1) No signature verification: attacker can push malicious firmware. "
            "(2) No encrypted transport: firmware can be intercepted and modified. "
            "(3) No rollback protection: attacker can downgrade to vulnerable version. "
            "(4) Hardcoded update credentials: attacker can authenticate to update server. "
            "(5) Cleartext firmware: secrets and keys extractable from firmware image. "
            "Extract firmware (binwalk), analyze for hardcoded secrets (strings, entropy analysis)."
        ),
        "cves": [],
        "severity": "high",
    },
    {
        "id": "hw-008",
        "name": "TPM Seal/Unseal Bypass",
        "category": "tpm",
        "targets": ["x86_intel", "x86_amd"],
        "desc": "TPM-based disk encryption can be bypassed by sniffing the LPC/SPI bus or through PCR manipulation.",
        "detection": "Check TPM version (1.2 vs 2.0). Check if TPM is discrete (bus sniffable) or firmware-based. Check PCR policy.",
        "prompt": (
            "For targets using TPM-based encryption (BitLocker, LUKS): "
            "(1) Discrete TPM: SPI/LPC bus between CPU and TPM can be sniffed "
            "with a logic analyzer to extract unsealing keys. "
            "(2) PCR manipulation: If boot measurements are predictable, "
            "attacker can recreate the expected PCR state. "
            "(3) Cold boot: DRAM retains data for seconds after power off; "
            "freeze RAM and read keys. "
            "Firmware TPM (fTPM) is harder to sniff but may be vulnerable "
            "to firmware-level attacks."
        ),
        "cves": ["CVE-2023-1017", "CVE-2023-1018"],
        "severity": "high",
    },
    {
        "id": "hw-009",
        "name": "Microarchitectural Data Sampling (MDS)",
        "category": "microarchitecture",
        "targets": ["x86_intel"],
        "desc": "Intel CPU internal buffers (store buffer, fill buffer, load port) leak data across security boundaries.",
        "detection": "Check: cat /sys/devices/system/cpu/vulnerabilities/mds. Affected Intel CPUs leak data from internal buffers during speculative execution.",
        "prompt": (
            "Check for MDS (Microarchitectural Data Sampling) vulnerabilities: "
            "RIDL, Fallout, ZombieLoad. Intel CPU internal buffers leak stale data "
            "from other security contexts (other processes, kernel, VMs). "
            "Variants: (1) MSBDS - Store buffer leak, (2) MFBDS - Fill buffer leak, "
            "(3) MLPDS - Load port leak, (4) MDSUM - Uncacheable memory leak. "
            "Mitigations: microcode update + verw instruction on context switch. "
            "Check: /sys/devices/system/cpu/vulnerabilities/mds"
        ),
        "cves": ["CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091"],
        "severity": "high",
    },
]


class HardwareVulnAnalyzer:
    """Provides hardware vulnerability knowledge for agent reasoning.

    This knowledge gets injected into agent prompts so the LLMs
    reason about hardware-level attack surfaces when analyzing targets.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, HardwareVulnPattern] = {}
        self._profiles: dict[str, HardwareProfile] = {}
        self._profile_counter = 0
        self._log = logger.bind(component="hardware_vuln_analyzer")

        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load hardware vulnerability patterns."""
        for data in HW_VULN_PATTERNS:
            pattern = HardwareVulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=HardwareVulnCategory(data["category"]),
                affected_targets=[
                    HardwareTarget(t) for t in data.get("targets", [])
                ],
                description=data.get("desc", ""),
                detection_approach=data.get("detection", ""),
                prompt_fragment=data.get("prompt", ""),
                real_world_cves=data.get("cves", []),
                severity=data.get("severity", "high"),
            )
            self._patterns[pattern.pattern_id] = pattern

    def create_profile(
        self,
        cpu_vendor: str = "",
        cpu_model: str = "",
        architecture: str = "x86_intel",
    ) -> HardwareProfile:
        """Create a hardware profile for a target."""
        self._profile_counter += 1

        try:
            arch = HardwareTarget(architecture)
        except ValueError:
            arch = HardwareTarget.X86_INTEL

        profile = HardwareProfile(
            profile_id=f"hwp-{self._profile_counter}",
            cpu_vendor=cpu_vendor,
            cpu_model=cpu_model,
            architecture=arch,
        )

        # Find applicable vulnerabilities
        for pattern in self._patterns.values():
            if arch in pattern.affected_targets:
                profile.applicable_vulns.append(pattern.pattern_id)

        self._profiles[profile.profile_id] = profile
        return profile

    def get_patterns_for_target(
        self,
        target_type: str,
    ) -> list[HardwareVulnPattern]:
        """Get hardware vuln patterns applicable to a target type."""
        try:
            arch = HardwareTarget(target_type)
        except ValueError:
            return []

        return [
            p for p in self._patterns.values()
            if arch in p.affected_targets
        ]

    def get_prompt_fragments(
        self,
        target_type: str = "",
        category: str = "",
    ) -> list[str]:
        """Get prompt fragments for hardware vuln awareness."""
        fragments = []

        for pattern in self._patterns.values():
            if target_type:
                try:
                    arch = HardwareTarget(target_type)
                    if arch not in pattern.affected_targets:
                        continue
                except ValueError:
                    continue

            if category:
                try:
                    cat = HardwareVulnCategory(category)
                    if pattern.category != cat:
                        continue
                except ValueError:
                    continue

            if pattern.prompt_fragment:
                fragments.append(pattern.prompt_fragment)

        return fragments

    def get_pattern(self, pattern_id: str) -> HardwareVulnPattern | None:
        return self._patterns.get(pattern_id)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            cat_counts[p.category.value] += 1
        return {
            "patterns": len(self._patterns),
            "profiles": len(self._profiles),
            "by_category": dict(cat_counts),
            "total_cves": sum(
                len(p.real_world_cves) for p in self._patterns.values()
            ),
        }
