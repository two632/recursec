"""Reverse engineering knowledge base.

Deep knowledge about reverse engineering:
1. Static binary analysis
2. Dynamic analysis and debugging
3. Firmware reverse engineering
4. Protocol reverse engineering
5. Anti-reverse-engineering bypass
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class REPattern:
    """A reverse engineering pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "medium"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:12],
        }


RE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "re-001", "name": "Static Binary Analysis",
        "category": "static", "severity": "medium",
        "desc": "Static binary analysis techniques.",
        "detection": (
            "STATIC BINARY ANALYSIS:\n"
            "INITIAL:\n"
            "  file binary          # file type\n"
            "  strings binary       # embedded strings\n"
            "  readelf -h binary    # ELF header\n"
            "  objdump -d binary    # disassembly\n"
            "  nm binary            # symbol table\n"
            "  ldd binary           # shared libraries\n"
            "DISASSEMBLY:\n"
            "  - Ghidra (free, NSA)\n"
            "    # Decompiler (C-like output)\n"
            "    # Cross-reference analysis\n"
            "    # Data flow tracking\n"
            "    # Script automation (Java/Python)\n"
            "  - IDA Pro (commercial)\n"
            "    # Industry standard\n"
            "    # FLIRT signatures\n"
            "    # IDAPython scripting\n"
            "  - Radare2 / Cutter\n"
            "    # Free, scriptable\n"
            "    # r2pipe for automation\n"
            "    # Visual mode\n"
            "  - Binary Ninja\n"
            "    # MLIL/HLIL intermediate language\n"
            "    # Plugin API\n"
            "PATTERNS:\n"
            "  - Function identification\n"
            "  - String cross-references\n"
            "  - Import/export analysis\n"
            "  - Control flow graph\n"
            "  - Call graph analysis\n"
            "  - Crypto constant detection\n"
            "  - Vulnerability signatures\n"
            "TOOLS:\n"
            "  Ghidra, radare2, Cutter, objdump"
        ),
        "tools": ["ghidra", "radare2"],
    },
    {
        "id": "re-002", "name": "Dynamic Analysis",
        "category": "dynamic", "severity": "medium",
        "desc": "Dynamic analysis and debugging.",
        "detection": (
            "DYNAMIC ANALYSIS:\n"
            "DEBUGGERS:\n"
            "  - GDB (GNU Debugger)\n"
            "    # gdb ./binary\n"
            "    # break main; run; step; next\n"
            "    # info registers; x/20x $esp\n"
            "    # GEF/PEDA/pwndbg extensions\n"
            "  - WinDbg (Windows)\n"
            "    # Kernel + user-mode debugging\n"
            "    # !analyze -v (crash analysis)\n"
            "  - x64dbg (Windows)\n"
            "    # User-friendly, plugin system\n"
            "    # Conditional breakpoints\n"
            "  - lldb (macOS/Linux)\n"
            "TRACING:\n"
            "  - strace (Linux syscalls)\n"
            "    strace -f -e trace=network ./binary\n"
            "  - ltrace (library calls)\n"
            "  - Process Monitor (Windows)\n"
            "  - DTrace/bpftrace\n"
            "  - Frida (dynamic instrumentation)\n"
            "    # Hook functions at runtime\n"
            "    # Modify arguments/returns\n"
            "    # Cross-platform\n"
            "    # JavaScript API\n"
            "SANDBOXING:\n"
            "  - Any.run (interactive)\n"
            "  - Cuckoo Sandbox\n"
            "  - CAPE\n"
            "  - Joe Sandbox\n"
            "  - Docker isolation\n"
            "TOOLS:\n"
            "  GDB/GEF, Frida, strace, x64dbg"
        ),
        "tools": ["gdb", "frida"],
    },
    {
        "id": "re-003", "name": "Firmware Reverse Engineering",
        "category": "firmware", "severity": "high",
        "desc": "Firmware reverse engineering.",
        "detection": (
            "FIRMWARE RE:\n"
            "EXTRACTION:\n"
            "  # binwalk\n"
            "  binwalk -e firmware.bin\n"
            "  # Identify embedded filesystems\n"
            "  binwalk firmware.bin\n"
            "  # dd extraction\n"
            "  dd if=firmware.bin bs=1 skip=OFFSET count=SIZE of=extracted\n"
            "  # ubi_reader (UBI filesystems)\n"
            "  # jefferson (JFFS2)\n"
            "  # sasquatch (SquashFS variants)\n"
            "ANALYSIS:\n"
            "  - Filesystem analysis\n"
            "    # Find config files, scripts, binaries\n"
            "    # Default credentials in configs\n"
            "    # SSL certificates and private keys\n"
            "    # Hardcoded API keys/tokens\n"
            "  - Binary analysis\n"
            "    # Cross-compile for emulation\n"
            "    # Identify architecture (ARM, MIPS)\n"
            "    # Find vulnerabilities in web server\n"
            "  - Bootloader analysis\n"
            "    # U-Boot environment\n"
            "    # Boot sequence modification\n"
            "EMULATION:\n"
            "  # QEMU (full system emulation)\n"
            "  qemu-system-mipsel -M malta -kernel vmlinux -hda rootfs.ext2\n"
            "  # FirmAE (automated emulation)\n"
            "  # FAT (Firmware Analysis Toolkit)\n"
            "  # firmadyne\n"
            "HARDWARE:\n"
            "  - UART connection (serial console)\n"
            "  - JTAG debugging\n"
            "  - SPI/I2C flash reading\n"
            "  - Chip-off (desolder flash)\n"
            "TOOLS:\n"
            "  binwalk, FirmAE, QEMU, Ghidra"
        ),
        "tools": ["binwalk"],
    },
    {
        "id": "re-004", "name": "Protocol Reverse Engineering",
        "category": "protocol", "severity": "medium",
        "desc": "Protocol reverse engineering.",
        "detection": (
            "PROTOCOL RE:\n"
            "NETWORK:\n"
            "  # Wireshark (packet analysis)\n"
            "  # Identify protocol structure\n"
            "  # Follow TCP/UDP streams\n"
            "  # Custom dissectors (Lua)\n"
            "  # mitmproxy (HTTPS intercept)\n"
            "  mitmproxy --mode transparent\n"
            "  # Burp Suite (HTTP/HTTPS)\n"
            "BINARY PROTOCOL:\n"
            "  - Message framing (length prefix, delimiter)\n"
            "  - Field identification\n"
            "    # Magic bytes\n"
            "    # Version fields\n"
            "    # Length fields\n"
            "    # Type/command codes\n"
            "    # Payload data\n"
            "  - Endianness detection\n"
            "  - Compression (zlib, gzip, lz4)\n"
            "  - Encryption (TLS, custom)\n"
            "TECHNIQUES:\n"
            "  - Differential analysis\n"
            "    # Send similar requests, compare\n"
            "    # Identify variable vs fixed fields\n"
            "  - Replay attacks\n"
            "  - Fuzzing protocol fields\n"
            "  - State machine reconstruction\n"
            "  - Traffic generation/injection\n"
            "SERIALIZATION:\n"
            "  - Protobuf (reverse .proto)\n"
            "  - MessagePack\n"
            "  - BSON\n"
            "  - Custom binary formats\n"
            "  # pbtk (Protobuf reverse)\n"
            "TOOLS:\n"
            "  Wireshark, mitmproxy, Burp Suite, pbtk"
        ),
        "tools": ["wireshark"],
    },
    {
        "id": "re-005", "name": "Anti-RE Bypass",
        "category": "anti_re", "severity": "high",
        "desc": "Anti-reverse-engineering bypass.",
        "detection": (
            "ANTI-RE BYPASS:\n"
            "OBFUSCATION:\n"
            "  - Control flow flattening\n"
            "    # Symbolic execution to resolve\n"
            "    # angr, Triton, Miasm\n"
            "  - String encryption\n"
            "    # Dynamic decryption at runtime\n"
            "    # Hook decryption function\n"
            "  - Opaque predicates\n"
            "  - Dead code insertion\n"
            "  - Metamorphic code\n"
            "PACKING:\n"
            "  - UPX: upx -d packed.exe\n"
            "  - Custom packers: run, dump, rebuild\n"
            "  - Multi-layer packing\n"
            "  # Detect: entropy analysis, section names\n"
            "  # DIE (Detect It Easy)\n"
            "ANTI-DEBUG:\n"
            "  - IsDebuggerPresent (Windows)\n"
            "  - ptrace check (Linux)\n"
            "  - Timing checks (RDTSC)\n"
            "  - Hardware breakpoint detection\n"
            "  - Self-modifying code\n"
            "  # Bypass: patch checks, Frida hooks\n"
            "ANTI-TAMPER:\n"
            "  - Code integrity checks\n"
            "  - Checksum verification\n"
            "  - Code signing validation\n"
            "  # Bypass: NOP out checks\n"
            "ANTI-VM:\n"
            "  - CPUID checks\n"
            "  - Registry artifacts\n"
            "  - MAC address prefixes\n"
            "  - File/driver presence\n"
            "  # Bypass: modify VM artifacts\n"
            "TOOLS:\n"
            "  angr, Triton, Frida, x64dbg, DIE"
        ),
        "tools": ["angr"],
    },
]


class ReverseEngineeringKB:
    """Reverse engineering knowledge base.

    Provides reverse engineering patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, REPattern] = {}
        self._log = logger.bind(component="re_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load RE patterns."""
        for data in RE_PATTERNS:
            pattern = REPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "medium"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[REPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_re_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build reverse engineering prompt."""
        lines = ["## Reverse Engineering\n"]
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
