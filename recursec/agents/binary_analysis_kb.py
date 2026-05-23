"""Binary analysis knowledge base.

Deep knowledge about binary/reverse engineering:
1. Buffer overflow exploitation
2. ROP chain construction
3. Format string attacks
4. Heap exploitation
5. Binary protection bypasses
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class BinaryPattern:
    """A binary analysis pattern."""
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
            "category": self.category[:15],
        }


BINARY_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "bin-001", "name": "Stack Buffer Overflow",
        "category": "memory", "severity": "critical",
        "desc": "Stack-based buffer overflows for code execution.",
        "detection": (
            "STACK BUFFER OVERFLOW:\n"
            "RECONNAISSANCE:\n"
            "  # Check binary protections\n"
            "  checksec --file=<binary>\n"
            "  # Protections to check:\n"
            "  - NX (No-Execute): Data segments not executable\n"
            "  - Stack Canary: Random value before return address\n"
            "  - ASLR: Address space layout randomization\n"
            "  - PIE: Position independent executable\n"
            "  - RELRO: Read-only relocations\n"
            "FUZZING FOR CRASHES:\n"
            "  # Generate pattern\n"
            "  pattern_create 1000  # or cyclic(1000) in pwntools\n"
            "  # Find offset\n"
            "  pattern_offset <EIP/RIP value>\n"
            "EXPLOITATION:\n"
            "  No NX, No Canary:\n"
            "    - Classic shellcode injection\n"
            "    - Overwrite return address → point to shellcode on stack\n"
            "  NX Enabled:\n"
            "    - ROP (Return-Oriented Programming)\n"
            "    - ret2libc: system(\"/bin/sh\")\n"
            "    - ret2plt: Call PLT entries\n"
            "  Canary Present:\n"
            "    - Leak canary via format string\n"
            "    - Brute force (fork-based servers)\n"
            "  ASLR:\n"
            "    - Information leak to find base address\n"
            "    - Partial overwrite (lower bytes are constant)\n"
            "    - Ret2plt (PLT addresses are fixed in non-PIE)"
        ),
        "tools": ["pwntools", "gdb", "checksec", "ropper"],
    },
    {
        "id": "bin-002", "name": "Return Oriented Programming",
        "category": "rop", "severity": "critical",
        "desc": "ROP chain construction for NX bypass.",
        "detection": (
            "ROP CHAIN CONSTRUCTION:\n"
            "GADGET FINDING:\n"
            "  ropper --file <binary> --search 'pop rdi'\n"
            "  ROPgadget --binary <binary> --ropchain\n"
            "  radare2: /R pop rdi; ret\n"
            "COMMON GADGETS:\n"
            "  - pop rdi; ret → Set first argument (x86_64)\n"
            "  - pop rsi; pop r15; ret → Set second argument\n"
            "  - pop rdx; ret → Set third argument\n"
            "  - leave; ret → Stack pivot\n"
            "  - syscall; ret → Direct syscall\n"
            "RET2LIBC:\n"
            "  1. Leak libc address (GOT read via puts/write)\n"
            "  2. Calculate libc base from leaked address\n"
            "  3. Find system() and '/bin/sh' in libc\n"
            "  4. Chain: pop rdi → '/bin/sh' → system()\n"
            "SIGRETURN (SROP):\n"
            "  - Use sigreturn syscall to set all registers\n"
            "  - Craft fake signal frame on stack\n"
            "  - One gadget: syscall + sigreturn\n"
            "TOOLS:\n"
            "  pwntools: ROP(elf), rop.find_gadget()\n"
            "  ropper: Interactive gadget search\n"
            "  one_gadget: Find one-shot RCE in libc"
        ),
        "tools": ["ropper", "ropgadget", "pwntools", "one_gadget"],
    },
    {
        "id": "bin-003", "name": "Format String Vulnerability",
        "category": "format_string", "severity": "critical",
        "desc": "Format string bugs for read/write primitives.",
        "detection": (
            "FORMAT STRING ATTACKS:\n"
            "DETECTION:\n"
            "  - Send %p%p%p%p to inputs → stack leak?\n"
            "  - Send %x.%x.%x.%x → hex values from stack?\n"
            "  - Send %s → crashes? (reads from stack pointer)\n"
            "READ PRIMITIVE:\n"
            "  - %N$p: Read Nth value from stack (hex)\n"
            "  - %N$s: Read string at address on stack position N\n"
            "  - Find offset: AAAA%N$p → when output shows 41414141\n"
            "WRITE PRIMITIVE:\n"
            "  - %n: Write number of characters printed to address\n"
            "  - %N$n: Write to address at stack position N\n"
            "  - %hhn: Write single byte\n"
            "  - %hn: Write two bytes\n"
            "EXPLOITATION:\n"
            "  1. Leak stack canary → bypass canary\n"
            "  2. Leak libc address → defeat ASLR\n"
            "  3. Overwrite GOT entry → redirect function call\n"
            "  4. Overwrite __malloc_hook → trigger on next malloc\n"
            "  5. Overwrite return address → redirect control flow\n"
            "PWNTOOLS:\n"
            "  fmtstr = FmtStr(execute_fmt)\n"
            "  fmtstr.write(got_addr, system_addr)\n"
            "  fmtstr.execute_writes()"
        ),
        "tools": ["pwntools", "gdb", "radare2"],
    },
    {
        "id": "bin-004", "name": "Heap Exploitation",
        "category": "heap", "severity": "critical",
        "desc": "Heap memory corruption attacks.",
        "detection": (
            "HEAP EXPLOITATION:\n"
            "TECHNIQUES (glibc):\n"
            "  Use After Free (UAF):\n"
            "    - Free chunk, allocate same size → reuse\n"
            "    - Corrupt function pointers in freed chunk\n"
            "    - tcache poisoning: Modify fd pointer in freed chunk\n"
            "  Double Free:\n"
            "    - Free same chunk twice\n"
            "    - Create circular free list\n"
            "    - tcache: free(A), free(B), free(A)\n"
            "    - fastbin: free(A), free(B), free(A)\n"
            "  Fastbin Dup:\n"
            "    - Allocate overlapping chunks\n"
            "    - Overwrite size field for consolidation\n"
            "  Tcache Poisoning (glibc 2.26+):\n"
            "    - No integrity checks (before 2.32)\n"
            "    - Overwrite fd → allocate anywhere\n"
            "    - glibc 2.32+: Safe-linking (XOR encrypt fd)\n"
            "    - Bypass: Leak heap address, compute XOR mask\n"
            "  House of Force:\n"
            "    - Overwrite top chunk size → very large\n"
            "    - Allocate to reach target address\n"
            "TOOLS:\n"
            "  - pwndbg: vis_heap_chunks, bins, heap\n"
            "  - heaptrack: Heap profiling\n"
            "  - how2heap: Reference implementations"
        ),
        "tools": ["pwntools", "gdb", "pwndbg", "heaptrack"],
    },
    {
        "id": "bin-005", "name": "Binary Protection Analysis",
        "category": "protections", "severity": "high",
        "desc": "Analyzing and bypassing binary protections.",
        "detection": (
            "BINARY PROTECTION ANALYSIS:\n"
            "CHECKSEC:\n"
            "  checksec --file=<binary>\n"
            "  Output:\n"
            "    RELRO:    Full RELRO / Partial RELRO / No RELRO\n"
            "    Stack:    Canary found / No canary found\n"
            "    NX:       NX enabled / NX disabled\n"
            "    PIE:      PIE enabled / No PIE\n"
            "    FORTIFY:  Enabled / Disabled\n"
            "BYPASS TECHNIQUES:\n"
            "  Stack Canary:\n"
            "    - Leak via format string / info disclosure\n"
            "    - Brute force in fork()-based servers\n"
            "    - Overwrite master canary in TLS\n"
            "  ASLR:\n"
            "    - Information leak (format string, partial overwrite)\n"
            "    - Brute force (32-bit: 256 attempts on avg)\n"
            "    - Return to PLT (non-PIE binaries)\n"
            "    - Heap spray\n"
            "  NX:\n"
            "    - ROP chains (code reuse)\n"
            "    - mprotect() to make region executable\n"
            "    - JIT spray\n"
            "  Full RELRO:\n"
            "    - Cannot overwrite GOT\n"
            "    - Target: __malloc_hook, __free_hook (before 2.34)\n"
            "    - Target: stack return address\n"
            "    - Target: function pointers in data"
        ),
        "tools": ["checksec", "pwntools", "gdb", "radare2"],
    },
]


class BinaryAnalysisKB:
    """Binary analysis security knowledge base.

    Provides binary exploitation patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, BinaryPattern] = {}
        self._log = logger.bind(component="binary_analysis_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load binary patterns."""
        for data in BINARY_PATTERNS:
            pattern = BinaryPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[BinaryPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_binary_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build binary analysis prompt."""
        lines = ["## Binary Exploitation Patterns\n"]
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
