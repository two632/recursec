"""Zero-day research knowledge base.

Deep knowledge about zero-day discovery:
1. Vulnerability research methodology
2. Fuzzing techniques
3. Binary exploitation patterns
4. Web zero-day patterns
5. Patch analysis and 1-day research
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ZeroDayPattern:
    """A zero-day research pattern."""
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


ZD_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "zd-001", "name": "Vulnerability Research Methodology",
        "category": "methodology", "severity": "critical",
        "desc": "Systematic vulnerability discovery.",
        "detection": (
            "VULNERABILITY RESEARCH METHODOLOGY:\n"
            "ATTACK SURFACE ANALYSIS:\n"
            "  1. Enumerate all entry points\n"
            "  2. Map data flows\n"
            "  3. Identify trust boundaries\n"
            "  4. Find complex state machines\n"
            "  5. Locate parser code\n"
            "  6. Review authentication flows\n"
            "  7. Check serialization/deserialization\n"
            "VARIANT ANALYSIS:\n"
            "  - Find similar bugs to known CVEs\n"
            "  - CodeQL (GitHub) for semantic search\n"
            "  - Semgrep custom rules\n"
            "  - Pattern: same developer, same function class\n"
            "  - Check adjacent functions\n"
            "  # CodeQL query example\n"
            "  # import cpp\n"
            "  # from Function f\n"
            "  # where f.getName().matches(\"%parse%\")\n"
            "  # select f\n"
            "CODE AUDIT TARGETS:\n"
            "  - Memory management (malloc/free/realloc)\n"
            "  - String operations (strcpy, sprintf)\n"
            "  - Integer overflow/underflow\n"
            "  - Format strings\n"
            "  - Type confusion\n"
            "  - Use-after-free\n"
            "  - Double-free\n"
            "  - Race conditions\n"
            "  - Deserialization\n"
            "  - Template injection\n"
            "TOOLS:\n"
            "  CodeQL, Semgrep, Ghidra, IDA Pro, AFL++"
        ),
        "tools": ["codeql", "semgrep"],
    },
    {
        "id": "zd-002", "name": "Fuzzing Techniques",
        "category": "fuzzing", "severity": "critical",
        "desc": "Advanced fuzzing for vulnerability discovery.",
        "detection": (
            "FUZZING TECHNIQUES:\n"
            "COVERAGE-GUIDED:\n"
            "  AFL++:\n"
            "    # Compile with instrumentation\n"
            "    afl-clang-fast target.c -o target_fuzz\n"
            "    # Run fuzzer\n"
            "    afl-fuzz -i input/ -o output/ -- ./target_fuzz @@\n"
            "    # Persistent mode (faster)\n"
            "    __AFL_FUZZ_INIT();\n"
            "    while (__AFL_LOOP(1000)) { ... }\n"
            "  LIBFUZZER:\n"
            "    # In-process fuzzer (LLVM)\n"
            "    extern \"C\" int LLVMFuzzerTestOneInput(\n"
            "        const uint8_t *data, size_t size) { ... }\n"
            "    # Compile: clang -fsanitize=fuzzer,address\n"
            "GRAMMAR-BASED:\n"
            "  - Peach Fuzzer (protocol fuzzing)\n"
            "  - Boofuzz (network protocol)\n"
            "  - Dharma (grammar generation)\n"
            "  - Domato (DOM fuzzing)\n"
            "SANITIZERS:\n"
            "  - AddressSanitizer (ASan): buffer overflow\n"
            "  - MemorySanitizer (MSan): uninitialized read\n"
            "  - UndefinedBehaviorSanitizer (UBSan)\n"
            "  - ThreadSanitizer (TSan): data races\n"
            "  # -fsanitize=address,undefined\n"
            "STRATEGIES:\n"
            "  - Corpus minimization (afl-cmin)\n"
            "  - Dictionary-based fuzzing\n"
            "  - Structure-aware fuzzing\n"
            "  - Snapshot fuzzing (faster startup)\n"
            "  - Kernel fuzzing (syzkaller)\n"
            "TOOLS:\n"
            "  AFL++, libFuzzer, Honggfuzz, syzkaller"
        ),
        "tools": ["afl++"],
    },
    {
        "id": "zd-003", "name": "Binary Exploitation Patterns",
        "category": "binary", "severity": "critical",
        "desc": "Binary exploitation techniques.",
        "detection": (
            "BINARY EXPLOITATION:\n"
            "MEMORY CORRUPTION:\n"
            "  STACK:\n"
            "    - Buffer overflow → RIP control\n"
            "    - Return-to-libc (ret2libc)\n"
            "    - ROP chains (Return Oriented Programming)\n"
            "    - Stack canary bypass (leak/brute)\n"
            "    - NX bypass via ROP\n"
            "  HEAP:\n"
            "    - Use-After-Free (UAF)\n"
            "    - Heap overflow\n"
            "    - Double free\n"
            "    - Tcache poisoning (glibc 2.26+)\n"
            "    - House of techniques\n"
            "    - fastbin attack\n"
            "    - unsorted bin attack\n"
            "  FORMAT STRING:\n"
            "    - %n write primitive\n"
            "    - Read arbitrary memory\n"
            "    - Write arbitrary memory\n"
            "MITIGATIONS:\n"
            "  - ASLR: Address Space Layout Randomization\n"
            "  - NX/DEP: Non-executable stack\n"
            "  - Stack canaries\n"
            "  - PIE: Position Independent Executable\n"
            "  - RELRO: Relocation Read-Only\n"
            "  - CFI: Control Flow Integrity\n"
            "  - Shadow stack\n"
            "BYPASS:\n"
            "  - ASLR: info leak, partial overwrite\n"
            "  - Canary: format string leak, brute force\n"
            "  - NX: ROP, JOP (Jump-Oriented)\n"
            "  - PIE: partial overwrite, ASLR leak\n"
            "TOOLS:\n"
            "  pwntools, ROPgadget, GEF, peda, Ghidra"
        ),
        "tools": ["ghidra"],
    },
    {
        "id": "zd-004", "name": "Web Zero-Day Patterns",
        "category": "web_0day", "severity": "critical",
        "desc": "Web application zero-day patterns.",
        "detection": (
            "WEB ZERO-DAY PATTERNS:\n"
            "DESERIALIZATION:\n"
            "  - Java: ysoserial gadget chains\n"
            "  - Python: pickle/yaml deserialization\n"
            "  - PHP: unserialize() → POP chains\n"
            "  - .NET: BinaryFormatter, XmlSerializer\n"
            "  - Ruby: Marshal.load()\n"
            "TEMPLATE INJECTION:\n"
            "  - SSTI (Server-Side Template Injection)\n"
            "  - Jinja2: {{config.__class__.__init__.__globals__}}\n"
            "  - Freemarker: <#assign ex=\"freemarker.template...\n"
            "  - Thymeleaf: __${T(java.lang.Runtime)...\n"
            "  - Detection: {{7*7}} = 49\n"
            "PROTOTYPE POLLUTION:\n"
            "  - JavaScript: __proto__, constructor.prototype\n"
            "  - Server-side (Node.js) → RCE\n"
            "  - Client-side → XSS, auth bypass\n"
            "RACE CONDITIONS:\n"
            "  - TOCTOU (Time of Check to Time of Use)\n"
            "  - Parallel requests to same endpoint\n"
            "  - Database race (balance manipulation)\n"
            "  - File operation races\n"
            "EMERGING:\n"
            "  - HTTP request smuggling\n"
            "  - Cache poisoning / deception\n"
            "  - WebSocket hijacking\n"
            "  - GraphQL batching attacks\n"
            "  - OAuth/OIDC flow manipulation\n"
            "TOOLS:\n"
            "  Burp Suite, custom scripts, turbo-intruder"
        ),
        "tools": ["burp"],
    },
    {
        "id": "zd-005", "name": "Patch Analysis / 1-Day Research",
        "category": "patch_analysis", "severity": "high",
        "desc": "Analyzing patches to find 1-day exploits.",
        "detection": (
            "PATCH ANALYSIS / 1-DAY:\n"
            "METHODOLOGY:\n"
            "  1. Monitor security advisories\n"
            "  2. Obtain patch diff\n"
            "  3. Identify vulnerable code path\n"
            "  4. Understand root cause\n"
            "  5. Write trigger/PoC\n"
            "  6. Test on unpatched version\n"
            "SOURCES:\n"
            "  - CVE databases (NVD, MITRE)\n"
            "  - Git commits (security fixes)\n"
            "  - Vendor advisories\n"
            "  - GitHub Security Advisories\n"
            "  - Chrome/Firefox bug trackers\n"
            "  - Linux kernel git log\n"
            "TECHNIQUES:\n"
            "  DIFF ANALYSIS:\n"
            "    git diff v1.0..v1.0.1\n"
            "    # Focus on: bounds checks added\n"
            "    # Null pointer checks added\n"
            "    # Sanitization added\n"
            "    # Access control changes\n"
            "  BINARY DIFF:\n"
            "    - BinDiff (Ghidra/IDA plugin)\n"
            "    - Diaphora (Ghidra/IDA)\n"
            "    - Compare function graphs\n"
            "    - Identify patched functions\n"
            "  REGRESSION:\n"
            "    - Build vulnerable version\n"
            "    - Reproduce from advisory\n"
            "    - Verify patch effectiveness\n"
            "    - Check for incomplete fixes\n"
            "N-DAY:\n"
            "  - Known vuln, public PoC, unpatched\n"
            "  - Shodan/Censys for version detection\n"
            "  - Nuclei templates for detection\n"
            "TOOLS:\n"
            "  BinDiff, Diaphora, Ghidra, Git"
        ),
        "tools": ["ghidra"],
    },
]


class ZeroDayKB:
    """Zero-day research knowledge base.

    Provides zero-day discovery patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, ZeroDayPattern] = {}
        self._log = logger.bind(component="zero_day_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load zero-day patterns."""
        for data in ZD_PATTERNS:
            pattern = ZeroDayPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[ZeroDayPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_zeroday_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build zero-day research prompt."""
        lines = ["## Zero-Day Research\n"]
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
