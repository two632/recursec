"""Zero-day hunting knowledge base.

Deep knowledge about zero-day discovery:
1. Fuzzing strategies
2. Code pattern analysis
3. Vulnerability class hunting
4. Patch diffing
5. Variant analysis
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ZeroDayPattern:
    """A zero-day hunting pattern."""
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


ZERODAY_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "zd-001", "name": "Fuzzing Strategies",
        "category": "fuzzing", "severity": "critical",
        "desc": "Advanced fuzzing for zero-day discovery.",
        "detection": (
            "FUZZING STRATEGIES:\n"
            "COVERAGE-GUIDED:\n"
            "  - AFL++ (state of the art)\n"
            "    # afl-fuzz -i corpus -o findings -- ./target @@\n"
            "    # Custom mutators\n"
            "    # Persistent mode (10-100x speed)\n"
            "    # QEMU mode (binary-only)\n"
            "    # Frida mode (instrumentation)\n"
            "  - LibFuzzer (in-process)\n"
            "    # LLVMFuzzerTestOneInput\n"
            "    # Sanitizer integration\n"
            "  - Honggfuzz\n"
            "    # Hardware-based coverage\n"
            "    # Persistent fuzzing\n"
            "GRAMMAR-BASED:\n"
            "  - Domato (browser DOM)\n"
            "  - Dharma (JS engine)\n"
            "  - Nautilus (grammar-based AFL)\n"
            "  - Fuzzilli (JS engine specific)\n"
            "NETWORK:\n"
            "  - boofuzz (network protocol)\n"
            "  - AFLNet (network services)\n"
            "  - Peach Fuzzer (model-based)\n"
            "KERNEL:\n"
            "  - Syzkaller (Linux kernel)\n"
            "  - kAFL (OS-independent)\n"
            "  - Trinity (syscall fuzzer)\n"
            "SANITIZERS:\n"
            "  - AddressSanitizer (ASAN)\n"
            "  - MemorySanitizer (MSAN)\n"
            "  - UndefinedBehaviorSanitizer (UBSAN)\n"
            "  - ThreadSanitizer (TSAN)\n"
            "TOOLS:\n"
            "  AFL++, LibFuzzer, Honggfuzz, Syzkaller"
        ),
        "tools": [],
    },
    {
        "id": "zd-002", "name": "Code Pattern Analysis",
        "category": "code_patterns", "severity": "high",
        "desc": "Code patterns indicating vulnerabilities.",
        "detection": (
            "CODE PATTERN ANALYSIS:\n"
            "MEMORY SAFETY:\n"
            "  - Buffer overflow patterns\n"
            "    # strcpy, strcat, sprintf (no bounds)\n"
            "    # memcpy with user-controlled size\n"
            "    # Array index without bounds check\n"
            "  - Use-after-free patterns\n"
            "    # Free then dereference\n"
            "    # Callback after cleanup\n"
            "    # Iterator invalidation\n"
            "  - Double-free patterns\n"
            "    # Error path cleanup\n"
            "    # Shared ownership confusion\n"
            "  - Integer overflow\n"
            "    # Multiplication before allocation\n"
            "    # Addition without overflow check\n"
            "    # Signed/unsigned confusion\n"
            "TYPE CONFUSION:\n"
            "  - Union type mishandling\n"
            "  - Variant/tagged union errors\n"
            "  - Virtual table corruption\n"
            "  - Serialization type mismatch\n"
            "RACE CONDITIONS:\n"
            "  - TOCTOU (Time of Check to Use)\n"
            "  - Signal handler races\n"
            "  - Lock ordering violations\n"
            "  - Shared memory races\n"
            "LOGIC BUGS:\n"
            "  - Off-by-one errors\n"
            "  - Integer truncation\n"
            "  - Null pointer dereference\n"
            "  - Resource exhaustion\n"
            "TOOLS:\n"
            "  CodeQL, Semgrep, Coverity, Infer"
        ),
        "tools": [],
    },
    {
        "id": "zd-003", "name": "Vulnerability Class Hunting",
        "category": "vuln_class", "severity": "critical",
        "desc": "Hunting for specific vulnerability classes.",
        "detection": (
            "VULNERABILITY CLASS HUNTING:\n"
            "WEB:\n"
            "  - Prototype pollution (JS)\n"
            "    # Object.prototype manipulation\n"
            "    # __proto__ in JSON\n"
            "  - Server-side template injection\n"
            "    # ${7*7} → 49 (confirm SSTI)\n"
            "  - Deserialization\n"
            "    # Java: ObjectInputStream\n"
            "    # PHP: unserialize()\n"
            "    # Python: pickle.loads()\n"
            "  - HTTP request smuggling\n"
            "    # CL.TE, TE.CL, TE.TE\n"
            "BINARY:\n"
            "  - Heap overflow\n"
            "    # Glibc ptmalloc exploitation\n"
            "    # tcache poisoning\n"
            "    # House of * techniques\n"
            "  - Stack buffer overflow\n"
            "    # ROP chain construction\n"
            "    # Stack pivot\n"
            "    # Return-to-libc\n"
            "  - Format string\n"
            "    # %n write-what-where\n"
            "    # GOT overwrite\n"
            "  - Kernel\n"
            "    # Privilege escalation\n"
            "    # Container escape\n"
            "    # Namespace bypass\n"
            "SUPPLY CHAIN:\n"
            "  - Dependency confusion\n"
            "  - Typosquatting\n"
            "  - Build pipeline injection\n"
            "  - Package maintainer takeover\n"
            "TOOLS:\n"
            "  GDB, pwntools, ROPgadget, one_gadget"
        ),
        "tools": [],
    },
    {
        "id": "zd-004", "name": "Patch Diffing",
        "category": "patch_diff", "severity": "high",
        "desc": "Finding vulnerabilities through patches.",
        "detection": (
            "PATCH DIFFING:\n"
            "METHODOLOGY:\n"
            "  1. Identify security patches\n"
            "  2. Diff the patch (before/after)\n"
            "  3. Understand the vulnerability\n"
            "  4. Develop exploit for pre-patch\n"
            "  5. Check for variants\n"
            "SOURCES:\n"
            "  - Vendor security advisories\n"
            "  - Git commit history\n"
            "  - CVE/NVD descriptions\n"
            "  - Bug tracker entries\n"
            "  - Changelog entries\n"
            "BINARY DIFFING:\n"
            "  - BinDiff (IDA Pro plugin)\n"
            "  - Diaphora (IDA/Ghidra)\n"
            "  - DarunGrim\n"
            "  - Turbodiff\n"
            "SOURCE DIFFING:\n"
            "  - git diff COMMIT~1 COMMIT\n"
            "  - GitHub compare view\n"
            "  - Semantic diff tools\n"
            "  - CodeQL for patch analysis\n"
            "1-DAY EXPLOITATION:\n"
            "  - Race condition: exploit before\n"
            "    organization patches\n"
            "  - Patch gap analysis\n"
            "  - Variant identification\n"
            "  - Regression testing\n"
            "TOOLS:\n"
            "  BinDiff, Diaphora, CodeQL, git"
        ),
        "tools": [],
    },
    {
        "id": "zd-005", "name": "Variant Analysis",
        "category": "variant", "severity": "critical",
        "desc": "Finding variants of known vulnerabilities.",
        "detection": (
            "VARIANT ANALYSIS:\n"
            "METHODOLOGY:\n"
            "  1. Study known vulnerability\n"
            "  2. Identify root cause pattern\n"
            "  3. Create detection rules/queries\n"
            "  4. Search codebase for pattern\n"
            "  5. Verify each match\n"
            "CODEQL:\n"
            "  - Write queries for vuln patterns\n"
            "    # import cpp\n"
            "    # from FunctionCall fc\n"
            "    # where fc.getTarget().getName() = \"strcpy\"\n"
            "    # select fc, \"Unsafe strcpy call\"\n"
            "  - LGTM (online CodeQL)\n"
            "  - Custom queries for project\n"
            "  - Taint tracking queries\n"
            "SEMGREP:\n"
            "  - Pattern matching rules\n"
            "  - Taint mode\n"
            "  - Custom rules\n"
            "    # rules:\n"
            "    # - id: unsafe-deserialization\n"
            "    #   pattern: pickle.loads(...)\n"
            "    #   severity: ERROR\n"
            "STRATEGIES:\n"
            "  - Same bug, different location\n"
            "  - Same root cause, different code\n"
            "  - Similar API misuse\n"
            "  - Incomplete fix (partial patch)\n"
            "  - Cross-project variants\n"
            "  - Language-specific patterns\n"
            "TOOLS:\n"
            "  CodeQL, Semgrep, grep, Joern"
        ),
        "tools": [],
    },
]


class ZeroDayKB:
    """Zero-day hunting knowledge base.

    Provides zero-day hunting patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, ZeroDayPattern] = {}
        self._log = logger.bind(component="zeroday_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load zero-day patterns."""
        for data in ZERODAY_PATTERNS:
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
        """Build zero-day hunting prompt."""
        lines = ["## Zero-Day Hunting\n"]
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
