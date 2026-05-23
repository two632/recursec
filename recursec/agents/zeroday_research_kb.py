"""Zero-day research knowledge base.

Deep knowledge about zero-day vulnerability research:
1. Fuzzing strategies for 0-day discovery
2. Variant analysis techniques
3. Root cause analysis
4. Vulnerability classes and patterns
5. Responsible disclosure
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


ZERODAY_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "zd-001", "name": "Fuzzing Strategies",
        "category": "fuzzing", "severity": "critical",
        "desc": "Fuzzing strategies for vulnerability discovery.",
        "detection": (
            "FUZZING STRATEGIES:\n"
            "COVERAGE-GUIDED:\n"
            "  # AFL++ (American Fuzzy Lop)\n"
            "  afl-fuzz -i input/ -o output/ -- ./target @@\n"
            "  # Instrument binary for coverage feedback\n"
            "  afl-clang-fast++ -o target target.cpp\n"
            "  # Corpus minimization\n"
            "  afl-cmin -i input/ -o min/ -- ./target @@\n"
            "MUTATION-BASED:\n"
            "  # Mutate existing inputs\n"
            "  # Bit flips, byte insertion, arithmetic\n"
            "  # Dictionary-guided mutations\n"
            "  # Radamsa (generic mutator)\n"
            "  radamsa sample.pdf > fuzz.pdf\n"
            "GENERATION-BASED:\n"
            "  # Protocol-aware fuzzing\n"
            "  # Grammar-based input generation\n"
            "  # Peach Fuzzer (protocol fuzzing)\n"
            "  # boofuzz (network protocol fuzzing)\n"
            "HYBRID:\n"
            "  # Combine fuzzing + symbolic execution\n"
            "  # QSYM, Driller, SymCC\n"
            "  # Increase coverage beyond fuzzing alone\n"
            "TARGETS:\n"
            "  - File parsers (PDF, image, video)\n"
            "  - Network protocols (HTTP, DNS, TLS)\n"
            "  - System calls (syzkaller for kernel)\n"
            "  - Browser engines (Domato for DOM)\n"
            "  - API endpoints (RESTler)\n"
            "TOOLS:\n"
            "  AFL++, libFuzzer, honggfuzz, syzkaller, boofuzz"
        ),
        "tools": ["afl++", "honggfuzz", "boofuzz"],
    },
    {
        "id": "zd-002", "name": "Variant Analysis",
        "category": "variant", "severity": "critical",
        "desc": "Variant analysis for finding related bugs.",
        "detection": (
            "VARIANT ANALYSIS:\n"
            "CONCEPT:\n"
            "  - Given a known bug, find similar bugs\n"
            "  - Same root cause, different trigger\n"
            "  - Same pattern, different location\n"
            "  - Historical: 1 bug → dozens of variants\n"
            "TECHNIQUES:\n"
            "  CODE PATTERN:\n"
            "    - Identify vulnerable pattern\n"
            "    - Search for same pattern elsewhere\n"
            "    - Tools: Semgrep, CodeQL, Joern\n"
            "  DATA FLOW:\n"
            "    - Trace user input to sink\n"
            "    - Find all paths: source → sanitizer? → sink\n"
            "    - CodeQL: taint tracking queries\n"
            "  DIFF ANALYSIS:\n"
            "    - Analyze security patches\n"
            "    - Identify what was fixed\n"
            "    - Check if fix is complete\n"
            "    - Look for similar unfixed code\n"
            "  REGRESSION:\n"
            "    - Bugs that were fixed then reintroduced\n"
            "    - Check old CVE fixes still apply\n"
            "    - Refactoring may undo security fixes\n"
            "CodeQL EXAMPLE:\n"
            "  from DataFlow::PathNode source, sink\n"
            "  where source.isUserInput() and sink.isSqlSink()\n"
            "  select source, sink, \"SQL injection\"\n"
            "TOOLS:\n"
            "  CodeQL, Semgrep, Joern, Weggli"
        ),
        "tools": ["codeql", "semgrep", "joern"],
    },
    {
        "id": "zd-003", "name": "Root Cause Analysis",
        "category": "rca", "severity": "high",
        "desc": "Root cause analysis of vulnerabilities.",
        "detection": (
            "ROOT CAUSE ANALYSIS:\n"
            "CRASH ANALYSIS:\n"
            "  # Triage crashes from fuzzing\n"
            "  # Deduplicate by stack trace\n"
            "  # Determine exploitability\n"
            "  # AddressSanitizer (ASAN)\n"
            "  clang -fsanitize=address -o target target.c\n"
            "  # MemorySanitizer (MSAN) — uninit memory\n"
            "  # UBSan — undefined behavior\n"
            "  # ThreadSanitizer (TSAN) — data races\n"
            "DEBUGGING:\n"
            "  # GDB with PEDA/GEF/pwndbg\n"
            "  gdb ./target core\n"
            "  # Reverse debugging (rr)\n"
            "  rr record ./target\n"
            "  rr replay\n"
            "  # Time travel debugging\n"
            "  # Set breakpoint at crash, work backwards\n"
            "ANALYSIS:\n"
            "  1. Identify crash point\n"
            "  2. Determine controlled inputs\n"
            "  3. Trace data flow backwards\n"
            "  4. Find missing check/validation\n"
            "  5. Determine vulnerability class\n"
            "  6. Assess exploitability\n"
            "EXPLOITABILITY:\n"
            "  # CERT BFF triage (exploitable plugin)\n"
            "  # Criteria:\n"
            "  - Controlled EIP/RIP → exploitable\n"
            "  - Controlled write → exploitable\n"
            "  - Read AV → info leak potential\n"
            "  - Stack corruption → likely exploitable"
        ),
        "tools": ["gdb", "rr"],
    },
    {
        "id": "zd-004", "name": "Vulnerability Classes",
        "category": "vuln_class", "severity": "critical",
        "desc": "Common vulnerability classes and patterns.",
        "detection": (
            "VULNERABILITY CLASSES:\n"
            "MEMORY SAFETY:\n"
            "  - Buffer overflow (stack, heap)\n"
            "  - Use-after-free\n"
            "  - Double free\n"
            "  - Integer overflow/underflow\n"
            "  - Type confusion\n"
            "  - Uninitialized memory\n"
            "  - Out-of-bounds read/write\n"
            "LOGIC:\n"
            "  - Authentication bypass\n"
            "  - Authorization failure\n"
            "  - Race condition (TOCTOU)\n"
            "  - State confusion\n"
            "  - Improper error handling\n"
            "INJECTION:\n"
            "  - SQL injection\n"
            "  - Command injection\n"
            "  - LDAP injection\n"
            "  - XPath injection\n"
            "  - Template injection (SSTI)\n"
            "  - Header injection\n"
            "CRYPTO:\n"
            "  - Weak algorithms (MD5, DES, RC4)\n"
            "  - ECB mode usage\n"
            "  - Missing MAC/HMAC\n"
            "  - Predictable IV/nonce\n"
            "  - Padding oracle\n"
            "  - Timing side-channel\n"
            "DESIGN:\n"
            "  - Insecure defaults\n"
            "  - Insufficient logging\n"
            "  - Missing rate limiting\n"
            "  - Unsafe deserialization\n"
            "  - SSRF / open redirect"
        ),
        "tools": [],
    },
    {
        "id": "zd-005", "name": "Responsible Disclosure",
        "category": "disclosure", "severity": "medium",
        "desc": "Responsible disclosure process.",
        "detection": (
            "RESPONSIBLE DISCLOSURE:\n"
            "PROCESS:\n"
            "  1. Discover vulnerability\n"
            "  2. Verify and document (PoC)\n"
            "  3. Contact vendor (security@, PSIRT)\n"
            "  4. Report with details:\n"
            "     - Affected product/version\n"
            "     - Steps to reproduce\n"
            "     - Impact assessment\n"
            "     - Suggested fix\n"
            "  5. Coordinate timeline (typically 90 days)\n"
            "  6. Publish advisory after fix\n"
            "PLATFORMS:\n"
            "  - HackerOne (bug bounty)\n"
            "  - Bugcrowd (bug bounty)\n"
            "  - vendor security@ email\n"
            "  - CERT/CC coordination\n"
            "  - Full Disclosure mailing list\n"
            "  - MITRE CVE request\n"
            "CVE PROCESS:\n"
            "  - Request CVE ID from CNA\n"
            "  - MITRE web form or CNA portal\n"
            "  - Include: product, version, vuln type\n"
            "  - CVSS scoring\n"
            "  - CWE classification\n"
            "ADVISORY WRITING:\n"
            "  - Title: [Product] [Vuln Type] in [Component]\n"
            "  - Affected versions\n"
            "  - CVSS score and vector\n"
            "  - Technical description\n"
            "  - PoC (after patch available)\n"
            "  - Remediation\n"
            "  - Timeline\n"
            "  - Credits"
        ),
        "tools": [],
    },
]


class ZeroDayResearchKB:
    """Zero-day research knowledge base.

    Provides 0-day research patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, ZeroDayPattern] = {}
        self._log = logger.bind(component="zeroday_research_kb")
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
