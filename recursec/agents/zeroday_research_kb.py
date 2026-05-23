"""Zero-day research knowledge base.

Advanced techniques for discovering novel vulnerabilities:
1. Fuzzing strategies (coverage-guided, grammar-based)
2. Variant analysis and root cause patterns
3. Binary reverse engineering approaches
4. Source-to-sink dataflow analysis
5. Race condition and timing attack discovery
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
    research_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:12],
        }


ZERODAY_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "zd-001", "name": "Coverage-Guided Fuzzing",
        "category": "fuzzing", "severity": "critical",
        "desc": "Advanced fuzzing strategies for discovering memory corruption bugs.",
        "strategy": (
            "COVERAGE-GUIDED FUZZING:\n"
            "AFL++ WORKFLOW:\n"
            "  # Compile with instrumentation\n"
            "  CC=afl-clang-fast ./configure\n"
            "  make\n"
            "  # Create seed corpus\n"
            "  mkdir seeds && echo 'test' > seeds/seed1\n"
            "  # Run fuzzer\n"
            "  afl-fuzz -i seeds -o output -m none -- ./target @@\n"
            "  # Persistent mode (10x faster)\n"
            "  afl-fuzz -i seeds -o output -- ./target_persistent\n"
            "LIBFUZZER:\n"
            "  # Compile with libFuzzer\n"
            "  clang -fsanitize=fuzzer,address target_fuzz.c -o target_fuzz\n"
            "  # Run with corpus\n"
            "  ./target_fuzz corpus/ -max_len=4096 -jobs=4\n"
            "SANITIZERS:\n"
            "  AddressSanitizer (ASan): heap-overflow, use-after-free, stack-overflow\n"
            "  UBSan: integer overflow, null deref, alignment\n"
            "  MSan: uninitialized memory reads\n"
            "  TSan: data races, deadlocks\n"
            "STRATEGY:\n"
            "  1. Identify attack surface (parsers, deserializers, protocol handlers)\n"
            "  2. Build minimal harness wrapping target function\n"
            "  3. Collect diverse seed corpus from test suites/real data\n"
            "  4. Enable multiple sanitizers\n"
            "  5. Run 24-72 hours minimum\n"
            "  6. Triage crashes: unique stack traces, severity\n"
            "  7. Minimize test cases: afl-tmin"
        ),
        "tools": ["afl++", "libfuzzer"],
    },
    {
        "id": "zd-002", "name": "Variant Analysis",
        "category": "variant", "severity": "critical",
        "desc": "Finding variants of known vulnerabilities in codebases.",
        "strategy": (
            "VARIANT ANALYSIS:\n"
            "APPROACH:\n"
            "  1. Study known CVE root cause deeply\n"
            "  2. Abstract the vulnerability pattern\n"
            "  3. Search for similar patterns across codebase\n"
            "  4. Check related components and forks\n"
            "PATTERN ABSTRACTION:\n"
            "  CVE example → Pattern:\n"
            "  - Buffer overflow in parser → All parsers using same pattern\n"
            "  - Type confusion in handler → All handlers with same signature\n"
            "  - Missing bounds check → All array accesses without validation\n"
            "CODEQL:\n"
            "  # Create database\n"
            "  codeql database create db --language=cpp --source-root=./src\n"
            "  # Run custom query\n"
            "  codeql query run query.ql --database=db\n"
            "  # Example: Find unchecked malloc\n"
            "  from FunctionCall call\n"
            "  where call.getTarget().getName() = 'malloc'\n"
            "  and not exists(IfStmt check | check.getCondition().getAChild*() = call)\n"
            "  select call, 'Unchecked malloc return value'\n"
            "SEMGREP:\n"
            "  # Custom pattern\n"
            "  semgrep --pattern 'memcpy($DST, $SRC, $SIZE)' \\\n"
            "    --lang c --config auto ./src\n"
            "STRATEGY:\n"
            "  1. CVE database → root cause analysis\n"
            "  2. Build CodeQL/Semgrep query for pattern\n"
            "  3. Run against target codebase\n"
            "  4. Manual review of results\n"
            "  5. Check patched vs unpatched branches"
        ),
        "tools": ["codeql", "semgrep"],
    },
    {
        "id": "zd-003", "name": "Binary Reverse Engineering",
        "category": "reversing", "severity": "critical",
        "desc": "Binary analysis for vulnerability discovery.",
        "strategy": (
            "BINARY REVERSE ENGINEERING:\n"
            "STATIC ANALYSIS:\n"
            "  # Ghidra headless analysis\n"
            "  analyzeHeadless /tmp/project projectName \\\n"
            "    -import target.bin -postScript decompile.py\n"
            "  # Radare2\n"
            "  r2 -A target.bin\n"
            "  afl  # List functions\n"
            "  pdf @ main  # Disassemble main\n"
            "  VV @ main  # Visual graph\n"
            "DYNAMIC ANALYSIS:\n"
            "  # GDB with GEF\n"
            "  gdb -q ./target\n"
            "  gef> checksec  # Check mitigations\n"
            "  gef> pattern create 200\n"
            "  gef> run < pattern\n"
            "  gef> pattern search $rsp  # Find offset\n"
            "  # Frida (dynamic instrumentation)\n"
            "  frida -U -f com.target.app -l hook.js --no-pause\n"
            "VULNERABILITY CLASSES:\n"
            "  - Stack buffer overflow: Check fixed-size buffers with unbounded copies\n"
            "  - Heap overflow: Allocations followed by unbounded writes\n"
            "  - Use-after-free: Free then use patterns\n"
            "  - Format string: User-controlled printf arguments\n"
            "  - Integer overflow: Arithmetic used for allocation size\n"
            "  - Double free: Multiple free() on same pointer\n"
            "TOOLS:\n"
            "  checksec --file=target  # Security mitigations\n"
            "  ropper --file target --search 'pop rdi'  # ROP gadgets\n"
            "  one_gadget /lib/x86_64-linux-gnu/libc.so.6  # One-shot"
        ),
        "tools": ["ghidra", "r2", "gdb"],
    },
    {
        "id": "zd-004", "name": "Source-to-Sink Dataflow",
        "category": "dataflow", "severity": "critical",
        "desc": "Tracking user input from source to dangerous sink.",
        "strategy": (
            "SOURCE-TO-SINK DATAFLOW:\n"
            "SOURCES (user input entry points):\n"
            "  Web: request.params, request.body, request.headers, cookies\n"
            "  Network: recv(), read(), fread(), socket input\n"
            "  File: file uploads, config files, env vars\n"
            "  API: JSON body, query params, path params\n"
            "SINKS (dangerous operations):\n"
            "  SQL: execute(), query(), raw SQL concatenation\n"
            "  Command: exec(), system(), popen(), subprocess\n"
            "  File: open(), write(), unlink(), rename()\n"
            "  XSS: innerHTML, document.write(), eval()\n"
            "  Deserialize: pickle.loads(), yaml.load(), JSON.parse()\n"
            "  SSRF: requests.get(), urllib.urlopen(), fetch()\n"
            "  LDAP: ldap_search(), ldap_bind()\n"
            "  Template: render(), render_template_string()\n"
            "ANALYSIS PROCESS:\n"
            "  1. Map all sources in the application\n"
            "  2. Map all dangerous sinks\n"
            "  3. Trace data flow from each source\n"
            "  4. Check for sanitization/validation at each step\n"
            "  5. Identify bypasses in validation\n"
            "TOOLS:\n"
            "  semgrep --config p/owasp-top-ten ./src\n"
            "  semgrep --config p/injection ./src\n"
            "  bandit -r ./src  # Python\n"
            "  brakeman ./  # Ruby on Rails\n"
            "  snyk code test  # Multi-language"
        ),
        "tools": ["semgrep", "bandit", "codeql"],
    },
    {
        "id": "zd-005", "name": "Race Conditions and Timing",
        "category": "race", "severity": "high",
        "desc": "Discovering race conditions and timing vulnerabilities.",
        "strategy": (
            "RACE CONDITIONS AND TIMING ATTACKS:\n"
            "TOCTOU (Time-of-Check-to-Time-of-Use):\n"
            "  - File system: Check permission then open\n"
            "  - Database: Check balance then deduct\n"
            "  - Auth: Validate token then use\n"
            "  - Testing: Send concurrent requests in tight window\n"
            "TESTING TECHNIQUES:\n"
            "  # Turbo Intruder (Burp)\n"
            "  # Single-packet attack: Multiple requests in one TCP packet\n"
            "  # HTTP/2 stream bundling\n"
            "  # Last-byte sync: Hold requests, release simultaneously\n"
            "COMMON RACE CONDITIONS:\n"
            "  - Double spending in payment systems\n"
            "  - Coupon/voucher reuse\n"
            "  - Follow/unfollow race (double count)\n"
            "  - File upload + access race\n"
            "  - Account registration race (duplicate)\n"
            "  - Rate limit bypass via parallelism\n"
            "TIMING SIDE-CHANNELS:\n"
            "  - Password comparison timing\n"
            "  - Token comparison timing\n"
            "  - Cache-based timing (hit vs miss)\n"
            "  - Database query timing (boolean blind)\n"
            "TESTING:\n"
            "  # Python concurrent requests\n"
            "  # asyncio.gather(*[send_request() for _ in range(100)])\n"
            "  # Use race-the-web, racepwn tools\n"
            "  # Monitor response time differences"
        ),
        "tools": ["burpsuite", "racepwn"],
    },
]


class ZeroDayResearchKB:
    """Zero-day research knowledge base.

    Provides advanced vulnerability research patterns
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
                research_strategy=data.get("strategy", ""),
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
        lines = ["## Zero-Day Research Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category.lower() not in [c.lower() for c in categories]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.category.upper()}]")
            lines.append(pattern.research_strategy)
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
