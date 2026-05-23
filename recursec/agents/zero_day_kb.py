"""Zero-day discovery strategy knowledge base.

Knowledge for discovering novel vulnerabilities:
1. Fuzzing strategies
2. Memory corruption patterns
3. Race condition discovery
4. Logic bug hunting
5. 1-day to 0-day conversion
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ZeroDayStrategy:
    """A zero-day discovery strategy."""
    strategy_id: str = ""
    name: str = ""
    category: str = ""
    difficulty: str = "hard"
    description: str = ""
    methodology: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.strategy_id,
            "name": self.name[:25],
            "category": self.category[:15],
        }


ZERODAY_STRATEGIES: list[dict[str, Any]] = [
    {
        "id": "zd-001", "name": "Coverage-Guided Fuzzing",
        "category": "fuzzing", "difficulty": "medium",
        "desc": "Using coverage-guided fuzzers to find memory corruption bugs.",
        "methodology": (
            "COVERAGE-GUIDED FUZZING:\n"
            "APPROACH:\n"
            "  1. Identify target binary/library\n"
            "  2. Create initial corpus (valid inputs)\n"
            "  3. Compile with coverage instrumentation\n"
            "  4. Run fuzzer with crash detection\n"
            "  5. Triage and root-cause crashes\n"
            "TOOLS:\n"
            "  AFL++: Best general-purpose fuzzer\n"
            "    afl-fuzz -i corpus/ -o findings/ -- ./target @@\n"
            "  LibFuzzer: Integrated into LLVM\n"
            "    clang -fsanitize=fuzzer,address target.c -o fuzz_target\n"
            "  Honggfuzz: Hardware-based coverage\n"
            "    honggfuzz -i corpus/ -- ./target ___FILE___\n"
            "HARNESS WRITING:\n"
            "  - Identify parsing functions (file, network, API)\n"
            "  - Write minimal harness calling target function\n"
            "  - Enable sanitizers: ASan, MSan, UBSan\n"
            "  - Use persistent mode for speed (10-100x)\n"
            "CORPUS CREATION:\n"
            "  - Collect real-world inputs (from tests, examples)\n"
            "  - Minimize corpus: afl-cmin\n"
            "  - Trim testcases: afl-tmin\n"
            "  - Use dictionary: afl-fuzz -x dict.txt\n"
            "TRIAGE:\n"
            "  - Deduplicate crashes: afl-collect\n"
            "  - Analyze with ASan report\n"
            "  - Minimize crash case: afl-tmin\n"
            "  - Determine exploitability: !exploitable, crashwalk"
        ),
        "tools": ["afl++", "libfuzzer", "honggfuzz"],
    },
    {
        "id": "zd-002", "name": "Protocol Fuzzing",
        "category": "fuzzing", "difficulty": "hard",
        "desc": "Fuzzing network protocols for server-side bugs.",
        "methodology": (
            "PROTOCOL FUZZING:\n"
            "APPROACH:\n"
            "  1. Capture legitimate protocol traffic\n"
            "  2. Model protocol grammar (or use existing)\n"
            "  3. Generate mutated protocol messages\n"
            "  4. Send to target server, monitor for crashes/hangs\n"
            "  5. Triage and analyze server-side crashes\n"
            "TOOLS:\n"
            "  Boofuzz: Python-based protocol fuzzer\n"
            "    - Define protocol blocks and primitives\n"
            "    - Automatic session management\n"
            "    - Crash detection via process monitoring\n"
            "  Peach: State-of-the-art protocol fuzzer\n"
            "    - XML-based protocol modeling\n"
            "    - State machine aware\n"
            "  AFL-Net: Coverage-guided network protocol fuzzer\n"
            "    - Extends AFL for stateful network protocols\n"
            "    - Sequence-aware mutation\n"
            "TARGET PROTOCOLS:\n"
            "  - HTTP/2, gRPC, WebSocket\n"
            "  - DNS, DHCP, NTP\n"
            "  - TLS/SSL handshake\n"
            "  - MQTT, CoAP, AMQP\n"
            "  - Custom proprietary protocols\n"
            "MONITORING:\n"
            "  - Attach debugger to server process\n"
            "  - Enable ASan for compiled servers\n"
            "  - Monitor logs for error messages\n"
            "  - Check for memory leaks (Valgrind)"
        ),
        "tools": ["boofuzz", "peach", "aflnet"],
    },
    {
        "id": "zd-003", "name": "Variant Analysis",
        "category": "analysis", "difficulty": "medium",
        "desc": "Finding variants of known vulnerabilities.",
        "methodology": (
            "VARIANT ANALYSIS:\n"
            "METHODOLOGY:\n"
            "  1. Study a known CVE in detail\n"
            "  2. Understand the root cause (CWE class)\n"
            "  3. Search for similar patterns in same codebase\n"
            "  4. Search in related/forked projects\n"
            "  5. Check if fix was complete or partial\n"
            "TECHNIQUES:\n"
            "  Code Pattern Search:\n"
            "    - Identify vulnerable code pattern\n"
            "    - Use Semgrep/CodeQL to find similar patterns\n"
            "    - Example: If CVE was in XML parsing, search all XML parsers\n"
            "  Patch Gap Analysis:\n"
            "    - Review the security patch\n"
            "    - Check if all instances were fixed\n"
            "    - Test edge cases not covered by fix\n"
            "  Cross-Project Search:\n"
            "    - Identify code that was copied/forked\n"
            "    - Check if downstream projects applied the fix\n"
            "    - Use grep.app, searchcode.com\n"
            "TOOLS:\n"
            "  - Semgrep: Custom rule for vulnerable pattern\n"
            "  - CodeQL: GitHub code scanning queries\n"
            "  - Joern: Code property graph analysis\n"
            "  - grep/ripgrep: Manual pattern search\n"
            "1-DAY TO 0-DAY:\n"
            "  - Study recent CVE patches\n"
            "  - Check if fix addresses root cause vs symptom\n"
            "  - Test bypasses for the specific fix\n"
            "  - Look for same pattern in different code paths"
        ),
        "tools": ["semgrep", "codeql", "joern"],
    },
    {
        "id": "zd-004", "name": "Logic Bug Discovery",
        "category": "logic", "difficulty": "hard",
        "desc": "Finding logic errors in application behavior.",
        "methodology": (
            "LOGIC BUG DISCOVERY:\n"
            "WEB APPLICATION LOGIC:\n"
            "  State Machine Analysis:\n"
            "    - Map all application states and transitions\n"
            "    - Identify impossible state transitions\n"
            "    - Test direct access to states (skip steps)\n"
            "    - Test concurrent state changes (race conditions)\n"
            "  Boundary Value Analysis:\n"
            "    - Test MIN/MAX/zero/negative for all numeric inputs\n"
            "    - Test empty string, null, undefined\n"
            "    - Test overflow: INT_MAX+1, very long strings\n"
            "    - Test type confusion: string where int expected\n"
            "  Business Logic:\n"
            "    - Understand expected business rules\n"
            "    - Test violation of each rule\n"
            "    - Test ordering assumptions\n"
            "    - Test concurrency assumptions\n"
            "RACE CONDITIONS:\n"
            "  - TOCTOU (Time of Check, Time of Use)\n"
            "  - Double-spend in financial operations\n"
            "  - Concurrent session manipulation\n"
            "  - Detection: Send N parallel identical requests\n"
            "  - Tools: Burp Turbo Intruder, race-the-web\n"
            "TYPE CONFUSION:\n"
            "  - PHP: strcmp(array, string) returns 0\n"
            "  - JavaScript: [] == false, '' == 0\n"
            "  - Python: isinstance() bypass with metaclasses"
        ),
        "tools": ["burp", "ffuf", "turbo-intruder"],
    },
    {
        "id": "zd-005", "name": "Differential Testing",
        "category": "testing", "difficulty": "medium",
        "desc": "Comparing implementations to find discrepancies.",
        "methodology": (
            "DIFFERENTIAL TESTING:\n"
            "CONCEPT:\n"
            "  - Same input to different implementations\n"
            "  - Differences indicate potential bugs\n"
            "  - Especially effective for parsers and protocols\n"
            "APPLICATIONS:\n"
            "  Parser Differential:\n"
            "    - Test same URL across URL parsers\n"
            "    - Python, Go, Java, JavaScript URL parsing\n"
            "    - Differences → SSRF bypass, access control bypass\n"
            "  HTTP Differential:\n"
            "    - Same request to different HTTP servers\n"
            "    - Apache vs Nginx vs Caddy vs IIS\n"
            "    - Header parsing differences → smuggling\n"
            "  JSON Differential:\n"
            "    - Duplicate keys: {\"a\":1, \"a\":2}\n"
            "    - Different parsers pick different values\n"
            "    - Leads to authorization bypass\n"
            "  TLS Differential:\n"
            "    - Different TLS implementations\n"
            "    - Certificate validation differences\n"
            "    - Cipher suite negotiation discrepancies\n"
            "METHODOLOGY:\n"
            "  1. Identify components that parse same format\n"
            "  2. Generate diverse test inputs (edge cases)\n"
            "  3. Compare outputs across implementations\n"
            "  4. Investigate all differences\n"
            "  5. Determine if difference is exploitable"
        ),
        "tools": ["curl", "python", "ffuf"],
    },
]


class ZeroDayKB:
    """Zero-day discovery strategy knowledge base.

    Provides 0-day hunting methodologies
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._strategies: dict[str, ZeroDayStrategy] = {}
        self._log = logger.bind(component="zero_day_kb")
        self._load_strategies()

    def _load_strategies(self) -> None:
        """Load zero-day strategies."""
        for data in ZERODAY_STRATEGIES:
            strategy = ZeroDayStrategy(
                strategy_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                difficulty=data.get("difficulty", "hard"),
                description=data.get("desc", ""),
                methodology=data.get("methodology", ""),
                tools=data.get("tools", []),
            )
            self._strategies[strategy.strategy_id] = strategy

    def get_by_category(self, category: str) -> list[ZeroDayStrategy]:
        """Get strategies by category."""
        return [
            s for s in self._strategies.values()
            if s.category.lower() == category.lower()
        ]

    def build_zeroday_prompt(
        self,
        categories: list[str] | None = None,
        max_strategies: int = 3,
    ) -> str:
        """Build zero-day hunting prompt."""
        lines = ["## Zero-Day Discovery Strategies\n"]
        count = 0
        for strategy in self._strategies.values():
            if categories and strategy.category.lower() not in [c.lower() for c in categories]:
                continue
            if count >= max_strategies:
                break
            lines.append(f"### {strategy.name} [{strategy.difficulty.upper()}]")
            lines.append(strategy.methodology)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = {}
        for s in self._strategies.values():
            cat_counts[s.category] = cat_counts.get(s.category, 0) + 1
        return {
            "strategies": len(self._strategies),
            "by_category": cat_counts,
        }
