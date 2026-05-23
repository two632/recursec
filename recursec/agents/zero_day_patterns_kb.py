"""Zero-day vulnerability patterns knowledge base.

Deep knowledge about discovering novel vulnerabilities:
1. Fuzzing strategies for unknown bugs
2. Variant analysis from known CVEs
3. Logic bug hunting patterns
4. Memory corruption discovery
5. Novel attack surface identification
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


ZERO_DAY_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "zd-001", "name": "Coverage-Guided Fuzzing",
        "category": "fuzzing", "severity": "critical",
        "desc": "Using coverage-guided fuzzers to find crashes.",
        "detection": (
            "COVERAGE-GUIDED FUZZING:\n"
            "AFL++ WORKFLOW:\n"
            "  1. Compile with instrumentation:\n"
            "     afl-clang-fast -o target target.c\n"
            "  2. Prepare seed corpus (valid inputs)\n"
            "  3. Run fuzzer:\n"
            "     afl-fuzz -i seeds/ -o findings/ -- ./target @@\n"
            "  4. Monitor for crashes and hangs\n"
            "STRATEGIES:\n"
            "  CMPLOG mode:\n"
            "    - Compile separate CMPLOG binary\n"
            "    - afl-fuzz -c ./target_cmplog -i seeds/ -o out/ -- ./target @@\n"
            "    - Solves magic byte comparisons automatically\n"
            "  Dictionary mode:\n"
            "    - Provide protocol-specific tokens\n"
            "    - afl-fuzz -x dict.txt -i seeds/ -o out/ -- ./target @@\n"
            "  Persistent mode:\n"
            "    - Use __AFL_FUZZ_INIT() for in-process fuzzing\n"
            "    - 10-100x faster than fork mode\n"
            "  Power schedules:\n"
            "    - -p explore: Good for new targets\n"
            "    - -p fast: Once initial coverage is found\n"
            "    - -p rare: Focus on rare edges\n"
            "CORPUS MINIMIZATION:\n"
            "  afl-cmin -i corpus/ -o minimized/ -- ./target @@\n"
            "  afl-tmin -i crash.txt -o min.txt -- ./target @@"
        ),
        "tools": ["afl++", "honggfuzz", "libfuzzer"],
    },
    {
        "id": "zd-002", "name": "CVE Variant Analysis",
        "category": "variant", "severity": "critical",
        "desc": "Finding variants of known vulnerabilities.",
        "detection": (
            "CVE VARIANT ANALYSIS:\n"
            "METHODOLOGY:\n"
            "  1. Study the original CVE:\n"
            "     - Root cause analysis\n"
            "     - Patch diff analysis (what was changed?)\n"
            "     - Affected code path\n"
            "  2. Identify variant patterns:\n"
            "     - Same bug class in different functions\n"
            "     - Incomplete patch (not all code paths fixed)\n"
            "     - Same pattern in related projects/forks\n"
            "     - Same pattern in different protocol handlers\n"
            "  3. Automated search:\n"
            "     - CodeQL: Write query matching the bug pattern\n"
            "     - Semgrep: Pattern-based source code search\n"
            "     - Binary diffing: Compare patched vs unpatched\n"
            "TOOLS:\n"
            "  CodeQL:\n"
            "    - codeql database create <db> --language=<lang>\n"
            "    - codeql query run <query.ql> --database=<db>\n"
            "    - Write custom queries for bug class\n"
            "  Binary Diff:\n"
            "    - BinDiff: Diff patched vs unpatched binaries\n"
            "    - Diaphora: IDA Pro plugin for binary diffing\n"
            "    - Identify patch location → find similar patterns\n"
            "COMMON VARIANT PATTERNS:\n"
            "  - Integer overflow in size calculation (one fixed, others not)\n"
            "  - Buffer overflow in parser (same pattern, different message type)\n"
            "  - Use-after-free (same object lifecycle issue, different trigger)"
        ),
        "tools": ["codeql", "semgrep", "bindiff"],
    },
    {
        "id": "zd-003", "name": "Logic Bug Hunting",
        "category": "logic", "severity": "critical",
        "desc": "Finding logic and state management bugs.",
        "detection": (
            "LOGIC BUG HUNTING:\n"
            "AUTHENTICATION/AUTHORIZATION:\n"
            "  - Test every endpoint with no auth → access granted?\n"
            "  - Test with lower privilege → escalation?\n"
            "  - Test state transitions out of order\n"
            "  - Race conditions in multi-step auth\n"
            "STATE MANAGEMENT:\n"
            "  - Initialize → partially setup → access\n"
            "  - Concurrent operations on shared state\n"
            "  - Unexpected state combinations\n"
            "  - Resource exhaustion leading to error state\n"
            "  - Recovery from error → stale state persists\n"
            "TYPE CONFUSION:\n"
            "  - Send integer where string expected\n"
            "  - Send array where object expected\n"
            "  - Send null where value expected\n"
            "  - Send very large values (2^31-1, 2^63-1)\n"
            "  - Send negative values where positive expected\n"
            "IMPLICIT ASSUMPTIONS:\n"
            "  - Assumes input is UTF-8 → send other encodings\n"
            "  - Assumes single-line input → send multiline\n"
            "  - Assumes small input → send very large\n"
            "  - Assumes ordered operations → send out-of-order\n"
            "  - Assumes unique identifiers → send duplicates"
        ),
        "tools": ["burp", "custom-scripts"],
    },
    {
        "id": "zd-004", "name": "Protocol-Level Fuzzing",
        "category": "protocol_fuzz", "severity": "critical",
        "desc": "Fuzzing network protocols for implementation bugs.",
        "detection": (
            "PROTOCOL FUZZING:\n"
            "NETWORK PROTOCOL:\n"
            "  boofuzz:\n"
            "    - Define protocol grammar\n"
            "    - Mutate fields systematically\n"
            "    - Monitor target for crashes/anomalies\n"
            "  AFLNet:\n"
            "    - Coverage-guided network fuzzing\n"
            "    - aflnet -N <host> <port> -P <protocol> -i seeds/\n"
            "    - Supports: HTTP, FTP, SMTP, RTSP, etc.\n"
            "HTTP/2 AND HTTP/3:\n"
            "  - h2c smuggling (cleartext HTTP/2 upgrade)\n"
            "  - Stream multiplexing abuse\n"
            "  - HPACK compression bombs\n"
            "  - Priority tree manipulation\n"
            "  - RST_STREAM floods\n"
            "TLS:\n"
            "  - tlsfuzzer: TLS handshake fuzzing\n"
            "  - Malformed certificates\n"
            "  - Version downgrade attempts\n"
            "  - Renegotiation attacks\n"
            "DNS:\n"
            "  - Malformed DNS responses\n"
            "  - DNS rebinding\n"
            "  - Subdomain takeover\n"
            "  - Zone transfer attempts\n"
            "BLUETOOTH/BLE:\n"
            "  - BLE advertising data fuzzing\n"
            "  - GATT profile fuzzing\n"
            "  - Pairing protocol fuzzing"
        ),
        "tools": ["boofuzz", "aflnet", "tlsfuzzer"],
    },
    {
        "id": "zd-005", "name": "Novel Attack Surface Discovery",
        "category": "attack_surface", "severity": "high",
        "desc": "Identifying new and unusual attack surfaces.",
        "detection": (
            "NOVEL ATTACK SURFACE DISCOVERY:\n"
            "HIDDEN INTERFACES:\n"
            "  - Debug endpoints left in production\n"
            "  - Admin interfaces on non-standard ports\n"
            "  - gRPC/Protobuf endpoints (not visible in browser)\n"
            "  - GraphQL introspection enabled\n"
            "  - WebSocket endpoints\n"
            "  - Server-Sent Events (SSE) streams\n"
            "SUPPLY CHAIN ENTRY POINTS:\n"
            "  - Third-party JS loaded from CDN\n"
            "  - Shared infrastructure (multi-tenant)\n"
            "  - CI/CD pipeline access\n"
            "  - Package manager registries\n"
            "  - Container base images\n"
            "CLOUD-NATIVE ATTACK SURFACE:\n"
            "  - Metadata endpoints (169.254.169.254)\n"
            "  - Service mesh sidecar proxies\n"
            "  - Serverless function triggers\n"
            "  - Message queue interfaces\n"
            "  - Object storage buckets\n"
            "AI/ML ATTACK SURFACE:\n"
            "  - Model inference endpoints\n"
            "  - Prompt injection\n"
            "  - Training data poisoning\n"
            "  - Model extraction via repeated queries\n"
            "  - Adversarial inputs\n"
            "EMBEDDED SYSTEMS:\n"
            "  - Debug headers in firmware\n"
            "  - Unprotected update mechanisms\n"
            "  - Default factory credentials"
        ),
        "tools": ["nmap", "nuclei", "ffuf"],
    },
]


class ZeroDayPatternsKB:
    """Zero-day pattern knowledge base.

    Provides zero-day discovery patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, ZeroDayPattern] = {}
        self._log = logger.bind(component="zero_day_patterns_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load zero-day patterns."""
        for data in ZERO_DAY_PATTERNS:
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

    def build_zero_day_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build zero-day discovery prompt."""
        lines = ["## Zero-Day Discovery Patterns\n"]
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
