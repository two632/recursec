"""Timing attack knowledge base.

Deep knowledge about timing-based vulnerabilities:
1. Time-based blind injection
2. Side-channel timing attacks
3. Race condition exploitation
4. Time-of-check-time-of-use (TOCTOU)
5. Timing oracle attacks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class TimingPattern:
    """A timing attack pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:15],
        }


TIMING_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "time-001", "name": "Time-Based Blind SQL Injection",
        "category": "injection", "severity": "critical",
        "desc": "SQL injection using time delays for data extraction.",
        "detection": (
            "TIME-BASED BLIND SQL INJECTION:\n"
            "PRINCIPLE:\n"
            "  - Application doesn't show SQL errors or result differences\n"
            "  - Use time delay functions to infer TRUE/FALSE\n"
            "  - Extract data one bit/character at a time\n"
            "PAYLOADS BY DATABASE:\n"
            "  MySQL: SLEEP(5), BENCHMARK(5000000, SHA1('test'))\n"
            "    ' OR SLEEP(5)-- -\n"
            "    ' OR IF(1=1, SLEEP(5), 0)-- -\n"
            "    ' OR IF(SUBSTRING(database(),1,1)='a', SLEEP(5), 0)-- -\n"
            "  PostgreSQL: pg_sleep(5)\n"
            "    '; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -\n"
            "  MSSQL: WAITFOR DELAY '0:0:5'\n"
            "    '; IF (1=1) WAITFOR DELAY '0:0:5'-- -\n"
            "  Oracle: DBMS_PIPE.RECEIVE_MESSAGE('a',5)\n"
            "  SQLite: randomblob(100000000)\n"
            "AUTOMATION:\n"
            "  sqlmap --technique=T --time-sec=5 --level=5 --risk=3\n"
            "  sqlmap --technique=T --string= --not-string= --dbms=mysql\n"
            "DETECTION TIPS:\n"
            "  - Baseline normal response time (5+ requests)\n"
            "  - Test delay of 5s, 10s to confirm controllability\n"
            "  - Use conditional delays: IF(condition, SLEEP(5), 0)\n"
            "  - Account for network jitter (use large delays)\n"
            "  - Binary search for character extraction efficiency"
        ),
        "tools": ["sqlmap", "ghauri"],
    },
    {
        "id": "time-002", "name": "Race Condition Exploitation",
        "category": "race", "severity": "high",
        "desc": "Exploiting time-of-check-time-of-use gaps.",
        "detection": (
            "RACE CONDITION ATTACKS:\n"
            "TOCTOU (Time-of-Check-Time-of-Use):\n"
            "  - Application checks condition, then acts on it\n"
            "  - Attacker changes state between check and use\n"
            "  - Common in: balance checks, coupon redemption, voting\n"
            "COMMON TARGETS:\n"
            "  1. Double-spend: Send 2 simultaneous transfer requests\n"
            "  2. Coupon reuse: Redeem same coupon in parallel\n"
            "  3. Rate limit bypass: Parallel requests before counter updates\n"
            "  4. File upload race: Upload file, access before validation\n"
            "  5. Privilege escalation: Change role during permission check\n"
            "EXPLOITATION TECHNIQUES:\n"
            "  - HTTP/2 single-packet attack (all requests in one TCP packet)\n"
            "  - Last-byte sync: Send all but last byte, then release simultaneously\n"
            "  - Thread pool: 20-50 parallel connections\n"
            "  - Turbo Intruder (Burp extension) for precise timing\n"
            "TOOLS:\n"
            "  - Burp Suite Turbo Intruder\n"
            "  - Python asyncio/aiohttp with semaphore\n"
            "  - curl with --parallel and --parallel-max\n"
            "DETECTION:\n"
            "  - Look for operations that should be atomic but aren't\n"
            "  - Check for missing database transactions/locks\n"
            "  - Test financial operations with concurrent requests\n"
            "  - Check session creation/deletion races"
        ),
        "tools": ["ffuf", "curl"],
    },
    {
        "id": "time-003", "name": "Timing Side-Channel Attacks",
        "category": "side_channel", "severity": "high",
        "desc": "Extracting information from response time differences.",
        "detection": (
            "TIMING SIDE-CHANNEL ATTACKS:\n"
            "USERNAME ENUMERATION:\n"
            "  - Login with valid username (slow: password check) vs invalid (fast: immediate fail)\n"
            "  - Measure response time difference (even 10-50ms can be significant)\n"
            "  - Statistical analysis: send 100+ requests per candidate\n"
            "  - Calculate mean and standard deviation per username\n"
            "PASSWORD/TOKEN COMPARISON:\n"
            "  - Byte-by-byte comparison leaks through timing\n"
            "  - Correct prefix bytes take slightly longer\n"
            "  - Requires many measurements and statistical analysis\n"
            "  - Tools: timing-attack-tools, timing-attack npm package\n"
            "CRYPTOGRAPHIC TIMING:\n"
            "  - RSA: Timing differences in modular exponentiation\n"
            "  - AES: Cache-timing attacks\n"
            "  - HMAC: Non-constant-time comparison\n"
            "  - Detection: Send same request 1000+ times, measure distribution\n"
            "API KEY VALIDATION:\n"
            "  - Character-by-character comparison leaks\n"
            "  - Detect via response time increase as correct prefix grows\n"
            "  - Mitigation: constant-time comparison (hmac.compare_digest)\n"
            "TESTING METHODOLOGY:\n"
            "  1. Establish baseline response time (100+ requests)\n"
            "  2. Test with known-valid vs known-invalid inputs\n"
            "  3. Use t-test or Mann-Whitney U test for significance\n"
            "  4. p-value < 0.05 indicates timing leak"
        ),
        "tools": ["curl", "python"],
    },
    {
        "id": "time-004", "name": "Time-Based Blind XPath/LDAP Injection",
        "category": "injection", "severity": "high",
        "desc": "Time-based extraction via XPath and LDAP injection.",
        "detection": (
            "TIME-BASED BLIND XPATH/LDAP INJECTION:\n"
            "XPATH INJECTION:\n"
            "  - Use concat() with large string operations for delay\n"
            "  - ' or count(//*)>1000 and '1'='1\n"
            "  - Extract data via substring() with time oracle\n"
            "  - Test: ' or string-length(name(/*[1]))>1 or '1'='1\n"
            "LDAP INJECTION:\n"
            "  - )(cn=*) — wildcard matching causes delay on large directories\n"
            "  - Use complex filters for timing oracle\n"
            "  - )(|(cn=admin)(cn=root)) — multi-match delays\n"
            "BLIND NOSQL INJECTION:\n"
            "  - MongoDB: {\"$where\": \"sleep(5000)\"}\n"
            "  - MongoDB: {\"$regex\": \"^a.*\"} with long strings\n"
            "  - Redis: EVAL with sleep-like Lua scripts\n"
            "DETECTION APPROACH:\n"
            "  1. Identify potential injection points\n"
            "  2. Test with benign delay payload\n"
            "  3. Confirm with longer/shorter delays\n"
            "  4. Automate extraction if confirmed"
        ),
        "tools": ["sqlmap", "ffuf", "curl"],
    },
    {
        "id": "time-005", "name": "HTTP Request Smuggling Timing",
        "category": "protocol", "severity": "critical",
        "desc": "Timing-based HTTP request smuggling detection.",
        "detection": (
            "HTTP REQUEST SMUGGLING TIMING:\n"
            "CL.TE DETECTION:\n"
            "  - Send request with Content-Length and Transfer-Encoding\n"
            "  - If CL.TE: front-end uses CL, back-end uses TE\n"
            "  - Timing: send incomplete chunked body, back-end waits → timeout difference\n"
            "  - Test: Content-Length: 4, Transfer-Encoding: chunked, body: '0\\r\\n\\r\\n'\n"
            "TE.CL DETECTION:\n"
            "  - Front-end uses TE, back-end uses CL\n"
            "  - Send body longer than Content-Length\n"
            "  - Back-end processes extra bytes as next request\n"
            "  - Timing: immediate response (front-end) vs delayed (back-end waits)\n"
            "TE.TE DETECTION:\n"
            "  - Both use TE but one can be confused with obfuscation\n"
            "  - Transfer-Encoding: chunked vs Transfer-Encoding: xchunked\n"
            "EXPLOITATION:\n"
            "  - Bypass access controls: smuggle request to restricted endpoint\n"
            "  - Cache poisoning: poison cache with smuggled response\n"
            "  - Credential hijacking: capture other users' requests\n"
            "TOOLS:\n"
            "  - smuggler.py (defparam)\n"
            "  - Burp Suite HTTP Request Smuggler extension\n"
            "  - h2csmuggler for HTTP/2 downgrade attacks"
        ),
        "tools": ["curl", "nuclei"],
    },
]


class TimingAttackKB:
    """Timing attack knowledge base.

    Provides timing-based attack patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, TimingPattern] = {}
        self._log = logger.bind(component="timing_attack_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load timing attack patterns."""
        for data in TIMING_PATTERNS:
            pattern = TimingPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[TimingPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_timing_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build timing attack prompt."""
        lines = ["## Timing Attack Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category.lower() not in [c.lower() for c in categories]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
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
