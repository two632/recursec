"""Pattern matcher — matches findings against known vulnerability patterns.

Implements:
1. Vulnerability signature database
2. Pattern matching against findings
3. False positive pattern detection
4. Attack pattern recognition
5. Technology-specific vulnerability patterns
6. OWASP Top 10 pattern matching
7. CWE pattern database
8. Custom pattern definition
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class VulnPattern:
    """A vulnerability pattern definition."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""               # owasp, cwe, technology, custom
    severity: str = "medium"
    indicators: list[str] = field(default_factory=list)    # Keywords/phrases
    regex_patterns: list[str] = field(default_factory=list)  # Regex patterns
    false_positive_indicators: list[str] = field(default_factory=list)
    cwe: str = ""
    owasp: str = ""
    remediation: str = ""
    confidence_base: float = 0.7

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id, "name": self.name[:60],
            "category": self.category, "severity": self.severity,
            "cwe": self.cwe, "owasp": self.owasp,
        }


@dataclass
class PatternMatch:
    """A pattern match result."""
    pattern: VulnPattern = field(default_factory=VulnPattern)
    matched_text: str = ""
    confidence: float = 0.7
    is_false_positive: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern.name[:60],
            "confidence": round(self.confidence, 2),
            "false_positive": self.is_false_positive,
            "severity": self.pattern.severity,
        }


# ── OWASP Top 10 Patterns ────────────────────────────────────

OWASP_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "owasp-a01", "name": "Broken Access Control",
        "category": "owasp", "severity": "high",
        "indicators": ["idor", "insecure direct object", "privilege escalation",
                        "missing access control", "cors misconfiguration",
                        "forced browsing", "directory traversal", "path traversal"],
        "cwe": "CWE-284", "owasp": "A01:2021",
        "remediation": "Implement proper access controls, deny by default",
    },
    {
        "id": "owasp-a02", "name": "Cryptographic Failures",
        "category": "owasp", "severity": "high",
        "indicators": ["weak cipher", "ssl", "tls 1.0", "md5", "sha1",
                        "clear text", "plaintext", "weak encryption",
                        "missing encryption", "http instead of https"],
        "cwe": "CWE-327", "owasp": "A02:2021",
        "remediation": "Use strong cryptographic algorithms, enforce TLS 1.2+",
    },
    {
        "id": "owasp-a03", "name": "Injection",
        "category": "owasp", "severity": "critical",
        "indicators": ["sql injection", "sqli", "xss", "cross-site scripting",
                        "command injection", "ldap injection", "xpath injection",
                        "template injection", "ssti", "nosql injection"],
        "regex_patterns": [r"(?:sql|command|ldap|xpath)\s*injection"],
        "cwe": "CWE-79", "owasp": "A03:2021",
        "remediation": "Use parameterized queries, input validation, output encoding",
    },
    {
        "id": "owasp-a04", "name": "Insecure Design",
        "category": "owasp", "severity": "medium",
        "indicators": ["missing rate limit", "no brute force protection",
                        "predictable tokens", "information disclosure",
                        "insecure design", "business logic flaw"],
        "cwe": "CWE-284", "owasp": "A04:2021",
        "remediation": "Implement threat modeling, secure design patterns",
    },
    {
        "id": "owasp-a05", "name": "Security Misconfiguration",
        "category": "owasp", "severity": "medium",
        "indicators": ["misconfiguration", "default credential", "debug mode",
                        "verbose error", "directory listing", "unnecessary features",
                        "default page", "exposed admin", "cors wildcard"],
        "cwe": "CWE-16", "owasp": "A05:2021",
        "remediation": "Harden configurations, remove defaults, disable debug",
    },
    {
        "id": "owasp-a06", "name": "Vulnerable Components",
        "category": "owasp", "severity": "high",
        "indicators": ["outdated", "vulnerable version", "known vulnerability",
                        "cve-", "end of life", "deprecated", "unpatched"],
        "regex_patterns": [r"CVE-\d{4}-\d+"],
        "cwe": "CWE-1035", "owasp": "A06:2021",
        "remediation": "Keep components updated, monitor CVEs, use SCA tools",
    },
    {
        "id": "owasp-a07", "name": "Authentication Failures",
        "category": "owasp", "severity": "high",
        "indicators": ["weak password", "default password", "brute force",
                        "credential stuffing", "session fixation", "missing mfa",
                        "jwt", "broken authentication"],
        "cwe": "CWE-287", "owasp": "A07:2021",
        "remediation": "Implement MFA, strong password policies, rate limiting",
    },
    {
        "id": "owasp-a08", "name": "Software and Data Integrity Failures",
        "category": "owasp", "severity": "high",
        "indicators": ["deserialization", "unsigned", "unverified update",
                        "ci/cd vulnerability", "supply chain", "unsigned code"],
        "cwe": "CWE-502", "owasp": "A08:2021",
        "remediation": "Verify integrity, use digital signatures, secure CI/CD",
    },
    {
        "id": "owasp-a09", "name": "Security Logging Failures",
        "category": "owasp", "severity": "low",
        "indicators": ["missing logs", "no monitoring", "insufficient logging",
                        "no alerting", "log injection"],
        "cwe": "CWE-778", "owasp": "A09:2021",
        "remediation": "Implement centralized logging, alerting, and monitoring",
    },
    {
        "id": "owasp-a10", "name": "SSRF",
        "category": "owasp", "severity": "high",
        "indicators": ["ssrf", "server-side request forgery", "internal service",
                        "metadata endpoint", "cloud metadata"],
        "cwe": "CWE-918", "owasp": "A10:2021",
        "remediation": "Validate URLs, block internal ranges, use allowlists",
    },
]

# ── False Positive Patterns ───────────────────────────────────

FALSE_POSITIVE_INDICATORS: list[dict[str, Any]] = [
    {
        "name": "WAF Reflection",
        "indicators": ["waf", "firewall", "blocked", "403 forbidden", "access denied"],
    },
    {
        "name": "CDN Response",
        "indicators": ["cloudflare", "akamai", "fastly", "cdn", "cache"],
    },
    {
        "name": "Rate Limiting",
        "indicators": ["rate limit", "too many requests", "429", "throttle"],
    },
    {
        "name": "Honeypot",
        "indicators": ["honeypot", "tarpit", "decoy"],
    },
]


class PatternMatcher:
    """Matches findings against known vulnerability patterns.

    Uses OWASP Top 10, CWE database, and custom
    patterns to classify and validate findings.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, VulnPattern] = {}
        self._match_count = 0
        self._fp_count = 0
        self._log = logger.bind(component="pattern_matcher")

        self._init_patterns()

    def _init_patterns(self) -> None:
        """Initialize pattern database."""
        for data in OWASP_PATTERNS:
            pattern = VulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", "owasp"),
                severity=data.get("severity", "medium"),
                indicators=data.get("indicators", []),
                regex_patterns=data.get("regex_patterns", []),
                cwe=data.get("cwe", ""),
                owasp=data.get("owasp", ""),
                remediation=data.get("remediation", ""),
            )
            self._patterns[data["id"]] = pattern

    def match(
        self,
        text: str,
        severity: str = "",
    ) -> list[PatternMatch]:
        """Match text against vulnerability patterns."""
        matches = []
        text_lower = text.lower()

        for pattern in self._patterns.values():
            match_score = 0.0
            total_indicators = len(pattern.indicators) + len(pattern.regex_patterns)

            if total_indicators == 0:
                continue

            # Keyword matching
            keyword_hits = sum(1 for ind in pattern.indicators if ind in text_lower)
            match_score += keyword_hits / max(1, len(pattern.indicators)) * 0.7

            # Regex matching
            for regex in pattern.regex_patterns:
                try:
                    if re.search(regex, text_lower):
                        match_score += 0.3 / max(1, len(pattern.regex_patterns))
                except re.error:
                    pass

            if match_score >= 0.15:
                confidence = min(0.95, pattern.confidence_base * match_score * 2)

                # Check for false positive indicators
                is_fp = self._check_false_positive(text_lower)

                if is_fp:
                    confidence *= 0.3
                    self._fp_count += 1

                self._match_count += 1
                matches.append(PatternMatch(
                    pattern=pattern,
                    matched_text=text[:100],
                    confidence=confidence,
                    is_false_positive=is_fp,
                ))

        matches.sort(key=lambda m: m.confidence, reverse=True)
        return matches

    def classify_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Classify a finding using pattern matching."""
        text = (
            finding.get("title", "") + " " +
            finding.get("description", "") + " " +
            finding.get("evidence", "")
        )

        matches = self.match(text, finding.get("severity", ""))

        if not matches:
            return {"classification": "unknown", "patterns": []}

        best = matches[0]
        return {
            "classification": best.pattern.name,
            "owasp": best.pattern.owasp,
            "cwe": best.pattern.cwe,
            "confidence": round(best.confidence, 2),
            "remediation": best.pattern.remediation[:200],
            "false_positive": best.is_false_positive,
            "patterns": [m.to_dict() for m in matches[:3]],
        }

    def _check_false_positive(self, text: str) -> bool:
        """Check if text indicates a false positive."""
        for fp_pattern in FALSE_POSITIVE_INDICATORS:
            hits = sum(1 for ind in fp_pattern["indicators"] if ind in text)
            if hits >= 2:
                return True
        return False

    def add_pattern(self, pattern: VulnPattern) -> None:
        self._patterns[pattern.pattern_id] = pattern

    def get_stats(self) -> dict[str, Any]:
        return {
            "patterns": len(self._patterns),
            "matches": self._match_count,
            "false_positives": self._fp_count,
        }
