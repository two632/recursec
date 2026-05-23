"""Vulnerability pattern library — pattern-based vulnerability detection.

Encodes deep security knowledge as reusable patterns:
1. Known vulnerability signatures (CWE-based)
2. Technology-specific patterns (WordPress, Apache, etc.)
3. Protocol-level patterns (HTTP, DNS, TLS, etc.)
4. Code patterns (injection, auth bypass, etc.)
5. Configuration patterns (misconfig, defaults, etc.)
6. Behavioral patterns (timing attacks, race conditions)

Each pattern includes:
- Detection logic (what to look for)
- Validation method (how to confirm)
- Exploitation guidance (how to test)
- Remediation advice (how to fix)
- False positive indicators (common FP triggers)

Patterns are organized hierarchically:
Category → Subcategory → Pattern → Variant
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PatternCategory(str, Enum):
    WEB_APPLICATION = "web_application"
    NETWORK = "network"
    CODE = "code"
    CONFIGURATION = "configuration"
    AUTHENTICATION = "authentication"
    CRYPTOGRAPHY = "cryptography"
    INJECTION = "injection"
    INFORMATION_DISCLOSURE = "information_disclosure"
    ACCESS_CONTROL = "access_control"
    DESERIALIZATION = "deserialization"


class PatternConfidence(str, Enum):
    DEFINITE = "definite"    # No false positives
    HIGH = "high"            # Rare false positives
    MEDIUM = "medium"        # Needs validation
    LOW = "low"              # Many false positives expected
    HEURISTIC = "heuristic"  # Educated guess


@dataclass
class VulnPattern:
    """A reusable vulnerability detection pattern."""
    pattern_id: str = ""
    name: str = ""
    description: str = ""
    category: PatternCategory = PatternCategory.WEB_APPLICATION
    subcategory: str = ""
    cwe_id: str = ""
    severity: str = "medium"
    confidence: PatternConfidence = PatternConfidence.MEDIUM

    # Detection
    regex_patterns: list[str] = field(default_factory=list)
    keyword_indicators: list[str] = field(default_factory=list)
    header_patterns: dict[str, str] = field(default_factory=dict)
    behavioral_checks: list[str] = field(default_factory=list)

    # Validation
    validation_steps: list[str] = field(default_factory=list)
    validation_payloads: list[str] = field(default_factory=list)

    # Context
    technologies: list[str] = field(default_factory=list)
    environments: list[str] = field(default_factory=list)

    # Response
    exploitation_notes: str = ""
    remediation: str = ""
    false_positive_indicators: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def matches_text(self, text: str) -> list[str]:
        """Check if text matches this pattern's detection rules."""
        matches = []
        text_lower = text.lower()

        # Keyword matching
        for keyword in self.keyword_indicators:
            if keyword.lower() in text_lower:
                matches.append(f"keyword:{keyword}")

        # Regex matching
        for pattern in self.regex_patterns:
            try:
                if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                    matches.append(f"regex:{pattern[:50]}")
            except re.error:
                continue

        return matches

    def matches_headers(self, headers: dict[str, str]) -> list[str]:
        """Check if HTTP headers match this pattern."""
        matches = []
        for header_name, expected_pattern in self.header_patterns.items():
            for name, value in headers.items():
                if name.lower() == header_name.lower():
                    try:
                        if re.search(expected_pattern, value, re.IGNORECASE):
                            matches.append(f"header:{header_name}")
                    except re.error:
                        continue
        return matches

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id, "name": self.name,
            "category": self.category.value,
            "subcategory": self.subcategory,
            "cwe": self.cwe_id, "severity": self.severity,
            "confidence": self.confidence.value,
            "technologies": self.technologies,
        }


# ── Built-in Pattern Library ──────────────────────────────────

def _build_web_patterns() -> list[VulnPattern]:
    return [
        VulnPattern(
            pattern_id="sql-injection-error",
            name="SQL Injection (Error-Based)",
            description="Error-based SQL injection detected through error messages in response",
            category=PatternCategory.INJECTION,
            subcategory="sql_injection",
            cwe_id="CWE-89",
            severity="high",
            confidence=PatternConfidence.HIGH,
            regex_patterns=[
                r"(?i)SQL syntax.*MySQL",
                r"(?i)Warning.*mysql_",
                r"(?i)valid MySQL result",
                r"(?i)MySqlClient\.",
                r"(?i)pg_query\(\).*failed",
                r"(?i)pg_exec\(\).*failed",
                r"(?i)Warning.*pg_",
                r"(?i)valid PostgreSQL result",
                r"(?i)Npgsql\.",
                r"(?i)ORA-\d{5}",
                r"(?i)Oracle error",
                r"(?i)Oracle.*Driver",
                r"(?i)Warning.*oci_",
                r"(?i)Warning.*ora_",
                r"(?i)Microsoft SQL Native Client error",
                r"(?i)ODBC SQL Server Driver",
                r"(?i)\bOLE DB\b.*\bSQL Server\b",
                r"(?i)SQLITE_ERROR",
                r"(?i)SQLite3::",
                r"(?i)Warning.*sqlite_",
                r"(?i)Warning.*SQLite3::",
                r"(?i)Unclosed quotation mark",
                r"(?i)Syntax error.*in query expression",
            ],
            keyword_indicators=[
                "sql syntax error", "mysql_fetch", "pg_query",
                "ORA-", "SQLITE_ERROR", "SQLServer",
            ],
            validation_payloads=[
                "' OR '1'='1", "\" OR \"1\"=\"1",
                "' UNION SELECT NULL--", "1' AND '1'='1",
                "' OR 1=1--", "admin' --",
            ],
            false_positive_indicators=[
                "error page with static sql example",
                "documentation mentioning sql",
            ],
            exploitation_notes="Extract data via UNION-based, blind, or time-based techniques",
            remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
        ),

        VulnPattern(
            pattern_id="xss-reflected",
            name="Reflected Cross-Site Scripting (XSS)",
            description="User input reflected in response without proper encoding",
            category=PatternCategory.WEB_APPLICATION,
            subcategory="xss",
            cwe_id="CWE-79",
            severity="medium",
            confidence=PatternConfidence.MEDIUM,
            regex_patterns=[
                r"<script[^>]*>.*?</script>",
                r"(?i)on\w+\s*=\s*['\"]",
                r"javascript\s*:",
                r"<img[^>]+onerror",
                r"<svg[^>]+onload",
                r"<iframe[^>]+src\s*=",
            ],
            keyword_indicators=["<script>", "onerror=", "onload=", "javascript:"],
            validation_payloads=[
                "<script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "'-alert(1)-'",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
            ],
            exploitation_notes="Can lead to session hijacking, credential theft, defacement",
            remediation="Apply context-appropriate output encoding. Use CSP headers.",
        ),

        VulnPattern(
            pattern_id="ssrf-basic",
            name="Server-Side Request Forgery (SSRF)",
            description="Application can be tricked into making requests to internal resources",
            category=PatternCategory.WEB_APPLICATION,
            subcategory="ssrf",
            cwe_id="CWE-918",
            severity="high",
            confidence=PatternConfidence.MEDIUM,
            keyword_indicators=[
                "localhost", "127.0.0.1", "0.0.0.0",
                "169.254.169.254", "metadata.google",
                "[::1]", "internal", "intranet",
            ],
            validation_payloads=[
                "http://127.0.0.1", "http://localhost",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]", "http://0x7f000001",
                "dict://localhost:6379",
                "gopher://localhost:25",
            ],
            exploitation_notes="Can access cloud metadata, internal services, scan internal network",
            remediation="Validate/whitelist URLs. Block private IP ranges. Use URL parsers.",
        ),

        VulnPattern(
            pattern_id="idor",
            name="Insecure Direct Object Reference (IDOR)",
            description="Direct access to objects/resources by manipulating identifiers",
            category=PatternCategory.ACCESS_CONTROL,
            subcategory="idor",
            cwe_id="CWE-639",
            severity="high",
            confidence=PatternConfidence.MEDIUM,
            regex_patterns=[
                r"(?i)id=\d+",
                r"(?i)user_id=\d+",
                r"(?i)order_id=\d+",
                r"(?i)account=\d+",
                r"(?i)/api/v\d+/users/\d+",
                r"(?i)/api/v\d+/\w+/\d+",
            ],
            behavioral_checks=[
                "Change numeric ID in URL and check if different user's data is returned",
                "Try sequential IDs to enumerate resources",
                "Check if authorization is enforced at object level",
            ],
            exploitation_notes="Access other users' data by changing object IDs",
            remediation="Implement object-level authorization. Use UUIDs instead of sequential IDs.",
        ),

        VulnPattern(
            pattern_id="open-redirect",
            name="Open Redirect",
            description="Application redirects to user-controlled URL without validation",
            category=PatternCategory.WEB_APPLICATION,
            subcategory="open_redirect",
            cwe_id="CWE-601",
            severity="low",
            confidence=PatternConfidence.MEDIUM,
            regex_patterns=[
                r"(?i)(redirect|url|next|return|goto|redir|destination)\s*=\s*https?://",
                r"(?i)Location:\s*https?://[^\s]+",
            ],
            validation_payloads=[
                "//evil.com", "https://evil.com",
                "/\\evil.com", "//evil%2Ecom",
            ],
            exploitation_notes="Used for phishing, token theft via referer header",
            remediation="Validate redirect URLs against a whitelist. Use relative paths.",
        ),

        VulnPattern(
            pattern_id="command-injection",
            name="OS Command Injection",
            description="User input passed to system commands without sanitization",
            category=PatternCategory.INJECTION,
            subcategory="command_injection",
            cwe_id="CWE-78",
            severity="critical",
            confidence=PatternConfidence.HIGH,
            regex_patterns=[
                r"(?i)root:.*:0:0:",
                r"(?i)uid=\d+\(.*?\)\s+gid=\d+",
                r"(?i)\b(bin|sbin|usr)/",
                r"(?i)windows\\system32",
                r"(?i)volume serial number",
            ],
            keyword_indicators=[
                "root:x:0:0", "uid=0(root)", "bin/bash",
                "C:\\Windows\\System32", "volume serial",
            ],
            validation_payloads=[
                "; id", "| id", "& id", "`id`",
                "$(id)", "; cat /etc/passwd",
                "| whoami", "& whoami",
            ],
            exploitation_notes="Full system compromise possible through command execution",
            remediation="Never pass user input to system commands. Use safe APIs.",
        ),

        VulnPattern(
            pattern_id="path-traversal",
            name="Path Traversal",
            description="Access files outside intended directory through path manipulation",
            category=PatternCategory.WEB_APPLICATION,
            subcategory="path_traversal",
            cwe_id="CWE-22",
            severity="high",
            confidence=PatternConfidence.HIGH,
            regex_patterns=[
                r"(?i)root:.*:0:0:",
                r"\[boot loader\]",
                r"(?i)<Directory ",
                r"(?i)\[fonts\]",
            ],
            validation_payloads=[
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "....//....//....//etc/passwd",
                "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                "..%252f..%252f..%252fetc/passwd",
            ],
            exploitation_notes="Read sensitive files (config, credentials, source code)",
            remediation="Validate paths against a whitelist. Use chroot. Canonicalize paths.",
        ),

        VulnPattern(
            pattern_id="ssti",
            name="Server-Side Template Injection (SSTI)",
            description="User input evaluated in server-side template engine",
            category=PatternCategory.INJECTION,
            subcategory="template_injection",
            cwe_id="CWE-1336",
            severity="critical",
            confidence=PatternConfidence.HIGH,
            regex_patterns=[
                r"49",  # {{7*7}}
                r"7777777",  # {{7*'7'}} Jinja2
            ],
            keyword_indicators=["49", "7777777"],
            validation_payloads=[
                "{{7*7}}", "${7*7}", "#{7*7}",
                "{{7*'7'}}", "<%= 7*7 %>",
                "${7*7}", "{{config}}",
                "{{self.__class__.__mro__}}",
            ],
            exploitation_notes="Can lead to RCE through template engine exploitation",
            remediation="Never pass user input to template rendering. Use sandboxed templates.",
        ),
    ]


def _build_network_patterns() -> list[VulnPattern]:
    return [
        VulnPattern(
            pattern_id="weak-tls",
            name="Weak TLS Configuration",
            description="Server supports weak TLS versions or cipher suites",
            category=PatternCategory.CRYPTOGRAPHY,
            subcategory="tls",
            cwe_id="CWE-326",
            severity="medium",
            confidence=PatternConfidence.DEFINITE,
            keyword_indicators=[
                "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1",
                "RC4", "DES", "3DES", "MD5", "NULL",
                "EXPORT", "anon",
            ],
            validation_steps=[
                "Test with: nmap --script ssl-enum-ciphers -p 443 target",
                "Check with: testssl.sh target:443",
            ],
            remediation="Disable TLS 1.0/1.1. Use TLS 1.2+ with strong cipher suites.",
        ),

        VulnPattern(
            pattern_id="default-creds",
            name="Default Credentials",
            description="Service accessible with default/common credentials",
            category=PatternCategory.AUTHENTICATION,
            subcategory="default_credentials",
            cwe_id="CWE-798",
            severity="critical",
            confidence=PatternConfidence.DEFINITE,
            keyword_indicators=[
                "admin:admin", "admin:password", "root:root",
                "admin:123456", "test:test", "guest:guest",
            ],
            behavioral_checks=[
                "Test common credential pairs against login forms",
                "Check documentation for default credentials",
            ],
            exploitation_notes="Immediate system access with default credentials",
            remediation="Change all default credentials. Implement account lockout.",
        ),

        VulnPattern(
            pattern_id="missing-security-headers",
            name="Missing Security Headers",
            description="HTTP response missing important security headers",
            category=PatternCategory.CONFIGURATION,
            subcategory="http_headers",
            cwe_id="CWE-693",
            severity="low",
            confidence=PatternConfidence.DEFINITE,
            header_patterns={
                "x-frame-options": r"^$",  # Missing
                "x-content-type-options": r"^$",
                "content-security-policy": r"^$",
                "strict-transport-security": r"^$",
                "x-xss-protection": r"^$",
            },
            validation_steps=[
                "Check response headers for security headers",
                "Verify CSP, HSTS, X-Frame-Options present",
            ],
            remediation="Add X-Frame-Options, CSP, HSTS, X-Content-Type-Options headers.",
        ),

        VulnPattern(
            pattern_id="dns-zone-transfer",
            name="DNS Zone Transfer",
            description="DNS server allows unauthorized zone transfers",
            category=PatternCategory.NETWORK,
            subcategory="dns",
            cwe_id="CWE-200",
            severity="medium",
            confidence=PatternConfidence.DEFINITE,
            behavioral_checks=[
                "dig @ns.target.com target.com AXFR",
                "host -l target.com ns.target.com",
            ],
            exploitation_notes="Reveals all DNS records, internal hostnames, network topology",
            remediation="Restrict zone transfers to authorized secondary DNS servers only.",
        ),

        VulnPattern(
            pattern_id="smb-signing-disabled",
            name="SMB Signing Disabled",
            description="SMB service does not require message signing",
            category=PatternCategory.NETWORK,
            subcategory="smb",
            cwe_id="CWE-311",
            severity="medium",
            confidence=PatternConfidence.DEFINITE,
            keyword_indicators=[
                "message_signing: disabled",
                "signing disabled",
                "SMBv1 enabled",
            ],
            behavioral_checks=[
                "nmap --script smb-security-mode -p 445 target",
                "crackmapexec smb target --gen-relay-list",
            ],
            exploitation_notes="Enables SMB relay attacks, man-in-the-middle",
            remediation="Enable mandatory SMB signing via Group Policy.",
        ),
    ]


def _build_config_patterns() -> list[VulnPattern]:
    return [
        VulnPattern(
            pattern_id="exposed-debug",
            name="Debug Interface Exposed",
            description="Debug/diagnostic interfaces accessible from network",
            category=PatternCategory.CONFIGURATION,
            subcategory="debug",
            cwe_id="CWE-489",
            severity="high",
            confidence=PatternConfidence.HIGH,
            keyword_indicators=[
                "Django Debug", "Werkzeug Debugger", "Rails console",
                "phpinfo()", "TRACE method enabled",
                "X-Debug-Token", "debug=true",
            ],
            regex_patterns=[
                r"(?i)werkzeug.*debugger",
                r"(?i)django.*debug.*true",
                r"(?i)php\s+info",
                r"(?i)x-debug-token-link",
            ],
            exploitation_notes="Debug interfaces often allow code execution or sensitive data access",
            remediation="Disable debug mode in production. Block debug endpoints.",
        ),

        VulnPattern(
            pattern_id="exposed-env",
            name="Environment File Exposed",
            description=".env or configuration file accessible via web",
            category=PatternCategory.INFORMATION_DISCLOSURE,
            subcategory="file_exposure",
            cwe_id="CWE-200",
            severity="critical",
            confidence=PatternConfidence.HIGH,
            regex_patterns=[
                r"(?i)(DB_PASSWORD|DATABASE_URL|SECRET_KEY|API_KEY)\s*=",
                r"(?i)(AWS_ACCESS_KEY|AWS_SECRET_KEY)\s*=",
                r"(?i)REDIS_URL\s*=",
                r"(?i)SMTP_PASSWORD\s*=",
            ],
            keyword_indicators=[
                "DB_PASSWORD=", "SECRET_KEY=", "API_KEY=",
                "AWS_ACCESS_KEY_ID=", "PRIVATE_KEY",
            ],
            behavioral_checks=[
                "Check /.env", "Check /.env.local",
                "Check /config.yml", "Check /application.properties",
            ],
            exploitation_notes="Direct access to credentials and secrets",
            remediation="Block access to dotfiles in web server config. Use proper secret management.",
        ),

        VulnPattern(
            pattern_id="cors-misconfigured",
            name="CORS Misconfiguration",
            description="Cross-Origin Resource Sharing headers too permissive",
            category=PatternCategory.WEB_APPLICATION,
            subcategory="cors",
            cwe_id="CWE-942",
            severity="medium",
            confidence=PatternConfidence.HIGH,
            header_patterns={
                "access-control-allow-origin": r"\*|null",
                "access-control-allow-credentials": r"(?i)true",
            },
            behavioral_checks=[
                "Send request with Origin: https://evil.com",
                "Check if response reflects origin in ACAO header",
                "Check if credentials are allowed with wildcard origin",
            ],
            exploitation_notes="Can steal data cross-origin if credentials are included",
            remediation="Use specific origin whitelist. Never use * with credentials.",
        ),

        VulnPattern(
            pattern_id="git-exposed",
            name="Git Repository Exposed",
            description=".git directory accessible via web server",
            category=PatternCategory.INFORMATION_DISCLOSURE,
            subcategory="scm_exposure",
            cwe_id="CWE-527",
            severity="high",
            confidence=PatternConfidence.DEFINITE,
            regex_patterns=[
                r"ref:\s+refs/heads/",
                r"\[core\]",
                r"repositoryformatversion",
            ],
            behavioral_checks=[
                "Check /.git/HEAD",
                "Check /.git/config",
                "Check /.git/index",
            ],
            exploitation_notes="Full source code recovery possible with git-dumper",
            remediation="Block access to .git directory in web server configuration.",
        ),
    ]


class VulnPatternLibrary:
    """Library of vulnerability detection patterns.

    Provides pattern matching against various data sources
    (tool output, HTTP responses, code, configurations).
    """

    def __init__(self) -> None:
        self._patterns: dict[str, VulnPattern] = {}
        self._by_category: dict[str, list[str]] = defaultdict(list)
        self._by_cwe: dict[str, list[str]] = defaultdict(list)
        self._log = logger.bind(component="vuln_patterns")

        # Load built-in patterns
        self._load_builtin()

    def _load_builtin(self) -> None:
        """Load all built-in patterns."""
        for pattern in _build_web_patterns():
            self.register(pattern)
        for pattern in _build_network_patterns():
            self.register(pattern)
        for pattern in _build_config_patterns():
            self.register(pattern)

    def register(self, pattern: VulnPattern) -> None:
        """Register a new pattern."""
        self._patterns[pattern.pattern_id] = pattern
        self._by_category[pattern.category.value].append(pattern.pattern_id)
        if pattern.cwe_id:
            self._by_cwe[pattern.cwe_id].append(pattern.pattern_id)

    def scan_text(self, text: str) -> list[tuple[VulnPattern, list[str]]]:
        """Scan text against all patterns."""
        results = []
        for pattern in self._patterns.values():
            matches = pattern.matches_text(text)
            if matches:
                results.append((pattern, matches))
        return results

    def scan_headers(self, headers: dict[str, str]) -> list[tuple[VulnPattern, list[str]]]:
        """Scan HTTP headers against patterns."""
        results = []
        for pattern in self._patterns.values():
            if pattern.header_patterns:
                matches = pattern.matches_headers(headers)
                if matches:
                    results.append((pattern, matches))
        return results

    def get_patterns_for_technology(self, technology: str) -> list[VulnPattern]:
        """Get patterns relevant to a specific technology."""
        tech_lower = technology.lower()
        return [
            p for p in self._patterns.values()
            if any(tech_lower in t.lower() for t in p.technologies)
        ]

    def get_patterns_for_category(self, category: PatternCategory) -> list[VulnPattern]:
        ids = self._by_category.get(category.value, [])
        return [self._patterns[pid] for pid in ids if pid in self._patterns]

    def get_validation_payloads(self, pattern_id: str) -> list[str]:
        """Get validation payloads for a specific pattern."""
        pattern = self._patterns.get(pattern_id)
        if pattern:
            return pattern.validation_payloads
        return []

    def get_pattern(self, pattern_id: str) -> VulnPattern | None:
        return self._patterns.get(pattern_id)

    def get_stats(self) -> dict[str, Any]:
        by_category: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            by_category[p.category.value] += 1
            by_severity[p.severity] += 1
        return {
            "total_patterns": len(self._patterns),
            "by_category": dict(by_category),
            "by_severity": dict(by_severity),
        }
