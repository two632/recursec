"""Web application security knowledge base.

Deep knowledge about web application attacks:
1. HTTP request smuggling
2. Cache poisoning
3. CORS misconfiguration
4. HTTP header injection
5. Host header attacks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class WebAppPattern:
    """A web application security pattern."""
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


WEBAPP_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "web-001", "name": "HTTP Request Smuggling",
        "category": "protocol", "severity": "critical",
        "desc": "Exploiting disagreements between front-end and back-end servers.",
        "detection": (
            "HTTP REQUEST SMUGGLING:\n"
            "TYPES:\n"
            "  CL.TE (Content-Length vs Transfer-Encoding):\n"
            "    Front-end uses Content-Length, back-end uses Transfer-Encoding\n"
            "    POST / HTTP/1.1\n"
            "    Host: target.com\n"
            "    Content-Length: 13\n"
            "    Transfer-Encoding: chunked\n"
            "    \\r\\n0\\r\\n\\r\\nSMUGGLED\n"
            "  TE.CL:\n"
            "    Front-end uses Transfer-Encoding, back-end uses Content-Length\n"
            "  TE.TE:\n"
            "    Both use Transfer-Encoding but disagree on obfuscation\n"
            "    Transfer-Encoding: chunked\n"
            "    Transfer-Encoding : chunked (extra space)\n"
            "    Transfer-Encoding: xchunked\n"
            "    Transfer-Encoding: chunked\\r\\nTransfer-encoding: x\n"
            "DETECTION:\n"
            "  - Time-based: Smuggled request causes timeout\n"
            "  - Differential: Different responses for same request\n"
            "  - Tools: smuggler.py, HTTP Request Smuggler (Burp extension)\n"
            "IMPACT:\n"
            "  - Bypass WAF rules\n"
            "  - Steal other users' requests\n"
            "  - Cache poisoning\n"
            "  - Session hijacking"
        ),
        "tools": ["smuggler", "burp"],
    },
    {
        "id": "web-002", "name": "Web Cache Poisoning",
        "category": "cache", "severity": "high",
        "desc": "Poisoning web caches to serve malicious content.",
        "detection": (
            "WEB CACHE POISONING:\n"
            "METHODOLOGY:\n"
            "  1. Identify unkeyed inputs:\n"
            "     - Headers not included in cache key\n"
            "     - X-Forwarded-Host, X-Forwarded-Scheme\n"
            "     - X-Original-URL, X-Rewrite-URL\n"
            "     - Tool: Param Miner (Burp extension)\n"
            "  2. Inject payload via unkeyed input:\n"
            "     X-Forwarded-Host: evil.com\n"
            "     → Response includes: <script src='//evil.com/script.js'>\n"
            "  3. Cache the poisoned response:\n"
            "     Repeat request until cached\n"
            "     Check: X-Cache: HIT header\n"
            "COMMON VECTORS:\n"
            "  - Fat GET: Body in GET request (different processing)\n"
            "  - Port-based: Host: target.com:evil-port\n"
            "  - Protocol-based: X-Forwarded-Proto\n"
            "  - Path normalization differences\n"
            "  - Cache key normalization\n"
            "TESTING:\n"
            "  - Use unique cache busters: ?cb=random\n"
            "  - Test each unkeyed header\n"
            "  - Check CDN behavior (Cloudflare, Akamai, etc.)\n"
            "  - Look for reflected unkeyed inputs in response"
        ),
        "tools": ["burp", "param-miner"],
    },
    {
        "id": "web-003", "name": "CORS Misconfiguration",
        "category": "cors", "severity": "high",
        "desc": "Cross-Origin Resource Sharing misconfigurations.",
        "detection": (
            "CORS MISCONFIGURATION:\n"
            "TESTING:\n"
            "  curl -H 'Origin: https://evil.com' -v <target>\n"
            "  Check response for:\n"
            "    Access-Control-Allow-Origin: https://evil.com\n"
            "    Access-Control-Allow-Credentials: true\n"
            "DANGEROUS PATTERNS:\n"
            "  - Reflect any origin:\n"
            "    Access-Control-Allow-Origin: <attacker-origin>\n"
            "  - null origin allowed:\n"
            "    Access-Control-Allow-Origin: null\n"
            "    (sandboxed iframes can have null origin)\n"
            "  - Regex bypass:\n"
            "    If server checks *.target.com\n"
            "    Try: evil-target.com, target.com.evil.com\n"
            "  - Subdomain wildcard:\n"
            "    *.target.com → XSS on any subdomain = full CORS bypass\n"
            "  - Pre-flight cache abuse:\n"
            "    Long Access-Control-Max-Age\n"
            "IMPACT:\n"
            "  - Read authenticated user data cross-origin\n"
            "  - API data exfiltration\n"
            "  - CSRF bypass (if credentials allowed)\n"
            "NUCLEI TEMPLATE:\n"
            "  nuclei -u <target> -t cors/"
        ),
        "tools": ["nuclei", "curl", "burp"],
    },
    {
        "id": "web-004", "name": "Host Header Injection",
        "category": "header", "severity": "high",
        "desc": "Manipulating the Host header for various attacks.",
        "detection": (
            "HOST HEADER INJECTION:\n"
            "ATTACKS:\n"
            "  Password Reset Poisoning:\n"
            "    - Send password reset request\n"
            "    - Set Host: attacker.com\n"
            "    - Reset link uses attacker's domain\n"
            "    - Victim clicks → token sent to attacker\n"
            "  Web Cache Poisoning:\n"
            "    - Host header reflected in cached response\n"
            "    - Import resources from attacker domain\n"
            "  SSRF:\n"
            "    - Host: internal-service\n"
            "    - Application routes to internal host\n"
            "  Virtual Host Bypass:\n"
            "    - Try internal hostnames\n"
            "    - Host: localhost, Host: admin.internal\n"
            "TESTING:\n"
            "  - Change Host header:\n"
            "    curl -H 'Host: evil.com' <target_ip>\n"
            "  - Duplicate Host header:\n"
            "    Host: target.com\\r\\nHost: evil.com\n"
            "  - X-Forwarded-Host override:\n"
            "    X-Forwarded-Host: evil.com\n"
            "  - Absolute URL + different Host:\n"
            "    GET http://target.com/ HTTP/1.1\n"
            "    Host: evil.com"
        ),
        "tools": ["curl", "burp", "nuclei"],
    },
    {
        "id": "web-005", "name": "HTTP Parameter Tampering",
        "category": "parameter", "severity": "medium",
        "desc": "Parameter manipulation and hidden parameter discovery.",
        "detection": (
            "HTTP PARAMETER TAMPERING:\n"
            "HIDDEN PARAMETER DISCOVERY:\n"
            "  Tools:\n"
            "    - Arjun: arjun -u <url> -m GET\n"
            "    - Param Miner: Burp extension (auto-discover)\n"
            "    - x8: x8 -u <url> -w <wordlist>\n"
            "  Wordlists:\n"
            "    - SecLists/Discovery/Web-Content/burp-parameter-names.txt\n"
            "    - Custom based on technology (Django, Rails, etc.)\n"
            "TAMPERING TECHNIQUES:\n"
            "  Type Juggling:\n"
            "    - Send array where string expected: param[]=value\n"
            "    - Send object: param[key]=value\n"
            "    - Send null/0/empty: param=&param2=test\n"
            "  HTTP Parameter Pollution:\n"
            "    - Duplicate params: ?a=1&a=2\n"
            "    - Server-dependent behavior (first/last/both)\n"
            "    - WAF bypass: ?id=1&id=2' OR 1=1--\n"
            "  Encoding Bypass:\n"
            "    - URL encoding: %27 for '\n"
            "    - Double encoding: %2527\n"
            "    - Unicode: %u0027\n"
            "    - HTML entities: &#39;\n"
            "TESTING:\n"
            "  1. Discover all parameters (visible + hidden)\n"
            "  2. Test type variations for each parameter\n"
            "  3. Test duplicate parameters\n"
            "  4. Test encoding variations for WAF bypass"
        ),
        "tools": ["arjun", "burp", "ffuf"],
    },
]


class WebAppKB:
    """Web application security knowledge base.

    Provides web application attack patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, WebAppPattern] = {}
        self._log = logger.bind(component="webapp_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load web app patterns."""
        for data in WEBAPP_PATTERNS:
            pattern = WebAppPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[WebAppPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_webapp_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build web app security prompt."""
        lines = ["## Web Application Security Patterns\n"]
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
