"""Web cache and CDN security knowledge base.

Deep knowledge about web caching security:
1. Cache poisoning attacks
2. Cache deception
3. CDN bypass techniques
4. Edge-side includes (ESI) injection
5. Request smuggling via caches
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class WebCachePattern:
    """A web cache security pattern."""
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
            "category": self.category[:12],
        }


WEBCACHE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "wc-001", "name": "Cache Poisoning",
        "category": "poisoning", "severity": "high",
        "desc": "Web cache poisoning attacks.",
        "detection": (
            "CACHE POISONING:\n"
            "UNKEYED HEADERS:\n"
            "  - X-Forwarded-Host\n"
            "    # Inject into cached page\n"
            "    # Redirect/XSS via Host header\n"
            "  - X-Forwarded-Scheme\n"
            "    # Force HTTP → HTTPS redirect loop\n"
            "  - X-Original-URL\n"
            "    # Override path\n"
            "  - X-Rewrite-URL\n"
            "  - X-Forwarded-Port\n"
            "TECHNIQUE:\n"
            "  1. Identify cache behavior\n"
            "     # Send request, check X-Cache, Age\n"
            "  2. Find unkeyed inputs\n"
            "     # Param Miner Burp extension\n"
            "     # Test each header for reflection\n"
            "  3. Craft poisoned response\n"
            "     # Inject XSS via unkeyed header\n"
            "     # Inject redirect via Host\n"
            "  4. Verify cached response\n"
            "     # Subsequent requests get poison\n"
            "CACHE HEADERS:\n"
            "  - X-Cache: HIT/MISS\n"
            "  - CF-Cache-Status (Cloudflare)\n"
            "  - Age: seconds since cached\n"
            "  - Vary: keyed headers\n"
            "  - Cache-Control\n"
            "FAT GET:\n"
            "  - Body in GET request\n"
            "  - Parameters processed but not keyed\n"
            "TOOLS:\n"
            "  Param Miner, Burp, Web Cache Vuln Scanner"
        ),
        "tools": [],
    },
    {
        "id": "wc-002", "name": "Cache Deception",
        "category": "deception", "severity": "high",
        "desc": "Web cache deception attacks.",
        "detection": (
            "CACHE DECEPTION:\n"
            "TECHNIQUE:\n"
            "  1. Find dynamic page with user data\n"
            "     # /account, /profile, /settings\n"
            "  2. Append static extension\n"
            "     # /account/non-exist.css\n"
            "     # /account/foo.js\n"
            "     # /account/img.png\n"
            "  3. Cache stores response (thinks static)\n"
            "  4. Attacker fetches cached page\n"
            "     # Gets victim's data\n"
            "PATH CONFUSION:\n"
            "  - Delimiter discrepancy\n"
            "    # /account;x.css\n"
            "    # /account%0a.css\n"
            "    # /account/.css\n"
            "  - Dot segment normalization\n"
            "    # /static/../account\n"
            "  - Double encoding\n"
            "    # /account%252f.css\n"
            "PREREQUISITES:\n"
            "  - Cache keys on URL path extension\n"
            "  - Server ignores non-existent path\n"
            "  - Response contains sensitive data\n"
            "  - No Cache-Control: private\n"
            "DETECTION:\n"
            "  # Check response headers\n"
            "  # Vary header analysis\n"
            "  # Cache-Control analysis\n"
            "TOOLS:\n"
            "  Burp, custom scripts"
        ),
        "tools": [],
    },
    {
        "id": "wc-003", "name": "CDN Bypass",
        "category": "cdn_bypass", "severity": "medium",
        "desc": "CDN bypass techniques.",
        "detection": (
            "CDN BYPASS:\n"
            "ORIGIN DISCOVERY:\n"
            "  - DNS history\n"
            "    # SecurityTrails, DNS Dumpster\n"
            "    # Historical A records\n"
            "  - SSL certificate search\n"
            "    # censys.io, crt.sh\n"
            "    # Certificate transparency logs\n"
            "  - Email headers\n"
            "    # Originating IP in headers\n"
            "  - Subdomain IP leaks\n"
            "    # Non-CDN subdomains\n"
            "    # Direct IP subdomains\n"
            "  - DNS rebinding\n"
            "  - IPv6 address (often not proxied)\n"
            "CLOUDFLARE SPECIFIC:\n"
            "  - CloudFlair tool\n"
            "  - Censys search for cert\n"
            "  - Historical DNS before CF\n"
            "  - Direct connect to origin IP\n"
            "    # Set Host header manually\n"
            "WAF BYPASS:\n"
            "  - Direct origin access\n"
            "  - Non-standard ports\n"
            "  - HTTP/2 downgrade\n"
            "  - Unicode normalization\n"
            "  - Chunked encoding\n"
            "  - Multipart content-type\n"
            "TOOLS:\n"
            "  CloudFlair, censys, SecurityTrails"
        ),
        "tools": [],
    },
    {
        "id": "wc-004", "name": "ESI Injection",
        "category": "esi", "severity": "high",
        "desc": "Edge-Side Includes injection.",
        "detection": (
            "ESI INJECTION:\n"
            "DETECTION:\n"
            "  - Check for ESI processing\n"
            "    # <esi:include src=url/> in response\n"
            "    # Surrogate-Control header\n"
            "    # X-ESI header\n"
            "  - Inject ESI tags in input\n"
            "    # If reflected and processed\n"
            "ATTACKS:\n"
            "  - SSRF via ESI include\n"
            "    # <esi:include src=\"http://internal/\"/>\n"
            "  - XSS via ESI inline\n"
            "    # <esi:inline name=\"/attack.html\">\n"
            "    # <script>alert(1)</script>\n"
            "    # </esi:inline>\n"
            "  - Header injection\n"
            "    # <esi:include src=\"$(HTTP_COOKIE)\"/>\n"
            "  - Cookie theft\n"
            "    # Exfiltrate via ESI include src\n"
            "  - Bypass HttpOnly\n"
            "    # ESI runs server-side, accesses all headers\n"
            "VULNERABLE:\n"
            "  - Varnish, Squid, Akamai\n"
            "  - Apache Traffic Server\n"
            "  - Oracle Web Cache\n"
            "  - Fastly\n"
            "TOOLS:\n"
            "  Burp, ESI injection tester"
        ),
        "tools": [],
    },
    {
        "id": "wc-005", "name": "Request Smuggling via Caches",
        "category": "smuggling", "severity": "critical",
        "desc": "HTTP request smuggling through caches.",
        "detection": (
            "REQUEST SMUGGLING VIA CACHES:\n"
            "CL.TE:\n"
            "  - Front-end: Content-Length\n"
            "  - Back-end: Transfer-Encoding\n"
            "  # POST / HTTP/1.1\n"
            "  # Content-Length: 13\n"
            "  # Transfer-Encoding: chunked\n"
            "  # 0\\r\\n\\r\\nSMUGGLED\n"
            "TE.CL:\n"
            "  - Front-end: Transfer-Encoding\n"
            "  - Back-end: Content-Length\n"
            "CACHE IMPACT:\n"
            "  - Cache poisoning via smuggling\n"
            "    # Smuggle request for static resource\n"
            "    # Poison cache with attacker content\n"
            "  - Request routing override\n"
            "  - Web socket smuggling\n"
            "  - Header injection\n"
            "H2.CL:\n"
            "  - HTTP/2 → HTTP/1.1 downgrade\n"
            "  - Content-Length discrepancy\n"
            "  - Request splitting\n"
            "DETECTION:\n"
            "  # Time-based detection\n"
            "  # CL.TE: delay in response\n"
            "  # TE.CL: delay in response\n"
            "  # Differential responses\n"
            "TOOLS:\n"
            "  smuggler.py, Burp, HTTP Request Smuggler"
        ),
        "tools": [],
    },
]


class WebCacheCDNKB:
    """Web cache and CDN security knowledge base.

    Provides web cache patterns injected
    into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, WebCachePattern] = {}
        self._log = logger.bind(component="webcache_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load web cache patterns."""
        for data in WEBCACHE_PATTERNS:
            pattern = WebCachePattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[WebCachePattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_webcache_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build web cache prompt."""
        lines = ["## Web Cache & CDN Security\n"]
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
