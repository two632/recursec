"""GraphQL and API security knowledge base.

Deep knowledge about API security:
1. GraphQL-specific attacks
2. REST API vulnerabilities
3. gRPC and WebSocket security
4. API authentication flaws
5. API rate limiting and DoS
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class APIPattern:
    """An API security pattern."""
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


API_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "api-001", "name": "GraphQL-Specific Attacks",
        "category": "graphql", "severity": "high",
        "desc": "GraphQL-specific attacks.",
        "detection": (
            "GRAPHQL ATTACKS:\n"
            "INTROSPECTION:\n"
            "  # Full schema dump\n"
            "  {__schema{types{name,fields{name,type{name}}}}}\n"
            "  # If disabled, use field suggestion/brute force\n"
            "  # Clairvoyance (schema recovery)\n"
            "INJECTION:\n"
            "  - SQL injection in arguments\n"
            "  - NoSQL injection\n"
            "  - OS command injection via resolvers\n"
            "  - SSRF via URL arguments\n"
            "COMPLEXITY ATTACKS:\n"
            "  - Deeply nested queries\n"
            "  - Circular fragment references\n"
            "  - Alias-based batching\n"
            "  - Field duplication\n"
            "  query { a:user(id:1){posts{author{posts{author}}}}} \n"
            "BATCHING:\n"
            "  # Multiple operations in one request\n"
            "  [{\"query\":\"q1\"},{\"query\":\"q2\"},...]\n"
            "  # Bypass rate limiting per request\n"
            "  # Brute force via batched mutations\n"
            "AUTHORIZATION:\n"
            "  - Missing field-level auth\n"
            "  - Access through nested types\n"
            "  - Mutation auth bypass\n"
            "  - Subscription auth issues\n"
            "  - Direct object reference in arguments\n"
            "INFORMATION DISCLOSURE:\n"
            "  - Debug mode enabled\n"
            "  - Verbose error messages\n"
            "  - Stack traces in responses\n"
            "  - Schema metadata leaks\n"
            "TOOLS:\n"
            "  GraphQL Voyager, InQL (Burp), Clairvoyance"
        ),
        "tools": [],
    },
    {
        "id": "api-002", "name": "REST API Vulnerabilities",
        "category": "rest", "severity": "high",
        "desc": "REST API vulnerabilities.",
        "detection": (
            "REST API VULNS:\n"
            "OWASP API TOP 10 (2023):\n"
            "  1. Broken Object Level Auth (BOLA/IDOR)\n"
            "  2. Broken Authentication\n"
            "  3. Broken Object Property Level Auth\n"
            "  4. Unrestricted Resource Consumption\n"
            "  5. Broken Function Level Auth\n"
            "  6. Unrestricted Access to Sensitive Flows\n"
            "  7. Server Side Request Forgery\n"
            "  8. Security Misconfiguration\n"
            "  9. Improper Inventory Management\n"
            "  10. Unsafe Consumption of APIs\n"
            "COMMON ISSUES:\n"
            "  - Mass assignment (extra params accepted)\n"
            "  - BOLA: change ID in /api/users/{id}\n"
            "  - Excessive data exposure (full objects)\n"
            "  - Missing pagination limits\n"
            "  - HTTP method tampering\n"
            "  - Content-Type manipulation\n"
            "  - Version endpoint discovery\n"
            "  - API key in URL (leaks in logs)\n"
            "DISCOVERY:\n"
            "  - /api/docs, /swagger, /openapi.json\n"
            "  - /api/v1, /api/v2 (old versions)\n"
            "  - /.well-known/openapi\n"
            "  - JavaScript file analysis\n"
            "  - Mobile app traffic analysis\n"
            "  - Wayback Machine API endpoints\n"
            "TOOLS:\n"
            "  Postman, Burp Suite, ffuf, Arjun, KITERUNNER"
        ),
        "tools": ["ffuf"],
    },
    {
        "id": "api-003", "name": "gRPC and WebSocket Security",
        "category": "grpc_ws", "severity": "high",
        "desc": "gRPC and WebSocket security.",
        "detection": (
            "gRPC & WEBSOCKET:\n"
            "gRPC:\n"
            "  - Server reflection enabled\n"
            "  # grpcurl -plaintext TARGET:PORT list\n"
            "  # grpcurl -plaintext TARGET:PORT describe\n"
            "  - No TLS (plaintext)\n"
            "  - Missing authentication\n"
            "  - Protobuf deserialization issues\n"
            "  - Method-level authorization missing\n"
            "  - Large message DoS\n"
            "  TESTING:\n"
            "    # grpcurl (CLI)\n"
            "    # grpcui (web UI)\n"
            "    # Postman (gRPC support)\n"
            "    # BloomRPC\n"
            "WEBSOCKET:\n"
            "  - Missing origin validation\n"
            "  - Cross-Site WebSocket Hijacking (CSWSH)\n"
            "  - No authentication on WS upgrade\n"
            "  - Injection via WS messages\n"
            "  - Missing message validation\n"
            "  - Lack of rate limiting\n"
            "  - Unencrypted (ws:// not wss://)\n"
            "  TESTING:\n"
            "    # wscat (CLI)\n"
            "    wscat -c ws://TARGET/socket\n"
            "    # Burp Suite (WS tab)\n"
            "    # Browser DevTools (Network → WS)\n"
            "SERVER-SENT EVENTS:\n"
            "  - No authentication\n"
            "  - Information disclosure\n"
            "  - Connection limit exhaustion\n"
            "TOOLS:\n"
            "  grpcurl, grpcui, wscat, Burp Suite"
        ),
        "tools": [],
    },
    {
        "id": "api-004", "name": "API Authentication Flaws",
        "category": "api_auth", "severity": "critical",
        "desc": "API authentication vulnerabilities.",
        "detection": (
            "API AUTHENTICATION:\n"
            "API KEYS:\n"
            "  - Keys in URLs (logged/cached)\n"
            "  - Keys in JavaScript bundles\n"
            "  - Hardcoded keys in mobile apps\n"
            "  - No key rotation\n"
            "  - Overly permissive key scopes\n"
            "  - Keys in public repos (GitHub search)\n"
            "JWT:\n"
            "  - None algorithm attack\n"
            "  - Algorithm confusion (RS256→HS256)\n"
            "  - Weak secret (brute force)\n"
            "  - Missing expiration\n"
            "  - No signature verification\n"
            "  - JWK/JKU injection\n"
            "  - Kid injection (SQL, path traversal)\n"
            "  # jwt_tool TOKEN -T (tamper)\n"
            "  # jwt_tool TOKEN -X a (alg attack)\n"
            "  # jwt_tool TOKEN -C -d wordlist.txt (crack)\n"
            "OAUTH:\n"
            "  - Authorization code interception\n"
            "  - Redirect URI manipulation\n"
            "  - Token theft via Referer\n"
            "  - CSRF on callback\n"
            "  - Client secret in client-side code\n"
            "BEARER TOKENS:\n"
            "  - No expiration\n"
            "  - Token not revoked after logout\n"
            "  - Token scope not validated\n"
            "  - Token reuse across sessions\n"
            "TOOLS:\n"
            "  jwt_tool, Burp Suite, Postman"
        ),
        "tools": ["jwt_tool"],
    },
    {
        "id": "api-005", "name": "API Rate Limiting and DoS",
        "category": "api_dos", "severity": "medium",
        "desc": "API rate limiting and DoS.",
        "detection": (
            "API RATE LIMITING & DoS:\n"
            "MISSING RATE LIMITS:\n"
            "  - No per-IP limit\n"
            "  - No per-user limit\n"
            "  - No per-endpoint limit\n"
            "  - Login endpoint (brute force)\n"
            "  - Password reset (email bomb)\n"
            "  - SMS OTP (cost attack)\n"
            "BYPASS:\n"
            "  - X-Forwarded-For rotation\n"
            "  - API key rotation\n"
            "  - Endpoint path variation\n"
            "  - HTTP method switching\n"
            "  - GraphQL batching\n"
            "  - HTTP/2 multiplexing\n"
            "RESOURCE EXHAUSTION:\n"
            "  - Large response payloads\n"
            "  - Missing pagination\n"
            "  - Regex DoS in parameters\n"
            "  - Expensive operations (sort, search)\n"
            "  - File upload size limits\n"
            "  - Memory exhaustion via large JSON\n"
            "TESTING:\n"
            "  - Send rapid requests (100/s)\n"
            "  - Check for 429 responses\n"
            "  - Verify Retry-After header\n"
            "  - Test reset window timing\n"
            "  - Check response time under load\n"
            "TOOLS:\n"
            "  wrk, vegeta, Turbo Intruder, k6"
        ),
        "tools": ["wrk"],
    },
]


class GraphQLAPIKB:
    """GraphQL and API security knowledge base.

    Provides API security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, APIPattern] = {}
        self._log = logger.bind(component="api_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load API patterns."""
        for data in API_PATTERNS:
            pattern = APIPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[APIPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_api_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build API security prompt."""
        lines = ["## API Security\n"]
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
