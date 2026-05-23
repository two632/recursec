"""API security knowledge base.

Deep knowledge about API vulnerabilities:
1. REST API testing methodology
2. GraphQL exploitation
3. gRPC/Protobuf attacks
4. API authentication bypass
5. Rate limiting and abuse
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
        "id": "api-001", "name": "REST API Vulnerability Testing",
        "category": "rest", "severity": "high",
        "desc": "Comprehensive REST API security testing.",
        "detection": (
            "REST API TESTING:\n"
            "ENDPOINT DISCOVERY:\n"
            "  # Swagger/OpenAPI discovery\n"
            "  ffuf -u https://<target>/FUZZ -w api-endpoints.txt\n"
            "  # Common paths:\n"
            "  /api/v1/ /api/v2/ /swagger/ /swagger.json\n"
            "  /openapi.json /api-docs /graphql /graphiql\n"
            "  /.well-known/ /actuator /health /metrics\n"
            "AUTHENTICATION TESTING:\n"
            "  - Test endpoints without auth token\n"
            "  - Test with expired token\n"
            "  - Test with token from different user\n"
            "  - Test with modified JWT claims\n"
            "  - Test with API key from different scope\n"
            "IDOR/BOLA:\n"
            "  - Change numeric IDs: /api/users/1 → /api/users/2\n"
            "  - Change UUIDs: Try sequential or predictable patterns\n"
            "  - Test with different object types in same endpoint\n"
            "  - Check batch endpoints: /api/users?ids=1,2,3\n"
            "MASS ASSIGNMENT:\n"
            "  - Add extra fields: {\"name\": \"x\", \"role\": \"admin\"}\n"
            "  - Add fields from API docs that aren't in UI\n"
            "  - Test PATCH with restricted fields\n"
            "RATE LIMITING:\n"
            "  - Test with rapid requests (no rate limit = DoS risk)\n"
            "  - Test from different IPs/headers\n"
            "  - Check X-Forwarded-For bypass"
        ),
        "tools": ["ffuf", "burp", "postman"],
    },
    {
        "id": "api-002", "name": "GraphQL Exploitation",
        "category": "graphql", "severity": "high",
        "desc": "Exploiting GraphQL endpoints.",
        "detection": (
            "GRAPHQL EXPLOITATION:\n"
            "INTROSPECTION:\n"
            "  # Full schema dump\n"
            "  {__schema{types{name,fields{name,args{name,type{name}}}}}}\n"
            "  # Tools\n"
            "  graphql-cop -t https://<target>/graphql\n"
            "  clairvoyance -o schema.json https://<target>/graphql\n"
            "  InQL (Burp extension)\n"
            "INJECTION:\n"
            "  # SQL injection through arguments\n"
            "  query { user(id: \"1' OR '1'='1\") { name, email }}\n"
            "  # NoSQL injection\n"
            "  query { user(filter: {\"$gt\": \"\"}) { name }}\n"
            "BATCHING ATTACKS:\n"
            "  # Send multiple queries in one request\n"
            "  [{\"query\": \"q1\"}, {\"query\": \"q2\"}, ...]\n"
            "  # Bypass rate limiting by batching\n"
            "  # Brute force via aliased queries\n"
            "  query { a1: login(user:\"a\",pass:\"1\") a2: login(user:\"a\",pass:\"2\") }\n"
            "DENIAL OF SERVICE:\n"
            "  # Deeply nested queries\n"
            "  query { user { friends { friends { friends { ... } } } } }\n"
            "  # Alias-based DoS\n"
            "  # Fragment-based circular queries\n"
            "AUTHORIZATION:\n"
            "  - Access mutations without proper roles\n"
            "  - Query fields that should be restricted\n"
            "  - Test subscription endpoints for data leaks"
        ),
        "tools": ["graphql-cop", "clairvoyance", "burp"],
    },
    {
        "id": "api-003", "name": "gRPC/Protobuf Attacks",
        "category": "grpc", "severity": "high",
        "desc": "Attacking gRPC and Protocol Buffer endpoints.",
        "detection": (
            "gRPC/PROTOBUF ATTACKS:\n"
            "DISCOVERY:\n"
            "  # Detect gRPC services\n"
            "  nmap -p 50051 --script=http-grpc <target>\n"
            "  # Server reflection (if enabled)\n"
            "  grpcurl -plaintext <host>:<port> list\n"
            "  grpcurl -plaintext <host>:<port> describe <service>\n"
            "  # If no reflection:\n"
            "  # Intercept .proto files from mobile apps/web\n"
            "  # Decompile from binary\n"
            "ENUMERATION:\n"
            "  # List all services\n"
            "  grpcurl -plaintext <host>:<port> list\n"
            "  # Describe service methods\n"
            "  grpcurl -plaintext <host>:<port> describe <Service>\n"
            "  # Call method\n"
            "  grpcurl -plaintext -d '{\"id\": 1}' <host>:<port> <Service>/<Method>\n"
            "ATTACKS:\n"
            "  - Missing authentication on methods\n"
            "  - IDOR through request parameters\n"
            "  - Protobuf deserialization issues\n"
            "  - Type confusion (send wrong type)\n"
            "  - Integer overflow in protobuf fields\n"
            "  - Large message DoS (no size limits)\n"
            "  - Stream abuse (bidirectional streaming)\n"
            "  - Metadata injection (HTTP/2 headers)"
        ),
        "tools": ["grpcurl", "nmap", "protobuf-inspector"],
    },
    {
        "id": "api-004", "name": "WebSocket Security",
        "category": "websocket", "severity": "high",
        "desc": "Testing WebSocket connections for vulnerabilities.",
        "detection": (
            "WEBSOCKET SECURITY:\n"
            "DETECTION:\n"
            "  - Look for ws:// or wss:// in source code\n"
            "  - Check for Upgrade: websocket headers\n"
            "  - Monitor network tab for WS connections\n"
            "  - Common endpoints: /ws /socket /socket.io /hub\n"
            "CROSS-SITE WEBSOCKET HIJACKING:\n"
            "  - Check if Origin header is validated\n"
            "  - If not → can connect from attacker's domain\n"
            "  - Test: Connect from different origin\n"
            "  - Exploit: Read messages, send commands\n"
            "INJECTION:\n"
            "  - Send SQL injection via WS messages\n"
            "  - Send XSS payloads through WS\n"
            "  - Send command injection via WS\n"
            "  - Test message format manipulation\n"
            "AUTHORIZATION:\n"
            "  - Connect without authentication\n"
            "  - Subscribe to channels of other users\n"
            "  - Send admin-level commands as regular user\n"
            "  - Test reconnection with stale tokens\n"
            "DENIAL OF SERVICE:\n"
            "  - Rapidly open many connections\n"
            "  - Send very large messages\n"
            "  - Send malformed frames"
        ),
        "tools": ["burp", "wscat", "autobahn-testsuite"],
    },
    {
        "id": "api-005", "name": "OAuth/OIDC Exploitation",
        "category": "oauth", "severity": "critical",
        "desc": "Exploiting OAuth 2.0 and OpenID Connect flaws.",
        "detection": (
            "OAUTH/OIDC EXPLOITATION:\n"
            "AUTHORIZATION CODE FLOW:\n"
            "  - Missing state parameter → CSRF\n"
            "  - Redirect URI manipulation:\n"
            "    redirect_uri=https://attacker.com\n"
            "    redirect_uri=https://legitimate.com@attacker.com\n"
            "    redirect_uri=https://legitimate.com/..%2F..%2Fattacker.com\n"
            "  - Authorization code replay (no PKCE)\n"
            "  - Code injection via redirect_uri path\n"
            "TOKEN ATTACKS:\n"
            "  - Token leakage via Referer header\n"
            "  - Token in URL fragment → leaked to JS\n"
            "  - Token scope escalation\n"
            "  - Refresh token rotation not enforced\n"
            "  - Token stored in localStorage (XSS risk)\n"
            "IMPLICIT FLOW ATTACKS:\n"
            "  - Access token in URL → history, logs, Referer\n"
            "  - Token substitution (use token from attacker app)\n"
            "  - Confused deputy (mix up client IDs)\n"
            "OIDC SPECIFIC:\n"
            "  - ID token validation bypass\n"
            "  - Nonce reuse → replay attack\n"
            "  - Issuer validation missing\n"
            "  - User info endpoint IDOR"
        ),
        "tools": ["burp", "oauth-tester"],
    },
]


class APISecurityKB:
    """API security knowledge base.

    Provides API vulnerability patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, APIPattern] = {}
        self._log = logger.bind(component="api_security_kb")
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
        lines = ["## API Security Patterns\n"]
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
