"""API security knowledge base.

Deep knowledge about API vulnerabilities:
1. REST API security issues
2. GraphQL exploitation
3. gRPC and WebSocket attacks
4. API authentication flaws
5. API rate limiting and abuse
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
        "id": "api-001", "name": "REST API Vulnerabilities",
        "category": "rest", "severity": "high",
        "desc": "Common REST API security issues.",
        "detection": (
            "REST API VULNERABILITIES:\n"
            "ENDPOINT DISCOVERY:\n"
            "  # Swagger/OpenAPI\n"
            "  /swagger.json, /openapi.json\n"
            "  /api-docs, /swagger-ui.html\n"
            "  /v1/docs, /v2/api-docs\n"
            "  /.well-known/openapi.json\n"
            "  # Wordlist fuzzing\n"
            "  ffuf -u https://target/api/FUZZ -w api-endpoints.txt\n"
            "BOLA (Broken Object Level Authorization):\n"
            "  - OWASP API Security #1\n"
            "  - Change resource IDs in URLs\n"
            "  - GET /api/users/123 → GET /api/users/124\n"
            "  - Test with different auth tokens\n"
            "BFLA (Broken Function Level Authorization):\n"
            "  - User accessing admin endpoints\n"
            "  - POST /api/admin/users (with user token)\n"
            "  - DELETE /api/users/123 (user deleting others)\n"
            "MASS ASSIGNMENT:\n"
            "  - POST /api/users {\"name\":\"test\",\"role\":\"admin\"}\n"
            "  - PUT /api/profile {\"isAdmin\":true}\n"
            "  - Include unexpected fields in request\n"
            "SSRF VIA API:\n"
            "  - URL parameters: ?url=http://169.254.169.254/\n"
            "  - Webhook URLs pointing to internal services\n"
            "  - File import from URL\n"
            "EXCESSIVE DATA EXPOSURE:\n"
            "  - API returning sensitive fields\n"
            "  - Debug information in responses\n"
            "  - Stack traces in error responses"
        ),
        "tools": ["ffuf", "nuclei", "burpsuite"],
    },
    {
        "id": "api-002", "name": "GraphQL Exploitation",
        "category": "graphql", "severity": "critical",
        "desc": "GraphQL-specific attack techniques.",
        "detection": (
            "GRAPHQL EXPLOITATION:\n"
            "DISCOVERY:\n"
            "  # Common endpoints\n"
            "  /graphql, /graphiql, /v1/graphql\n"
            "  /api/graphql, /query, /gql\n"
            "  # Introspection query\n"
            "  {__schema{types{name fields{name type{name}}}}}\n"
            "  # Check if introspection is enabled\n"
            "  {__type(name:\"Query\"){name fields{name}}}\n"
            "ATTACKS:\n"
            "  INJECTION:\n"
            "    - SQL injection in resolvers\n"
            "    - NoSQL injection in filters\n"
            "    query { users(filter: \"{$ne: null}\") { name } }\n"
            "  BATCHING:\n"
            "    - Send multiple queries in one request\n"
            "    - Bypass rate limiting\n"
            "    [{\"query\":\"...\"},{ \"query\":\"...\"}]\n"
            "  DEPTH ATTACK:\n"
            "    - Nested queries causing DoS\n"
            "    { users { friends { friends { friends { ... } } } } }\n"
            "  FIELD SUGGESTION:\n"
            "    - Misspell field names to get suggestions\n"
            "    - Reveals schema without introspection\n"
            "AUTHORIZATION:\n"
            "  - Query other users' data\n"
            "  - Mutation without proper auth\n"
            "  - Subscription access control\n"
            "TOOLS:\n"
            "  graphql-voyager  # Schema visualization\n"
            "  InQL (Burp extension)  # GraphQL testing\n"
            "  graphw00f  # GraphQL fingerprinting"
        ),
        "tools": ["graphw00f", "burpsuite"],
    },
    {
        "id": "api-003", "name": "WebSocket Attacks",
        "category": "websocket", "severity": "high",
        "desc": "WebSocket security vulnerabilities.",
        "detection": (
            "WEBSOCKET ATTACKS:\n"
            "DISCOVERY:\n"
            "  - Look for ws:// or wss:// connections\n"
            "  - Check Upgrade: websocket headers\n"
            "  - Browser DevTools → Network → WS filter\n"
            "CROSS-SITE WEBSOCKET HIJACKING:\n"
            "  - No Origin header validation\n"
            "  - Create malicious page that connects to target WS\n"
            "  - Steal data from authenticated WS connection\n"
            "  - Similar to CSRF but for WebSockets\n"
            "MESSAGE MANIPULATION:\n"
            "  - Intercept and modify WS messages\n"
            "  - Inject additional messages\n"
            "  - Replay captured messages\n"
            "  - Test for injection in message content\n"
            "AUTHENTICATION:\n"
            "  - Token in URL parameter (leaks in logs)\n"
            "  - No authentication on WS upgrade\n"
            "  - Session token not validated per message\n"
            "DoS:\n"
            "  - Flood with messages\n"
            "  - Large message payload\n"
            "  - Many concurrent connections\n"
            "TESTING:\n"
            "  - Burp Suite WebSocket support\n"
            "  - wscat CLI tool\n"
            "  wscat -c ws://target/ws"
        ),
        "tools": ["burpsuite", "wscat"],
    },
    {
        "id": "api-004", "name": "API Authentication Flaws",
        "category": "api_auth", "severity": "critical",
        "desc": "API authentication and key management issues.",
        "detection": (
            "API AUTHENTICATION FLAWS:\n"
            "API KEY ISSUES:\n"
            "  - Keys in URL parameters (logged)\n"
            "  - Keys in client-side code (exposed)\n"
            "  - Keys in git repositories\n"
            "  - No key rotation\n"
            "  - Overly permissive key scope\n"
            "  # Search for exposed keys\n"
            "  trufflehog git https://github.com/org/repo\n"
            "  gitleaks detect --source .\n"
            "JWT ISSUES:\n"
            "  - Algorithm confusion (RS256 → HS256)\n"
            "  - Weak signing key\n"
            "  - No expiration validation\n"
            "  - Token in URL (referer leakage)\n"
            "  - Claim manipulation (role, sub)\n"
            "BEARER TOKEN:\n"
            "  - Token leakage in logs\n"
            "  - No token revocation\n"
            "  - Long-lived tokens\n"
            "  - Token reuse across services\n"
            "API KEY ENUMERATION:\n"
            "  - Predictable key format\n"
            "  - Key in response headers\n"
            "  - Key generation endpoint without auth\n"
            "TESTING:\n"
            "  1. Test with no auth\n"
            "  2. Test with expired token\n"
            "  3. Test with modified token\n"
            "  4. Test with different user's token"
        ),
        "tools": ["trufflehog", "gitleaks", "jwt_tool"],
    },
    {
        "id": "api-005", "name": "gRPC Security",
        "category": "grpc", "severity": "high",
        "desc": "gRPC and Protocol Buffer security issues.",
        "detection": (
            "gRPC SECURITY:\n"
            "DISCOVERY:\n"
            "  - Port scanning for gRPC (common: 50051)\n"
            "  - gRPC reflection enabled?\n"
            "  grpcurl -plaintext target:50051 list\n"
            "  grpcurl -plaintext target:50051 describe <service>\n"
            "ATTACKS:\n"
            "  - No TLS (plaintext gRPC)\n"
            "  - Reflection enabled in production\n"
            "  - Missing authentication metadata\n"
            "  - Message size limit abuse\n"
            "  - Protobuf deserialization issues\n"
            "TESTING:\n"
            "  # List services\n"
            "  grpcurl -plaintext target:50051 list\n"
            "  # Describe service\n"
            "  grpcurl -plaintext target:50051 describe pkg.Service\n"
            "  # Invoke method\n"
            "  grpcurl -plaintext -d '{\"id\": 1}' target:50051 pkg.Service/GetUser\n"
            "  # Test auth\n"
            "  grpcurl -plaintext -H 'authorization: Bearer <token>' \\\n"
            "    target:50051 pkg.Service/AdminMethod\n"
            "PROTOBUF:\n"
            "  - Decode unknown protobuf messages\n"
            "  - Modify field values\n"
            "  - Add unexpected fields\n"
            "  - Fuzz protobuf messages with random data\n"
            "TOOLS:\n"
            "  grpcurl  # gRPC CLI\n"
            "  grpcui  # gRPC web UI\n"
            "  protobuf-inspector  # Decode protobufs"
        ),
        "tools": ["grpcurl", "grpcui"],
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
