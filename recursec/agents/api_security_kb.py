"""API security knowledge base.

Deep knowledge about API security testing:
1. REST API security
2. GraphQL security
3. gRPC security
4. WebSocket security
5. API authentication attacks
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class APIVulnPattern:
    """An API vulnerability pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    owasp_api: str = ""          # OWASP API Security Top 10
    description: str = ""
    testing_methodology: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "owasp": self.owasp_api[:8],
        }


API_VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "api-001", "name": "REST API Security Testing",
        "category": "rest", "severity": "high",
        "owasp_api": "API1-API10",
        "desc": "REST API security assessment.",
        "testing": (
            "REST API SECURITY TESTING:\n"
            "1. AUTHENTICATION (API2:2023 Broken Auth):\n"
            "   - JWT testing:\n"
            "     * Decode: echo {token} | base64 -d\n"
            "     * Check algorithm: none, HS256 vs RS256 confusion\n"
            "     * Crack weak secrets: hashcat -m 16500 jwt.txt wordlist\n"
            "     * Expired token reuse\n"
            "     * Token in URL parameter (logged in server logs)\n"
            "     * Missing signature validation\n"
            "   - API key testing:\n"
            "     * Key in URL vs header\n"
            "     * Key enumeration/brute force\n"
            "     * Leaked keys in client-side code\n"
            "   - OAuth2 testing:\n"
            "     * Open redirect in redirect_uri\n"
            "     * CSRF on authorization endpoint\n"
            "     * Token theft via referrer\n"
            "     * Scope escalation\n"
            "2. AUTHORIZATION (API1:2023 BOLA):\n"
            "   - IDOR testing:\n"
            "     * Change numeric IDs: /api/users/1 → /api/users/2\n"
            "     * Change UUID: Try other users' UUIDs\n"
            "     * Change resource references in request body\n"
            "   - BFLA (Broken Function Level Authorization):\n"
            "     * Access admin endpoints as regular user\n"
            "     * Change HTTP method: GET → PUT/DELETE\n"
            "     * Add admin parameters: ?admin=true, ?role=admin\n"
            "3. INJECTION (API8:2023):\n"
            "   - SQL injection in query parameters and JSON body\n"
            "   - NoSQL injection:\n"
            "     * MongoDB: {\"$gt\": \"\"}, {\"$ne\": \"\"}\n"
            "     * {\"username\": {\"$regex\": \"admin\"}, \"password\": {\"$ne\": \"\"}}\n"
            "   - Server-Side Request Forgery (SSRF):\n"
            "     * URL parameters: ?url=http://169.254.169.254/\n"
            "     * Webhook endpoints: POST body with internal URLs\n"
            "4. RATE LIMITING (API4:2023):\n"
            "   - Check for rate limits:\n"
            "     for i in $(seq 1 100); do curl -s -o /dev/null -w '%{http_code}' {url}; done\n"
            "   - Check different endpoints\n"
            "   - IP rotation bypass\n"
            "   - User-Agent rotation\n"
            "5. MASS ASSIGNMENT (API3:2023):\n"
            "   - Add extra fields to request body:\n"
            "     {\"name\": \"user\", \"role\": \"admin\", \"verified\": true}\n"
            "   - Check if server accepts and processes unexpected fields\n"
            "6. DOCUMENTATION:\n"
            "   - Swagger/OpenAPI: /swagger.json, /api-docs, /openapi.json\n"
            "   - Postman collections leak\n"
            "   - GraphQL introspection"
        ),
        "tools": ["Burp Suite", "jwt_tool", "Postman", "ffuf"],
    },
    {
        "id": "api-002", "name": "GraphQL Security Testing",
        "category": "graphql", "severity": "high",
        "owasp_api": "API1,API3,API5",
        "desc": "GraphQL-specific security testing.",
        "testing": (
            "GRAPHQL SECURITY TESTING:\n"
            "1. DISCOVERY:\n"
            "   - Common endpoints:\n"
            "     /graphql, /graphiql, /graphql/console, /v1/graphql\n"
            "     /playground, /altair, /api/graphql\n"
            "   - Detect GraphQL: POST with {\"query\": \"{__typename}\"}\n"
            "2. INTROSPECTION:\n"
            "   - Full schema dump:\n"
            "     {\"query\": \"{__schema{types{name fields{name type{name}}}}\"}\n"
            "   - IntrospectionQuery (full):\n"
            "     Use graphql-voyager to visualize schema\n"
            "   - If introspection disabled:\n"
            "     * Field suggestions in error messages\n"
            "     * Clairvoyance: Brute force field/type names\n"
            "3. AUTHORIZATION:\n"
            "   - Query depth attacks:\n"
            "     {user{posts{comments{author{posts{comments{...}}}}}}}\n"
            "   - Batch query attacks:\n"
            "     [{\"query\": \"...\"}, {\"query\": \"...\"}, ...] (100+ queries)\n"
            "   - Alias-based attacks:\n"
            "     {a: user(id: 1) {...}, b: user(id: 2) {...}, ...}\n"
            "   - Field-level authorization:\n"
            "     Can user A query user B's private fields?\n"
            "4. INJECTION:\n"
            "   - SQL injection in arguments:\n"
            "     {user(id: \"1' OR '1'='1\") {name}}\n"
            "   - SSRF in arguments:\n"
            "     mutation{importData(url: \"http://internal-service/\")}\n"
            "5. DENIAL OF SERVICE:\n"
            "   - Deeply nested queries (no depth limit)\n"
            "   - Circular fragment references\n"
            "   - Large result sets (no pagination limit)\n"
            "   - Aliases amplification\n"
            "6. MUTATIONS:\n"
            "   - Test all mutations for authorization\n"
            "   - Mass assignment via mutations\n"
            "   - File upload via multipart GraphQL\n"
            "TOOLS: graphql-voyager, Clairvoyance, InQL (Burp extension)"
        ),
        "tools": ["InQL", "graphql-voyager", "Clairvoyance", "Burp Suite"],
    },
    {
        "id": "api-003", "name": "gRPC Security Testing",
        "category": "grpc", "severity": "high",
        "owasp_api": "API2,API8",
        "desc": "gRPC-specific security testing.",
        "testing": (
            "GRPC SECURITY TESTING:\n"
            "1. DISCOVERY:\n"
            "   - gRPC reflection:\n"
            "     grpcurl -plaintext {host}:{port} list\n"
            "     grpcurl -plaintext {host}:{port} describe {service}\n"
            "   - Proto file extraction:\n"
            "     grpcurl -plaintext {host}:{port} describe | protoc --decode_raw\n"
            "   - Common ports: 50051, 443 (with TLS)\n"
            "2. AUTHENTICATION:\n"
            "   - No auth: Try calling methods without credentials\n"
            "   - Token in metadata:\n"
            "     grpcurl -H 'authorization: Bearer {token}' ...\n"
            "   - mTLS: Check if client cert is required\n"
            "3. AUTHORIZATION:\n"
            "   - Call privileged methods as unprivileged user\n"
            "   - IDOR in request messages\n"
            "   - Horizontal privilege escalation\n"
            "4. INJECTION:\n"
            "   - Protobuf field injection\n"
            "   - Unknown field handling\n"
            "   - Large message DoS\n"
            "5. TLS:\n"
            "   - Plaintext gRPC (no TLS)\n"
            "   - Certificate validation disabled\n"
            "   - Weak TLS configuration\n"
            "TOOLS: grpcurl, ghz (load testing), grpc-web-devtools"
        ),
        "tools": ["grpcurl", "ghz", "grpc-web-devtools"],
    },
    {
        "id": "api-004", "name": "WebSocket Security Testing",
        "category": "websocket", "severity": "high",
        "owasp_api": "API2,API8",
        "desc": "WebSocket-specific security testing.",
        "testing": (
            "WEBSOCKET SECURITY TESTING:\n"
            "1. DISCOVERY:\n"
            "   - WebSocket upgrade in HTTP response headers:\n"
            "     Upgrade: websocket, Connection: Upgrade\n"
            "   - Common endpoints: /ws, /socket, /websocket, /realtime\n"
            "   - Socket.IO: /socket.io/?EIO=4&transport=polling\n"
            "2. AUTHENTICATION:\n"
            "   - Token in URL: ws://host/ws?token=xxx (logged!)\n"
            "   - No auth after upgrade (HTTP auth only)\n"
            "   - Session fixation via WebSocket\n"
            "   - Cross-Site WebSocket Hijacking (CSWSH):\n"
            "     * Check Origin header validation\n"
            "     * If no Origin check → any page can connect\n"
            "3. MESSAGE INJECTION:\n"
            "   - XSS in WebSocket messages (reflected in UI)\n"
            "   - SQL injection in message parameters\n"
            "   - Command injection in message processing\n"
            "   - JSON message manipulation\n"
            "4. DENIAL OF SERVICE:\n"
            "   - Connection flooding: Open thousands of connections\n"
            "   - Large message: Send multi-MB messages\n"
            "   - Slow read: Accept data very slowly\n"
            "   - Ping/pong abuse\n"
            "5. DATA EXPOSURE:\n"
            "   - Subscribe to privileged channels\n"
            "   - Broadcast message interception\n"
            "   - Unencrypted ws:// (not wss://)\n"
            "TOOLS: wscat, websocat, Burp Suite WebSocket tab"
        ),
        "tools": ["wscat", "websocat", "Burp Suite"],
    },
]


class APISecurityKB:
    """API security knowledge base.

    Provides API-specific security testing methodology
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, APIVulnPattern] = {}
        self._log = logger.bind(component="api_security_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load API vulnerability patterns."""
        for data in API_VULN_PATTERNS:
            pattern = APIVulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                owasp_api=data.get("owasp_api", ""),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_category(
        self,
        category: str,
    ) -> list[APIVulnPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category == category
        ]

    def build_api_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 3,
    ) -> str:
        """Build API security prompt."""
        lines = ["## API Security Testing\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category not in categories:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            if pattern.owasp_api:
                lines.append(f"OWASP API: {pattern.owasp_api}")
            lines.append(pattern.testing_methodology)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            cat_counts[p.category] += 1
        return {
            "patterns": len(self._patterns),
            "by_category": dict(cat_counts),
        }
