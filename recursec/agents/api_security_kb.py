"""API security knowledge base.

Deep knowledge about API security:
1. REST API security
2. GraphQL security
3. gRPC security
4. WebSocket security
5. API authentication attacks
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
        "id": "api-001", "name": "REST API Security",
        "category": "rest", "severity": "high",
        "desc": "REST API security testing.",
        "detection": (
            "REST API SECURITY:\n"
            "OWASP API TOP 10 (2023):\n"
            "  API1: Broken Object Level Authorization (BOLA)\n"
            "    - Horizontal privilege escalation\n"
            "    - IDOR (Insecure Direct Object Ref)\n"
            "    - Test: change resource IDs in requests\n"
            "  API2: Broken Authentication\n"
            "    - Weak token validation\n"
            "    - Missing rate limiting on auth\n"
            "    - Token leakage in URLs/logs\n"
            "  API3: Broken Object Property Level Auth\n"
            "    - Mass assignment\n"
            "    - Excessive data exposure\n"
            "    - Hidden fields in responses\n"
            "  API4: Unrestricted Resource Consumption\n"
            "    - Missing rate limits\n"
            "    - Large payload DoS\n"
            "    - Pagination abuse\n"
            "  API5: Broken Function Level Auth (BFLA)\n"
            "    - Vertical privilege escalation\n"
            "    - Admin function access\n"
            "  API6: Unrestricted Access to Sensitive Flows\n"
            "    - Automation abuse\n"
            "    - Business logic bypass\n"
            "  API7: Server-Side Request Forgery (SSRF)\n"
            "    - Internal network access\n"
            "    - Cloud metadata (169.254.169.254)\n"
            "  API8: Security Misconfiguration\n"
            "    - Verbose errors\n"
            "    - Missing CORS restrictions\n"
            "    - Default credentials\n"
            "  API9: Improper Inventory Management\n"
            "    - Undocumented endpoints\n"
            "    - Old API versions\n"
            "  API10: Unsafe Consumption of APIs\n"
            "    - Third-party API trust\n"
            "TOOLS:\n"
            "  Burp Suite, Postman, REST-assured"
        ),
        "tools": ["burp"],
    },
    {
        "id": "api-002", "name": "GraphQL Security",
        "category": "graphql", "severity": "high",
        "desc": "GraphQL API security testing.",
        "detection": (
            "GRAPHQL SECURITY:\n"
            "INTROSPECTION:\n"
            "  # Query full schema\n"
            "  { __schema { types { name fields { name } } } }\n"
            "  # Tools\n"
            "  graphql-voyager\n"
            "  InQL (Burp extension)\n"
            "  graphw00f (fingerprint)\n"
            "ATTACKS:\n"
            "  INJECTION:\n"
            "    - SQL injection via arguments\n"
            "    - NoSQL injection\n"
            "    - OS command injection\n"
            "    mutation { createUser(name: \"'; DROP TABLE--\") }\n"
            "  DENIAL OF SERVICE:\n"
            "    - Deeply nested queries\n"
            "    { user { friends { friends { friends { ... } } } } }\n"
            "    - Circular fragments\n"
            "    - Batch query abuse\n"
            "    - Alias overloading\n"
            "  AUTHORIZATION:\n"
            "    - Missing field-level auth\n"
            "    - Mutations without auth\n"
            "    - Subscription data leaks\n"
            "  INFORMATION DISCLOSURE:\n"
            "    - Stack traces in errors\n"
            "    - Suggestions in errors\n"
            "    - Introspection enabled in prod\n"
            "DEFENSE BYPASS:\n"
            "  - Query depth limiting bypass\n"
            "  - Cost analysis bypass\n"
            "  - Rate limiting per-query bypass\n"
            "  - Persisted query abuse\n"
            "TOOLS:\n"
            "  InQL, GraphQLmap, Clairvoyance, BatchQL"
        ),
        "tools": ["inql"],
    },
    {
        "id": "api-003", "name": "gRPC Security",
        "category": "grpc", "severity": "medium",
        "desc": "gRPC API security testing.",
        "detection": (
            "gRPC SECURITY:\n"
            "RECONNAISSANCE:\n"
            "  # gRPC reflection\n"
            "  grpcurl -plaintext localhost:50051 list\n"
            "  grpcurl -plaintext localhost:50051 describe\n"
            "  # Proto file extraction\n"
            "  # grpc-client-cli\n"
            "ATTACKS:\n"
            "  AUTHENTICATION:\n"
            "    - Missing mTLS\n"
            "    - Weak token validation\n"
            "    - Metadata header injection\n"
            "    - Interceptor bypass\n"
            "  INJECTION:\n"
            "    - Protobuf message manipulation\n"
            "    - Field type confusion\n"
            "    - Oneof field abuse\n"
            "    - Repeated field overflow\n"
            "  DENIAL OF SERVICE:\n"
            "    - Large message (default 4MB limit)\n"
            "    - Stream flooding\n"
            "    - Keepalive abuse\n"
            "    - Deadline propagation\n"
            "  INFORMATION DISCLOSURE:\n"
            "    - Reflection service enabled\n"
            "    - Error messages leaking\n"
            "    - Server version exposure\n"
            "INTERCEPTOR BYPASS:\n"
            "  - Auth interceptor ordering\n"
            "  - Stream vs unary auth gaps\n"
            "  - Metadata forwarding trust\n"
            "TOOLS:\n"
            "  grpcurl, grpc-client-cli, ghz (load test)"
        ),
        "tools": ["grpcurl"],
    },
    {
        "id": "api-004", "name": "WebSocket Security",
        "category": "websocket", "severity": "high",
        "desc": "WebSocket security testing.",
        "detection": (
            "WEBSOCKET SECURITY:\n"
            "HANDSHAKE:\n"
            "  - Origin header validation\n"
            "  - Cross-Site WebSocket Hijacking (CSWSH)\n"
            "  - Missing authentication in upgrade\n"
            "  - Sec-WebSocket-Key manipulation\n"
            "ATTACKS:\n"
            "  INJECTION:\n"
            "    - SQL/NoSQL via WS messages\n"
            "    - XSS via WS reflected data\n"
            "    - Command injection\n"
            "  AUTHORIZATION:\n"
            "    - Missing message-level auth\n"
            "    - Channel subscription abuse\n"
            "    - Race conditions\n"
            "  DENIAL OF SERVICE:\n"
            "    - Large frame flooding\n"
            "    - Connection exhaustion\n"
            "    - Slow-read attacks\n"
            "    - Ping/pong abuse\n"
            "  DATA MANIPULATION:\n"
            "    - Message tampering\n"
            "    - Replay attacks\n"
            "    - Out-of-order messages\n"
            "    - Binary frame injection\n"
            "TESTING:\n"
            "  - Burp Suite WebSocket tab\n"
            "  - websocat (CLI WebSocket client)\n"
            "  - Custom Python (websockets lib)\n"
            "  - Browser DevTools (WS inspector)\n"
            "TOOLS:\n"
            "  Burp Suite, websocat, OWASP ZAP"
        ),
        "tools": ["burp"],
    },
    {
        "id": "api-005", "name": "API Authentication Attacks",
        "category": "auth", "severity": "critical",
        "desc": "API authentication attack patterns.",
        "detection": (
            "API AUTH ATTACKS:\n"
            "JWT:\n"
            "  - None algorithm attack\n"
            "    {\"alg\":\"none\"} → unsigned token\n"
            "  - Algorithm confusion (RS256→HS256)\n"
            "    Symmetric key = public key\n"
            "  - Weak secret brute force\n"
            "    hashcat -m 16500 jwt.txt wordlist\n"
            "  - JKU/X5U header injection\n"
            "    Point to attacker JWKS\n"
            "  - Kid header injection\n"
            "    SQL injection in kid parameter\n"
            "  - Expired token acceptance\n"
            "  - Missing audience/issuer validation\n"
            "OAUTH2:\n"
            "  - Authorization code theft\n"
            "  - PKCE bypass\n"
            "  - Token exchange abuse\n"
            "  - Open redirect → token steal\n"
            "  - Client credential exposure\n"
            "  - Scope escalation\n"
            "  - State parameter bypass (CSRF)\n"
            "API KEYS:\n"
            "  - Key exposure (GitHub, logs, URLs)\n"
            "  - Insufficient key scoping\n"
            "  - Key rotation gaps\n"
            "  - Shared keys across environments\n"
            "  - Missing key revocation\n"
            "SAML:\n"
            "  - XML Signature Wrapping\n"
            "  - Assertion replay\n"
            "  - Comment injection\n"
            "  - Parser differential\n"
            "TOOLS:\n"
            "  jwt_tool, Burp JWT extensions, oauth-tools"
        ),
        "tools": ["jwt_tool"],
    },
]


class APISecurityKB:
    """API security knowledge base.

    Provides API security patterns
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
