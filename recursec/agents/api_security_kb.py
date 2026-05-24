"""API security knowledge base.

Deep knowledge about API security testing:
1. REST API vulnerabilities
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
        "id": "api-001", "name": "REST API Vulnerabilities",
        "category": "rest", "severity": "high",
        "desc": "REST API security vulnerabilities.",
        "detection": (
            "REST API VULNERABILITIES:\n"
            "OWASP API TOP 10 (2023):\n"
            "  API1: Broken Object Level Authorization (BOLA/IDOR)\n"
            "    - Change ID in /api/users/123 → /api/users/124\n"
            "    - UUID enumeration\n"
            "    - Check every endpoint with different user IDs\n"
            "  API2: Broken Authentication\n"
            "    - Weak JWT (none algo, weak secret)\n"
            "    - API key exposure\n"
            "    - No rate limiting on auth endpoints\n"
            "  API3: Broken Object Property Level Authorization\n"
            "    - Mass assignment: send extra fields in PUT/PATCH\n"
            "    - Excessive data exposure in responses\n"
            "  API4: Unrestricted Resource Consumption\n"
            "    - No pagination limits\n"
            "    - GraphQL depth/complexity\n"
            "    - File upload size limits\n"
            "  API5: Broken Function Level Authorization\n"
            "    - Admin endpoints accessible to users\n"
            "    - HTTP method tampering (GET→DELETE)\n"
            "  API6: Unrestricted Access to Sensitive Business Flows\n"
            "    - Purchase flow abuse\n"
            "    - Comment/review spam\n"
            "  API7: Server Side Request Forgery\n"
            "  API8: Security Misconfiguration\n"
            "    - CORS misconfiguration\n"
            "    - Verbose error messages\n"
            "    - Default credentials\n"
            "  API9: Improper Inventory Management\n"
            "    - Deprecated API versions still active\n"
            "    - Shadow APIs\n"
            "  API10: Unsafe Consumption of APIs\n"
            "    - Trusting third-party API responses\n"
            "TOOLS:\n"
            "  Burp Suite, Postman, ffuf, nuclei, arjun"
        ),
        "tools": ["burp", "postman", "arjun"],
    },
    {
        "id": "api-002", "name": "GraphQL Security",
        "category": "graphql", "severity": "high",
        "desc": "GraphQL API security testing.",
        "detection": (
            "GRAPHQL SECURITY:\n"
            "INTROSPECTION:\n"
            "  # Query schema\n"
            "  {__schema{types{name,fields{name,args{name}}}}}\n"
            "  # Tools: graphql-voyager, InQL\n"
            "  # Disable in production!\n"
            "ATTACKS:\n"
            "  INJECTION:\n"
            "    - SQLi through GraphQL variables\n"
            "    - NoSQLi in resolvers\n"
            "    - SSRF via URL fields\n"
            "  AUTHORIZATION:\n"
            "    - Query fields you shouldn't access\n"
            "    - Nested object access (user.admin.settings)\n"
            "    - Mutation authorization bypass\n"
            "    - Batch queries to bypass rate limits\n"
            "  DENIAL OF SERVICE:\n"
            "    - Deep nesting: {a{b{c{d{e{f}}}}}}\n"
            "    - Circular fragments\n"
            "    - Aliases: query { a1:user(id:1) a2:user(id:2) ... }\n"
            "    - Unbounded list queries\n"
            "  INFORMATION DISCLOSURE:\n"
            "    - Field suggestions (typo reveals field names)\n"
            "    - Debug mode errors\n"
            "    - Stack traces\n"
            "PREVENTION:\n"
            "  - Disable introspection in prod\n"
            "  - Query depth limiting\n"
            "  - Query complexity analysis\n"
            "  - Persisted queries only\n"
            "TOOLS:\n"
            "  InQL, graphw00f, GraphQL Voyager, clairvoyance"
        ),
        "tools": ["inql", "graphw00f"],
    },
    {
        "id": "api-003", "name": "gRPC Security",
        "category": "grpc", "severity": "medium",
        "desc": "gRPC API security testing.",
        "detection": (
            "gRPC SECURITY:\n"
            "DISCOVERY:\n"
            "  # Server reflection (if enabled)\n"
            "  grpcurl -plaintext host:port list\n"
            "  grpcurl -plaintext host:port describe <service>\n"
            "  # Protobuf file extraction\n"
            "  # Service enumeration\n"
            "ATTACKS:\n"
            "  AUTHENTICATION:\n"
            "    - Missing auth on streams\n"
            "    - Token in metadata vs channel\n"
            "    - mTLS misconfiguration\n"
            "  INJECTION:\n"
            "    - Protobuf field manipulation\n"
            "    - Type confusion (int32 overflow)\n"
            "    - Unknown field numbers\n"
            "  AUTHORIZATION:\n"
            "    - Method-level access control\n"
            "    - Stream message authorization\n"
            "    - Cross-service requests\n"
            "  RESOURCE:\n"
            "    - Large message payload\n"
            "    - Stream flooding\n"
            "    - Deadline manipulation\n"
            "  INTERCEPTION:\n"
            "    - Plaintext gRPC (no TLS)\n"
            "    - HTTP/2 MITM\n"
            "    - Channel credential theft\n"
            "TOOLS:\n"
            "  grpcurl, grpcui, protobuf-inspector, evans"
        ),
        "tools": ["grpcurl", "evans"],
    },
    {
        "id": "api-004", "name": "WebSocket Security",
        "category": "websocket", "severity": "high",
        "desc": "WebSocket security testing.",
        "detection": (
            "WEBSOCKET SECURITY:\n"
            "CONNECTION:\n"
            "  - Upgrade from HTTP(S)\n"
            "  - Origin header validation (CSWSH)\n"
            "  - Authentication in handshake\n"
            "  - Token in URL query string (logged!)\n"
            "ATTACKS:\n"
            "  CROSS-SITE WEBSOCKET HIJACKING:\n"
            "    - Malicious page opens WS to target\n"
            "    - No Origin check → full hijack\n"
            "    - Read/write messages as victim\n"
            "  INJECTION:\n"
            "    - SQLi through WS messages\n"
            "    - XSS via WS → DOM render\n"
            "    - Command injection in message\n"
            "  AUTHORIZATION:\n"
            "    - Subscribe to unauthorized channels\n"
            "    - Send admin-only messages\n"
            "    - Replay messages\n"
            "  DENIAL OF SERVICE:\n"
            "    - Connection flooding\n"
            "    - Large message frames\n"
            "    - Slow read attack\n"
            "  INFORMATION LEAK:\n"
            "    - Sensitive data in WS messages\n"
            "    - Broadcast to wrong recipients\n"
            "    - Debug messages in production\n"
            "TESTING:\n"
            "  - Intercept with Burp (Repeater → WS)\n"
            "  - wscat for manual testing\n"
            "  - Autobahn for fuzzing\n"
            "TOOLS:\n"
            "  Burp Suite, wscat, websocat, Autobahn"
        ),
        "tools": ["burp", "wscat"],
    },
    {
        "id": "api-005", "name": "API Auth Attacks",
        "category": "auth", "severity": "critical",
        "desc": "API authentication attack techniques.",
        "detection": (
            "API AUTHENTICATION ATTACKS:\n"
            "JWT ATTACKS:\n"
            "  - Algorithm confusion (RS256→HS256)\n"
            "  - None algorithm: {\"alg\":\"none\"}\n"
            "  - Weak secret (hashcat -m 16500)\n"
            "  - Kid injection (path traversal in kid)\n"
            "  - JKU/X5U header injection\n"
            "  - JWT expiry not enforced\n"
            "  - No audience/issuer validation\n"
            "OAUTH:\n"
            "  - Open redirect in redirect_uri\n"
            "  - CSRF in OAuth flow (missing state)\n"
            "  - Token leakage in Referer\n"
            "  - Scope escalation\n"
            "  - Client credential theft\n"
            "  - PKCE downgrade\n"
            "API KEY:\n"
            "  - Key in URL (logged everywhere)\n"
            "  - Key reuse across environments\n"
            "  - No per-key rate limiting\n"
            "  - No key rotation\n"
            "  - Key scope too broad\n"
            "SESSION:\n"
            "  - Session fixation\n"
            "  - Session hijacking\n"
            "  - Insufficient session expiry\n"
            "  - No concurrent session limit\n"
            "  - Missing secure/httponly flags\n"
            "TOOLS:\n"
            "  jwt_tool, Burp JWT extensions, oauth-tester"
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
