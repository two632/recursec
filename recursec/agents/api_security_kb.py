"""API security knowledge base.

Deep knowledge about API vulnerabilities:
1. REST API security patterns
2. GraphQL security issues
3. gRPC attack vectors
4. WebSocket security
5. OAuth/JWT attacks
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
    api_type: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "type": self.api_type[:10],
        }


API_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "api-001", "name": "GraphQL Introspection and Injection",
        "api_type": "graphql", "severity": "high",
        "desc": "GraphQL-specific attack patterns.",
        "detection": (
            "GRAPHQL SECURITY:\n"
            "INTROSPECTION:\n"
            "  - Query: { __schema { types { name fields { name } } } }\n"
            "  - Full introspection: { __schema { queryType { name } mutationType { name } "
            "types { name kind fields { name args { name type { name } } } } } }\n"
            "  - Tools: graphql-voyager (visualization), InQL (Burp extension)\n"
            "  - Check: POST /graphql with introspection query\n"
            "INJECTION:\n"
            "  - SQL injection in arguments: { user(id: \"1' OR 1=1--\") { name } }\n"
            "  - NoSQL injection: { user(filter: \"{\\\"$gt\\\": \\\"\\\"}\") { name } }\n"
            "  - Nested query DoS (batching): [{query: q1}, {query: q2}, ...]\n"
            "AUTHORIZATION:\n"
            "  - Query depth attacks: deeply nested relationships\n"
            "  - Field-level authorization bypass\n"
            "  - Mutation authorization: test if mutations work without auth\n"
            "  - Subscription eavesdropping\n"
            "INFORMATION DISCLOSURE:\n"
            "  - Verbose error messages with stack traces\n"
            "  - Debug/development mode enabled\n"
            "  - Suggestions in errors revealing field names\n"
            "TESTING:\n"
            "  1. Test for introspection (should be disabled in production)\n"
            "  2. Map all queries, mutations, subscriptions\n"
            "  3. Test authorization on each field/type\n"
            "  4. Test input validation on all arguments\n"
            "  5. Test query complexity limits (DoS)"
        ),
        "tools": ["graphql-voyager", "inql", "burp"],
    },
    {
        "id": "api-002", "name": "REST API Mass Assignment",
        "api_type": "rest", "severity": "high",
        "desc": "Mass assignment / parameter pollution in REST APIs.",
        "detection": (
            "REST API MASS ASSIGNMENT:\n"
            "DETECTION:\n"
            "  - Find API endpoints that accept JSON objects\n"
            "  - Add extra fields not in the UI: {\"name\": \"test\", \"role\": \"admin\"}\n"
            "  - Common fields to try:\n"
            "    {\"is_admin\": true}\n"
            "    {\"role\": \"admin\"}\n"
            "    {\"verified\": true}\n"
            "    {\"active\": true}\n"
            "    {\"balance\": 99999}\n"
            "    {\"plan\": \"enterprise\"}\n"
            "    {\"discount\": 100}\n"
            "TESTING METHODOLOGY:\n"
            "  1. Capture normal request with all expected fields\n"
            "  2. Study API documentation or response format for additional fields\n"
            "  3. Add extra fields from response into request\n"
            "  4. Check if server accepted the extra fields\n"
            "  5. Test PUT, PATCH, and POST endpoints\n"
            "PARAMETER POLLUTION:\n"
            "  - Duplicate params: ?id=1&id=2 (server-dependent behavior)\n"
            "  - Array injection: ?id[]=1&id[]=2\n"
            "  - JSON in query: ?filter={\"role\":\"admin\"}\n"
            "  - Nested objects: user[role]=admin\n"
            "COMMON VULNERABLE FRAMEWORKS:\n"
            "  - Ruby on Rails: Strong Parameters bypass\n"
            "  - Django: ModelSerializer accepting all fields\n"
            "  - Express: body-parser accepting nested objects"
        ),
        "tools": ["burp", "ffuf", "curl"],
    },
    {
        "id": "api-003", "name": "WebSocket Security",
        "api_type": "websocket", "severity": "high",
        "desc": "WebSocket protocol security issues.",
        "detection": (
            "WEBSOCKET SECURITY:\n"
            "DISCOVERY:\n"
            "  - Look for ws:// or wss:// URLs in JavaScript\n"
            "  - Check for Upgrade: websocket headers\n"
            "  - Common paths: /ws, /socket, /socket.io, /realtime\n"
            "CROSS-SITE WEBSOCKET HIJACKING:\n"
            "  - WebSocket doesn't follow same-origin policy by default\n"
            "  - Test: Open WebSocket from different origin\n"
            "  - If server doesn't check Origin header → hijackable\n"
            "  - Exploit: Create malicious page that connects to victim's WS\n"
            "INJECTION:\n"
            "  - Send malicious payloads via WebSocket messages\n"
            "  - XSS if messages are rendered in DOM\n"
            "  - SQL injection if messages query database\n"
            "  - Command injection if messages trigger system commands\n"
            "AUTHENTICATION:\n"
            "  - Check if WS requires authentication\n"
            "  - Token handling: Is token validated per message or only on connect?\n"
            "  - Session fixation: Can you replay old WS session?\n"
            "RATE LIMITING:\n"
            "  - Most WS implementations lack rate limiting\n"
            "  - Flood testing: Send many messages rapidly\n"
            "  - Resource exhaustion: Send very large messages"
        ),
        "tools": ["burp", "wssip", "curl"],
    },
    {
        "id": "api-004", "name": "OAuth 2.0 Vulnerabilities",
        "api_type": "oauth", "severity": "critical",
        "desc": "OAuth 2.0 implementation vulnerabilities.",
        "detection": (
            "OAUTH 2.0 ATTACKS:\n"
            "REDIRECT URI MANIPULATION:\n"
            "  - Open redirect: redirect_uri=https://evil.com\n"
            "  - Subdomain takeover: redirect_uri=https://sub.legitimate.com\n"
            "  - Path traversal: redirect_uri=https://legitimate.com/../evil\n"
            "  - Fragment injection: redirect_uri=https://legitimate.com#evil\n"
            "CSRF ATTACKS:\n"
            "  - Missing state parameter → CSRF in OAuth flow\n"
            "  - Predictable state values\n"
            "  - State parameter not bound to session\n"
            "TOKEN ATTACKS:\n"
            "  - Authorization code reuse (should be single-use)\n"
            "  - Token leakage via Referer header\n"
            "  - Implicit flow token in URL fragment\n"
            "  - Client secret exposure in JavaScript\n"
            "SCOPE MANIPULATION:\n"
            "  - Request elevated scope: scope=admin\n"
            "  - Scope upgrade after initial grant\n"
            "  - Missing scope validation on resource server\n"
            "TESTING:\n"
            "  1. Map complete OAuth flow (authorization, token, resource)\n"
            "  2. Test redirect_uri validation\n"
            "  3. Test state parameter implementation\n"
            "  4. Test authorization code for single-use\n"
            "  5. Test scope enforcement"
        ),
        "tools": ["burp", "oauth-tools", "curl"],
    },
    {
        "id": "api-005", "name": "API Rate Limiting and DoS",
        "api_type": "rest", "severity": "medium",
        "desc": "API rate limiting bypass and denial of service.",
        "detection": (
            "API RATE LIMITING AND DoS:\n"
            "ENUMERATION:\n"
            "  - Check response headers: X-RateLimit-Limit, X-RateLimit-Remaining\n"
            "  - Retry-After header\n"
            "  - 429 Too Many Requests status code\n"
            "BYPASS TECHNIQUES:\n"
            "  - IP rotation headers: X-Forwarded-For, X-Real-IP\n"
            "  - HTTP method variation: GET vs POST vs OPTIONS\n"
            "  - Endpoint variation: /api/v1/users vs /api/v1/users/\n"
            "  - User-Agent rotation\n"
            "  - API key rotation (if multiple available)\n"
            "  - Distributed requests from multiple IPs\n"
            "RESOURCE EXHAUSTION:\n"
            "  - Large payload: Send very large JSON body\n"
            "  - Regex DoS (ReDoS): Craft input that triggers exponential regex\n"
            "  - Pagination abuse: ?page=1&limit=1000000\n"
            "  - Search abuse: Complex search queries\n"
            "  - File upload: Very large file or many concurrent uploads\n"
            "  - GraphQL complexity: Deeply nested queries\n"
            "TESTING:\n"
            "  1. Identify rate-limited endpoints\n"
            "  2. Measure rate limit thresholds\n"
            "  3. Test bypass techniques\n"
            "  4. Test resource exhaustion vectors"
        ),
        "tools": ["ffuf", "nuclei", "curl"],
    },
]


class APISecurityKB:
    """API security knowledge base.

    Provides API-specific attack patterns
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
                api_type=data.get("api_type", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_type(self, api_type: str) -> list[APIPattern]:
        """Get patterns by API type."""
        return [
            p for p in self._patterns.values()
            if p.api_type.lower() == api_type.lower()
        ]

    def build_api_prompt(
        self,
        api_types: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build API security prompt."""
        lines = ["## API Security Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if api_types and pattern.api_type.lower() not in [t.lower() for t in api_types]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.api_type.upper()}]")
            lines.append(pattern.detection_strategy)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for p in self._patterns.values():
            type_counts[p.api_type] = type_counts.get(p.api_type, 0) + 1
        return {
            "patterns": len(self._patterns),
            "by_type": type_counts,
        }
