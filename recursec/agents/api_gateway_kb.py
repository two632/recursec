"""API gateway and proxy security knowledge base.

Deep knowledge about API security:
1. REST API vulnerabilities
2. GraphQL attacks
3. gRPC security
4. API gateway misconfiguration
5. Rate limiting and abuse
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class APIGatewayPattern:
    """An API gateway security pattern."""
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


APIGATEWAY_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "api-001", "name": "REST API Vulnerabilities",
        "category": "rest", "severity": "high",
        "desc": "REST API security vulnerabilities.",
        "detection": (
            "REST API VULNERABILITIES:\n"
            "AUTHENTICATION:\n"
            "  - Missing authentication on endpoints\n"
            "  - Broken JWT validation\n"
            "    # None algorithm\n"
            "    # Weak secret (brute force)\n"
            "    # Algorithm confusion (RS256→HS256)\n"
            "    # Kid header injection\n"
            "  - API key exposure\n"
            "  - OAuth misconfig\n"
            "    # Redirect URI validation\n"
            "    # CSRF in OAuth flow\n"
            "    # Token leakage\n"
            "AUTHORIZATION:\n"
            "  - BOLA (Broken Object Level Auth)\n"
            "    # IDOR: /api/users/123 → /api/users/124\n"
            "    # UUID enumeration\n"
            "  - BFLA (Broken Function Level Auth)\n"
            "    # Admin endpoints accessible to users\n"
            "    # HTTP method tampering (GET→PUT)\n"
            "  - Mass assignment\n"
            "    # {\"role\":\"admin\",\"isVerified\":true}\n"
            "    # Hidden parameters\n"
            "DATA EXPOSURE:\n"
            "  - Excessive data in responses\n"
            "  - Debug/error info leakage\n"
            "  - Stack traces in errors\n"
            "  - Verbose error messages\n"
            "  - API documentation exposure\n"
            "    # /swagger-ui.html\n"
            "    # /api-docs\n"
            "    # /openapi.json\n"
            "TOOLS:\n"
            "  Burp Suite, Postman, jwt_tool, Arjun"
        ),
        "tools": [],
    },
    {
        "id": "api-002", "name": "GraphQL Attacks",
        "category": "graphql", "severity": "high",
        "desc": "GraphQL-specific attack techniques.",
        "detection": (
            "GRAPHQL ATTACKS:\n"
            "INTROSPECTION:\n"
            "  - Full schema dump\n"
            "    # query { __schema { types { name fields { name } } } }\n"
            "  - Disabled? Try:\n"
            "    # Alternate endpoints (/graphql, /api/graphql)\n"
            "    # GET vs POST\n"
            "    # Field suggestion errors\n"
            "INJECTION:\n"
            "  - SQL injection in resolvers\n"
            "  - NoSQL injection\n"
            "  - OS command injection\n"
            "  - SSRF in resolvers\n"
            "ABUSE:\n"
            "  - Nested query DoS\n"
            "    # query { user { friends { friends { friends ... } } } }\n"
            "  - Batch attacks\n"
            "    # [{query: q1}, {query: q2}, ...]\n"
            "  - Alias-based rate limit bypass\n"
            "    # query { a: user(id:1) b: user(id:2) ... }\n"
            "  - Directive overloading\n"
            "AUTHORIZATION:\n"
            "  - Query-level auth bypass\n"
            "  - Mutation without auth\n"
            "  - Subscription leakage\n"
            "  - Field-level access control\n"
            "TOOLS:\n"
            "  GraphQLmap, InQL, Clairvoyance, graphw00f"
        ),
        "tools": [],
    },
    {
        "id": "api-003", "name": "gRPC Security",
        "category": "grpc", "severity": "medium",
        "desc": "gRPC security assessment.",
        "detection": (
            "GRPC SECURITY:\n"
            "DISCOVERY:\n"
            "  - Server reflection enabled\n"
            "    # grpcurl -plaintext HOST:PORT list\n"
            "    # grpcurl -plaintext HOST:PORT describe SERVICE\n"
            "  - Proto file recovery\n"
            "  - Port scanning (50051 default)\n"
            "TESTING:\n"
            "  - No TLS (plaintext gRPC)\n"
            "  - Missing authentication\n"
            "    # No metadata/token validation\n"
            "  - Authorization bypass\n"
            "  - Input validation on protobuf\n"
            "    # Type confusion\n"
            "    # Overflow fields\n"
            "    # Missing required fields\n"
            "  - Streaming abuse\n"
            "    # Infinite stream DoS\n"
            "    # Large message\n"
            "PROTOBUF:\n"
            "  - Decode unknown messages\n"
            "    # protoc --decode_raw < binary\n"
            "  - Schema guessing\n"
            "  - Field manipulation\n"
            "INTERCEPTION:\n"
            "  - mitmproxy with gRPC\n"
            "  - Burp with gRPC-web\n"
            "  - Custom protobuf proxies\n"
            "TOOLS:\n"
            "  grpcurl, grpcui, Postman, mitmproxy"
        ),
        "tools": [],
    },
    {
        "id": "api-004", "name": "API Gateway Misconfiguration",
        "category": "gateway", "severity": "critical",
        "desc": "API gateway misconfiguration.",
        "detection": (
            "API GATEWAY MISCONFIGURATION:\n"
            "NGINX:\n"
            "  - Path traversal via normalization\n"
            "    # /api/../admin → /admin\n"
            "    # Double URL encoding\n"
            "  - Alias misconfiguration\n"
            "  - Proxy header injection\n"
            "  - Missing Host validation\n"
            "KONG:\n"
            "  - Admin API exposure (port 8001)\n"
            "  - Plugin misconfiguration\n"
            "  - JWT validation bypass\n"
            "  - Rate limiting bypass\n"
            "AWS API GATEWAY:\n"
            "  - Missing auth on resources\n"
            "  - Lambda injection via proxy\n"
            "  - Stage variable injection\n"
            "  - CORS misconfiguration\n"
            "  - WAF bypass techniques\n"
            "ENVOY:\n"
            "  - Admin interface exposure\n"
            "  - Route manipulation\n"
            "  - Header injection\n"
            "GENERAL:\n"
            "  - Request smuggling\n"
            "    # CL.TE / TE.CL discrepancies\n"
            "  - SSRF via backend routing\n"
            "  - Version/path parameter bypass\n"
            "    # /api/v1/admin → /api/v2/admin\n"
            "  - Caching poisoning\n"
            "TOOLS:\n"
            "  Burp Suite, smuggler, httpx"
        ),
        "tools": [],
    },
    {
        "id": "api-005", "name": "Rate Limiting and Abuse",
        "category": "rate_limit", "severity": "medium",
        "desc": "Rate limiting bypass and API abuse.",
        "detection": (
            "RATE LIMITING & ABUSE:\n"
            "BYPASS TECHNIQUES:\n"
            "  - IP rotation (proxies)\n"
            "  - Header manipulation\n"
            "    # X-Forwarded-For: 127.0.0.1\n"
            "    # X-Real-IP: random\n"
            "    # X-Originating-IP\n"
            "  - User-Agent rotation\n"
            "  - Path variation\n"
            "    # /api/users vs /API/users\n"
            "    # /api/users/ vs /api/users\n"
            "    # /api/./users\n"
            "  - Parameter pollution\n"
            "    # ?id=1&id=2\n"
            "  - GraphQL alias batching\n"
            "  - API version switching\n"
            "  - HTTP method change\n"
            "ABUSE PATTERNS:\n"
            "  - Account enumeration\n"
            "  - Credential stuffing\n"
            "  - Scraping/data harvesting\n"
            "  - Resource exhaustion\n"
            "  - Price manipulation\n"
            "  - Coupon/reward abuse\n"
            "DETECTION:\n"
            "  - Response time analysis\n"
            "  - Error rate monitoring\n"
            "  - Behavioral analysis\n"
            "  - Token bucket testing\n"
            "TOOLS:\n"
            "  Burp Intruder, custom scripts, wrk"
        ),
        "tools": [],
    },
]


class APIGatewayKB:
    """API gateway security knowledge base.

    Provides API security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, APIGatewayPattern] = {}
        self._log = logger.bind(component="api_gw_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load API patterns."""
        for data in APIGATEWAY_PATTERNS:
            pattern = APIGatewayPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[APIGatewayPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_apigateway_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build API gateway security prompt."""
        lines = ["## API Gateway Security\n"]
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
