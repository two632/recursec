"""API security knowledge base — REST, GraphQL, gRPC attack patterns.

Deep knowledge about API vulnerabilities:
1. BOLA/IDOR (Broken Object Level Authorization)
2. Broken Authentication
3. Excessive Data Exposure
4. Rate Limiting bypass
5. BFLA (Broken Function Level Authorization)
6. Mass Assignment
7. SSRF via API
8. GraphQL-specific attacks
9. gRPC-specific attacks
10. API versioning attacks
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class APIVulnPattern:
    """An API vulnerability pattern with methodology."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    owasp_api: str = ""           # OWASP API Security Top 10
    description: str = ""
    testing_methodology: str = ""
    detection_indicators: list[str] = field(default_factory=list)
    api_types: list[str] = field(default_factory=list)   # rest, graphql, grpc, soap

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "category": self.category[:15],
            "owasp": self.owasp_api[:10],
        }


API_VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "api-001", "name": "BOLA / IDOR",
        "category": "authorization", "severity": "critical",
        "owasp_api": "API1:2023",
        "api_types": ["rest", "graphql"],
        "desc": "Broken Object Level Authorization — accessing other users' resources by changing IDs.",
        "testing": (
            "BOLA/IDOR TESTING METHODOLOGY:\n"
            "1. IDENTIFY OBJECT REFERENCES:\n"
            "   - URL path: /api/users/{id}/profile, /api/orders/{id}\n"
            "   - Query params: ?user_id=123, ?order_id=456\n"
            "   - Request body: {\"user_id\": 123}\n"
            "   - Headers: X-User-ID, X-Account-ID\n"
            "2. TEST HORIZONTAL ESCALATION:\n"
            "   - Create two accounts (A and B)\n"
            "   - Use A's token to access B's resources by changing ID\n"
            "   - Test all CRUD operations: GET, POST, PUT, PATCH, DELETE\n"
            "3. ID ENUMERATION:\n"
            "   - Sequential IDs: Try id-1, id+1, id+2...\n"
            "   - UUID guessing: Check if UUIDs are time-based (v1) → predictable\n"
            "   - Leaked IDs: Check if IDs appear in other API responses\n"
            "4. ADVANCED TECHNIQUES:\n"
            "   - Parameter pollution: ?id=1&id=2 (which one is used?)\n"
            "   - Type juggling: id=1 vs id=\"1\" vs id=true\n"
            "   - Nested objects: /api/orgs/{org_id}/users/{user_id}\n"
            "   - Bulk operations: /api/users?ids=1,2,3,4,5\n"
            "5. GraphQL BOLA:\n"
            "   query { user(id: \"OTHER_USER_ID\") { email, address } }\n"
            "   mutation { updateUser(id: \"OTHER_USER_ID\", data: {...}) }"
        ),
        "indicators": ["API", "REST", "object ID", "user_id", "resource access"],
    },
    {
        "id": "api-002", "name": "Broken Authentication",
        "category": "authentication", "severity": "critical",
        "owasp_api": "API2:2023",
        "api_types": ["rest", "graphql", "grpc"],
        "desc": "Weak or flawed API authentication mechanisms.",
        "testing": (
            "API AUTHENTICATION TESTING:\n"
            "1. TOKEN ANALYSIS:\n"
            "   - JWT: Decode header/payload (base64), check algorithm\n"
            "   - alg:none attack: Set algorithm to 'none', remove signature\n"
            "   - RS256→HS256: Change from RSA to HMAC, sign with public key\n"
            "   - Weak secret: Brute-force JWT secret (hashcat mode 16500)\n"
            "   - KID injection: {\"kid\": \"../../dev/null\"} → empty key\n"
            "2. API KEY TESTING:\n"
            "   - Check if API key is in URL (leaked in logs, referrer)\n"
            "   - Test key revocation: Does revoking actually invalidate?\n"
            "   - Rate limiting per key vs per IP\n"
            "   - Key scope: Does one key work across all endpoints?\n"
            "3. OAUTH FLAWS:\n"
            "   - Missing state parameter → CSRF on OAuth flow\n"
            "   - Open redirect in redirect_uri → token theft\n"
            "   - Token in URL fragment → leaked in referrer\n"
            "   - Refresh token rotation: Is old refresh token invalidated?\n"
            "4. SESSION MANAGEMENT:\n"
            "   - Session fixation: Can attacker set session ID?\n"
            "   - Concurrent sessions: Login from multiple devices\n"
            "   - Logout: Does session actually get invalidated?\n"
            "5. PASSWORD RESET:\n"
            "   - Token predictability (sequential, time-based)\n"
            "   - Token reuse: Can same token be used twice?\n"
            "   - Host header injection in reset email"
        ),
        "indicators": ["JWT", "API key", "OAuth", "Bearer token", "authentication"],
    },
    {
        "id": "api-003", "name": "Excessive Data Exposure",
        "category": "data_exposure", "severity": "high",
        "owasp_api": "API3:2023",
        "api_types": ["rest", "graphql"],
        "desc": "API returns more data than necessary, relying on client-side filtering.",
        "testing": (
            "EXCESSIVE DATA EXPOSURE TESTING:\n"
            "1. RESPONSE ANALYSIS:\n"
            "   - Compare API response fields with what UI actually displays\n"
            "   - Look for: password hashes, tokens, internal IDs, PII, admin flags\n"
            "   - Check /api/users/me → does it return other users' data?\n"
            "2. DEBUG/VERBOSE MODES:\n"
            "   - Add ?debug=true, ?verbose=1, ?format=debug\n"
            "   - Check for stack traces, SQL queries in error responses\n"
            "   - X-Debug: 1 header\n"
            "3. CONTENT TYPE MANIPULATION:\n"
            "   - Request Accept: application/xml (may expose more fields)\n"
            "   - Request different API versions: /v1/ vs /v2/ vs /v3/\n"
            "4. GraphQL SPECIFIC:\n"
            "   - Introspection query: {__schema{types{name,fields{name}}}}\n"
            "   - Request ALL fields on a type\n"
            "   - Nested queries to reach hidden relationships\n"
            "5. BATCH REQUESTS:\n"
            "   - /api/users?limit=10000 (return all users)\n"
            "   - Pagination abuse: Follow all pages to enumerate"
        ),
        "indicators": ["API response", "JSON", "user profile", "list endpoint"],
    },
    {
        "id": "api-004", "name": "Rate Limiting Bypass",
        "category": "availability", "severity": "medium",
        "owasp_api": "API4:2023",
        "api_types": ["rest", "graphql", "grpc"],
        "desc": "Circumventing API rate limits to abuse functionality.",
        "testing": (
            "RATE LIMITING BYPASS TESTING:\n"
            "1. IDENTIFY LIMITS:\n"
            "   - Send rapid requests, note when throttled\n"
            "   - Check headers: X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After\n"
            "2. BYPASS TECHNIQUES:\n"
            "   - IP rotation: Use different source IPs\n"
            "   - Header spoofing: X-Forwarded-For: 1.2.3.4 (new IP each request)\n"
            "   - X-Real-IP, X-Originating-IP, X-Client-IP headers\n"
            "   - API key rotation: Use different API keys\n"
            "   - Endpoint variation: /api/login vs /API/LOGIN vs /api/login/\n"
            "   - HTTP method change: POST vs PUT (same endpoint, different counter)\n"
            "3. RACE CONDITION:\n"
            "   - Send requests simultaneously to bypass per-second limits\n"
            "   - Multiple connections in parallel\n"
            "4. GraphQL SPECIFIC:\n"
            "   - Batch queries: [{query1}, {query2}, ..., {query100}] in single request\n"
            "   - Aliases: { a: user(id:1), b: user(id:2), ... } → many queries in one\n"
            "5. IMPACT:\n"
            "   - Brute force credentials\n"
            "   - SMS/email bombing\n"
            "   - Resource exhaustion (DoS)"
        ),
        "indicators": ["rate limit", "throttle", "too many requests", "429"],
    },
    {
        "id": "api-005", "name": "BFLA (Broken Function Level Auth)",
        "category": "authorization", "severity": "critical",
        "owasp_api": "API5:2023",
        "api_types": ["rest", "graphql", "grpc"],
        "desc": "Accessing admin/privileged functions without proper authorization.",
        "testing": (
            "BFLA TESTING METHODOLOGY:\n"
            "1. DISCOVER ADMIN ENDPOINTS:\n"
            "   - Fuzz for: /api/admin/, /api/internal/, /api/management/\n"
            "   - Check JavaScript/mobile app for hidden API calls\n"
            "   - OpenAPI/Swagger docs: /swagger.json, /openapi.yaml\n"
            "   - Check for different HTTP methods: GET vs POST vs PUT vs DELETE\n"
            "2. PRIVILEGE ESCALATION:\n"
            "   - Use regular user token to access admin endpoints\n"
            "   - Change role in request: {\"role\": \"admin\"}\n"
            "   - Access admin UI endpoints from API\n"
            "3. FUNCTION-LEVEL TESTING:\n"
            "   - Regular user → try: create/delete users, change config\n"
            "   - Test each HTTP method separately (GET allowed, DELETE should be denied)\n"
            "   - Test batch operations: Can regular user batch-delete?\n"
            "4. HIDDEN FUNCTIONS:\n"
            "   - GraphQL: Check mutations available to all users\n"
            "   - gRPC: List all available services/methods via reflection\n"
            "   - SOAP: Read WSDL for all available operations\n"
            "5. RBAC BYPASS:\n"
            "   - Test with different roles: viewer, editor, admin, super-admin\n"
            "   - Test role hierarchy: can editor do admin things?"
        ),
        "indicators": ["admin API", "role-based", "authorization", "privilege"],
    },
    {
        "id": "api-006", "name": "Mass Assignment",
        "category": "injection", "severity": "high",
        "owasp_api": "API6:2023",
        "api_types": ["rest", "graphql"],
        "desc": "Modifying object properties that should not be client-modifiable.",
        "testing": (
            "MASS ASSIGNMENT TESTING:\n"
            "1. IDENTIFY WRITABLE ENDPOINTS:\n"
            "   - POST /api/users (create user)\n"
            "   - PUT /api/users/{id} (update user)\n"
            "   - PATCH /api/users/{id} (partial update)\n"
            "2. ADD EXTRA FIELDS:\n"
            "   Normal: {\"name\": \"John\", \"email\": \"john@example.com\"}\n"
            "   Attack: {\"name\": \"John\", \"email\": \"john@example.com\", "
            "\"role\": \"admin\", \"is_admin\": true, \"credits\": 99999}\n"
            "3. COMMON TARGET FIELDS:\n"
            "   - role, is_admin, admin, privilege, permissions\n"
            "   - credits, balance, points, plan, tier\n"
            "   - verified, email_verified, approved, active\n"
            "   - password, password_hash (set known password)\n"
            "   - created_at, updated_at (backdate)\n"
            "   - user_id, owner_id (change ownership)\n"
            "4. GraphQL SPECIFIC:\n"
            "   mutation { updateUser(input: {id: 1, role: \"admin\"}) }\n"
            "   Check which fields are accepted in mutation input types\n"
            "5. DETECTION:\n"
            "   - Compare GET response fields with PUT/PATCH accepted fields\n"
            "   - Any field returned by GET that changes behavior = test target"
        ),
        "indicators": ["update endpoint", "PUT", "PATCH", "user profile edit"],
    },
    {
        "id": "api-007", "name": "GraphQL Deep Query DoS",
        "category": "availability", "severity": "high",
        "owasp_api": "API4:2023",
        "api_types": ["graphql"],
        "desc": "Deeply nested or circular GraphQL queries causing resource exhaustion.",
        "testing": (
            "GraphQL DoS TESTING:\n"
            "1. DEEP NESTING:\n"
            "   query {\n"
            "     users {\n"
            "       posts {\n"
            "         comments {\n"
            "           author {\n"
            "             posts {\n"
            "               comments { ... }\n"
            "             }\n"
            "           }\n"
            "         }\n"
            "       }\n"
            "     }\n"
            "   }\n"
            "   Increase depth until server times out or errors\n"
            "2. FIELD DUPLICATION:\n"
            "   query { users { name name name name name ... (1000 times) } }\n"
            "3. BATCH QUERIES:\n"
            "   Send array of 1000+ queries in single request\n"
            "4. ALIAS ABUSE:\n"
            "   query { a: users { name } b: users { name } c: users { name } ... }\n"
            "   Each alias is a separate database query\n"
            "5. INTROSPECTION ABUSE:\n"
            "   Full schema introspection on large schemas = expensive\n"
            "6. FRAGMENT CYCLES:\n"
            "   fragment A on User { ...B } fragment B on User { ...A }\n"
            "7. MITIGATIONS TO CHECK:\n"
            "   - Query depth limit\n"
            "   - Query complexity analysis\n"
            "   - Timeout per query\n"
            "   - Rate limiting"
        ),
        "indicators": ["GraphQL", "graphql endpoint", "/graphql"],
    },
    {
        "id": "api-008", "name": "API Schema Discovery",
        "category": "recon", "severity": "medium",
        "owasp_api": "API9:2023",
        "api_types": ["rest", "graphql", "grpc", "soap"],
        "desc": "Discovering undocumented API endpoints and schemas.",
        "testing": (
            "API SCHEMA DISCOVERY:\n"
            "1. DOCUMENTATION ENDPOINTS:\n"
            "   - /swagger.json, /swagger.yaml, /swagger-ui/\n"
            "   - /openapi.json, /openapi.yaml, /api-docs\n"
            "   - /graphql (introspection enabled by default)\n"
            "   - /grpc/reflection/v1alpha/ServerReflection\n"
            "   - ?wsdl (SOAP)\n"
            "2. COMMON API PATHS:\n"
            "   - /api/v1/, /api/v2/, /api/v3/ (version enumeration)\n"
            "   - /api/internal/, /api/admin/, /api/debug/\n"
            "   - /_api/, /rest/, /service/, /ws/\n"
            "3. SOURCE CODE ANALYSIS:\n"
            "   - JavaScript bundles contain API routes\n"
            "   - Mobile app decompilation reveals API endpoints\n"
            "   - .map files contain original source\n"
            "4. HISTORICAL:\n"
            "   - Wayback Machine: web.archive.org for old API docs\n"
            "   - Search GitHub for company's API references\n"
            "5. FUZZING:\n"
            "   - Fuzz endpoint names with SecLists API wordlists\n"
            "   - Fuzz HTTP methods on known endpoints\n"
            "   - Fuzz content types: JSON, XML, form, multipart"
        ),
        "indicators": ["API", "REST", "JSON", "swagger", "openapi"],
    },
]


class APISecurityKB:
    """API security knowledge base.

    Provides deep API attack methodology that gets injected
    into agent prompts for comprehensive API assessment.
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
                detection_indicators=data.get("indicators", []),
                api_types=data.get("api_types", ["rest"]),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_api_type(
        self,
        api_type: str,
    ) -> list[APIVulnPattern]:
        """Get patterns for a specific API type."""
        return [
            p for p in self._patterns.values()
            if api_type.lower() in p.api_types
        ]

    def get_testing_prompts(
        self,
        api_types: list[str] | None = None,
        max_patterns: int = 5,
    ) -> list[str]:
        """Get testing prompts for agent context injection."""
        prompts = []
        for pattern in self._patterns.values():
            if api_types:
                if not any(t in pattern.api_types for t in api_types):
                    continue
            if pattern.testing_methodology:
                prompts.append(pattern.testing_methodology)
            if len(prompts) >= max_patterns:
                break
        return prompts

    def detect_api_indicators(self, text: str) -> list[APIVulnPattern]:
        """Detect which API patterns are relevant."""
        text_lower = text.lower()
        relevant = []
        for pattern in self._patterns.values():
            for indicator in pattern.detection_indicators:
                if indicator.lower() in text_lower:
                    relevant.append(pattern)
                    break
        return relevant

    def build_api_testing_prompt(
        self,
        api_type: str = "rest",
        max_patterns: int = 3,
    ) -> str:
        """Build comprehensive API testing prompt."""
        relevant = self.get_patterns_for_api_type(api_type)

        lines = [f"## API Security Testing ({api_type.upper()})\n"]
        for pattern in relevant[:max_patterns]:
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            if pattern.owasp_api:
                lines.append(f"OWASP API: {pattern.owasp_api}")
            lines.append(pattern.testing_methodology)
            lines.append("")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            cat_counts[p.category] += 1
        return {
            "patterns": len(self._patterns),
            "by_category": dict(cat_counts),
        }
