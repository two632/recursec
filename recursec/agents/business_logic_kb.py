"""Business logic vulnerability knowledge base.

Deep knowledge about business logic flaws:
1. Authentication bypass patterns
2. Authorization flaws (IDOR, BOLA, BFLA)
3. Payment/transaction manipulation
4. Workflow bypass attacks
5. Rate limiting and abuse patterns
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class BusinessLogicPattern:
    """A business logic vulnerability pattern."""
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
            "category": self.category[:15],
        }


BUSINESS_LOGIC_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "biz-001", "name": "IDOR / BOLA (Broken Object Level Auth)",
        "category": "authorization", "severity": "critical",
        "desc": "Accessing other users' objects by manipulating IDs.",
        "detection": (
            "IDOR / BOLA DETECTION:\n"
            "METHODOLOGY:\n"
            "  1. Create 2+ test accounts (Account A and Account B)\n"
            "  2. Perform actions as Account A, capture all API calls\n"
            "  3. Identify endpoints with object references (IDs, UUIDs)\n"
            "  4. Replay requests as Account B with Account A's object IDs\n"
            "  5. Check if Account B can access Account A's objects\n"
            "COMMON ID LOCATIONS:\n"
            "  - URL path: /api/users/123/profile\n"
            "  - Query parameter: /api/orders?id=456\n"
            "  - Request body: {\"user_id\": 789}\n"
            "  - Headers: X-User-Id: 123\n"
            "  - GraphQL: query { user(id: 123) { ... } }\n"
            "ID PATTERNS TO TEST:\n"
            "  - Sequential integers: 1, 2, 3 (most vulnerable)\n"
            "  - UUIDs: Try other known UUIDs from API responses\n"
            "  - Encoded IDs: base64 decode, modify, re-encode\n"
            "  - Composite keys: user_id + object_id combinations\n"
            "ESCALATION:\n"
            "  - Read access: View other users' data\n"
            "  - Write access: Modify other users' data\n"
            "  - Delete access: Remove other users' resources\n"
            "  - Admin access: Access admin-only objects\n"
            "TOOLS:\n"
            "  - Burp Suite Autorize extension\n"
            "  - OWASP ZAP Access Control Testing\n"
            "  - Custom scripts with 2 session tokens"
        ),
        "tools": ["burp", "ffuf", "curl"],
    },
    {
        "id": "biz-002", "name": "Payment and Transaction Manipulation",
        "category": "payment", "severity": "critical",
        "desc": "Manipulating prices, quantities, and payment flows.",
        "detection": (
            "PAYMENT MANIPULATION:\n"
            "PRICE MANIPULATION:\n"
            "  - Intercept checkout request, modify price field\n"
            "  - Change price to 0, negative, or very small value\n"
            "  - Modify quantity to negative (refund generation)\n"
            "  - Change currency code to weaker currency\n"
            "  - Apply coupon/discount multiple times\n"
            "CHECKOUT FLOW BYPASS:\n"
            "  - Skip payment step (direct to order confirmation)\n"
            "  - Replay successful payment token for different order\n"
            "  - Race condition: place order during payment processing\n"
            "  - Modify order after payment confirmation\n"
            "COUPON/DISCOUNT ABUSE:\n"
            "  - Apply same coupon multiple times\n"
            "  - Stack incompatible discounts\n"
            "  - Use expired coupons (check server-side validation)\n"
            "  - Generate valid coupons (predictable patterns)\n"
            "  - Apply staff/internal discounts\n"
            "REFUND MANIPULATION:\n"
            "  - Request refund for items not returned\n"
            "  - Double-refund via race condition\n"
            "  - Partial refund > original amount\n"
            "TESTING APPROACH:\n"
            "  1. Map entire payment flow with Burp\n"
            "  2. Identify all modifiable parameters\n"
            "  3. Test each parameter with boundary values\n"
            "  4. Test flow bypass by skipping steps\n"
            "  5. Test race conditions on financial operations"
        ),
        "tools": ["burp", "curl", "ffuf"],
    },
    {
        "id": "biz-003", "name": "Authentication Bypass Patterns",
        "category": "authentication", "severity": "critical",
        "desc": "Bypassing authentication mechanisms.",
        "detection": (
            "AUTHENTICATION BYPASS:\n"
            "COMMON BYPASSES:\n"
            "  - Default credentials (admin:admin, test:test)\n"
            "  - SQL injection in login: ' OR 1=1-- -\n"
            "  - Response manipulation: Change 'success: false' to 'success: true'\n"
            "  - Token forging: JWT none algorithm, weak secret\n"
            "  - Password reset flow manipulation\n"
            "JWT ATTACKS:\n"
            "  - Algorithm confusion: RS256 → HS256 with public key as secret\n"
            "  - None algorithm: {\"alg\": \"none\"}\n"
            "  - Weak secret: hashcat/john on JWT token\n"
            "  - JWT kid injection: header manipulation\n"
            "  - Expired token acceptance\n"
            "  - Token not bound to user session\n"
            "PASSWORD RESET:\n"
            "  - Predictable reset tokens\n"
            "  - Token reuse after password change\n"
            "  - Host header injection for reset link\n"
            "  - Rate limiting bypass on reset endpoint\n"
            "  - Account takeover via email change → reset\n"
            "2FA BYPASS:\n"
            "  - Missing 2FA check on certain endpoints\n"
            "  - Brute force 2FA code (4-6 digits)\n"
            "  - Response manipulation to skip 2FA\n"
            "  - Backup code guessing\n"
            "  - Session fixation before 2FA"
        ),
        "tools": ["burp", "hydra", "jwt_tool"],
    },
    {
        "id": "biz-004", "name": "Rate Limiting and Abuse",
        "category": "abuse", "severity": "high",
        "desc": "Bypassing rate limits and abusing functionality.",
        "detection": (
            "RATE LIMITING BYPASS:\n"
            "BYPASS TECHNIQUES:\n"
            "  - IP rotation: X-Forwarded-For, X-Real-IP headers\n"
            "  - Add headers: X-Forwarded-For: 127.0.0.1\n"
            "  - Case variation: /api/login vs /API/LOGIN vs /Api/Login\n"
            "  - Path variation: /api/login vs /api/./login vs /api/login/\n"
            "  - HTTP method: POST vs PUT vs PATCH\n"
            "  - Parameter pollution: id=1&id=2\n"
            "  - Unicode normalization: admin vs ɑdmin\n"
            "  - Adding null bytes: %00, %0d, %0a\n"
            "TESTING METHODOLOGY:\n"
            "  1. Identify rate-limited endpoints\n"
            "  2. Determine limit (requests per time window)\n"
            "  3. Test bypass techniques systematically\n"
            "  4. Test distributed bypass (multiple source IPs)\n"
            "  5. Test per-account vs per-IP limits\n"
            "ABUSE PATTERNS:\n"
            "  - Mass account creation (spam)\n"
            "  - Credential stuffing\n"
            "  - Resource exhaustion (large file upload)\n"
            "  - Email bombing via notification triggers\n"
            "  - SMS bombing via phone verification\n"
            "  - API abuse for data scraping"
        ),
        "tools": ["ffuf", "curl", "hydra"],
    },
    {
        "id": "biz-005", "name": "Workflow and State Manipulation",
        "category": "workflow", "severity": "high",
        "desc": "Bypassing multi-step workflows and state transitions.",
        "detection": (
            "WORKFLOW MANIPULATION:\n"
            "STEP SKIPPING:\n"
            "  - Directly access step 3 URL without completing steps 1-2\n"
            "  - Modify step counter in request (step=1 → step=3)\n"
            "  - Delete intermediate state tokens/cookies\n"
            "  - Access completion endpoint directly\n"
            "STATE MANIPULATION:\n"
            "  - Modify state parameters: status=pending → status=approved\n"
            "  - Change role during multi-step process\n"
            "  - Access denied state resources via direct URL\n"
            "  - Resubmit completed workflow (double execution)\n"
            "COMMON VULNERABLE WORKFLOWS:\n"
            "  1. Account registration: Skip email verification\n"
            "  2. KYC verification: Bypass document upload\n"
            "  3. Approval process: Self-approve requests\n"
            "  4. Checkout: Skip payment step\n"
            "  5. Password change: Skip old password verification\n"
            "  6. File upload: Skip antivirus scan\n"
            "TESTING:\n"
            "  - Map all workflow steps with Burp\n"
            "  - Identify state parameters and tokens\n"
            "  - Test each step independently\n"
            "  - Test backward navigation\n"
            "  - Test concurrent workflow instances"
        ),
        "tools": ["burp", "curl"],
    },
]


class BusinessLogicKB:
    """Business logic vulnerability knowledge base.

    Provides business logic attack patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, BusinessLogicPattern] = {}
        self._log = logger.bind(component="business_logic_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load business logic patterns."""
        for data in BUSINESS_LOGIC_PATTERNS:
            pattern = BusinessLogicPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[BusinessLogicPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_business_logic_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build business logic attack prompt."""
        lines = ["## Business Logic Vulnerability Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category.lower() not in [c.lower() for c in categories]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
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
