"""Business logic vulnerability knowledge base.

Deep knowledge about business logic attacks:
1. Authentication bypass patterns
2. Authorization flaws (IDOR, privilege escalation)
3. Race condition exploitation
4. Payment/transaction manipulation
5. Workflow bypass attacks
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
        "id": "biz-001", "name": "IDOR (Insecure Direct Object Reference)",
        "category": "authorization", "severity": "high",
        "desc": "Accessing unauthorized objects by manipulating references.",
        "detection": (
            "IDOR DETECTION:\n"
            "METHODOLOGY:\n"
            "  1. Create two accounts (User A, User B)\n"
            "  2. Perform actions as User A, note all object IDs\n"
            "  3. Try accessing User A's objects as User B\n"
            "COMMON LOCATIONS:\n"
            "  - /api/user/123/profile → change 123 to another ID\n"
            "  - /api/orders/456 → access other users' orders\n"
            "  - /api/documents/789 → download other users' files\n"
            "  - /api/messages/inbox?user_id=123\n"
            "ID TYPES:\n"
            "  Sequential integers: 1, 2, 3 → easy to enumerate\n"
            "  UUIDs: Harder but sometimes leaked in responses\n"
            "  Encoded: Base64, hex → decode and modify\n"
            "  Hashed: Sometimes predictable (MD5 of email)\n"
            "TESTING:\n"
            "  Horizontal IDOR: Same role, different user's data\n"
            "  Vertical IDOR: Lower role accessing admin data\n"
            "  Method-based: GET blocked but PUT/DELETE allowed\n"
            "  Parameter pollution: ?id=1&id=2 (server-dependent)\n"
            "TOOLS:\n"
            "  - Burp Autorize extension (automated IDOR checking)\n"
            "  - Replace parameter values systematically\n"
            "  - Check response differences (200 vs 403/404)"
        ),
        "tools": ["burp", "curl"],
    },
    {
        "id": "biz-002", "name": "Race Condition Exploitation",
        "category": "race_condition", "severity": "critical",
        "desc": "Exploiting TOCTOU and parallel request processing.",
        "detection": (
            "RACE CONDITION ATTACKS:\n"
            "TIME-OF-CHECK-TO-TIME-OF-USE (TOCTOU):\n"
            "  - Application checks condition, then acts\n"
            "  - Window between check and act is exploitable\n"
            "  - Send identical requests simultaneously\n"
            "COMMON TARGETS:\n"
            "  Limit Bypass:\n"
            "    - Coupon/promo code: Apply same code multiple times\n"
            "    - Free trial: Create multiple simultaneous signups\n"
            "    - Voting: Send multiple votes in parallel\n"
            "  Financial:\n"
            "    - Double withdrawal: Two transfers, balance checked once\n"
            "    - Overdraft: Transfer more than balance in parallel\n"
            "    - Gift card: Redeem same card in parallel requests\n"
            "  Account:\n"
            "    - Email change + password reset race\n"
            "    - Invite accept race condition\n"
            "TESTING:\n"
            "  # Using Burp Turbo Intruder:\n"
            "  # Send 10-20 identical requests at once\n"
            "  # Check if action occurred more than once\n"
            "  # Python (requests with threading):\n"
            "  from concurrent.futures import ThreadPoolExecutor\n"
            "  with ThreadPoolExecutor(max_workers=20) as pool:\n"
            "      futures = [pool.submit(send_request) for _ in range(20)]\n"
            "  # Check: Did 20 coupons apply? Did balance go negative?"
        ),
        "tools": ["burp", "turbo-intruder"],
    },
    {
        "id": "biz-003", "name": "Payment and Transaction Manipulation",
        "category": "payment", "severity": "critical",
        "desc": "Manipulating payment flows and transaction logic.",
        "detection": (
            "PAYMENT MANIPULATION:\n"
            "PRICE MANIPULATION:\n"
            "  - Modify price in request (client-side price)\n"
            "  - Change quantity to negative → credit instead of charge\n"
            "  - Change currency code (USD → weaker currency)\n"
            "  - Apply excessive discount (100% or more)\n"
            "  - Remove items from cart after discount applied\n"
            "FLOW BYPASS:\n"
            "  - Skip payment step (go directly to confirmation)\n"
            "  - Reuse successful payment callback\n"
            "  - Modify payment status in request\n"
            "  - Cancel payment after confirmation but before fulfillment\n"
            "  - Race condition on payment + order creation\n"
            "TESTING:\n"
            "  1. Map entire payment flow (add → cart → checkout → pay → confirm)\n"
            "  2. Intercept each request with Burp\n"
            "  3. Modify price, quantity, discounts\n"
            "  4. Skip steps (jump from cart to confirmation)\n"
            "  5. Test with negative values\n"
            "  6. Test with zero-value transactions\n"
            "  7. Test refund logic (refund more than paid)\n"
            "  8. Test currency conversion edge cases"
        ),
        "tools": ["burp", "curl"],
    },
    {
        "id": "biz-004", "name": "Authentication Logic Flaws",
        "category": "auth_logic", "severity": "critical",
        "desc": "Bypassing authentication through logic errors.",
        "detection": (
            "AUTHENTICATION LOGIC FLAWS:\n"
            "MFA BYPASS:\n"
            "  - Skip MFA step (go directly to authenticated page)\n"
            "  - Reuse MFA code from previous session\n"
            "  - Brute force short MFA codes (4-6 digits)\n"
            "  - MFA code in response body or headers\n"
            "  - Backup codes not rate limited\n"
            "  - Change email before MFA → MFA for new email\n"
            "PASSWORD RESET:\n"
            "  - Token in URL (no expiry or long expiry)\n"
            "  - Predictable reset tokens (timestamp-based)\n"
            "  - Host header injection for token theft\n"
            "  - Reset token reuse after password change\n"
            "  - Password reset for arbitrary user via parameter tampering\n"
            "SESSION:\n"
            "  - Session fixation: Set session before login\n"
            "  - Session not invalidated on password change\n"
            "  - Session not invalidated on logout\n"
            "  - Concurrent session limit bypass\n"
            "OAUTH:\n"
            "  - Missing state parameter (CSRF)\n"
            "  - Open redirect in redirect_uri\n"
            "  - Token leakage via Referer header\n"
            "  - Account linking without verification"
        ),
        "tools": ["burp", "curl", "nuclei"],
    },
    {
        "id": "biz-005", "name": "Workflow and State Manipulation",
        "category": "workflow", "severity": "high",
        "desc": "Manipulating application state machines and workflows.",
        "detection": (
            "WORKFLOW MANIPULATION:\n"
            "STATE BYPASS:\n"
            "  - Skip mandatory workflow steps\n"
            "  - Example: Pending → Approved (skip Review)\n"
            "  - Directly call API endpoint for later stage\n"
            "  - Manipulate state parameter in request\n"
            "PRIVILEGE ESCALATION:\n"
            "  - Change role in request body (role='admin')\n"
            "  - Modify JWT claims (role, permissions)\n"
            "  - Access admin functionality via direct URL\n"
            "  - Parameter manipulation on user creation (isAdmin=true)\n"
            "APPROVAL BYPASS:\n"
            "  - Self-approve own requests\n"
            "  - Modify approver field in request\n"
            "  - Race condition on approval check\n"
            "  - Approve then immediately modify approved content\n"
            "DATA VALIDATION:\n"
            "  - Test boundary values (max/min/zero/negative)\n"
            "  - Test field length limits\n"
            "  - Test special characters in business fields\n"
            "  - Test date/time manipulation (future dates, past dates)\n"
            "  - Test with empty required fields\n"
            "  - Test enum values not in expected set"
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
        """Build business logic prompt."""
        lines = ["## Business Logic Vulnerability Patterns\n"]
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
