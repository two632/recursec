"""Business logic vulnerability knowledge base.

Deep knowledge about business logic flaws:
1. Payment and financial logic flaws
2. Access control bypass patterns
3. Rate limiting and abuse prevention
4. Workflow manipulation attacks
5. Data validation bypass techniques
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
            "category": self.category[:12],
        }


BUSINESS_LOGIC_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "biz-001", "name": "Payment Logic Flaws",
        "category": "payment", "severity": "critical",
        "desc": "Payment and financial logic manipulation.",
        "detection": (
            "PAYMENT LOGIC FLAWS:\n"
            "PRICE MANIPULATION:\n"
            "  - Modify price in request body\n"
            "  - Change currency code (USD → INR conversion abuse)\n"
            "  - Negative quantity (refund without return)\n"
            "  - Zero-price items through coupon stacking\n"
            "  - Integer overflow on price calculation\n"
            "COUPON/DISCOUNT ABUSE:\n"
            "  - Apply same coupon multiple times\n"
            "  - Race condition: apply coupon concurrently\n"
            "  - Transfer coupon between accounts\n"
            "  - Expired coupon replay\n"
            "  - Coupon code brute force (predictable format)\n"
            "PAYMENT FLOW:\n"
            "  - Skip payment step (jump to confirmation)\n"
            "  - Modify payment callback response\n"
            "  - Double charge prevention bypass\n"
            "  - Partial payment acceptance\n"
            "  - Gift card balance transfer exploit\n"
            "TESTING:\n"
            "  1. Intercept checkout request\n"
            "  2. Modify price, quantity, discount fields\n"
            "  3. Test negative values\n"
            "  4. Test boundary values (0, MAX_INT)\n"
            "  5. Test currency conversion edge cases\n"
            "  6. Test concurrent coupon application"
        ),
        "tools": ["burpsuite"],
    },
    {
        "id": "biz-002", "name": "Access Control Bypass",
        "category": "access", "severity": "critical",
        "desc": "Business logic access control bypass patterns.",
        "detection": (
            "ACCESS CONTROL BYPASS:\n"
            "IDOR (Insecure Direct Object Reference):\n"
            "  - Increment/decrement resource IDs\n"
            "  - Replace UUID with another user's UUID\n"
            "  - Access /api/users/123 → /api/users/124\n"
            "  - Check all API endpoints for IDOR\n"
            "  - Test with low-privilege vs high-privilege tokens\n"
            "HORIZONTAL ESCALATION:\n"
            "  - Access other users' data with same role\n"
            "  - Modify other users' settings\n"
            "  - View other users' orders/transactions\n"
            "  - Change delivery address after payment\n"
            "VERTICAL ESCALATION:\n"
            "  - Add admin role in registration request\n"
            "  - Modify role field in profile update\n"
            "  - Access admin endpoints with user token\n"
            "  - Change isAdmin flag in JWT claims\n"
            "  - Parameter pollution: role=user&role=admin\n"
            "FORCED BROWSING:\n"
            "  - /admin, /administrator, /console\n"
            "  - /api/admin/users\n"
            "  - /debug, /status, /health\n"
            "  - Directory traversal: /../../admin\n"
            "TESTING:\n"
            "  1. Map all endpoints and roles\n"
            "  2. Test each endpoint with each role\n"
            "  3. Test object-level access with different users\n"
            "  4. Test function-level access across roles"
        ),
        "tools": ["burpsuite", "autorize"],
    },
    {
        "id": "biz-003", "name": "Rate Limiting Bypass",
        "category": "ratelimit", "severity": "medium",
        "desc": "Rate limiting and abuse prevention bypass.",
        "detection": (
            "RATE LIMITING BYPASS:\n"
            "IP-BASED BYPASS:\n"
            "  - X-Forwarded-For: 127.0.0.1\n"
            "  - X-Real-IP: <spoofed>\n"
            "  - X-Originating-IP: 127.0.0.1\n"
            "  - X-Client-IP: <spoofed>\n"
            "  - True-Client-IP: <spoofed>\n"
            "  - Via: 1.1 <spoofed>\n"
            "REQUEST MANIPULATION:\n"
            "  - Add null bytes: user%00name\n"
            "  - URL encoding variations\n"
            "  - Case change: /Login vs /login\n"
            "  - Add parameters: /login?x=1 vs /login?x=2\n"
            "  - HTTP method change: POST → PUT\n"
            "  - Change Content-Type header\n"
            "CAPTCHA BYPASS:\n"
            "  - OCR-based solving (tesseract)\n"
            "  - Audio CAPTCHA + speech-to-text\n"
            "  - Cookie replay after solving once\n"
            "  - Check if CAPTCHA is validated server-side\n"
            "  - Remove CAPTCHA parameter from request\n"
            "TIMING:\n"
            "  - Distribute requests over time\n"
            "  - Use multiple sessions\n"
            "  - Reset rate limit via password reset flow\n"
            "  - Account lockout bypass via concurrent requests"
        ),
        "tools": ["burpsuite"],
    },
    {
        "id": "biz-004", "name": "Workflow Manipulation",
        "category": "workflow", "severity": "high",
        "desc": "Workflow and state machine manipulation attacks.",
        "detection": (
            "WORKFLOW MANIPULATION:\n"
            "STEP SKIPPING:\n"
            "  - Skip email verification (access directly)\n"
            "  - Skip payment (go to order confirmation)\n"
            "  - Skip 2FA step\n"
            "  - Skip terms acceptance\n"
            "  - Access step 3 without completing step 1/2\n"
            "STATE MANIPULATION:\n"
            "  - Change order status (pending → shipped)\n"
            "  - Reverse transaction state\n"
            "  - Replay completed workflow\n"
            "  - Modify state in client-side storage\n"
            "  - Tamper with workflow tokens\n"
            "MULTI-STEP PROCESS:\n"
            "  - Password reset: Use reset token for different user\n"
            "  - Email change: Verify with old email, change to new\n"
            "  - Account merge: Force merge with admin account\n"
            "  - Invitation: Modify invite to change role\n"
            "TESTING:\n"
            "  1. Map all multi-step workflows\n"
            "  2. Try accessing each step directly\n"
            "  3. Modify state parameters between steps\n"
            "  4. Test with expired/replayed tokens\n"
            "  5. Test concurrent workflow instances"
        ),
        "tools": ["burpsuite"],
    },
    {
        "id": "biz-005", "name": "Data Validation Bypass",
        "category": "validation", "severity": "high",
        "desc": "Input validation bypass and data integrity attacks.",
        "detection": (
            "DATA VALIDATION BYPASS:\n"
            "TYPE JUGGLING:\n"
            "  - PHP: '0' == false, '' == 0, '0e1' == 0\n"
            "  - JavaScript: '0' == false, null == undefined\n"
            "  - Python: 0 == False, '' == False\n"
            "  - Send integer where string expected\n"
            "  - Send array where scalar expected: param[]=value\n"
            "ENCODING BYPASS:\n"
            "  - URL encoding: %3Cscript%3E\n"
            "  - Double encoding: %253Cscript%253E\n"
            "  - Unicode normalization: \\u0041 → A\n"
            "  - HTML entities: &lt;script&gt;\n"
            "  - UTF-7: +ADw-script+AD4-\n"
            "  - Null byte: %00\n"
            "LENGTH BYPASS:\n"
            "  - Exceed max length (buffer overflow)\n"
            "  - Exact boundary values\n"
            "  - Empty string vs null vs missing\n"
            "  - Unicode characters (multi-byte)\n"
            "LOGIC BYPASS:\n"
            "  - Negative numbers where positive expected\n"
            "  - Decimal values where integer expected\n"
            "  - Date manipulation (future/past)\n"
            "  - Email format: user@domain(comment)@evil.com\n"
            "  - JSON injection in string fields\n"
            "  - Prototype pollution: __proto__"
        ),
        "tools": ["burpsuite"],
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
