"""Business logic attacks knowledge base.

Deep knowledge about business logic flaws:
1. Authentication and authorization logic
2. Payment and transaction logic
3. Rate limiting and abuse
4. Workflow manipulation
5. Race conditions and TOCTOU
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class BizLogicPattern:
    """A business logic attack pattern."""
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


BIZLOGIC_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "bl-001", "name": "Auth/Authz Logic Flaws",
        "category": "auth_logic", "severity": "critical",
        "desc": "Authentication and authorization logic flaws.",
        "detection": (
            "AUTH/AUTHZ LOGIC:\n"
            "IDOR (Insecure Direct Object Reference):\n"
            "  - Change user_id in requests\n"
            "  - Sequential/predictable IDs\n"
            "  - UUID not always safe (leaked in URLs)\n"
            "  - Bulk IDOR (iterate all objects)\n"
            "  TEST:\n"
            "    # Create 2 accounts\n"
            "    # Access account A's resources as B\n"
            "    # Try: /api/users/123/data as user 456\n"
            "PRIVILEGE ESCALATION:\n"
            "  - Horizontal: access other users' data\n"
            "  - Vertical: user → admin\n"
            "  - Role parameter manipulation\n"
            "  - Hidden admin endpoints\n"
            "  - isAdmin=true in request\n"
            "  - Role in JWT claims modification\n"
            "FORCED BROWSING:\n"
            "  - /admin, /debug, /internal\n"
            "  - Backup files (.bak, .old)\n"
            "  - API version endpoints\n"
            "  - Swagger/OpenAPI exposure\n"
            "REGISTRATION ABUSE:\n"
            "  - Register with admin email\n"
            "  - Unicode normalization bypass\n"
            "  - Case sensitivity issues\n"
            "  - Duplicate registration\n"
            "  - Email verification bypass\n"
            "TOOLS:\n"
            "  Burp Suite, Autorize extension, ffuf"
        ),
        "tools": ["burpsuite"],
    },
    {
        "id": "bl-002", "name": "Payment and Transaction Logic",
        "category": "payment", "severity": "critical",
        "desc": "Payment and transaction logic flaws.",
        "detection": (
            "PAYMENT/TRANSACTION LOGIC:\n"
            "PRICE MANIPULATION:\n"
            "  - Modify price in request\n"
            "  - Negative quantity → refund\n"
            "  - Negative price → credit\n"
            "  - Currency conversion abuse\n"
            "  - Discount code stacking\n"
            "  - Coupon reuse\n"
            "  - Integer overflow → free items\n"
            "CHECKOUT FLOW:\n"
            "  - Skip payment step\n"
            "  - Modify cart after payment calc\n"
            "  - Race condition on checkout\n"
            "  - Partial payment + order complete\n"
            "  - Gift card generation\n"
            "  - Promo code brute force\n"
            "REFUND ABUSE:\n"
            "  - Duplicate refund requests\n"
            "  - Refund without return\n"
            "  - Partial refund manipulation\n"
            "  - Refund to different payment method\n"
            "SUBSCRIPTION:\n"
            "  - Trial abuse (multiple accounts)\n"
            "  - Plan downgrade keeps features\n"
            "  - Cancel timing exploit\n"
            "  - Grace period abuse\n"
            "TESTING:\n"
            "  - Intercept all payment requests\n"
            "  - Modify amounts, quantities, IDs\n"
            "  - Test boundary values (0, -1, MAX)\n"
            "  - Race condition testing\n"
            "TOOLS:\n"
            "  Burp Suite, custom scripts"
        ),
        "tools": [],
    },
    {
        "id": "bl-003", "name": "Rate Limiting and Abuse",
        "category": "rate_limit", "severity": "high",
        "desc": "Rate limiting bypass and abuse.",
        "detection": (
            "RATE LIMITING BYPASS:\n"
            "TECHNIQUES:\n"
            "  - IP rotation (proxy lists)\n"
            "  - X-Forwarded-For manipulation\n"
            "  - X-Real-IP header injection\n"
            "  - Case variation in endpoints\n"
            "  - Path parameter variation\n"
            "    /api/v1/login vs /API/V1/LOGIN\n"
            "    /api/v1/login/ vs /api/v1/login\n"
            "  - HTTP method change (GET↔POST)\n"
            "  - API version switching\n"
            "  - Blank/null byte insertion\n"
            "  - Unicode normalization tricks\n"
            "RESOURCE ABUSE:\n"
            "  - Email bombing (password reset spam)\n"
            "  - SMS OTP cost attack\n"
            "  - API resource exhaustion\n"
            "  - File upload storage abuse\n"
            "  - Database query abuse (search DoS)\n"
            "AUTOMATION ABUSE:\n"
            "  - Scraping\n"
            "  - Account creation bots\n"
            "  - Ticket/inventory hoarding\n"
            "  - Review/rating manipulation\n"
            "  - Referral program abuse\n"
            "TESTING:\n"
            "  - Send rapid requests\n"
            "  - Check response codes (429?)\n"
            "  - Check Retry-After header\n"
            "  - Test bypass techniques\n"
            "TOOLS:\n"
            "  Burp Intruder, custom scripts, Turbo Intruder"
        ),
        "tools": [],
    },
    {
        "id": "bl-004", "name": "Workflow Manipulation",
        "category": "workflow", "severity": "high",
        "desc": "Workflow and state manipulation.",
        "detection": (
            "WORKFLOW MANIPULATION:\n"
            "STATE BYPASS:\n"
            "  - Skip steps in multi-step process\n"
            "  - Access step 3 directly (skip 1,2)\n"
            "  - Modify state in requests\n"
            "  - Replay completed steps\n"
            "  - Go back to modify approved data\n"
            "APPROVAL BYPASS:\n"
            "  - Self-approval\n"
            "  - Approve then modify\n"
            "  - Bypass review chain\n"
            "  - Manipulate approval thresholds\n"
            "ORDER OF OPERATIONS:\n"
            "  - Delete then access (use-after-free)\n"
            "  - Create then delete → orphaned refs\n"
            "  - Modify during processing\n"
            "  - Double-submit forms\n"
            "FILE UPLOAD:\n"
            "  - Upload malicious content\n"
            "  - Bypass extension validation\n"
            "  - Null byte in filename\n"
            "  - MIME type mismatch\n"
            "  - Polyglot files\n"
            "  - SVG with JavaScript\n"
            "  - Image metadata injection\n"
            "  - ZIP slip (path traversal)\n"
            "  - Unrestricted file size\n"
            "TESTING:\n"
            "  - Map full workflow state machine\n"
            "  - Try every state transition\n"
            "  - Skip, repeat, reorder steps\n"
            "TOOLS:\n"
            "  Burp Suite, state diagrams"
        ),
        "tools": [],
    },
    {
        "id": "bl-005", "name": "Race Conditions and TOCTOU",
        "category": "race", "severity": "critical",
        "desc": "Race conditions and TOCTOU bugs.",
        "detection": (
            "RACE CONDITIONS:\n"
            "TIME-OF-CHECK-TIME-OF-USE (TOCTOU):\n"
            "  - Check balance → deduct → race window\n"
            "  - Verify permission → execute → race\n"
            "  - Read file → check → open → race\n"
            "DOUBLE SPEND:\n"
            "  - Send 2 withdrawal requests simultaneously\n"
            "  - Balance checked before either deducted\n"
            "  - Both succeed → double withdrawal\n"
            "  - Same for coupon redemption\n"
            "TECHNIQUES:\n"
            "  # Turbo Intruder (Burp)\n"
            "  # Send parallel requests\n"
            "  # Python threading\n"
            "  import threading\n"
            "  threads = [threading.Thread(target=send_request)]\n"
            "  for t in threads: t.start()\n"
            "  # HTTP/2 single-packet attack\n"
            "  # Send multiple requests in one TCP packet\n"
            "  # Ensures near-simultaneous arrival\n"
            "COMMON TARGETS:\n"
            "  - Financial transactions\n"
            "  - Coupon/promo codes\n"
            "  - Vote/like/follow counts\n"
            "  - File operations\n"
            "  - Invitation acceptance\n"
            "  - Limited quantity items\n"
            "DETECTION:\n"
            "  - Look for check-then-act patterns\n"
            "  - Non-atomic operations on shared data\n"
            "  - Missing database locking\n"
            "  - Absence of idempotency keys\n"
            "TOOLS:\n"
            "  Turbo Intruder, Race-the-Web, custom scripts"
        ),
        "tools": [],
    },
]


class BusinessLogicKB:
    """Business logic attacks knowledge base.

    Provides business logic attack patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, BizLogicPattern] = {}
        self._log = logger.bind(component="bizlogic_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load business logic patterns."""
        for data in BIZLOGIC_PATTERNS:
            pattern = BizLogicPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[BizLogicPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_bizlogic_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build business logic prompt."""
        lines = ["## Business Logic Attacks\n"]
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
