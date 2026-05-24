"""Business logic vulnerability knowledge base.

Attack patterns for business logic flaws:
1. Authentication Logic Flaws — MFA bypass, session fixation, race conditions
2. Authorization Logic Flaws — IDOR, privilege escalation, role confusion
3. Payment/Transaction Logic — price manipulation, currency rounding, replay
4. Workflow Bypass — step skipping, state manipulation, process abuse
5. Rate Limiting & Abuse — enumeration, brute force, resource exhaustion
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class BusinessLogicType(str, Enum):
    AUTH_LOGIC = "auth_logic"
    AUTHZ_LOGIC = "authz_logic"
    PAYMENT_LOGIC = "payment_logic"
    WORKFLOW_BYPASS = "workflow_bypass"
    RATE_ABUSE = "rate_abuse"


@dataclass
class BusinessLogicPattern:
    """A business logic attack pattern."""
    name: str = ""
    logic_type: BusinessLogicType = BusinessLogicType.AUTH_LOGIC
    description: str = ""
    detection_strategies: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    test_cases: list[str] = field(default_factory=list)
    severity: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.logic_type.value,
            "severity": self.severity,
            "tests": len(self.test_cases),
        }


BUSINESS_LOGIC_PATTERNS: list[BusinessLogicPattern] = [
    BusinessLogicPattern(
        name="Authentication Logic Flaws",
        logic_type=BusinessLogicType.AUTH_LOGIC,
        description=(
            "Flaws in authentication logic: MFA bypass via response "
            "manipulation, session fixation, race conditions in login, "
            "password reset token reuse, and OAuth state parameter abuse."
        ),
        detection_strategies=[
            "Test MFA bypass by modifying server response from 403 to 200",
            "Check if MFA code is validated server-side or client-side only",
            "Test session fixation by setting session cookie before auth",
            "Send parallel login requests to test race conditions",
            "Reuse password reset tokens after password is changed",
            "Test OAuth state parameter for CSRF (missing/predictable)",
            "Check if failed login lockout can be bypassed via API endpoint",
            "Test remember-me token for predictable generation",
        ],
        indicators=[
            "MFA validation only in frontend JavaScript",
            "Session ID unchanged after successful authentication",
            "Password reset tokens valid after use",
            "OAuth flow without state parameter validation",
            "Login rate limiting only on IP, not account",
            "JWT tokens without expiration or rotation",
        ],
        tools=["burpsuite", "mitmproxy", "turbo-intruder", "authmatrix"],
        commands=[
            "curl -X POST /api/login -d '{\"user\":\"a\",\"pass\":\"b\"}' -v",
            "curl -X POST /api/mfa/verify -d '{\"code\":\"000000\"}' -v",
            "curl /api/reset-password?token=<old_token> -v",
            "sqlmap -u '/api/login' --data='user=*&pass=test' --level=3",
            "ffuf -u /api/FUZZ -w auth-endpoints.txt -mc 200,301,302",
        ],
        test_cases=[
            "Login with valid creds, intercept MFA response, change to 200",
            "Set session cookie, login, check if session ID changes",
            "Request password reset, use token, try token again",
            "Send 10 concurrent login requests with same creds",
            "Login via OAuth without state parameter",
        ],
        severity="critical",
    ),
    BusinessLogicPattern(
        name="Authorization Logic Flaws",
        logic_type=BusinessLogicType.AUTHZ_LOGIC,
        description=(
            "Flaws in authorization logic: IDOR via parameter tampering, "
            "horizontal/vertical privilege escalation, role confusion in "
            "multi-tenant systems, and missing function-level access control."
        ),
        detection_strategies=[
            "Test IDOR by changing numeric IDs in API paths (/user/123 to /user/124)",
            "Replace UUID parameters with other users UUIDs",
            "Access admin endpoints with regular user session",
            "Change role/permission fields in JWT tokens",
            "Test tenant isolation by cross-tenant resource access",
            "Check if API enforces object-level authorization",
            "Test GraphQL for authorization bypass via nested queries",
            "Modify request body role/group fields during registration",
        ],
        indicators=[
            "Sequential/predictable resource IDs in URLs",
            "Authorization checks only on frontend/UI level",
            "JWT contains mutable role/permission claims",
            "No tenant ID validation in API queries",
            "Admin endpoints accessible with user tokens",
            "GraphQL resolvers without field-level auth checks",
        ],
        tools=["burpsuite", "autorize", "authmatrix", "postman"],
        commands=[
            "curl -H 'Auth: user_token' /api/admin/users -v",
            "curl /api/users/VICTIM_ID -H 'Auth: attacker_token'",
            "curl -X PUT /api/users/me -d '{\"role\":\"admin\"}'",
            "python3 -c 'import jwt; print(jwt.decode(TOKEN, options={\"verify_signature\":False}))'",
            "ffuf -u /api/admin/FUZZ -w admin-endpoints.txt -H 'Auth: user_token'",
        ],
        test_cases=[
            "Access other user resources by changing ID parameter",
            "Access admin panel with regular user session",
            "Modify JWT role claim from user to admin",
            "Access tenant B resources with tenant A credentials",
            "Call undocumented API endpoints with user token",
        ],
        severity="critical",
    ),
    BusinessLogicPattern(
        name="Payment/Transaction Logic",
        logic_type=BusinessLogicType.PAYMENT_LOGIC,
        description=(
            "Flaws in payment and transaction processing: price manipulation "
            "via parameter tampering, currency rounding exploitation, "
            "transaction replay, negative quantity attacks, coupon abuse."
        ),
        detection_strategies=[
            "Intercept checkout request, modify price/amount fields",
            "Test negative quantities in shopping cart",
            "Apply same discount code multiple times",
            "Test currency conversion rounding errors at scale",
            "Replay successful payment confirmation to server",
            "Modify subscription tier in upgrade/downgrade request",
            "Test if server validates total or trusts client calculation",
            "Check for TOCTOU issues in multi-step checkout",
        ],
        indicators=[
            "Price/amount in client-side request body",
            "Cart total calculated client-side only",
            "Discount codes not invalidated after use",
            "No server-side validation of line items vs total",
            "Payment confirmation accepted without nonce/idempotency",
            "Subscription changes processed without re-authorization",
        ],
        tools=["burpsuite", "mitmproxy", "postman", "turbo-intruder"],
        commands=[
            "curl -X POST /api/checkout -d '{\"price\":0.01,\"qty\":1}'",
            "curl -X POST /api/cart/add -d '{\"qty\":-1,\"id\":\"expensive\"}'",
            "curl -X POST /api/apply-coupon -d '{\"code\":\"SAVE50\"}'",
            "curl -X POST /api/payment -d '{\"amount\":0}'",
            "# Replay captured payment confirmation request",
        ],
        test_cases=[
            "Change product price to 0.01 in checkout request",
            "Add item with quantity -1 to reduce total",
            "Apply discount code 100 times via race condition",
            "Process payment with amount=0 or negative amount",
            "Upgrade subscription, intercept, change plan to premium",
        ],
        severity="critical",
    ),
    BusinessLogicPattern(
        name="Workflow Bypass",
        logic_type=BusinessLogicType.WORKFLOW_BYPASS,
        description=(
            "Bypassing multi-step workflows: skipping verification steps, "
            "manipulating state machines, accessing future steps directly, "
            "and exploiting process logic assumptions."
        ),
        detection_strategies=[
            "Map all workflow steps and try accessing step N+1 directly",
            "Skip email verification by directly calling confirmed endpoint",
            "Modify workflow state parameter (step=1 to step=3)",
            "Complete purchase without going through payment step",
            "Access post-approval resources without approval",
            "Test if cancelled orders can be re-activated",
            "Modify form wizard step counter to skip validation",
            "Test parallel requests at different workflow stages",
        ],
        indicators=[
            "Workflow step tracked client-side (URL/form field)",
            "No server-side validation of prerequisite steps",
            "Email verification bypassable via direct API call",
            "State transitions not validated (skip from START to DONE)",
            "Cancelled/expired resources still accessible",
            "Multi-step form skippable via direct POST",
        ],
        tools=["burpsuite", "postman", "curl", "turbo-intruder"],
        commands=[
            "curl /api/onboarding/complete -d '{\"step\":5}'",
            "curl /api/verify-email -d '{\"verified\":true}'",
            "curl /api/order/confirm -d '{\"order_id\":\"x\"}' # skip payment",
            "curl /api/document/download/DOC_ID # skip approval",
            "curl -X POST /api/account/activate -d '{\"status\":\"active\"}'",
        ],
        test_cases=[
            "Skip email verification and access protected resources",
            "Jump from step 1 to step 5 in registration wizard",
            "Complete order without payment authorization",
            "Access document before approval workflow completes",
            "Reactivate cancelled subscription via direct API",
        ],
        severity="high",
    ),
    BusinessLogicPattern(
        name="Rate Limiting & Abuse",
        logic_type=BusinessLogicType.RATE_ABUSE,
        description=(
            "Abusing rate limiting gaps: user enumeration, brute force "
            "via endpoint hopping, resource exhaustion, API quota bypass, "
            "and distributed abuse via header manipulation."
        ),
        detection_strategies=[
            "Test rate limit on login (how many attempts before lockout)",
            "Try different API endpoints for same function (rate limit each?)",
            "Bypass rate limit via X-Forwarded-For header rotation",
            "Test if rate limit resets on different User-Agent",
            "Check API rate limit per-user vs per-IP vs per-endpoint",
            "Enumerate users via timing differences on login",
            "Test referral/invite abuse via automated signup",
            "Check if rate limit applies to API keys vs session tokens",
        ],
        indicators=[
            "Rate limit only on IP, bypassable with X-Forwarded-For",
            "Different rate limits on /login vs /api/auth/login",
            "User enumeration via different error messages",
            "No rate limit on password reset endpoint",
            "API rate limit reset by rotating API keys",
            "Timing-based user enumeration (valid vs invalid user)",
        ],
        tools=["turbo-intruder", "ffuf", "wfuzz", "hydra", "patator"],
        commands=[
            "ffuf -u /api/login -X POST -d 'user=admin&pass=FUZZ' -w passwords.txt -rate 100",
            "hydra -l admin -P passwords.txt target http-post-form '/login:user=^USER^&pass=^PASS^:F=invalid'",
            "wfuzz -z range,1-1000 -u /api/user/FUZZ --hc 404",
            "curl -H 'X-Forwarded-For: 1.2.3.FUZZ' /api/login",
            "turbo-intruder: race.py /api/apply-coupon",
        ],
        test_cases=[
            "Send 1000 login requests, check when rate limited",
            "Rotate X-Forwarded-For header to bypass rate limit",
            "Enumerate users via response time difference",
            "Exhaust free tier API quota via automated requests",
            "Abuse referral system via automated account creation",
        ],
        severity="high",
    ),
]


def build_business_logic_prompt(
    focus_type: BusinessLogicType | None = None,
    max_patterns: int = 5,
) -> str:
    """Build LLM prompt with business logic attack knowledge."""
    lines = ["## Business Logic Vulnerability Knowledge\n"]

    patterns = BUSINESS_LOGIC_PATTERNS
    if focus_type:
        patterns = [p for p in patterns if p.logic_type == focus_type]

    for pattern in patterns[:max_patterns]:
        lines.append(f"### {pattern.name} [{pattern.severity}]")
        lines.append(pattern.description)
        lines.append("\nDetection:")
        for strategy in pattern.detection_strategies[:4]:
            lines.append(f"  - {strategy}")
        lines.append("\nIndicators:")
        for indicator in pattern.indicators[:3]:
            lines.append(f"  - {indicator}")
        lines.append("\nTest Cases:")
        for tc in pattern.test_cases[:3]:
            lines.append(f"  - {tc}")
        lines.append("\nCommands:")
        for cmd in pattern.commands[:3]:
            lines.append(f"  $ {cmd}")
        lines.append("")

    return "\n".join(lines)
