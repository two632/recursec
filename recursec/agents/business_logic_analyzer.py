"""Business logic analyzer — discovers logic vulnerabilities via LLM reasoning.

Implements:
1. Business rule extraction from application behavior
2. State machine modeling
3. Workflow step skipping detection
4. Financial logic abuse (price manipulation, double-spend)
5. Authorization logic bypass
6. Multi-step process manipulation
7. Rate/limit circumvention
8. Coupon/discount stacking detection
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class BusinessRuleType(str, Enum):
    FINANCIAL = "financial"           # Price, payment, balance
    AUTHORIZATION = "authorization"   # Access control, roles
    WORKFLOW = "workflow"             # Multi-step process
    RATE_LIMIT = "rate_limit"        # Quotas, limits
    DATA_INTEGRITY = "data_integrity" # Consistency, validation
    TEMPORAL = "temporal"            # Time-based rules


class LogicFlawType(str, Enum):
    PRICE_MANIPULATION = "price_manipulation"
    COUPON_STACKING = "coupon_stacking"
    NEGATIVE_QUANTITY = "negative_quantity"
    WORKFLOW_SKIP = "workflow_skip"
    STATE_MANIPULATION = "state_manipulation"
    AUTH_LOGIC_BYPASS = "auth_logic_bypass"
    DOUBLE_SPEND = "double_spend"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    IDOR = "idor"
    PARAMETER_POLLUTION = "parameter_pollution"
    MASS_ASSIGNMENT = "mass_assignment"
    INSUFFICIENT_VALIDATION = "insufficient_validation"


@dataclass
class BusinessRule:
    """A business rule the application should enforce."""
    rule_id: str = ""
    name: str = ""
    rule_type: BusinessRuleType = BusinessRuleType.FINANCIAL
    description: str = ""
    enforcement_point: str = ""     # Where in the app it's enforced
    parameters: dict[str, Any] = field(default_factory=dict)
    verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "name": self.name[:25],
            "type": self.rule_type.value,
            "verified": self.verified,
        }


@dataclass
class WorkflowState:
    """A state in the application workflow."""
    state_id: str = ""
    name: str = ""
    transitions: dict[str, str] = field(default_factory=dict)
    required_data: list[str] = field(default_factory=list)
    is_terminal: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.state_id,
            "name": self.name[:20],
            "transitions": len(self.transitions),
            "terminal": self.is_terminal,
        }


@dataclass
class LogicFlaw:
    """A business logic vulnerability."""
    flaw_id: str = ""
    flaw_type: LogicFlawType = LogicFlawType.PRICE_MANIPULATION
    title: str = ""
    description: str = ""
    severity: str = "high"
    affected_rule: str = ""
    reproduction_steps: list[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    model_used: str = ""       # Which LLM found this

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.flaw_id,
            "type": self.flaw_type.value,
            "title": self.title[:30],
            "severity": self.severity,
            "steps": len(self.reproduction_steps),
        }


@dataclass
class TestCase:
    """A test case for business logic validation."""
    test_id: str = ""
    name: str = ""
    flaw_type: LogicFlawType = LogicFlawType.PRICE_MANIPULATION
    endpoint: str = ""
    method: str = "POST"
    parameters: dict[str, Any] = field(default_factory=dict)
    expected_behavior: str = ""
    actual_behavior: str = ""
    is_vulnerable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.test_id,
            "name": self.name[:25],
            "type": self.flaw_type.value,
            "endpoint": self.endpoint[:20],
            "vulnerable": self.is_vulnerable,
        }


# ── Default Business Logic Test Templates ─────────────────────

LOGIC_TEST_TEMPLATES: list[dict[str, Any]] = [
    # Financial logic
    {
        "name": "Negative quantity in cart",
        "type": "negative_quantity",
        "desc": "Add item with negative quantity to get credit",
        "steps": ["Add item to cart", "Modify quantity to -1 or -100", "Proceed to checkout", "Check if total is negative (credit)"],
        "severity": "critical",
        "impact": "Free goods or account credit",
        "remediation": "Validate quantity > 0 server-side",
    },
    {
        "name": "Zero price manipulation",
        "type": "price_manipulation",
        "desc": "Modify price parameter in request to 0 or 0.01",
        "steps": ["Select item", "Intercept checkout request", "Change price to 0 or 0.01", "Submit modified request"],
        "severity": "critical",
        "impact": "Purchase items at arbitrary price",
        "remediation": "Never trust client-side price; use server-side pricing",
    },
    {
        "name": "Multiple coupon stacking",
        "type": "coupon_stacking",
        "desc": "Apply same or multiple coupons to get excessive discount",
        "steps": ["Apply coupon code", "Apply same coupon again", "Apply different coupon", "Check if discounts stack"],
        "severity": "high",
        "impact": "Excessive discounts, potentially free items",
        "remediation": "Enforce one coupon per order server-side",
    },
    {
        "name": "Double-spend via race condition",
        "type": "double_spend",
        "desc": "Send concurrent requests to spend same balance twice",
        "steps": ["Check account balance", "Send two concurrent purchase requests", "Both deduct from same balance", "Total spent > original balance"],
        "severity": "critical",
        "impact": "Financial loss, double-spending",
        "remediation": "Use database transactions with row-level locking",
    },
    # Workflow logic
    {
        "name": "Skip payment step",
        "type": "workflow_skip",
        "desc": "Jump directly to order confirmation skipping payment",
        "steps": ["Add items to cart", "Note the confirmation URL pattern", "Skip payment step by going directly to confirmation URL", "Check if order is placed without payment"],
        "severity": "critical",
        "impact": "Free goods without payment",
        "remediation": "Server-side workflow state tracking, validate all steps completed",
    },
    {
        "name": "Skip verification step",
        "type": "workflow_skip",
        "desc": "Bypass email/phone verification in registration",
        "steps": ["Start registration", "Submit form data", "Skip verification step by directly accessing dashboard", "Check if account is active without verification"],
        "severity": "high",
        "impact": "Account creation without verification",
        "remediation": "Enforce verification before activating account",
    },
    # Authorization logic
    {
        "name": "IDOR on user resources",
        "type": "idor",
        "desc": "Access other users' resources by changing ID parameter",
        "steps": ["Access own resource: /api/user/123/data", "Change ID to another user: /api/user/124/data", "Check if data is returned", "Try with POST/PUT/DELETE methods"],
        "severity": "high",
        "impact": "Unauthorized access to other users' data",
        "remediation": "Check resource ownership server-side",
    },
    {
        "name": "Mass assignment role escalation",
        "type": "mass_assignment",
        "desc": "Include admin/role field in profile update to escalate privileges",
        "steps": ["Update profile normally", "Add role=admin or is_admin=true to request", "Check if role was updated", "Verify admin access"],
        "severity": "critical",
        "impact": "Privilege escalation to admin",
        "remediation": "Whitelist updateable fields, never bind role/permissions",
    },
    {
        "name": "Parameter pollution bypass",
        "type": "parameter_pollution",
        "desc": "Send same parameter multiple times with different values",
        "steps": ["Send request with email=victim@x.com&email=attacker@x.com", "Server may use first for auth check, second for action", "Check which email receives the action"],
        "severity": "medium",
        "impact": "Authorization bypass, action misdirection",
        "remediation": "Reject requests with duplicate parameters",
    },
    # Rate limit
    {
        "name": "Rate limit bypass via headers",
        "type": "rate_limit_bypass",
        "desc": "Bypass rate limiting by rotating IP headers",
        "steps": ["Hit rate limit normally", "Add X-Forwarded-For: random_ip", "Add X-Real-IP: random_ip", "Check if rate limit is reset"],
        "severity": "medium",
        "impact": "Brute force attacks, enumeration",
        "remediation": "Rate limit by authenticated user, not just IP",
    },
]


class BusinessLogicAnalyzer:
    """Discovers logic vulnerabilities via LLM-guided analysis.

    Models application business rules, workflows, and state machines,
    then systematically tests for logic bypasses.
    """

    def __init__(self) -> None:
        self._rules: dict[str, BusinessRule] = {}
        self._states: dict[str, WorkflowState] = {}
        self._flaws: list[LogicFlaw] = []
        self._test_cases: list[TestCase] = []
        self._rule_counter = 0
        self._state_counter = 0
        self._flaw_counter = 0
        self._test_counter = 0
        self._log = logger.bind(component="business_logic_analyzer")

    def add_rule(
        self,
        name: str,
        rule_type: BusinessRuleType,
        description: str = "",
        enforcement_point: str = "",
    ) -> BusinessRule:
        """Add a business rule to track."""
        self._rule_counter += 1
        rule = BusinessRule(
            rule_id=f"br-{self._rule_counter}",
            name=name,
            rule_type=rule_type,
            description=description,
            enforcement_point=enforcement_point,
        )
        self._rules[rule.rule_id] = rule
        return rule

    def add_workflow_state(
        self,
        name: str,
        transitions: dict[str, str] | None = None,
        required_data: list[str] | None = None,
        is_terminal: bool = False,
    ) -> WorkflowState:
        """Add a workflow state."""
        self._state_counter += 1
        state = WorkflowState(
            state_id=f"ws-{self._state_counter}",
            name=name,
            transitions=transitions or {},
            required_data=required_data or [],
            is_terminal=is_terminal,
        )
        self._states[state.state_id] = state
        return state

    def generate_test_cases(self) -> list[TestCase]:
        """Generate test cases from templates."""
        tests = []
        for tmpl in LOGIC_TEST_TEMPLATES:
            self._test_counter += 1
            test = TestCase(
                test_id=f"tc-{self._test_counter}",
                name=tmpl["name"],
                flaw_type=LogicFlawType(tmpl["type"]),
                expected_behavior=tmpl.get("desc", ""),
            )
            tests.append(test)
        self._test_cases.extend(tests)
        return tests

    def record_flaw(
        self,
        flaw_type: LogicFlawType,
        title: str,
        description: str = "",
        severity: str = "high",
        reproduction_steps: list[str] | None = None,
        impact: str = "",
        remediation: str = "",
        model_used: str = "",
    ) -> LogicFlaw:
        """Record a business logic flaw."""
        self._flaw_counter += 1
        flaw = LogicFlaw(
            flaw_id=f"blf-{self._flaw_counter}",
            flaw_type=flaw_type,
            title=title,
            description=description,
            severity=severity,
            reproduction_steps=reproduction_steps or [],
            impact=impact,
            remediation=remediation,
            model_used=model_used,
        )
        self._flaws.append(flaw)
        return flaw

    def check_workflow_skip(self) -> list[LogicFlaw]:
        """Check if workflow steps can be skipped."""
        findings = []

        states = list(self._states.values())
        terminal_states = [s for s in states if s.is_terminal]
        non_terminal = [s for s in states if not s.is_terminal]

        for terminal in terminal_states:
            for state in non_terminal:
                # Check if terminal state is directly reachable
                for action, target in state.transitions.items():
                    if target == terminal.state_id:
                        # Check if there are intermediate required states
                        intermediate_required = [
                            s for s in non_terminal
                            if s.required_data and s.state_id != state.state_id
                        ]
                        if intermediate_required:
                            self._flaw_counter += 1
                            findings.append(LogicFlaw(
                                flaw_id=f"blf-{self._flaw_counter}",
                                flaw_type=LogicFlawType.WORKFLOW_SKIP,
                                title=f"Potential skip from {state.name} to {terminal.name}",
                                description=(
                                    f"Direct transition exists from {state.name} to "
                                    f"terminal state {terminal.name} via '{action}', "
                                    f"potentially bypassing intermediate steps"
                                ),
                                severity="high",
                                reproduction_steps=[
                                    f"Start at state: {state.name}",
                                    f"Trigger action: {action}",
                                    f"Arrive at: {terminal.name}",
                                    "Verify intermediate steps were skipped",
                                ],
                            ))

        self._flaws.extend(findings)
        return findings

    def get_prompt_for_analysis(self, target_info: str = "") -> str:
        """Generate a prompt for LLM-based business logic analysis."""
        rules_text = ""
        if self._rules:
            rules_text = "Known business rules:\n"
            for rule in self._rules.values():
                rules_text += f"- {rule.name}: {rule.description}\n"

        return (
            f"Analyze the following application for business logic vulnerabilities.\n\n"
            f"Target information:\n{target_info}\n\n"
            f"{rules_text}\n"
            f"Look for:\n"
            f"1. Price manipulation (can price/quantity be modified client-side?)\n"
            f"2. Workflow skipping (can steps be bypassed?)\n"
            f"3. Authorization bypasses (can user access others' data?)\n"
            f"4. Rate limit circumvention\n"
            f"5. Double-spend/race conditions on financial operations\n"
            f"6. Mass assignment (can hidden fields be set?)\n"
            f"7. Parameter pollution\n\n"
            f"For each finding, provide: type, severity, reproduction steps, impact."
        )

    def get_stats(self) -> dict[str, Any]:
        flaw_types: dict[str, int] = defaultdict(int)
        for flaw in self._flaws:
            flaw_types[flaw.flaw_type.value] += 1
        return {
            "rules": len(self._rules),
            "states": len(self._states),
            "flaws": len(self._flaws),
            "test_cases": len(self._test_cases),
            "flaw_types": dict(flaw_types),
        }
