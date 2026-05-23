"""Policy engine — configurable rules governing agent behavior.

Policies define what agents can and cannot do:
1. Scope policies: What targets are in/out of scope
2. Safety policies: What actions are too risky
3. Rate limit policies: How fast agents can operate
4. Escalation policies: When to ask for human approval
5. Stealth policies: How to avoid detection
6. Compliance policies: Regulatory requirements
7. Tool policies: Which tools can be used and when

Policies are evaluated before every agent action.
Actions that violate policies are blocked.

Policy evaluation is fast (no LLM calls) —
all rules are deterministic and pre-computed.
"""

from __future__ import annotations

import ipaddress
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"
    REQUIRE_APPROVAL = "require_approval"
    RATE_LIMIT = "rate_limit"


class PolicyCategory(str, Enum):
    SCOPE = "scope"
    SAFETY = "safety"
    RATE_LIMIT = "rate_limit"
    ESCALATION = "escalation"
    STEALTH = "stealth"
    COMPLIANCE = "compliance"
    TOOL = "tool"


@dataclass
class PolicyRule:
    """A single policy rule."""
    rule_id: str = ""
    name: str = ""
    category: PolicyCategory = PolicyCategory.SAFETY
    description: str = ""
    condition: str = ""   # Rule condition expression
    decision: PolicyDecision = PolicyDecision.DENY
    message: str = ""
    priority: int = 5     # Lower = higher priority (evaluated first)
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id, "name": self.name,
            "category": self.category.value,
            "decision": self.decision.value,
            "enabled": self.enabled,
            "priority": self.priority,
        }


@dataclass
class PolicyEvaluation:
    """Result of evaluating a policy."""
    decision: PolicyDecision = PolicyDecision.ALLOW
    matched_rules: list[PolicyRule] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision in (PolicyDecision.ALLOW, PolicyDecision.WARN)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "allowed": self.allowed,
            "rules": [r.rule_id for r in self.matched_rules],
            "messages": self.messages[:5],
        }


class ScopeManager:
    """Manages target scope — what's in and out of scope."""

    def __init__(self) -> None:
        self._in_scope_domains: list[str] = []
        self._in_scope_ips: list[str] = []  # CIDR notation
        self._in_scope_urls: list[str] = []
        self._out_of_scope_domains: list[str] = []
        self._out_of_scope_ips: list[str] = []
        self._out_of_scope_urls: list[str] = []

    def configure(
        self,
        in_scope_domains: list[str] | None = None,
        in_scope_ips: list[str] | None = None,
        in_scope_urls: list[str] | None = None,
        out_of_scope_domains: list[str] | None = None,
        out_of_scope_ips: list[str] | None = None,
        out_of_scope_urls: list[str] | None = None,
    ) -> None:
        if in_scope_domains:
            self._in_scope_domains = [d.lower() for d in in_scope_domains]
        if in_scope_ips:
            self._in_scope_ips = in_scope_ips
        if in_scope_urls:
            self._in_scope_urls = in_scope_urls
        if out_of_scope_domains:
            self._out_of_scope_domains = [d.lower() for d in out_of_scope_domains]
        if out_of_scope_ips:
            self._out_of_scope_ips = out_of_scope_ips
        if out_of_scope_urls:
            self._out_of_scope_urls = out_of_scope_urls

    def is_in_scope(self, target: str) -> bool:
        """Check if a target is in scope."""
        target_lower = target.lower()

        # Check out of scope first (takes precedence)
        for domain in self._out_of_scope_domains:
            if domain in target_lower:
                return False
        for url in self._out_of_scope_urls:
            if url in target_lower:
                return False
        for cidr in self._out_of_scope_ips:
            if self._ip_in_cidr(target, cidr):
                return False

        # If no in-scope rules defined, everything is in scope
        if not self._in_scope_domains and not self._in_scope_ips and not self._in_scope_urls:
            return True

        # Check in-scope
        for domain in self._in_scope_domains:
            if domain in target_lower:
                return True
        for url in self._in_scope_urls:
            if url in target_lower:
                return True
        for cidr in self._in_scope_ips:
            if self._ip_in_cidr(target, cidr):
                return True

        return False

    def _ip_in_cidr(self, ip_str: str, cidr: str) -> bool:
        """Check if an IP address is within a CIDR range."""
        try:
            ip = ipaddress.ip_address(ip_str)
            network = ipaddress.ip_network(cidr, strict=False)
            return ip in network
        except ValueError:
            return False


class RateLimiter:
    """Rate limiting for agent actions."""

    def __init__(self) -> None:
        self._limits: dict[str, tuple[int, float]] = {}  # key → (max_count, window_s)
        self._counters: dict[str, list[float]] = defaultdict(list)

    def set_limit(self, key: str, max_count: int, window_s: float) -> None:
        """Set a rate limit: max_count actions per window_s seconds."""
        self._limits[key] = (max_count, window_s)

    def check(self, key: str) -> bool:
        """Check if action is within rate limit. Returns True if allowed."""
        if key not in self._limits:
            return True

        max_count, window_s = self._limits[key]
        now = time.time()
        cutoff = now - window_s

        # Clean old entries
        self._counters[key] = [t for t in self._counters[key] if t > cutoff]

        return len(self._counters[key]) < max_count

    def record(self, key: str) -> None:
        """Record that an action was taken."""
        self._counters[key].append(time.time())


# ── Default Safety Rules ─────────────────────────────────────

DANGEROUS_TOOLS = [
    "rm", "format", "fdisk", "mkfs", "dd",
    "shutdown", "reboot", "init", "halt",
    "iptables-flush-all", "kill-all",
]

DANGEROUS_PAYLOADS = [
    "rm -rf", ":(){ :|:& };:", "format c:",
    "del /f /s /q", "> /dev/sda",
]

HIGH_IMPACT_TOOLS = [
    "metasploit", "sqlmap", "hydra", "john",
    "hashcat", "responder", "impacket",
    "mimikatz", "crackmapexec",
]


class PolicyEngine:
    """Configurable policy engine governing agent behavior.

    Evaluates rules before every agent action to ensure
    compliance with scope, safety, and operational policies.
    """

    def __init__(self) -> None:
        self._rules: list[PolicyRule] = []
        self._scope = ScopeManager()
        self._rate_limiter = RateLimiter()
        self._violation_log: list[dict[str, Any]] = []
        self._log = logger.bind(component="policy_engine")

        # Load default rules
        self._load_defaults()

    def configure_scope(self, **kwargs: Any) -> None:
        """Configure target scope."""
        self._scope.configure(**kwargs)

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a custom policy rule."""
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)

    def set_rate_limit(self, action: str, max_count: int, window_s: float) -> None:
        """Set a rate limit for an action type."""
        self._rate_limiter.set_limit(action, max_count, window_s)

    def evaluate_action(
        self,
        action: str,
        agent_id: str = "",
        target: str = "",
        tool: str = "",
        payload: str = "",
    ) -> PolicyEvaluation:
        """Evaluate whether an action is allowed."""
        evaluation = PolicyEvaluation()

        # Check scope
        if target and not self._scope.is_in_scope(target):
            evaluation.decision = PolicyDecision.DENY
            evaluation.messages.append(f"Target '{target}' is out of scope")
            self._log_violation(agent_id, "scope", f"Out of scope target: {target}")
            return evaluation

        # Check rate limits
        rate_key = f"{agent_id}:{action}"
        if not self._rate_limiter.check(rate_key):
            evaluation.decision = PolicyDecision.RATE_LIMIT
            evaluation.messages.append(f"Rate limit exceeded for {action}")
            return evaluation
        self._rate_limiter.record(rate_key)

        # Check safety rules
        if tool:
            tool_lower = tool.lower()
            if any(dt in tool_lower for dt in DANGEROUS_TOOLS):
                evaluation.decision = PolicyDecision.DENY
                evaluation.messages.append(f"Tool '{tool}' is blocked by safety policy")
                self._log_violation(agent_id, "safety", f"Dangerous tool: {tool}")
                return evaluation

            if any(ht in tool_lower for ht in HIGH_IMPACT_TOOLS):
                evaluation.decision = PolicyDecision.WARN
                evaluation.messages.append(f"Tool '{tool}' is high-impact — proceed with caution")

        # Check payload safety
        if payload:
            payload_lower = payload.lower()
            if any(dp in payload_lower for dp in DANGEROUS_PAYLOADS):
                evaluation.decision = PolicyDecision.DENY
                evaluation.messages.append("Dangerous payload detected")
                self._log_violation(agent_id, "safety", f"Dangerous payload: {payload[:50]}")
                return evaluation

        # Evaluate custom rules
        for rule in self._rules:
            if not rule.enabled:
                continue
            if self._matches_rule(rule, action, agent_id, target, tool, payload):
                evaluation.matched_rules.append(rule)
                evaluation.messages.append(rule.message or rule.name)
                # Most restrictive decision wins
                if self._is_more_restrictive(rule.decision, evaluation.decision):
                    evaluation.decision = rule.decision

        return evaluation

    def get_violations(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._violation_log[-limit:]

    def get_rules(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._rules]

    # ── Internal ─────────────────────────────────────────

    def _load_defaults(self) -> None:
        """Load default safety rules."""
        # Rate limits
        self._rate_limiter.set_limit("tool_call", 60, 60.0)   # 60 tool calls per minute
        self._rate_limiter.set_limit("llm_call", 120, 60.0)   # 120 LLM calls per minute
        self._rate_limiter.set_limit("exploit", 10, 60.0)     # 10 exploit attempts per minute
        self._rate_limiter.set_limit("brute_force", 5, 60.0)  # 5 brute force attempts per minute

    def _matches_rule(
        self,
        rule: PolicyRule,
        action: str,
        agent_id: str,
        target: str,
        tool: str,
        payload: str,
    ) -> bool:
        """Check if a rule matches the current action context."""
        condition = rule.condition.lower()
        if not condition:
            return False

        # Simple pattern matching
        if condition.startswith("tool:"):
            return tool.lower() == condition[5:].strip()
        if condition.startswith("action:"):
            return action.lower() == condition[7:].strip()
        if condition.startswith("agent:"):
            return agent_id.lower() == condition[6:].strip()
        if condition.startswith("target_contains:"):
            return condition[16:].strip() in target.lower()
        if condition.startswith("payload_contains:"):
            return condition[17:].strip() in payload.lower()

        return False

    def _is_more_restrictive(self, new: PolicyDecision, current: PolicyDecision) -> bool:
        """Check if new decision is more restrictive than current."""
        order = {
            PolicyDecision.ALLOW: 0,
            PolicyDecision.WARN: 1,
            PolicyDecision.RATE_LIMIT: 2,
            PolicyDecision.REQUIRE_APPROVAL: 3,
            PolicyDecision.DENY: 4,
        }
        return order.get(new, 0) > order.get(current, 0)

    def _log_violation(self, agent_id: str, category: str, description: str) -> None:
        self._violation_log.append({
            "agent": agent_id, "category": category,
            "description": description,
            "timestamp": time.time(),
        })
        if len(self._violation_log) > 1000:
            self._violation_log = self._violation_log[-1000:]

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_rules": len(self._rules),
            "total_violations": len(self._violation_log),
            "scope_configured": bool(self._scope._in_scope_domains or self._scope._in_scope_ips),
        }
