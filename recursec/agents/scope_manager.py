"""Scope manager — enforces assessment scope boundaries.

Implements:
1. Target scope definition (in-scope, out-of-scope)
2. IP/CIDR range validation
3. Domain/subdomain matching
4. URL path restrictions
5. Time window enforcement
6. Rate limiting per target
7. Scope violation detection and alerting
8. Dynamic scope updates
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger()


@dataclass
class ScopeRule:
    """A single scope rule."""
    rule_id: str = ""
    rule_type: str = ""          # domain, ip, cidr, url, port
    pattern: str = ""
    is_include: bool = True      # True=in-scope, False=exclusion
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id, "type": self.rule_type,
            "pattern": self.pattern[:80],
            "include": self.is_include,
        }


@dataclass
class RateLimit:
    """Rate limit for a target."""
    target: str = ""
    max_requests_per_minute: int = 60
    max_requests_per_second: int = 5
    current_minute_count: int = 0
    current_second_count: int = 0
    minute_window_start: float = field(default_factory=time.time)
    second_window_start: float = field(default_factory=time.time)


@dataclass
class ScopeViolation:
    """A detected scope violation."""
    target: str = ""
    action: str = ""
    rule: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:80],
            "action": self.action[:60],
            "rule": self.rule[:60],
        }


class ScopeManager:
    """Enforces assessment scope boundaries.

    Validates all targets and actions against defined
    scope rules. Blocks out-of-scope operations.
    """

    def __init__(self) -> None:
        self._include_rules: list[ScopeRule] = []
        self._exclude_rules: list[ScopeRule] = []
        self._rate_limits: dict[str, RateLimit] = {}
        self._violations: list[ScopeViolation] = []
        self._rule_counter = 0
        self._time_start: float = 0
        self._time_end: float = 0
        self._log = logger.bind(component="scope_manager")

    def add_target(self, target: str, description: str = "") -> str:
        """Add a target to scope (auto-detects type)."""
        self._rule_counter += 1
        rule_id = f"scope-{self._rule_counter}"

        rule_type = self._detect_type(target)

        rule = ScopeRule(
            rule_id=rule_id,
            rule_type=rule_type,
            pattern=target,
            is_include=True,
            description=description,
        )

        self._include_rules.append(rule)

        # Auto-add subdomains for domains
        if rule_type == "domain":
            self._rule_counter += 1
            sub_rule = ScopeRule(
                rule_id=f"scope-{self._rule_counter}",
                rule_type="domain",
                pattern=f"*.{target}",
                is_include=True,
                description=f"Subdomains of {target}",
            )
            self._include_rules.append(sub_rule)

        return rule_id

    def add_exclusion(self, target: str, description: str = "") -> str:
        """Add an exclusion to scope."""
        self._rule_counter += 1
        rule_id = f"scope-{self._rule_counter}"

        rule = ScopeRule(
            rule_id=rule_id,
            rule_type=self._detect_type(target),
            pattern=target,
            is_include=False,
            description=description,
        )

        self._exclude_rules.append(rule)
        return rule_id

    def set_time_window(self, start: float, end: float) -> None:
        """Set allowed time window for testing."""
        self._time_start = start
        self._time_end = end

    def set_rate_limit(
        self,
        target: str,
        per_minute: int = 60,
        per_second: int = 5,
    ) -> None:
        """Set rate limit for a target."""
        self._rate_limits[target] = RateLimit(
            target=target,
            max_requests_per_minute=per_minute,
            max_requests_per_second=per_second,
        )

    def is_in_scope(self, target: str) -> bool:
        """Check if a target is in scope."""
        # Time window check
        if self._time_start and self._time_end:
            now = time.time()
            if now < self._time_start or now > self._time_end:
                self._record_violation(target, "access", "Outside time window")
                return False

        # Check exclusions first (exclusions override includes)
        for rule in self._exclude_rules:
            if self._matches(target, rule):
                return False

        # Check includes
        if not self._include_rules:
            return True  # No rules = everything in scope

        for rule in self._include_rules:
            if self._matches(target, rule):
                return True

        self._record_violation(target, "access", "Not in scope")
        return False

    def check_rate_limit(self, target: str) -> bool:
        """Check if rate limit allows the request."""
        limit = self._rate_limits.get(target)
        if not limit:
            return True

        now = time.time()

        # Reset second window
        if now - limit.second_window_start >= 1.0:
            limit.current_second_count = 0
            limit.second_window_start = now

        # Reset minute window
        if now - limit.minute_window_start >= 60.0:
            limit.current_minute_count = 0
            limit.minute_window_start = now

        if limit.current_second_count >= limit.max_requests_per_second:
            return False

        if limit.current_minute_count >= limit.max_requests_per_minute:
            return False

        limit.current_second_count += 1
        limit.current_minute_count += 1
        return True

    def _matches(self, target: str, rule: ScopeRule) -> bool:
        """Check if a target matches a scope rule."""
        if rule.rule_type == "domain":
            return self._match_domain(target, rule.pattern)
        elif rule.rule_type == "ip":
            return self._match_ip(target, rule.pattern)
        elif rule.rule_type == "cidr":
            return self._match_cidr(target, rule.pattern)
        elif rule.rule_type == "url":
            return self._match_url(target, rule.pattern)
        return target == rule.pattern

    def _match_domain(self, target: str, pattern: str) -> bool:
        """Match domain with wildcard support."""
        # Extract hostname from URL if needed
        hostname = target
        if "://" in target:
            parsed = urlparse(target)
            hostname = parsed.hostname or target

        hostname = hostname.lower().strip()
        pattern = pattern.lower().strip()

        if pattern.startswith("*."):
            suffix = pattern[2:]
            return hostname == suffix or hostname.endswith("." + suffix)

        return hostname == pattern

    def _match_ip(self, target: str, pattern: str) -> bool:
        """Match IP address."""
        try:
            return ipaddress.ip_address(target) == ipaddress.ip_address(pattern)
        except ValueError:
            return target == pattern

    def _match_cidr(self, target: str, pattern: str) -> bool:
        """Match IP against CIDR range."""
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            addr = ipaddress.ip_address(target)
            return addr in network
        except ValueError:
            return False

    def _match_url(self, target: str, pattern: str) -> bool:
        """Match URL pattern."""
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        return target.startswith(pattern)

    def _detect_type(self, target: str) -> str:
        """Detect target type."""
        if "/" in target and "." in target.split("/")[0]:
            # Could be CIDR
            try:
                ipaddress.ip_network(target, strict=False)
                return "cidr"
            except ValueError:
                pass

        try:
            ipaddress.ip_address(target)
            return "ip"
        except ValueError:
            pass

        if target.startswith(("http://", "https://")):
            return "url"

        if "." in target:
            return "domain"

        return "domain"

    def _record_violation(self, target: str, action: str, rule: str) -> None:
        violation = ScopeViolation(target=target, action=action, rule=rule)
        self._violations.append(violation)
        if len(self._violations) > 1000:
            self._violations = self._violations[-1000:]

    def get_violations(self, limit: int = 50) -> list[dict[str, Any]]:
        return [v.to_dict() for v in self._violations[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        return {
            "include_rules": len(self._include_rules),
            "exclude_rules": len(self._exclude_rules),
            "violations": len(self._violations),
            "rate_limits": len(self._rate_limits),
        }
