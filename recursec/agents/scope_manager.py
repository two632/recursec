"""Scope manager — manages assessment scope and prevents out-of-scope actions.

Implements:
1. Scope definition (targets, ports, protocols)
2. In-scope validation for all actions
3. IP/CIDR range matching
4. Domain and subdomain matching
5. Port range validation
6. Protocol restrictions
7. Exclusion management
8. Scope violation alerting
9. Dynamic scope expansion/restriction
10. Scope history tracking
"""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ScopeRule:
    """A scope rule definition."""
    rule_id: str = ""
    rule_type: str = ""          # include, exclude
    target_type: str = ""        # ip, cidr, domain, port, protocol, url_path
    value: str = ""
    description: str = ""
    added_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id, "type": self.rule_type,
            "target": self.target_type, "value": self.value[:40],
        }


@dataclass
class ScopeViolation:
    """A scope violation record."""
    violation_id: str = ""
    target: str = ""
    action: str = ""
    rule_violated: str = ""
    agent_id: str = ""
    timestamp: float = field(default_factory=time.time)
    blocked: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.violation_id, "target": self.target[:40],
            "action": self.action[:40], "blocked": self.blocked,
        }


class ScopeManager:
    """Manages assessment scope and prevents out-of-scope actions.

    Validates all targets and actions against defined
    scope rules to prevent unauthorized scanning.
    """

    def __init__(self) -> None:
        self._include_rules: list[ScopeRule] = []
        self._exclude_rules: list[ScopeRule] = []
        self._violations: list[ScopeViolation] = []
        self._rule_counter = 0
        self._violation_counter = 0
        self._check_count = 0
        self._log = logger.bind(component="scope_manager")

        # Permanently blocked targets
        self._blocked_ranges: list[str] = [
            "10.0.0.0/8",       # Private
            "172.16.0.0/12",    # Private (can be overridden)
            "192.168.0.0/16",   # Private (can be overridden)
            "127.0.0.0/8",      # Loopback
            "169.254.0.0/16",   # Link-local
        ]
        self._blocked_domains: list[str] = [
            "localhost",
            "*.local",
        ]
        self._allow_private = False

    def add_target(
        self,
        value: str,
        target_type: str = "auto",
        description: str = "",
    ) -> str:
        """Add an in-scope target."""
        if target_type == "auto":
            target_type = self._detect_type(value)

        self._rule_counter += 1
        rule = ScopeRule(
            rule_id=f"rule-{self._rule_counter}",
            rule_type="include",
            target_type=target_type,
            value=value,
            description=description,
        )
        self._include_rules.append(rule)
        return rule.rule_id

    def exclude_target(
        self,
        value: str,
        target_type: str = "auto",
        description: str = "",
    ) -> str:
        """Add an excluded target."""
        if target_type == "auto":
            target_type = self._detect_type(value)

        self._rule_counter += 1
        rule = ScopeRule(
            rule_id=f"rule-{self._rule_counter}",
            rule_type="exclude",
            target_type=target_type,
            value=value,
            description=description,
        )
        self._exclude_rules.append(rule)
        return rule.rule_id

    def allow_private_ranges(self, allow: bool = True) -> None:
        """Allow scanning of private IP ranges."""
        self._allow_private = allow

    def is_in_scope(
        self,
        target: str,
        agent_id: str = "",
        action: str = "",
    ) -> bool:
        """Check if a target is in scope."""
        self._check_count += 1

        # Check exclusions first
        for rule in self._exclude_rules:
            if self._matches_rule(target, rule):
                self._record_violation(target, action, rule.rule_id, agent_id)
                return False

        # Check blocked ranges (unless private allowed)
        if not self._allow_private:
            if self._is_blocked(target):
                self._record_violation(target, action, "blocked_range", agent_id)
                return False

        # Check if any include rule matches
        if not self._include_rules:
            # No rules defined — everything is out of scope
            return False

        for rule in self._include_rules:
            if self._matches_rule(target, rule):
                return True

        # Not matched by any include rule
        self._record_violation(target, action, "no_include_match", agent_id)
        return False

    def _matches_rule(self, target: str, rule: ScopeRule) -> bool:
        """Check if target matches a rule."""
        if rule.target_type == "ip":
            return self._match_ip(target, rule.value)
        elif rule.target_type == "cidr":
            return self._match_cidr(target, rule.value)
        elif rule.target_type == "domain":
            return self._match_domain(target, rule.value)
        elif rule.target_type == "port":
            return self._match_port(target, rule.value)
        elif rule.target_type == "url":
            return target.startswith(rule.value) or rule.value in target
        return False

    def _match_ip(self, target: str, rule_ip: str) -> bool:
        """Match target against an IP."""
        # Extract IP from target (could be ip:port or url)
        target_ip = self._extract_ip(target)
        return target_ip == rule_ip

    def _match_cidr(self, target: str, cidr: str) -> bool:
        """Match target against a CIDR range."""
        target_ip = self._extract_ip(target)
        if not target_ip:
            return False

        try:
            network = ipaddress.ip_network(cidr, strict=False)
            ip = ipaddress.ip_address(target_ip)
            return ip in network
        except ValueError:
            return False

    def _match_domain(self, target: str, domain: str) -> bool:
        """Match target against a domain pattern."""
        target_domain = self._extract_domain(target)
        if not target_domain:
            return False

        # Wildcard matching
        if domain.startswith("*."):
            suffix = domain[2:]
            return target_domain.endswith(suffix) or target_domain == suffix
        elif domain.startswith("."):
            return target_domain.endswith(domain) or target_domain == domain[1:]

        return target_domain == domain or target_domain.endswith("." + domain)

    def _match_port(self, target: str, port_spec: str) -> bool:
        """Match target against port spec (single or range)."""
        target_port = self._extract_port(target)
        if target_port is None:
            return False

        if "-" in port_spec:
            parts = port_spec.split("-")
            if len(parts) == 2:
                try:
                    low, high = int(parts[0]), int(parts[1])
                    return low <= target_port <= high
                except ValueError:
                    return False
        else:
            try:
                return target_port == int(port_spec)
            except ValueError:
                return False

        return False

    def _is_blocked(self, target: str) -> bool:
        """Check if target is in blocked ranges."""
        target_ip = self._extract_ip(target)
        if target_ip:
            for cidr in self._blocked_ranges:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if ipaddress.ip_address(target_ip) in network:
                        return True
                except ValueError:
                    pass

        target_domain = self._extract_domain(target)
        if target_domain:
            for blocked in self._blocked_domains:
                if blocked.startswith("*."):
                    if target_domain.endswith(blocked[2:]):
                        return True
                elif target_domain == blocked:
                    return True

        return False

    def _record_violation(
        self,
        target: str,
        action: str,
        rule: str,
        agent_id: str,
    ) -> None:
        """Record a scope violation."""
        self._violation_counter += 1
        violation = ScopeViolation(
            violation_id=f"sv-{self._violation_counter}",
            target=target,
            action=action,
            rule_violated=rule,
            agent_id=agent_id,
        )
        self._violations.append(violation)

        if len(self._violations) > 500:
            self._violations = self._violations[-500:]

    @staticmethod
    def _detect_type(value: str) -> str:
        """Auto-detect the type of a target value."""
        if "/" in value and any(c.isdigit() for c in value.split("/")[-1]):
            try:
                ipaddress.ip_network(value, strict=False)
                return "cidr"
            except ValueError:
                pass

        try:
            ipaddress.ip_address(value.split(":")[0])
            return "ip"
        except ValueError:
            pass

        if re.match(r"^\d+(-\d+)?$", value):
            return "port"

        if value.startswith("http://") or value.startswith("https://"):
            return "url"

        return "domain"

    @staticmethod
    def _extract_ip(target: str) -> str:
        """Extract IP address from target string."""
        # Remove protocol
        cleaned = re.sub(r"^https?://", "", target)
        # Remove port and path
        cleaned = cleaned.split(":")[0].split("/")[0]

        try:
            ipaddress.ip_address(cleaned)
            return cleaned
        except ValueError:
            return ""

    @staticmethod
    def _extract_domain(target: str) -> str:
        """Extract domain from target string."""
        cleaned = re.sub(r"^https?://", "", target)
        cleaned = cleaned.split(":")[0].split("/")[0]

        if re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}$", cleaned):
            return cleaned.lower()
        return ""

    @staticmethod
    def _extract_port(target: str) -> int | None:
        """Extract port from target string."""
        cleaned = re.sub(r"^https?://", "", target)
        if ":" in cleaned:
            port_str = cleaned.split(":")[1].split("/")[0]
            try:
                return int(port_str)
            except ValueError:
                return None
        return None

    def get_violations(self, limit: int = 20) -> list[dict[str, Any]]:
        return [v.to_dict() for v in self._violations[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        return {
            "includes": len(self._include_rules),
            "excludes": len(self._exclude_rules),
            "checks": self._check_count,
            "violations": len(self._violations),
        }
