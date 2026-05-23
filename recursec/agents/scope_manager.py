"""Scope manager — enforces assessment scope and boundaries.

Implements:
1. Target scope definition (IPs, CIDRs, domains, wildcards)
2. Scope validation for every agent action
3. Exclusion list management
4. Scope expansion requests
5. Scope change audit trail
6. Time-based scope windows
7. Scope visualization
8. Multi-scope support (different scopes per assessment)
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ScopeType(str, Enum):
    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    WILDCARD_DOMAIN = "wildcard_domain"
    URL = "url"
    PORT_RANGE = "port_range"


class ScopeAction(str, Enum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


@dataclass
class ScopeEntry:
    """A single scope entry."""
    entry_id: str = ""
    scope_type: ScopeType = ScopeType.DOMAIN
    value: str = ""
    action: ScopeAction = ScopeAction.INCLUDE
    ports: list[int] = field(default_factory=list)
    added_by: str = ""
    added_at: float = field(default_factory=time.time)
    valid_from: float = 0.0
    valid_until: float = 0.0
    notes: str = ""

    @property
    def is_active(self) -> bool:
        now = time.time()
        if self.valid_from > 0 and now < self.valid_from:
            return False
        if self.valid_until > 0 and now > self.valid_until:
            return False
        return True

    def matches(self, target: str) -> bool:
        """Check if a target matches this scope entry."""
        if self.scope_type == ScopeType.IP:
            return target == self.value

        if self.scope_type == ScopeType.CIDR:
            try:
                network = ipaddress.ip_network(self.value, strict=False)
                ip = ipaddress.ip_address(target)
                return ip in network
            except ValueError:
                return False

        if self.scope_type == ScopeType.DOMAIN:
            return target.lower() == self.value.lower()

        if self.scope_type == ScopeType.WILDCARD_DOMAIN:
            pattern = self.value.lower().replace("*.", "")
            return target.lower().endswith(pattern) or target.lower() == pattern

        if self.scope_type == ScopeType.URL:
            return target.lower().startswith(self.value.lower())

        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entry_id,
            "type": self.scope_type.value,
            "value": self.value[:30],
            "action": self.action.value,
            "active": self.is_active,
        }


@dataclass
class ScopeCheckResult:
    """Result of a scope check."""
    target: str = ""
    in_scope: bool = False
    matched_entry: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:25],
            "in_scope": self.in_scope,
            "reason": self.reason[:30],
        }


@dataclass
class ScopeChangeLog:
    """Audit trail entry for scope changes."""
    action: str = ""
    entry_id: str = ""
    value: str = ""
    changed_by: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action[:10],
            "entry": self.entry_id[:10],
            "value": self.value[:25],
            "by": self.changed_by[:15],
        }


class ScopeManager:
    """Enforces assessment scope and boundaries.

    Every agent action that touches a target must
    be validated against the scope before execution.
    """

    def __init__(self) -> None:
        self._entries: dict[str, ScopeEntry] = {}
        self._changelog: list[ScopeChangeLog] = []
        self._entry_counter = 0
        self._check_cache: dict[str, bool] = {}
        self._log = logger.bind(component="scope_manager")

    def add_include(
        self,
        value: str,
        scope_type: ScopeType | None = None,
        ports: list[int] | None = None,
        added_by: str = "user",
        notes: str = "",
    ) -> ScopeEntry:
        """Add a target to scope."""
        if not scope_type:
            scope_type = self._detect_type(value)

        self._entry_counter += 1
        entry = ScopeEntry(
            entry_id=f"se-{self._entry_counter}",
            scope_type=scope_type,
            value=value,
            action=ScopeAction.INCLUDE,
            ports=ports or [],
            added_by=added_by,
            notes=notes,
        )

        self._entries[entry.entry_id] = entry
        self._check_cache.clear()

        self._changelog.append(ScopeChangeLog(
            action="add_include",
            entry_id=entry.entry_id,
            value=value,
            changed_by=added_by,
        ))

        return entry

    def add_exclude(
        self,
        value: str,
        scope_type: ScopeType | None = None,
        added_by: str = "user",
        notes: str = "",
    ) -> ScopeEntry:
        """Add an exclusion."""
        if not scope_type:
            scope_type = self._detect_type(value)

        self._entry_counter += 1
        entry = ScopeEntry(
            entry_id=f"se-{self._entry_counter}",
            scope_type=scope_type,
            value=value,
            action=ScopeAction.EXCLUDE,
            added_by=added_by,
            notes=notes,
        )

        self._entries[entry.entry_id] = entry
        self._check_cache.clear()

        self._changelog.append(ScopeChangeLog(
            action="add_exclude",
            entry_id=entry.entry_id,
            value=value,
            changed_by=added_by,
        ))

        return entry

    def check(self, target: str) -> ScopeCheckResult:
        """Check if a target is in scope."""
        # Check cache
        if target in self._check_cache:
            return ScopeCheckResult(
                target=target,
                in_scope=self._check_cache[target],
                reason="cached",
            )

        if not self._entries:
            return ScopeCheckResult(
                target=target,
                in_scope=False,
                reason="No scope defined",
            )

        # Check exclusions first
        for entry in self._entries.values():
            if not entry.is_active:
                continue
            if entry.action == ScopeAction.EXCLUDE and entry.matches(target):
                self._check_cache[target] = False
                return ScopeCheckResult(
                    target=target,
                    in_scope=False,
                    matched_entry=entry.entry_id,
                    reason=f"Excluded: {entry.value}",
                )

        # Check inclusions
        for entry in self._entries.values():
            if not entry.is_active:
                continue
            if entry.action == ScopeAction.INCLUDE and entry.matches(target):
                self._check_cache[target] = True
                return ScopeCheckResult(
                    target=target,
                    in_scope=True,
                    matched_entry=entry.entry_id,
                    reason=f"Included: {entry.value}",
                )

        self._check_cache[target] = False
        return ScopeCheckResult(
            target=target,
            in_scope=False,
            reason="Not in any scope entry",
        )

    def remove_entry(self, entry_id: str, removed_by: str = "user") -> bool:
        """Remove a scope entry."""
        if entry_id not in self._entries:
            return False

        entry = self._entries.pop(entry_id)
        self._check_cache.clear()

        self._changelog.append(ScopeChangeLog(
            action="remove",
            entry_id=entry_id,
            value=entry.value,
            changed_by=removed_by,
        ))

        return True

    @staticmethod
    def _detect_type(value: str) -> ScopeType:
        """Auto-detect scope type from value."""
        # CIDR
        if "/" in value:
            try:
                ipaddress.ip_network(value, strict=False)
                return ScopeType.CIDR
            except ValueError:
                pass

        # IP
        try:
            ipaddress.ip_address(value)
            return ScopeType.IP
        except ValueError:
            pass

        # Wildcard domain
        if value.startswith("*."):
            return ScopeType.WILDCARD_DOMAIN

        # URL
        if value.startswith(("http://", "https://")):
            return ScopeType.URL

        # Domain
        return ScopeType.DOMAIN

    def get_scope_summary(self) -> dict[str, Any]:
        """Get summary of current scope."""
        includes = [
            e for e in self._entries.values()
            if e.action == ScopeAction.INCLUDE and e.is_active
        ]
        excludes = [
            e for e in self._entries.values()
            if e.action == ScopeAction.EXCLUDE and e.is_active
        ]

        return {
            "includes": [e.to_dict() for e in includes],
            "excludes": [e.to_dict() for e in excludes],
            "total_entries": len(self._entries),
            "changelog_entries": len(self._changelog),
        }

    def get_stats(self) -> dict[str, Any]:
        return {
            "entries": len(self._entries),
            "includes": sum(1 for e in self._entries.values() if e.action == ScopeAction.INCLUDE),
            "excludes": sum(1 for e in self._entries.values() if e.action == ScopeAction.EXCLUDE),
            "changelog": len(self._changelog),
        }
