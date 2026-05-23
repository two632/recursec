"""Target scope manager — manages assessment boundaries.

Implements:
1. Target definition and scope boundaries
2. IP/CIDR/domain inclusion and exclusion
3. Asset discovery tracking
4. Attack surface enumeration state
5. Service/port mapping
6. Technology fingerprinting cache
7. Scope violation detection
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"
    SERVICE = "service"
    TECHNOLOGY = "technology"


class AssetStatus(str, Enum):
    DISCOVERED = "discovered"
    SCANNED = "scanned"
    VULNERABLE = "vulnerable"
    EXPLOITED = "exploited"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass
class Asset:
    """A discovered asset."""
    asset_id: str = ""
    asset_type: AssetType = AssetType.DOMAIN
    value: str = ""
    status: AssetStatus = AssetStatus.DISCOVERED
    parent_id: str = ""          # Parent asset (e.g., domain for subdomain)
    ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    findings_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)
    last_scanned_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.asset_id[:10],
            "type": self.asset_type.value,
            "value": self.value[:30],
            "status": self.status.value,
            "ports": len(self.ports),
            "findings": self.findings_count,
        }


@dataclass
class ScopeRule:
    """An inclusion or exclusion rule."""
    rule_id: str = ""
    pattern: str = ""
    rule_type: str = "include"     # "include" or "exclude"
    asset_type: AssetType = AssetType.DOMAIN

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id[:10],
            "type": self.rule_type,
            "pattern": self.pattern[:30],
        }


@dataclass
class ScopeConfig:
    """Target scope configuration."""
    target_name: str = ""
    primary_target: str = ""
    include_rules: list[ScopeRule] = field(default_factory=list)
    exclude_rules: list[ScopeRule] = field(default_factory=list)
    include_subdomains: bool = True
    max_depth: int = 3          # Max recursion depth for discovery
    max_assets: int = 10000

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target_name[:20],
            "primary": self.primary_target[:30],
            "includes": len(self.include_rules),
            "excludes": len(self.exclude_rules),
        }


class TargetScope:
    """Manages assessment target scope.

    Tracks discovered assets, enforces scope
    boundaries, and provides attack surface
    enumeration state.
    """

    def __init__(
        self,
        config: ScopeConfig | None = None,
    ) -> None:
        self._config = config or ScopeConfig()
        self._assets: dict[str, Asset] = {}
        self._counter = 0
        self._rule_counter = 0
        self._log = logger.bind(component="target_scope")

    def set_target(
        self,
        primary_target: str,
        name: str = "",
        include_subdomains: bool = True,
    ) -> None:
        """Set the primary target."""
        self._config.primary_target = primary_target
        self._config.target_name = name or primary_target
        self._config.include_subdomains = include_subdomains

        # Auto-add primary as include
        self._rule_counter += 1
        rule = ScopeRule(
            rule_id=f"rule-{self._rule_counter}",
            pattern=primary_target,
            rule_type="include",
        )
        self._config.include_rules.append(rule)

    def add_include(self, pattern: str, asset_type: AssetType = AssetType.DOMAIN) -> ScopeRule:
        """Add an inclusion rule."""
        self._rule_counter += 1
        rule = ScopeRule(
            rule_id=f"rule-{self._rule_counter}",
            pattern=pattern,
            rule_type="include",
            asset_type=asset_type,
        )
        self._config.include_rules.append(rule)
        return rule

    def add_exclude(self, pattern: str, asset_type: AssetType = AssetType.DOMAIN) -> ScopeRule:
        """Add an exclusion rule."""
        self._rule_counter += 1
        rule = ScopeRule(
            rule_id=f"rule-{self._rule_counter}",
            pattern=pattern,
            rule_type="exclude",
            asset_type=asset_type,
        )
        self._config.exclude_rules.append(rule)
        return rule

    def is_in_scope(self, value: str) -> bool:
        """Check if a value is in scope."""
        # Check exclusions first
        for rule in self._config.exclude_rules:
            if self._matches_rule(value, rule):
                return False

        # Check inclusions
        for rule in self._config.include_rules:
            if self._matches_rule(value, rule):
                return True

        # Check subdomain inclusion
        if self._config.include_subdomains and self._config.primary_target:
            if value.endswith("." + self._config.primary_target):
                return True

        return False

    def _matches_rule(self, value: str, rule: ScopeRule) -> bool:
        """Check if a value matches a scope rule."""
        pattern = rule.pattern.lower()
        val = value.lower()

        # Exact match
        if val == pattern:
            return True

        # Wildcard
        if pattern.startswith("*.") and val.endswith(pattern[1:]):
            return True

        # CIDR match for IPs
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            addr = ipaddress.ip_address(val)
            return addr in network
        except ValueError:
            pass

        return False

    def add_asset(
        self,
        value: str,
        asset_type: AssetType,
        parent_id: str = "",
        ports: list[int] | None = None,
        services: list[str] | None = None,
        technologies: list[str] | None = None,
    ) -> Asset | None:
        """Add a discovered asset."""
        # Check scope
        if not self.is_in_scope(value):
            self._log.debug("out_of_scope", value=value[:30])
            return None

        # Check max assets
        if len(self._assets) >= self._config.max_assets:
            return None

        # Dedup
        for existing in self._assets.values():
            if existing.value == value and existing.asset_type == asset_type:
                # Update existing
                if ports:
                    existing.ports = list(set(existing.ports + ports))
                if services:
                    existing.services = list(set(existing.services + services))
                if technologies:
                    existing.technologies = list(set(existing.technologies + technologies))
                return existing

        self._counter += 1
        asset = Asset(
            asset_id=f"asset-{self._counter}",
            asset_type=asset_type,
            value=value,
            parent_id=parent_id,
            ports=ports or [],
            services=services or [],
            technologies=technologies or [],
        )
        self._assets[asset.asset_id] = asset
        return asset

    def get_unscanned(self) -> list[Asset]:
        """Get assets that haven't been scanned."""
        return [
            a for a in self._assets.values()
            if a.status == AssetStatus.DISCOVERED
        ]

    def get_by_type(self, asset_type: AssetType) -> list[Asset]:
        """Get assets by type."""
        return [
            a for a in self._assets.values()
            if a.asset_type == asset_type
        ]

    def mark_scanned(self, asset_id: str) -> None:
        """Mark an asset as scanned."""
        asset = self._assets.get(asset_id)
        if asset:
            asset.status = AssetStatus.SCANNED
            asset.last_scanned_at = time.time()

    def mark_vulnerable(self, asset_id: str) -> None:
        """Mark an asset as vulnerable."""
        asset = self._assets.get(asset_id)
        if asset:
            asset.status = AssetStatus.VULNERABLE
            asset.findings_count += 1

    def build_scope_prompt(self) -> str:
        """Build scope context for LLM."""
        lines = [
            "## Target Scope\n",
            f"Primary target: {self._config.primary_target}",
            f"Assets discovered: {len(self._assets)}",
            "",
        ]

        # Group by type
        by_type: dict[str, list[Asset]] = {}
        for asset in self._assets.values():
            by_type.setdefault(asset.asset_type.value, []).append(asset)

        for asset_type, assets in by_type.items():
            lines.append(f"### {asset_type.upper()} ({len(assets)})")
            for a in assets[:10]:
                status_marker = ""
                if a.status == AssetStatus.VULNERABLE:
                    status_marker = " [VULN]"
                elif a.status == AssetStatus.EXPLOITED:
                    status_marker = " [EXPLOITED]"
                lines.append(f"  - {a.value}{status_marker}")
            if len(assets) > 10:
                lines.append(f"  ... and {len(assets) - 10} more")
            lines.append("")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        status_counts: dict[str, int] = {}
        for a in self._assets.values():
            type_counts[a.asset_type.value] = type_counts.get(a.asset_type.value, 0) + 1
            status_counts[a.status.value] = status_counts.get(a.status.value, 0) + 1

        return {
            "total_assets": len(self._assets),
            "by_type": type_counts,
            "by_status": status_counts,
            "scope_rules": len(self._config.include_rules) + len(self._config.exclude_rules),
        }
