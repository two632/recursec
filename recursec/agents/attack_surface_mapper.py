"""Attack surface mapper — comprehensive target analysis and surface mapping.

Implements:
1. Target decomposition (domain → subdomains → hosts → services)
2. Technology fingerprinting via response analysis
3. Entry point cataloging (URLs, forms, APIs, ports)
4. Attack surface scoring and prioritization
5. Surface change detection
6. Asset relationship mapping
7. LLM-integrated surface analysis prompts
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    PORT = "port"
    SERVICE = "service"
    URL = "url"
    FORM = "form"
    API_ENDPOINT = "api_endpoint"
    PARAMETER = "parameter"
    FILE = "file"
    CERTIFICATE = "certificate"
    EMAIL = "email"
    CLOUD_RESOURCE = "cloud_resource"


class AssetStatus(str, Enum):
    DISCOVERED = "discovered"
    FINGERPRINTED = "fingerprinted"
    SCANNED = "scanned"
    TESTED = "tested"
    EXPLOITED = "exploited"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SurfaceAsset:
    """A discovered asset on the attack surface."""
    asset_id: str = ""
    asset_type: AssetType = AssetType.DOMAIN
    status: AssetStatus = AssetStatus.DISCOVERED
    value: str = ""            # Domain name, IP, URL, etc.
    parent_id: str = ""        # Parent asset
    risk: RiskLevel = RiskLevel.INFO
    technologies: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    ports: list[int] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    @property
    def age_hours(self) -> float:
        return (time.time() - self.discovered_at) / 3600

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.asset_id[:10],
            "type": self.asset_type.value,
            "value": self.value[:30],
            "status": self.status.value,
            "risk": self.risk.value,
            "techs": len(self.technologies),
            "findings": len(self.findings),
        }


@dataclass
class EntryPoint:
    """An entry point into the target."""
    entry_id: str = ""
    asset_id: str = ""
    entry_type: str = ""      # form, api, parameter, file_upload, etc.
    url: str = ""
    method: str = "GET"
    parameters: list[str] = field(default_factory=list)
    auth_required: bool = False
    risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entry_id[:10],
            "type": self.entry_type[:10],
            "url": self.url[:30],
            "method": self.method,
            "params": len(self.parameters),
            "risk": round(self.risk_score, 2),
        }


# ── Technology fingerprint patterns ──────────────────────────

TECH_FINGERPRINTS: dict[str, list[str]] = {
    "nginx": ["server: nginx", "x-powered-by: nginx"],
    "apache": ["server: apache", "x-powered-by: apache"],
    "iis": ["server: microsoft-iis", "x-aspnet-version"],
    "nodejs": ["x-powered-by: express", "server: node"],
    "php": ["x-powered-by: php", "set-cookie: phpsessid"],
    "django": ["x-frame-options: deny", "csrfmiddlewaretoken"],
    "rails": ["x-powered-by: phusion", "set-cookie: _session_id"],
    "spring": ["x-application-context", "set-cookie: jsessionid"],
    "aspnet": ["x-aspnet-version", "x-aspnetmvc-version", "__viewstate"],
    "wordpress": ["wp-content", "wp-includes", "wp-json"],
    "joomla": ["joomla", "com_content"],
    "drupal": ["x-drupal-cache", "x-generator: drupal"],
    "react": ["data-reactroot", "__next"],
    "angular": ["ng-version", "ng-app"],
    "vue": ["data-v-", "vue-meta"],
    "cloudflare": ["server: cloudflare", "cf-ray"],
    "aws_alb": ["server: awselb"],
    "fastapi": ["openapi", "fastapi"],
    "graphql": ["/graphql", "graphiql"],
}

# Risk scoring by service
SERVICE_RISK: dict[str, float] = {
    "http": 0.3, "https": 0.2,
    "ssh": 0.4, "ftp": 0.7,
    "telnet": 0.9, "rdp": 0.7,
    "smb": 0.6, "mysql": 0.7,
    "postgres": 0.6, "mssql": 0.7,
    "mongodb": 0.7, "redis": 0.8,
    "memcached": 0.7, "elasticsearch": 0.6,
    "smtp": 0.3, "dns": 0.3,
    "ldap": 0.6, "snmp": 0.5,
}


class AttackSurfaceMapper:
    """Maps and manages the attack surface of a target.

    Discovers assets, fingerprints technologies,
    catalogs entry points, and prioritizes targets
    based on risk scoring.
    """

    def __init__(self) -> None:
        self._assets: dict[str, SurfaceAsset] = {}
        self._entry_points: dict[str, EntryPoint] = {}
        self._counter = 0
        self._log = logger.bind(component="attack_surface_mapper")

    def add_asset(
        self,
        asset_type: AssetType,
        value: str,
        parent_id: str = "",
        technologies: list[str] | None = None,
        ports: list[int] | None = None,
    ) -> SurfaceAsset:
        """Add a discovered asset."""
        # Dedup check
        for existing in self._assets.values():
            if existing.asset_type == asset_type and existing.value == value:
                existing.last_seen = time.time()
                return existing

        self._counter += 1
        asset = SurfaceAsset(
            asset_id=f"asset-{self._counter}",
            asset_type=asset_type,
            value=value,
            parent_id=parent_id,
            technologies=technologies or [],
            ports=ports or [],
        )

        # Auto-score risk
        asset.risk = self._assess_risk(asset)

        self._assets[asset.asset_id] = asset
        return asset

    def add_entry_point(
        self,
        asset_id: str,
        entry_type: str,
        url: str,
        method: str = "GET",
        parameters: list[str] | None = None,
        auth_required: bool = False,
    ) -> EntryPoint:
        """Add an entry point."""
        self._counter += 1
        ep = EntryPoint(
            entry_id=f"ep-{self._counter}",
            asset_id=asset_id,
            entry_type=entry_type,
            url=url,
            method=method,
            parameters=parameters or [],
            auth_required=auth_required,
        )

        # Risk score based on characteristics
        ep.risk_score = self._score_entry_point(ep)
        self._entry_points[ep.entry_id] = ep
        return ep

    def fingerprint_from_headers(
        self,
        asset_id: str,
        headers: dict[str, str],
    ) -> list[str]:
        """Fingerprint technologies from HTTP headers."""
        asset = self._assets.get(asset_id)
        if not asset:
            return []

        detected: list[str] = []
        header_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()

        for tech, patterns in TECH_FINGERPRINTS.items():
            for pattern in patterns:
                if pattern.lower() in header_str:
                    if tech not in asset.technologies:
                        asset.technologies.append(tech)
                        detected.append(tech)
                    break

        if detected:
            asset.status = AssetStatus.FINGERPRINTED
            asset.headers = headers

        return detected

    def get_high_priority_targets(self, limit: int = 10) -> list[SurfaceAsset]:
        """Get highest-priority targets for testing."""
        scored: list[tuple[float, SurfaceAsset]] = []
        for asset in self._assets.values():
            score = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(asset.risk.value, 0)
            # Bonus for un-tested assets
            if asset.status == AssetStatus.DISCOVERED:
                score += 1
            elif asset.status == AssetStatus.FINGERPRINTED:
                score += 0.5
            scored.append((score, asset))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [asset for _, asset in scored[:limit]]

    def get_surface_summary(self) -> dict[str, Any]:
        """Get a summary of the attack surface."""
        type_counts: dict[str, int] = {}
        risk_counts: dict[str, int] = {}
        all_techs: set[str] = set()

        for asset in self._assets.values():
            type_counts[asset.asset_type.value] = type_counts.get(asset.asset_type.value, 0) + 1
            risk_counts[asset.risk.value] = risk_counts.get(asset.risk.value, 0) + 1
            all_techs.update(asset.technologies)

        return {
            "total_assets": len(self._assets),
            "entry_points": len(self._entry_points),
            "by_type": type_counts,
            "by_risk": risk_counts,
            "technologies": sorted(all_techs),
        }

    def build_surface_prompt(self, max_assets: int = 10) -> str:
        """Build attack surface context for LLM."""
        lines = ["## Attack Surface\n"]
        summary = self.get_surface_summary()

        lines.append(f"Assets: {summary['total_assets']} | Entry points: {summary['entry_points']}")
        if summary["technologies"]:
            lines.append(f"Technologies: {', '.join(summary['technologies'][:8])}")

        # High priority targets
        targets = self.get_high_priority_targets(max_assets)
        if targets:
            lines.append("\nPriority targets:")
            for asset in targets:
                techs = ",".join(asset.technologies[:3]) if asset.technologies else "unknown"
                lines.append(
                    f"  [{asset.risk.value[0].upper()}] {asset.asset_type.value}:"
                    f"{asset.value[:25]} ({techs})"
                )

        # Entry points
        high_risk_eps = sorted(
            self._entry_points.values(),
            key=lambda ep: ep.risk_score,
            reverse=True,
        )[:5]
        if high_risk_eps:
            lines.append("\nHigh-risk entry points:")
            for ep in high_risk_eps:
                lines.append(
                    f"  {ep.method} {ep.url[:30]} "
                    f"({len(ep.parameters)} params, risk={ep.risk_score:.1f})"
                )

        return "\n".join(lines)

    def _assess_risk(self, asset: SurfaceAsset) -> RiskLevel:
        """Assess risk level of an asset."""
        score = 0.0

        # Port-based risk
        for port in asset.ports:
            if port in (21, 23, 3389):
                score += 0.8
            elif port in (22, 445, 3306, 5432, 1433, 27017, 6379):
                score += 0.5
            elif port in (80, 443, 8080, 8443):
                score += 0.3

        # Technology-based risk
        risky_tech = {"php", "wordpress", "joomla", "drupal", "telnet", "ftp"}
        for tech in asset.technologies:
            if tech.lower() in risky_tech:
                score += 0.3

        if score >= 0.8:
            return RiskLevel.CRITICAL
        if score >= 0.5:
            return RiskLevel.HIGH
        if score >= 0.3:
            return RiskLevel.MEDIUM
        if score > 0:
            return RiskLevel.LOW
        return RiskLevel.INFO

    def _score_entry_point(self, ep: EntryPoint) -> float:
        """Score risk of an entry point."""
        score = 0.0

        # Parameters increase risk
        score += len(ep.parameters) * 0.1

        # POST/PUT/DELETE are riskier
        if ep.method in ("POST", "PUT", "DELETE", "PATCH"):
            score += 0.3

        # Certain entry types
        type_scores = {
            "file_upload": 0.8, "form": 0.4,
            "api": 0.3, "parameter": 0.2,
            "login": 0.5, "search": 0.4,
            "admin": 0.7, "graphql": 0.5,
        }
        score += type_scores.get(ep.entry_type, 0.1)

        # Unauthenticated access
        if not ep.auth_required:
            score += 0.2

        return min(1.0, score)

    def get_stats(self) -> dict[str, Any]:
        return self.get_surface_summary()
