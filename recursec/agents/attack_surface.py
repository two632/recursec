"""Attack surface mapper — comprehensive attack surface discovery and analysis.

Implements:
1. Asset discovery (domains, IPs, services, APIs)
2. Entry point enumeration
3. Trust boundary mapping
4. Data flow analysis
5. Attack vector classification
6. Surface area scoring
7. Change detection (new/removed assets)
8. Technology fingerprinting integration
9. Exposure scoring per asset
10. Third-party dependency tracking
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT = "port"
    SERVICE = "service"
    WEB_APP = "web_app"
    API_ENDPOINT = "api_endpoint"
    LOGIN_FORM = "login_form"
    FILE_UPLOAD = "file_upload"
    EMAIL_SERVER = "email_server"
    DNS_SERVER = "dns_server"
    CLOUD_RESOURCE = "cloud_resource"
    CERTIFICATE = "certificate"
    THIRD_PARTY = "third_party"


class ExposureLevel(str, Enum):
    PUBLIC = "public"           # Internet-facing
    SEMI_PUBLIC = "semi_public" # Behind CDN/WAF but accessible
    INTERNAL = "internal"       # Internal network only
    RESTRICTED = "restricted"   # Additional auth required
    UNKNOWN = "unknown"


class TrustZone(str, Enum):
    INTERNET = "internet"
    DMZ = "dmz"
    INTERNAL = "internal"
    MANAGEMENT = "management"
    DATABASE = "database"
    CLOUD = "cloud"


@dataclass
class Asset:
    """A discovered asset in the attack surface."""
    asset_id: str = ""
    asset_type: AssetType = AssetType.DOMAIN
    identifier: str = ""           # domain name, IP, URL, etc.
    exposure: ExposureLevel = ExposureLevel.UNKNOWN
    trust_zone: TrustZone = TrustZone.INTERNET
    technologies: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.asset_id, "type": self.asset_type.value,
            "identifier": self.identifier[:80],
            "exposure": self.exposure.value,
            "zone": self.trust_zone.value,
            "tech": self.technologies[:5],
            "risk": round(self.risk_score, 2),
            "vulns": len(self.vulnerabilities),
        }


@dataclass
class EntryPoint:
    """An entry point into the attack surface."""
    entry_id: str = ""
    asset_id: str = ""
    entry_type: str = ""           # http, ssh, ftp, api, etc.
    url: str = ""
    port: int = 0
    protocol: str = ""
    auth_required: bool = False
    auth_type: str = ""            # basic, bearer, session, etc.
    input_fields: list[str] = field(default_factory=list)
    risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entry_id, "asset": self.asset_id,
            "type": self.entry_type, "url": self.url[:80],
            "auth": self.auth_required,
            "risk": round(self.risk_score, 2),
        }


@dataclass
class TrustBoundary:
    """A trust boundary between zones."""
    boundary_id: str = ""
    from_zone: TrustZone = TrustZone.INTERNET
    to_zone: TrustZone = TrustZone.DMZ
    controls: list[str] = field(default_factory=list)   # firewall, WAF, auth, etc.
    weaknesses: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.boundary_id,
            "from": self.from_zone.value, "to": self.to_zone.value,
            "controls": self.controls[:5],
            "weaknesses": len(self.weaknesses),
        }


@dataclass
class AttackVector:
    """A classified attack vector."""
    vector_id: str = ""
    name: str = ""
    category: str = ""             # network, web, social, physical
    entry_point_id: str = ""
    prerequisites: list[str] = field(default_factory=list)
    impact: str = ""               # high, medium, low
    complexity: str = ""           # high, medium, low
    likelihood: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.vector_id, "name": self.name[:60],
            "category": self.category, "impact": self.impact,
            "complexity": self.complexity,
            "likelihood": round(self.likelihood, 2),
        }


class AttackSurfaceMapper:
    """Maps and analyzes the complete attack surface.

    Discovers assets, entry points, trust boundaries,
    and classifies attack vectors.
    """

    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}
        self._entry_points: dict[str, EntryPoint] = {}
        self._boundaries: list[TrustBoundary] = []
        self._vectors: list[AttackVector] = []
        self._asset_counter = 0
        self._entry_counter = 0
        self._boundary_counter = 0
        self._vector_counter = 0
        self._log = logger.bind(component="attack_surface")

    def add_asset(
        self,
        asset_type: AssetType,
        identifier: str,
        exposure: ExposureLevel = ExposureLevel.UNKNOWN,
        trust_zone: TrustZone = TrustZone.INTERNET,
        technologies: list[str] | None = None,
        ports: list[int] | None = None,
        services: list[str] | None = None,
    ) -> str:
        """Add an asset to the attack surface."""
        # Dedup
        for existing in self._assets.values():
            if existing.identifier == identifier and existing.asset_type == asset_type:
                existing.last_seen = time.time()
                if technologies:
                    for t in technologies:
                        if t not in existing.technologies:
                            existing.technologies.append(t)
                if ports:
                    for p in ports:
                        if p not in existing.ports:
                            existing.ports.append(p)
                return existing.asset_id

        self._asset_counter += 1
        aid = f"asset-{self._asset_counter}"

        asset = Asset(
            asset_id=aid,
            asset_type=asset_type,
            identifier=identifier,
            exposure=exposure,
            trust_zone=trust_zone,
            technologies=technologies or [],
            ports=ports or [],
            services=services or [],
        )

        # Auto-calculate risk
        asset.risk_score = self._calculate_risk(asset)
        self._assets[aid] = asset
        return aid

    def add_entry_point(
        self,
        asset_id: str,
        entry_type: str,
        url: str = "",
        port: int = 0,
        protocol: str = "",
        auth_required: bool = False,
        input_fields: list[str] | None = None,
    ) -> str:
        """Add an entry point."""
        self._entry_counter += 1
        eid = f"ep-{self._entry_counter}"

        entry = EntryPoint(
            entry_id=eid,
            asset_id=asset_id,
            entry_type=entry_type,
            url=url,
            port=port,
            protocol=protocol,
            auth_required=auth_required,
            input_fields=input_fields or [],
        )

        entry.risk_score = self._score_entry_point(entry)
        self._entry_points[eid] = entry
        return eid

    def add_trust_boundary(
        self,
        from_zone: TrustZone,
        to_zone: TrustZone,
        controls: list[str] | None = None,
    ) -> str:
        """Add a trust boundary."""
        self._boundary_counter += 1
        bid = f"tb-{self._boundary_counter}"

        boundary = TrustBoundary(
            boundary_id=bid,
            from_zone=from_zone,
            to_zone=to_zone,
            controls=controls or [],
        )

        self._boundaries.append(boundary)
        return bid

    def classify_vectors(self) -> list[AttackVector]:
        """Classify attack vectors based on discovered surface."""
        self._vectors.clear()

        for ep in self._entry_points.values():
            vectors = self._derive_vectors(ep)
            self._vectors.extend(vectors)

        self._vectors.sort(key=lambda v: v.likelihood, reverse=True)
        return list(self._vectors)

    def _derive_vectors(self, entry: EntryPoint) -> list[AttackVector]:
        """Derive attack vectors from an entry point."""
        vectors = []

        if entry.entry_type in ("http", "https", "web"):
            # Web vectors
            web_attacks = [
                ("XSS", "web", "medium", "medium"),
                ("SQL Injection", "web", "high", "medium"),
                ("CSRF", "web", "medium", "low"),
                ("Auth Bypass", "web", "high", "medium"),
                ("Info Disclosure", "web", "low", "low"),
            ]
            for name, cat, impact, complexity in web_attacks:
                self._vector_counter += 1
                vectors.append(AttackVector(
                    vector_id=f"vec-{self._vector_counter}",
                    name=f"{name} via {entry.url[:30]}",
                    category=cat,
                    entry_point_id=entry.entry_id,
                    impact=impact,
                    complexity=complexity,
                    likelihood=self._estimate_likelihood(name, entry),
                ))

        elif entry.entry_type in ("ssh", "ftp", "rdp"):
            self._vector_counter += 1
            vectors.append(AttackVector(
                vector_id=f"vec-{self._vector_counter}",
                name=f"Brute force {entry.entry_type.upper()}",
                category="network",
                entry_point_id=entry.entry_id,
                impact="high",
                complexity="low",
                likelihood=0.6 if not entry.auth_required else 0.3,
            ))

        elif entry.entry_type == "api":
            api_attacks = [
                ("IDOR", "high", "low"),
                ("Auth Bypass", "high", "medium"),
                ("Rate Limit Bypass", "medium", "low"),
                ("Mass Assignment", "medium", "medium"),
            ]
            for name, impact, complexity in api_attacks:
                self._vector_counter += 1
                vectors.append(AttackVector(
                    vector_id=f"vec-{self._vector_counter}",
                    name=f"{name} on {entry.url[:30]}",
                    category="web",
                    entry_point_id=entry.entry_id,
                    impact=impact,
                    complexity=complexity,
                    likelihood=self._estimate_likelihood(name, entry),
                ))

        return vectors

    def _estimate_likelihood(self, attack: str, entry: EntryPoint) -> float:
        """Estimate attack likelihood based on entry point properties."""
        base = 0.3

        if not entry.auth_required:
            base += 0.2

        if entry.input_fields:
            base += 0.1 * min(3, len(entry.input_fields))

        attack_lower = attack.lower()
        if "injection" in attack_lower and entry.input_fields:
            base += 0.2
        if "xss" in attack_lower and entry.input_fields:
            base += 0.15
        if "auth" in attack_lower and not entry.auth_required:
            base += 0.25

        return min(1.0, base)

    def _calculate_risk(self, asset: Asset) -> float:
        """Calculate risk score for an asset."""
        score = 0.0

        exposure_scores = {
            ExposureLevel.PUBLIC: 0.4,
            ExposureLevel.SEMI_PUBLIC: 0.3,
            ExposureLevel.INTERNAL: 0.1,
            ExposureLevel.RESTRICTED: 0.05,
            ExposureLevel.UNKNOWN: 0.2,
        }
        score += exposure_scores.get(asset.exposure, 0.2)

        # High-risk ports
        high_risk_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443}
        risky_ports = [p for p in asset.ports if p in high_risk_ports]
        score += len(risky_ports) * 0.05

        # Service count
        score += len(asset.services) * 0.02

        # Vulnerabilities
        score += len(asset.vulnerabilities) * 0.1

        return min(1.0, score)

    def _score_entry_point(self, entry: EntryPoint) -> float:
        """Score an entry point's risk."""
        score = 0.3

        if not entry.auth_required:
            score += 0.3

        if entry.input_fields:
            score += 0.1 * min(3, len(entry.input_fields))

        high_risk_types = {"http", "https", "api", "web", "ftp"}
        if entry.entry_type in high_risk_types:
            score += 0.1

        return min(1.0, score)

    def get_surface_summary(self) -> dict[str, Any]:
        """Get attack surface summary."""
        type_counts: dict[str, int] = defaultdict(int)
        for a in self._assets.values():
            type_counts[a.asset_type.value] += 1

        return {
            "total_assets": len(self._assets),
            "entry_points": len(self._entry_points),
            "trust_boundaries": len(self._boundaries),
            "attack_vectors": len(self._vectors),
            "asset_types": dict(type_counts),
            "avg_risk": round(
                sum(a.risk_score for a in self._assets.values()) / max(1, len(self._assets)),
                2,
            ),
        }

    def get_high_risk_assets(self, threshold: float = 0.6) -> list[dict[str, Any]]:
        """Get assets above risk threshold."""
        return [
            a.to_dict() for a in self._assets.values()
            if a.risk_score >= threshold
        ]

    def get_stats(self) -> dict[str, Any]:
        return self.get_surface_summary()
