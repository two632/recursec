"""Target profiler — builds intelligence on targets.

Implements:
1. Target information aggregation
2. Technology stack detection
3. Attack surface mapping
4. Risk profile scoring
5. Historical comparison
6. Target prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TargetType(str, Enum):
    WEB = "web"
    NETWORK = "network"
    CLOUD = "cloud"
    MOBILE = "mobile"
    IOT = "iot"
    API = "api"
    INTERNAL = "internal"
    EXTERNAL = "external"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class ServiceInfo:
    """Information about a discovered service."""
    port: int = 0
    protocol: str = ""
    service: str = ""
    version: str = ""
    banner: str = ""
    cpe: str = ""
    vulns_known: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "svc": self.service[:12],
            "ver": self.version[:15],
        }


@dataclass
class TechStackEntry:
    """A technology in the stack."""
    name: str = ""
    category: str = ""      # framework, server, language, cms, db
    version: str = ""
    confidence: float = 0.5
    known_vulns: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:15],
            "cat": self.category[:8],
            "ver": self.version[:10],
        }


@dataclass
class AttackSurface:
    """Attack surface assessment."""
    open_ports: int = 0
    web_endpoints: int = 0
    api_endpoints: int = 0
    subdomains: int = 0
    technologies: int = 0
    exposed_services: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)

    @property
    def surface_score(self) -> float:
        """Higher score = larger attack surface."""
        return min(10.0, (
            self.open_ports * 0.1
            + self.web_endpoints * 0.05
            + self.subdomains * 0.1
            + len(self.exposed_services) * 0.5
        ))

    def to_dict(self) -> dict[str, Any]:
        return {
            "ports": self.open_ports,
            "web": self.web_endpoints,
            "subs": self.subdomains,
            "score": f"{self.surface_score:.1f}",
        }


@dataclass
class TargetProfile:
    """Complete profile of a target."""
    target_id: str = ""
    target: str = ""           # Domain, IP, URL
    target_type: TargetType = TargetType.EXTERNAL
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    services: list[ServiceInfo] = field(default_factory=list)
    tech_stack: list[TechStackEntry] = field(default_factory=list)
    attack_surface: AttackSurface = field(default_factory=AttackSurface)
    subdomains: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    findings_count: int = 0
    critical_findings: int = 0
    notes: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:20],
            "type": self.target_type.value[:6],
            "risk": self.risk_level.value[:6],
            "services": len(self.services),
            "tech": len(self.tech_stack),
            "findings": self.findings_count,
        }


class TargetProfiler:
    """Builds intelligence on targets.

    Aggregates data from recon tools, technology
    detection, and vulnerability scanning into
    comprehensive target profiles for LLM context.
    """

    def __init__(self) -> None:
        self._profiles: dict[str, TargetProfile] = {}
        self._profile_counter = 0
        self._log = logger.bind(component="target_profiler")

    def create_profile(
        self,
        target: str,
        target_type: TargetType = TargetType.EXTERNAL,
    ) -> TargetProfile:
        """Create a new target profile."""
        self._profile_counter += 1

        profile = TargetProfile(
            target_id=f"tgt-{self._profile_counter}",
            target=target,
            target_type=target_type,
        )

        self._profiles[profile.target_id] = profile
        return profile

    def add_service(
        self,
        profile_id: str,
        port: int,
        protocol: str = "tcp",
        service: str = "",
        version: str = "",
        banner: str = "",
    ) -> ServiceInfo | None:
        """Add a discovered service."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return None

        svc = ServiceInfo(
            port=port,
            protocol=protocol,
            service=service,
            version=version,
            banner=banner,
        )
        profile.services.append(svc)
        profile.attack_surface.open_ports = len(profile.services)
        profile.updated_at = time.time()

        # Auto-detect exposed services
        high_risk_services = {"ssh", "rdp", "smb", "ftp", "telnet", "mysql", "postgres", "redis", "mongodb", "elasticsearch"}
        if service.lower() in high_risk_services:
            if service not in profile.attack_surface.exposed_services:
                profile.attack_surface.exposed_services.append(service)

        return svc

    def add_technology(
        self,
        profile_id: str,
        name: str,
        category: str = "",
        version: str = "",
        confidence: float = 0.7,
    ) -> TechStackEntry | None:
        """Add a detected technology."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return None

        tech = TechStackEntry(
            name=name,
            category=category,
            version=version,
            confidence=confidence,
        )
        profile.tech_stack.append(tech)
        profile.attack_surface.technologies = len(profile.tech_stack)
        profile.updated_at = time.time()
        return tech

    def add_subdomain(self, profile_id: str, subdomain: str) -> bool:
        """Add a discovered subdomain."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return False

        if subdomain not in profile.subdomains:
            profile.subdomains.append(subdomain)
            profile.attack_surface.subdomains = len(profile.subdomains)
            profile.updated_at = time.time()
        return True

    def update_risk(self, profile_id: str) -> RiskLevel:
        """Recalculate risk level."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return RiskLevel.UNKNOWN

        score = profile.attack_surface.surface_score

        if profile.critical_findings > 0 or score > 7:
            profile.risk_level = RiskLevel.CRITICAL
        elif profile.findings_count > 5 or score > 5:
            profile.risk_level = RiskLevel.HIGH
        elif profile.findings_count > 0 or score > 3:
            profile.risk_level = RiskLevel.MEDIUM
        else:
            profile.risk_level = RiskLevel.LOW

        return profile.risk_level

    def get_profile(self, profile_id: str) -> TargetProfile | None:
        """Get a profile by ID."""
        return self._profiles.get(profile_id)

    def build_target_prompt(self, profile_id: str = "") -> str:
        """Build target intelligence context for LLM."""
        if profile_id and profile_id in self._profiles:
            profile = self._profiles[profile_id]
            return self._format_profile(profile)

        lines = ["## Target Intelligence\n"]
        lines.append(f"Profiles: {len(self._profiles)}")
        for p in list(self._profiles.values())[:3]:
            lines.append(f"  {p.target[:20]} [{p.target_type.value}] risk={p.risk_level.value}")
        return "\n".join(lines)

    def _format_profile(self, profile: TargetProfile) -> str:
        """Format a profile for LLM."""
        lines = [f"## Target: {profile.target}\n"]
        lines.append(f"Type: {profile.target_type.value} | Risk: {profile.risk_level.value}")
        lines.append(f"Attack surface score: {profile.attack_surface.surface_score:.1f}/10")

        if profile.services:
            lines.append(f"\nServices ({len(profile.services)}):")
            for svc in profile.services[:10]:
                lines.append(f"  {svc.port}/{svc.protocol} — {svc.service} {svc.version}")

        if profile.tech_stack:
            lines.append(f"\nTech stack ({len(profile.tech_stack)}):")
            for tech in profile.tech_stack[:8]:
                lines.append(f"  {tech.name} {tech.version} [{tech.category}]")

        if profile.subdomains:
            lines.append(f"\nSubdomains: {len(profile.subdomains)}")
            for sub in profile.subdomains[:5]:
                lines.append(f"  {sub}")

        if profile.attack_surface.exposed_services:
            lines.append(f"\nExposed services: {', '.join(profile.attack_surface.exposed_services)}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        risk_counts: dict[str, int] = {}
        for p in self._profiles.values():
            r = p.risk_level.value
            risk_counts[r] = risk_counts.get(r, 0) + 1

        return {
            "profiles": len(self._profiles),
            "by_risk": risk_counts,
            "total_services": sum(len(p.services) for p in self._profiles.values()),
        }
