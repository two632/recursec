"""Target profiler — builds and maintains target profiles.

Implements:
1. Target fingerprinting
2. Technology stack detection
3. Attack surface mapping
4. Risk scoring
5. Vulnerability correlation
6. Target profile prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TargetCategory(str, Enum):
    WEB_APP = "web_app"
    API = "api"
    NETWORK = "network"
    CLOUD = "cloud"
    MOBILE = "mobile"
    IOT = "iot"
    INTERNAL = "internal"
    ACTIVE_DIRECTORY = "active_directory"
    CONTAINER = "container"
    WIRELESS = "wireless"
    ICS = "ics"
    UNKNOWN = "unknown"


class ServiceType(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    DNS = "dns"
    DATABASE = "database"
    RDP = "rdp"
    SMB = "smb"
    LDAP = "ldap"
    CUSTOM = "custom"


@dataclass
class DetectedTechnology:
    """A detected technology on the target."""
    name: str = ""
    version: str = ""
    category: str = ""  # framework, server, os, library, etc.
    confidence: float = 0.5
    cve_count: int = 0
    risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:15],
            "version": self.version[:10],
            "conf": f"{self.confidence:.2f}",
        }


@dataclass
class DetectedService:
    """A detected service on the target."""
    port: int = 0
    protocol: str = "tcp"
    service_type: ServiceType = ServiceType.CUSTOM
    product: str = ""
    version: str = ""
    banner: str = ""
    state: str = "open"

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "service": self.service_type.value[:5],
            "product": self.product[:12],
        }


@dataclass
class TargetProfile:
    """Complete profile for a target."""
    target_id: str = ""
    address: str = ""  # IP, domain, or URL
    category: TargetCategory = TargetCategory.UNKNOWN
    services: list[DetectedService] = field(default_factory=list)
    technologies: list[DetectedTechnology] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    attack_surface_score: float = 0.0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    @property
    def open_ports(self) -> list[int]:
        return [s.port for s in self.services if s.state == "open"]

    @property
    def tech_stack_str(self) -> str:
        return ", ".join(
            f"{t.name} {t.version}".strip()
            for t in self.technologies[:5]
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.address[:20],
            "category": self.category.value[:10],
            "services": len(self.services),
            "techs": len(self.technologies),
            "risk": f"{self.risk_score:.1f}",
        }


class TargetProfiler:
    """Builds and maintains target profiles.

    Aggregates recon data, detects technologies,
    maps attack surface, and correlates risks.
    """

    def __init__(self) -> None:
        self._profiles: dict[str, TargetProfile] = {}
        self._profile_counter = 0
        self._log = logger.bind(component="profiler")

    def create_profile(
        self,
        address: str,
        category: TargetCategory = TargetCategory.UNKNOWN,
    ) -> TargetProfile:
        """Create a new target profile."""
        self._profile_counter += 1

        profile = TargetProfile(
            target_id=f"target-{self._profile_counter}",
            address=address,
            category=category,
        )
        self._profiles[profile.target_id] = profile
        return profile

    def add_service(
        self,
        target_id: str,
        port: int,
        protocol: str = "tcp",
        service_type: ServiceType = ServiceType.CUSTOM,
        product: str = "",
        version: str = "",
        banner: str = "",
    ) -> None:
        """Add a detected service."""
        profile = self._profiles.get(target_id)
        if not profile:
            return

        service = DetectedService(
            port=port,
            protocol=protocol,
            service_type=service_type,
            product=product,
            version=version,
            banner=banner[:200],
        )
        profile.services.append(service)
        profile.updated_at = time.time()
        self._update_risk(target_id)

    def add_technology(
        self,
        target_id: str,
        name: str,
        version: str = "",
        category: str = "",
        confidence: float = 0.5,
    ) -> None:
        """Add a detected technology."""
        profile = self._profiles.get(target_id)
        if not profile:
            return

        # Check for duplicates
        for tech in profile.technologies:
            if tech.name.lower() == name.lower():
                if confidence > tech.confidence:
                    tech.confidence = confidence
                    tech.version = version or tech.version
                return

        tech = DetectedTechnology(
            name=name,
            version=version,
            category=category,
            confidence=confidence,
        )
        profile.technologies.append(tech)
        profile.updated_at = time.time()

    def add_finding(
        self,
        target_id: str,
        finding: dict[str, Any],
    ) -> None:
        """Add a finding to the profile."""
        profile = self._profiles.get(target_id)
        if profile:
            profile.findings.append(finding)
            profile.updated_at = time.time()
            self._update_risk(target_id)

    def add_endpoints(
        self,
        target_id: str,
        endpoints: list[str],
    ) -> None:
        """Add discovered endpoints."""
        profile = self._profiles.get(target_id)
        if profile:
            for ep in endpoints:
                if ep not in profile.endpoints:
                    profile.endpoints.append(ep)
            profile.updated_at = time.time()

    def _update_risk(self, target_id: str) -> None:
        """Recalculate risk score."""
        profile = self._profiles.get(target_id)
        if not profile:
            return

        score = 0.0

        # Service risk (more services = more attack surface)
        score += min(3.0, len(profile.services) * 0.3)

        # Finding severity
        severity_scores = {
            "critical": 4.0,
            "high": 3.0,
            "medium": 2.0,
            "low": 1.0,
            "info": 0.2,
        }
        for f in profile.findings:
            sev = f.get("severity", "medium").lower()
            score += severity_scores.get(sev, 1.0)

        # Technology risk (outdated = higher risk)
        for tech in profile.technologies:
            if tech.cve_count > 0:
                score += min(2.0, tech.cve_count * 0.5)

        profile.risk_score = min(10.0, score)
        profile.attack_surface_score = min(10.0, (
            len(profile.services) * 0.5 +
            len(profile.endpoints) * 0.1 +
            len(profile.subdomains) * 0.3
        ))

    def infer_category(self, target_id: str) -> TargetCategory:
        """Infer target category from detected services/tech."""
        profile = self._profiles.get(target_id)
        if not profile:
            return TargetCategory.UNKNOWN

        service_types = [s.service_type for s in profile.services]
        tech_names = [t.name.lower() for t in profile.technologies]

        if ServiceType.HTTP in service_types or ServiceType.HTTPS in service_types:
            for name in tech_names:
                if any(w in name for w in ["react", "angular", "vue", "django", "flask", "express", "rails"]):
                    return TargetCategory.WEB_APP
            return TargetCategory.WEB_APP

        if ServiceType.SMB in service_types or ServiceType.LDAP in service_types:
            return TargetCategory.ACTIVE_DIRECTORY

        if any(w in " ".join(tech_names) for w in ["docker", "kubernetes", "k8s"]):
            return TargetCategory.CONTAINER

        if any(w in " ".join(tech_names) for w in ["aws", "azure", "gcp"]):
            return TargetCategory.CLOUD

        return TargetCategory.NETWORK

    def build_profile_prompt(self, target_id: str = "") -> str:
        """Build target profile context for LLM."""
        if target_id and target_id in self._profiles:
            return self._build_single_profile(self._profiles[target_id])

        lines = ["## Targets\n"]
        lines.append(f"Profiles: {len(self._profiles)}")

        for profile in list(self._profiles.values())[-3:]:
            lines.append(
                f"\n{profile.address[:20]} [{profile.category.value[:8]}]"
            )
            lines.append(f"  Services: {len(profile.services)}")
            lines.append(f"  Techs: {profile.tech_stack_str[:40]}")
            lines.append(f"  Risk: {profile.risk_score:.1f}/10")

        return "\n".join(lines)

    def _build_single_profile(self, profile: TargetProfile) -> str:
        """Build detailed profile for a single target."""
        lines = [f"## Target: {profile.address}\n"]
        lines.append(f"Category: {profile.category.value}")
        lines.append(f"Risk: {profile.risk_score:.1f}/10")
        lines.append(f"Attack surface: {profile.attack_surface_score:.1f}/10")

        if profile.services:
            lines.append(f"\nServices ({len(profile.services)}):")
            for s in profile.services[:10]:
                lines.append(
                    f"  {s.port}/{s.protocol} {s.service_type.value} "
                    f"({s.product} {s.version})".strip()
                )

        if profile.technologies:
            lines.append(f"\nTechnologies ({len(profile.technologies)}):")
            for t in profile.technologies[:10]:
                lines.append(f"  {t.name} {t.version} [{t.category}]")

        if profile.findings:
            lines.append(f"\nFindings ({len(profile.findings)}):")
            for f in profile.findings[:5]:
                sev = f.get("severity", "?")
                title = f.get("title", "?")[:30]
                lines.append(f"  [{sev[:4]}] {title}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "profiles": len(self._profiles),
            "total_services": sum(
                len(p.services) for p in self._profiles.values()
            ),
            "total_findings": sum(
                len(p.findings) for p in self._profiles.values()
            ),
        }
