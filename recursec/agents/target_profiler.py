"""Target profiler — builds comprehensive target profiles.

Implements:
1. Target type detection (web/network/api/cloud/code)
2. Technology stack identification
3. Attack surface enumeration
4. Service fingerprinting
5. Component mapping
6. Risk profile generation
7. Strategy recommendation based on profile
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TargetType(str, Enum):
    WEB = "web"
    NETWORK = "network"
    API = "api"
    CLOUD = "cloud"
    CODE = "code"
    MOBILE = "mobile"
    IOT = "iot"
    AD = "active_directory"
    UNKNOWN = "unknown"


class ServiceType(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    FTP = "ftp"
    SMB = "smb"
    RDP = "rdp"
    DNS = "dns"
    SMTP = "smtp"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    REDIS = "redis"
    MONGODB = "mongodb"
    LDAP = "ldap"
    KERBEROS = "kerberos"
    SNMP = "snmp"
    CUSTOM = "custom"




@dataclass
class Service:
    """A discovered service."""
    port: int = 0
    protocol: str = "tcp"
    service_type: ServiceType = ServiceType.CUSTOM
    version: str = ""
    banner: str = ""
    tls: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "service": self.service_type.value,
            "version": self.version[:20],
            "tls": self.tls,
        }


@dataclass
class Technology:
    """A detected technology."""
    name: str = ""
    version: str = ""
    category: str = ""       # framework, server, language, cms, db
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:20],
            "version": self.version[:10],
            "category": self.category[:10],
        }


@dataclass
class TargetProfile:
    """A comprehensive target profile."""
    profile_id: str = ""
    target: str = ""
    target_type: TargetType = TargetType.UNKNOWN
    services: list[Service] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    os_guess: str = ""
    risk_level: str = "medium"
    attack_surface_score: float = 0.0
    recommended_strategies: list[str] = field(default_factory=list)
    recommended_tools: list[str] = field(default_factory=list)
    recommended_kbs: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.profile_id[:10],
            "target": self.target[:20],
            "type": self.target_type.value,
            "services": len(self.services),
            "technologies": len(self.technologies),
            "ports": len(self.open_ports),
            "risk": self.risk_level,
            "attack_surface": round(self.attack_surface_score, 2),
        }


# ── Technology detection patterns ─────────────────────────────

TECH_PATTERNS: list[dict[str, Any]] = [
    # Web servers
    {"regex": r"(?i)nginx/?(\S+)?", "name": "Nginx", "cat": "server"},
    {"regex": r"(?i)apache/?(\S+)?", "name": "Apache", "cat": "server"},
    {"regex": r"(?i)iis/?(\S+)?", "name": "IIS", "cat": "server"},
    {"regex": r"(?i)lighttpd/?(\S+)?", "name": "Lighttpd", "cat": "server"},
    {"regex": r"(?i)caddy/?(\S+)?", "name": "Caddy", "cat": "server"},
    # Frameworks
    {"regex": r"(?i)django/?(\S+)?", "name": "Django", "cat": "framework"},
    {"regex": r"(?i)flask/?(\S+)?", "name": "Flask", "cat": "framework"},
    {"regex": r"(?i)express/?(\S+)?", "name": "Express.js", "cat": "framework"},
    {"regex": r"(?i)rails/?(\S+)?", "name": "Ruby on Rails", "cat": "framework"},
    {"regex": r"(?i)laravel/?(\S+)?", "name": "Laravel", "cat": "framework"},
    {"regex": r"(?i)spring/?(\S+)?", "name": "Spring", "cat": "framework"},
    {"regex": r"(?i)next\.?js/?(\S+)?", "name": "Next.js", "cat": "framework"},
    {"regex": r"(?i)react/?(\S+)?", "name": "React", "cat": "framework"},
    {"regex": r"(?i)vue\.?js/?(\S+)?", "name": "Vue.js", "cat": "framework"},
    {"regex": r"(?i)angular/?(\S+)?", "name": "Angular", "cat": "framework"},
    # CMS
    {"regex": r"(?i)wordpress/?(\S+)?", "name": "WordPress", "cat": "cms"},
    {"regex": r"(?i)drupal/?(\S+)?", "name": "Drupal", "cat": "cms"},
    {"regex": r"(?i)joomla/?(\S+)?", "name": "Joomla", "cat": "cms"},
    # Languages
    {"regex": r"(?i)php/?(\S+)?", "name": "PHP", "cat": "language"},
    {"regex": r"(?i)python/?(\S+)?", "name": "Python", "cat": "language"},
    {"regex": r"(?i)node\.?js/?(\S+)?", "name": "Node.js", "cat": "language"},
    {"regex": r"(?i)java/?(\S+)?", "name": "Java", "cat": "language"},
    {"regex": r"(?i)\.net/?(\S+)?", "name": ".NET", "cat": "language"},
    {"regex": r"(?i)go/?(\S+)?", "name": "Go", "cat": "language"},
    {"regex": r"(?i)rust/?(\S+)?", "name": "Rust", "cat": "language"},
    # Databases
    {"regex": r"(?i)mysql/?(\S+)?", "name": "MySQL", "cat": "database"},
    {"regex": r"(?i)postgres(?:ql)?/?(\S+)?", "name": "PostgreSQL", "cat": "database"},
    {"regex": r"(?i)mongodb/?(\S+)?", "name": "MongoDB", "cat": "database"},
    {"regex": r"(?i)redis/?(\S+)?", "name": "Redis", "cat": "database"},
    {"regex": r"(?i)elasticsearch/?(\S+)?", "name": "Elasticsearch", "cat": "database"},
]

# ── Target type detection ─────────────────────────────────────

IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$")
CIDR_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")
DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$")
URL_PATTERN = re.compile(r"^https?://")


# ── Strategy recommendations ─────────────────────────────────

STRATEGY_MAP: dict[str, dict[str, Any]] = {
    "web": {
        "strategies": ["web_full_scan", "api_test", "auth_test", "injection_test", "business_logic"],
        "tools": ["nuclei", "nikto", "sqlmap", "dalfox", "ffuf", "gobuster", "wpscan", "httpx"],
        "kbs": ["web_vuln", "api_security", "secrets_detection"],
    },
    "network": {
        "strategies": ["port_scan", "service_enum", "vuln_scan", "lateral_movement", "privesc"],
        "tools": ["nmap", "masscan", "enum4linux", "crackmapexec", "hydra", "responder"],
        "kbs": ["network_security", "privesc", "active_directory"],
    },
    "api": {
        "strategies": ["api_discovery", "auth_test", "injection_test", "rate_limit_test"],
        "tools": ["nuclei", "ffuf", "sqlmap", "httpx", "curl"],
        "kbs": ["api_security", "web_vuln", "secrets_detection"],
    },
    "cloud": {
        "strategies": ["cloud_config_audit", "iam_review", "storage_access", "network_exposure"],
        "tools": ["trivy", "kube-bench", "nuclei"],
        "kbs": ["cloud_security", "container_security", "secrets_detection"],
    },
    "code": {
        "strategies": ["sast_scan", "dependency_audit", "secret_detection", "code_review"],
        "tools": ["semgrep", "bandit", "trufflehog", "gitleaks", "trivy", "grype"],
        "kbs": ["secrets_detection", "web_vuln", "advanced_strategy"],
    },
}


class TargetProfiler:
    """Builds comprehensive target profiles.

    Detects target type, identifies technologies,
    and recommends strategies and tools.
    """

    def __init__(self) -> None:
        self._profiles: dict[str, TargetProfile] = {}
        self._counter = 0
        self._log = logger.bind(component="target_profiler")

    def create_profile(self, target: str) -> TargetProfile:
        """Create a new target profile."""
        self._counter += 1
        target_type = self._detect_target_type(target)

        profile = TargetProfile(
            profile_id=f"profile-{self._counter}",
            target=target,
            target_type=target_type,
        )

        # Auto-recommend based on type
        self._recommend_strategy(profile)

        self._profiles[profile.profile_id] = profile
        return profile

    def _detect_target_type(self, target: str) -> TargetType:
        """Detect the type of target."""
        if URL_PATTERN.match(target):
            if "/api/" in target or "/graphql" in target:
                return TargetType.API
            return TargetType.WEB
        if CIDR_PATTERN.match(target):
            return TargetType.NETWORK
        if IP_PATTERN.match(target):
            return TargetType.NETWORK
        if DOMAIN_PATTERN.match(target):
            return TargetType.WEB
        if target.endswith((".git", ".zip", ".tar.gz")) or "/" in target:
            return TargetType.CODE

        return TargetType.UNKNOWN

    def add_service(
        self,
        profile_id: str,
        port: int,
        service_type: str = "custom",
        version: str = "",
        banner: str = "",
        tls: bool = False,
    ) -> Service | None:
        """Add a discovered service to the profile."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return None

        try:
            svc_type = ServiceType(service_type)
        except ValueError:
            svc_type = ServiceType.CUSTOM

        service = Service(
            port=port,
            service_type=svc_type,
            version=version,
            banner=banner,
            tls=tls,
        )
        profile.services.append(service)
        if port not in profile.open_ports:
            profile.open_ports.append(port)

        # Auto-detect technology from banner
        self._detect_tech_from_banner(profile, banner)

        # Recalculate attack surface
        self._calculate_attack_surface(profile)

        return service

    def add_technology(
        self,
        profile_id: str,
        name: str,
        version: str = "",
        category: str = "",
        confidence: float = 0.8,
    ) -> Technology | None:
        """Add a detected technology."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return None

        # Avoid duplicates
        for existing in profile.technologies:
            if existing.name.lower() == name.lower():
                if confidence > existing.confidence:
                    existing.confidence = confidence
                    existing.version = version or existing.version
                return existing

        tech = Technology(
            name=name,
            version=version,
            category=category,
            confidence=confidence,
        )
        profile.technologies.append(tech)

        # Update recommendations
        self._recommend_strategy(profile)

        return tech

    def _detect_tech_from_banner(
        self,
        profile: TargetProfile,
        banner: str,
    ) -> None:
        """Detect technologies from a banner string."""
        if not banner:
            return

        for pattern in TECH_PATTERNS:
            match = re.search(pattern["regex"], banner)
            if match:
                version = match.group(1) if match.lastindex else ""
                self.add_technology(
                    profile.profile_id,
                    name=pattern["name"],
                    version=version or "",
                    category=pattern["cat"],
                    confidence=0.7,
                )

    def _calculate_attack_surface(self, profile: TargetProfile) -> None:
        """Calculate attack surface score."""
        # Factors: services, technologies, subdomains
        service_score = min(1.0, len(profile.services) / 10)
        tech_score = min(1.0, len(profile.technologies) / 5)
        subdomain_score = min(1.0, len(profile.subdomains) / 20)
        port_score = min(1.0, len(profile.open_ports) / 20)

        profile.attack_surface_score = (
            service_score * 0.3
            + tech_score * 0.2
            + subdomain_score * 0.2
            + port_score * 0.3
        )

        # Risk level
        if profile.attack_surface_score >= 0.7:
            profile.risk_level = "critical"
        elif profile.attack_surface_score >= 0.5:
            profile.risk_level = "high"
        elif profile.attack_surface_score >= 0.3:
            profile.risk_level = "medium"
        else:
            profile.risk_level = "low"

    def _recommend_strategy(self, profile: TargetProfile) -> None:
        """Recommend strategies based on profile."""
        type_key = profile.target_type.value
        rec = STRATEGY_MAP.get(type_key, STRATEGY_MAP.get("web", {}))

        profile.recommended_strategies = rec.get("strategies", [])
        profile.recommended_tools = rec.get("tools", [])
        profile.recommended_kbs = rec.get("kbs", [])

        # Technology-specific additions
        for tech in profile.technologies:
            name_lower = tech.name.lower()
            if "wordpress" in name_lower:
                if "wpscan" not in profile.recommended_tools:
                    profile.recommended_tools.append("wpscan")
            elif "graphql" in name_lower:
                if "api_security" not in profile.recommended_kbs:
                    profile.recommended_kbs.append("api_security")

    def build_profile_prompt(self, profile_id: str) -> str:
        """Build a prompt from the target profile."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return ""

        lines = ["## Target Profile\n"]
        lines.append(f"Target: {profile.target}")
        lines.append(f"Type: {profile.target_type.value}")
        lines.append(f"Risk: {profile.risk_level}")
        lines.append(f"Attack Surface: {profile.attack_surface_score:.2f}")

        if profile.services:
            lines.append("\nServices:")
            for svc in profile.services[:10]:
                lines.append(f"  {svc.port}/{svc.protocol}: {svc.service_type.value} {svc.version}")

        if profile.technologies:
            lines.append("\nTechnologies:")
            for tech in profile.technologies[:10]:
                lines.append(f"  {tech.name} {tech.version} ({tech.category})")

        if profile.recommended_strategies:
            lines.append(f"\nStrategies: {', '.join(profile.recommended_strategies[:5])}")

        if profile.recommended_tools:
            lines.append(f"Tools: {', '.join(profile.recommended_tools[:8])}")

        return "\n".join(lines)

    def get_profile(self, profile_id: str) -> TargetProfile | None:
        """Get a profile by ID."""
        return self._profiles.get(profile_id)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for p in self._profiles.values():
            type_counts[p.target_type.value] += 1

        return {
            "profiles": len(self._profiles),
            "by_type": dict(type_counts),
        }
