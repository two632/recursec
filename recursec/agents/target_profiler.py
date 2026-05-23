"""Target profiler — builds comprehensive profiles of assessment targets.

Implements:
1. Target type classification (web, API, cloud, IoT, etc.)
2. Technology stack detection guidance
3. Attack surface enumeration
4. Risk profile calculation
5. Recommended strategies per target profile
6. Historical target comparison
7. Target complexity scoring
8. LLM prompt generation for profiling
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TargetType(str, Enum):
    WEB_APPLICATION = "web_application"
    API_SERVICE = "api_service"
    MICROSERVICE_ARCH = "microservice_architecture"
    MOBILE_BACKEND = "mobile_backend"
    E_COMMERCE = "e_commerce"
    SAAS_APP = "saas_app"
    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"
    NETWORK_INFRASTRUCTURE = "network_infrastructure"
    IOT_DEVICE = "iot_device"
    AI_POWERED_APP = "ai_powered_application"
    SINGLE_PAGE_APP = "single_page_app"
    LEGACY_APP = "legacy_app"


class TechCategory(str, Enum):
    FRONTEND = "frontend"
    BACKEND = "backend"
    DATABASE = "database"
    CACHE = "cache"
    AUTH = "auth"
    CDN = "cdn"
    WAF = "waf"
    CONTAINER = "container"
    CLOUD = "cloud"
    API_GATEWAY = "api_gateway"
    MESSAGE_QUEUE = "message_queue"
    SEARCH = "search"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class TechDetection:
    """A detected technology."""
    name: str = ""
    version: str = ""
    category: TechCategory = TechCategory.BACKEND
    confidence: float = 0.5
    source: str = ""     # How it was detected
    cve_count: int = 0   # Known CVEs for this version

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:20],
            "version": self.version[:10],
            "category": self.category.value,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class AttackSurface:
    """An identified attack surface."""
    surface_id: str = ""
    name: str = ""
    surface_type: str = ""  # port, endpoint, form, api, etc.
    url: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    notes: str = ""
    technologies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.surface_id,
            "name": self.name[:25],
            "type": self.surface_type[:15],
            "risk": self.risk_level.value,
        }


@dataclass
class TargetProfile:
    """Complete profile of an assessment target."""
    profile_id: str = ""
    target: str = ""               # hostname, IP, URL
    target_type: TargetType = TargetType.WEB_APPLICATION
    technologies: list[TechDetection] = field(default_factory=list)
    attack_surfaces: list[AttackSurface] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    has_waf: bool = False
    has_cdn: bool = False
    has_api_gateway: bool = False
    auth_type: str = ""
    api_style: str = ""            # REST, GraphQL, gRPC
    cloud_provider: str = ""
    complexity_score: float = 0.0  # 0-10
    risk_score: float = 0.0        # 0-10
    recommended_strategies: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.profile_id,
            "target": self.target[:30],
            "type": self.target_type.value,
            "tech_count": len(self.technologies),
            "surfaces": len(self.attack_surfaces),
            "ports": len(self.open_ports),
            "complexity": round(self.complexity_score, 1),
            "risk": round(self.risk_score, 1),
            "strategies": len(self.recommended_strategies),
        }


# ── Technology → Vulnerability Patterns ───────────────────────

TECH_VULN_PATTERNS: dict[str, list[str]] = {
    "wordpress": ["sqli", "xss", "rce", "file_upload", "plugin_vulns"],
    "drupal": ["sqli", "rce", "access_bypass", "deserialization"],
    "rails": ["mass_assignment", "sqli", "csrf", "deserialization"],
    "django": ["sqli", "ssti", "csrf", "debug_exposure"],
    "spring": ["rce", "sqli", "deserialization", "actuator_exposure"],
    "express": ["prototype_pollution", "ssrf", "path_traversal"],
    "laravel": ["sqli", "debug_mode", "env_exposure", "mass_assignment"],
    "flask": ["ssti", "sqli", "debug_mode", "path_traversal"],
    "apache": ["path_traversal", "ssrf", "misconfig", "version_disclosure"],
    "nginx": ["misconfig", "path_traversal", "header_injection"],
    "tomcat": ["rce", "path_traversal", "manager_exposure", "deserialization"],
    "iis": ["path_traversal", "tilde_enum", "webdav", "buffer_overflow"],
    "react": ["xss", "open_redirect", "sensitive_data_exposure"],
    "angular": ["xss", "template_injection", "csp_bypass"],
    "jwt": ["alg_none", "key_confusion", "brute_force", "expired_tokens"],
    "graphql": ["introspection", "batching_attack", "deep_query", "sqli"],
    "mysql": ["sqli", "udf_exploit", "weak_auth", "info_disclosure"],
    "postgres": ["sqli", "copy_to_file", "lo_export", "extension_abuse"],
    "mongodb": ["nosql_injection", "default_creds", "exposed_port"],
    "redis": ["unauthenticated_access", "rce_via_lua", "replication_rce"],
    "elasticsearch": ["unauthenticated_access", "rce", "ssrf"],
    "kubernetes": ["api_exposure", "rbac_misconfig", "secret_exposure", "container_escape"],
    "docker": ["escape", "socket_exposure", "privileged_mode"],
    "aws": ["ssrf_metadata", "iam_misconfig", "s3_exposure", "lambda_escape"],
    "azure": ["ssrf_metadata", "managed_identity", "blob_exposure"],
    "gcp": ["ssrf_metadata", "service_account", "gcs_exposure"],
}

# ── Target Type → Strategy Recommendations ────────────────────

TARGET_STRATEGY_RECOMMENDATIONS: dict[str, list[str]] = {
    "web_application": [
        "deep_infrastructure_fingerprint",
        "hidden_attack_surface_discovery",
        "timing_race_condition_testing",
        "business_logic_analysis",
        "classic_vuln_scanning",
        "crypto_weakness_analysis",
    ],
    "api_service": [
        "deep_infrastructure_fingerprint",
        "api_gateway_bypass_testing",
        "timing_race_condition_testing",
        "crypto_weakness_analysis",
        "classic_vuln_scanning",
    ],
    "microservice_architecture": [
        "emergent_complexity_analysis",
        "deep_infrastructure_fingerprint",
        "timing_race_condition_testing",
        "api_gateway_bypass_testing",
    ],
    "e_commerce": [
        "business_logic_analysis",
        "timing_race_condition_testing",
        "supply_chain_analysis",
        "classic_vuln_scanning",
    ],
    "ai_powered_application": [
        "ai_llm_vuln_testing",
        "business_logic_analysis",
        "classic_vuln_scanning",
    ],
    "cloud_infrastructure": [
        "cloud_misconfig_scanning",
        "lateral_movement_assessment",
        "supply_chain_analysis",
    ],
    "saas_app": [
        "business_logic_analysis",
        "timing_race_condition_testing",
        "hidden_attack_surface_discovery",
        "classic_vuln_scanning",
    ],
    "iot_device": [
        "deep_infrastructure_fingerprint",
        "crypto_weakness_analysis",
        "classic_vuln_scanning",
    ],
}


class TargetProfiler:
    """Builds comprehensive profiles of assessment targets.

    Classifies targets, detects technologies, maps attack surfaces,
    calculates risk, and recommends assessment strategies.
    """

    def __init__(self) -> None:
        self._profiles: dict[str, TargetProfile] = {}
        self._profile_counter = 0
        self._surface_counter = 0
        self._log = logger.bind(component="target_profiler")

    def create_profile(
        self,
        target: str,
        target_type: TargetType | None = None,
    ) -> TargetProfile:
        """Create a new target profile."""
        self._profile_counter += 1

        if not target_type:
            target_type = self._classify_target(target)

        profile = TargetProfile(
            profile_id=f"tp-{self._profile_counter}",
            target=target,
            target_type=target_type,
        )

        # Auto-recommend strategies based on target type
        profile.recommended_strategies = list(
            TARGET_STRATEGY_RECOMMENDATIONS.get(target_type.value, [])
        )

        self._profiles[profile.profile_id] = profile
        return profile

    def add_technology(
        self,
        profile_id: str,
        name: str,
        version: str = "",
        category: TechCategory = TechCategory.BACKEND,
        confidence: float = 0.7,
        source: str = "",
    ) -> TechDetection | None:
        """Add a detected technology to the profile."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return None

        tech = TechDetection(
            name=name,
            version=version,
            category=category,
            confidence=confidence,
            source=source,
        )
        profile.technologies.append(tech)

        # Update risk based on known vuln patterns
        self._update_risk(profile)

        return tech

    def add_attack_surface(
        self,
        profile_id: str,
        name: str,
        surface_type: str,
        url: str = "",
        risk_level: RiskLevel = RiskLevel.MEDIUM,
        notes: str = "",
    ) -> AttackSurface | None:
        """Add an attack surface to the profile."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return None

        self._surface_counter += 1
        surface = AttackSurface(
            surface_id=f"as-{self._surface_counter}",
            name=name,
            surface_type=surface_type,
            url=url,
            risk_level=risk_level,
            notes=notes,
        )
        profile.attack_surfaces.append(surface)

        self._update_complexity(profile)
        return surface

    def get_vuln_patterns(self, profile_id: str) -> list[str]:
        """Get potential vulnerability patterns based on detected technologies."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return []

        patterns: set[str] = set()
        for tech in profile.technologies:
            tech_name = tech.name.lower()
            for key, vulns in TECH_VULN_PATTERNS.items():
                if key in tech_name:
                    patterns.update(vulns)

        return sorted(patterns)

    def generate_profiling_prompt(self, profile_id: str) -> str:
        """Generate an LLM prompt for target profiling."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return ""

        tech_list = ""
        for tech in profile.technologies:
            tech_list += f"  - {tech.name}"
            if tech.version:
                tech_list += f" {tech.version}"
            tech_list += f" ({tech.category.value})\n"

        surface_list = ""
        for surface in profile.attack_surfaces:
            surface_list += f"  - {surface.name} ({surface.surface_type}): {surface.risk_level.value}\n"

        vuln_patterns = self.get_vuln_patterns(profile_id)

        return (
            f"Target: {profile.target}\n"
            f"Type: {profile.target_type.value}\n"
            f"Open ports: {profile.open_ports[:20]}\n"
            f"WAF: {profile.has_waf}, CDN: {profile.has_cdn}\n"
            f"Auth: {profile.auth_type}, API: {profile.api_style}\n\n"
            f"Detected technologies:\n{tech_list}\n"
            f"Attack surfaces:\n{surface_list}\n"
            f"Known vuln patterns for this stack: {', '.join(vuln_patterns[:10])}\n\n"
            f"Based on this profile, what are the highest-priority "
            f"vulnerability tests to run? Consider both traditional "
            f"vulnerabilities AND advanced attack surfaces (timing attacks, "
            f"business logic, emergent complexity, AI/LLM if applicable)."
        )

    @staticmethod
    def _classify_target(target: str) -> TargetType:
        """Classify target type from the target string."""
        target_lower = target.lower()

        if any(kw in target_lower for kw in ("api.", "/api/", "graphql")):
            return TargetType.API_SERVICE

        if any(kw in target_lower for kw in ("shop", "store", "cart", "pay")):
            return TargetType.E_COMMERCE

        if any(kw in target_lower for kw in ("aws", "azure", "gcp", "cloud")):
            return TargetType.CLOUD_INFRASTRUCTURE

        if any(kw in target_lower for kw in ("ai.", "chat.", "llm", "gpt")):
            return TargetType.AI_POWERED_APP

        if any(kw in target_lower for kw in ("app.", "dashboard", "portal")):
            return TargetType.SAAS_APP

        return TargetType.WEB_APPLICATION

    @staticmethod
    def _update_risk(profile: TargetProfile) -> None:
        """Update risk score based on technologies."""
        risk = 0.0

        for tech in profile.technologies:
            tech_lower = tech.name.lower()
            # Higher risk for known-risky tech
            if any(kw in tech_lower for kw in ("wordpress", "drupal", "joomla")):
                risk += 2.0
            elif any(kw in tech_lower for kw in ("tomcat", "iis", "php")):
                risk += 1.5
            elif any(kw in tech_lower for kw in ("redis", "elasticsearch", "mongodb")):
                risk += 1.0
            else:
                risk += 0.5

        if profile.has_waf:
            risk -= 1.0  # WAF reduces risk slightly

        profile.risk_score = max(0, min(10, risk))

    @staticmethod
    def _update_complexity(profile: TargetProfile) -> None:
        """Update complexity score."""
        complexity = 0.0
        complexity += len(profile.technologies) * 0.5
        complexity += len(profile.attack_surfaces) * 0.3
        complexity += len(profile.open_ports) * 0.1

        if profile.has_waf:
            complexity += 1.0
        if profile.has_cdn:
            complexity += 0.5
        if profile.has_api_gateway:
            complexity += 0.5

        profile.complexity_score = min(10, complexity)

    def get_profile(self, profile_id: str) -> TargetProfile | None:
        return self._profiles.get(profile_id)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for profile in self._profiles.values():
            type_counts[profile.target_type.value] += 1
        return {
            "profiles": len(self._profiles),
            "by_type": dict(type_counts),
            "total_surfaces": sum(
                len(p.attack_surfaces) for p in self._profiles.values()
            ),
        }
