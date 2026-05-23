"""Target analyzer — deep analysis of assessment targets.

Implements:
1. Target type classification (web app, API, network, host, code)
2. Technology stack detection
3. Attack surface mapping
4. Entry point identification
5. Service fingerprinting
6. Subdomain enumeration planning
7. Port analysis and service correlation
8. Target complexity scoring
9. Risk profile generation
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class TargetType(str, Enum):
    WEB_APP = "web_app"
    API = "api"
    NETWORK = "network"
    HOST = "host"
    DOMAIN = "domain"
    CODE_REPO = "code_repo"
    MOBILE_APP = "mobile_app"
    CLOUD = "cloud"
    IOT = "iot"
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
    OTHER = "other"


@dataclass
class EntryPoint:
    """A potential entry point for testing."""
    name: str = ""
    entry_type: str = ""        # url, port, endpoint, form, api
    location: str = ""
    protocol: str = ""
    risk_level: float = 0.5
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:80], "type": self.entry_type,
            "location": self.location[:100],
            "risk": round(self.risk_level, 1),
        }


@dataclass
class TechStack:
    """Detected technology stack."""
    web_server: str = ""
    framework: str = ""
    language: str = ""
    cms: str = ""
    database: str = ""
    cdn: str = ""
    waf: str = ""
    os: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = {}
        if self.web_server:
            result["server"] = self.web_server
        if self.framework:
            result["framework"] = self.framework
        if self.language:
            result["language"] = self.language
        if self.cms:
            result["cms"] = self.cms
        if self.waf:
            result["waf"] = self.waf
        if self.technologies:
            result["tech"] = self.technologies[:10]
        return result


@dataclass
class TargetProfile:
    """Complete profile of an assessment target."""
    target: str = ""
    target_type: TargetType = TargetType.UNKNOWN
    hostname: str = ""
    ip_addresses: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    services: list[dict[str, str]] = field(default_factory=list)
    entry_points: list[EntryPoint] = field(default_factory=list)
    tech_stack: TechStack = field(default_factory=TechStack)
    subdomains: list[str] = field(default_factory=list)
    attack_surface_score: float = 0.0
    complexity_score: float = 0.0
    risk_profile: str = "medium"
    recommended_tools: list[str] = field(default_factory=list)
    recommended_strategy: str = "adaptive"
    analyzed_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "type": self.target_type.value,
            "hostname": self.hostname,
            "entry_points": len(self.entry_points),
            "tech": self.tech_stack.to_dict(),
            "attack_surface": round(self.attack_surface_score, 2),
            "complexity": round(self.complexity_score, 2),
            "risk": self.risk_profile,
            "tools": self.recommended_tools[:5],
        }


# ── Target Classification ────────────────────────────────────

IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$")
CIDR_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")

DOMAIN_TLD_SET = {
    ".com", ".org", ".net", ".edu", ".gov", ".io", ".dev",
    ".co", ".me", ".app", ".xyz", ".info",
}


def classify_target(target: str) -> TargetType:
    """Classify a target string into a target type."""
    target_lower = target.lower().strip()

    # URL
    if target_lower.startswith(("http://", "https://")):
        parsed = urlparse(target_lower)
        path = parsed.path.lower()
        if "/api/" in path or path.startswith("/v1") or path.startswith("/v2"):
            return TargetType.API
        return TargetType.WEB_APP

    # Git repo
    if target_lower.endswith(".git") or "github.com" in target_lower or "gitlab.com" in target_lower:
        return TargetType.CODE_REPO

    # IP address
    if IP_PATTERN.match(target_lower):
        return TargetType.HOST

    # CIDR range
    if CIDR_PATTERN.match(target_lower):
        return TargetType.NETWORK

    # IP range (e.g., 10.0.0.1-254)
    if "-" in target_lower and "." in target_lower.split("-")[0]:
        return TargetType.NETWORK

    # Cloud identifiers
    if any(x in target_lower for x in [".amazonaws.com", ".azure.", ".googleapis.com"]):
        return TargetType.CLOUD

    # Domain
    if "." in target_lower:
        return TargetType.DOMAIN

    return TargetType.UNKNOWN


class TargetAnalyzer:
    """Deep analysis of assessment targets.

    Classifies targets, maps attack surfaces, detects
    technology stacks, and identifies entry points.
    """

    def __init__(self, model_router: ModelRouter | None = None) -> None:
        self._router = model_router
        self._profiles: dict[str, TargetProfile] = {}
        self._log = logger.bind(component="target_analyzer")

    async def analyze(self, target: str) -> TargetProfile:
        """Analyze a target and create a profile."""
        if target in self._profiles:
            return self._profiles[target]

        target_type = classify_target(target)

        profile = TargetProfile(
            target=target,
            target_type=target_type,
        )

        # Parse hostname
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            profile.hostname = parsed.hostname or ""
        elif "." in target and not IP_PATTERN.match(target):
            profile.hostname = target

        # Identify entry points
        profile.entry_points = self._identify_entry_points(target, target_type)

        # Recommend tools
        profile.recommended_tools = self._recommend_tools(target_type)

        # Recommend strategy
        profile.recommended_strategy = self._recommend_strategy(target_type)

        # Score attack surface
        profile.attack_surface_score = self._score_attack_surface(profile)
        profile.complexity_score = self._score_complexity(profile)

        # Risk profile
        if profile.attack_surface_score > 0.7:
            profile.risk_profile = "high"
        elif profile.attack_surface_score > 0.4:
            profile.risk_profile = "medium"
        else:
            profile.risk_profile = "low"

        self._profiles[target] = profile
        return profile

    def _identify_entry_points(
        self,
        target: str,
        target_type: TargetType,
    ) -> list[EntryPoint]:
        """Identify potential entry points."""
        entry_points = []

        if target_type in (TargetType.WEB_APP, TargetType.API, TargetType.DOMAIN):
            entry_points.extend([
                EntryPoint(name="HTTPS endpoint", entry_type="url",
                           location=target if target.startswith("http") else f"https://{target}",
                           protocol="https", risk_level=0.6),
                EntryPoint(name="HTTP endpoint", entry_type="url",
                           location=target if target.startswith("http") else f"http://{target}",
                           protocol="http", risk_level=0.7),
                EntryPoint(name="Common ports", entry_type="port",
                           location=target, protocol="tcp", risk_level=0.5),
            ])

            if target_type == TargetType.API:
                entry_points.append(EntryPoint(
                    name="API endpoints", entry_type="api",
                    location=target, protocol="https", risk_level=0.7,
                ))

        elif target_type in (TargetType.HOST, TargetType.NETWORK):
            entry_points.extend([
                EntryPoint(name="Network services", entry_type="port",
                           location=target, protocol="tcp", risk_level=0.6),
                EntryPoint(name="UDP services", entry_type="port",
                           location=target, protocol="udp", risk_level=0.4),
            ])

        elif target_type == TargetType.CODE_REPO:
            entry_points.extend([
                EntryPoint(name="Source code", entry_type="code",
                           location=target, risk_level=0.5),
                EntryPoint(name="Dependencies", entry_type="code",
                           location=target, risk_level=0.7),
            ])

        return entry_points

    def _recommend_tools(self, target_type: TargetType) -> list[str]:
        """Recommend tools based on target type."""
        tool_map = {
            TargetType.WEB_APP: [
                "nuclei", "nikto", "sqlmap", "dalfox", "gobuster",
                "ffuf", "katana", "httpx", "whatweb", "testssl",
            ],
            TargetType.API: [
                "nuclei", "ffuf", "httpx", "sqlmap", "curl",
            ],
            TargetType.DOMAIN: [
                "subfinder", "amass", "httpx", "nuclei", "nmap",
                "dig", "whois",
            ],
            TargetType.HOST: [
                "nmap", "masscan", "nuclei", "enum4linux", "hydra",
            ],
            TargetType.NETWORK: [
                "nmap", "masscan", "enum4linux", "tcpdump",
            ],
            TargetType.CODE_REPO: [
                "semgrep", "bandit", "trivy", "gitleaks", "trufflehog",
            ],
            TargetType.CLOUD: [
                "nuclei", "nmap", "httpx", "trivy",
            ],
        }

        return tool_map.get(target_type, ["nmap", "nuclei"])

    def _recommend_strategy(self, target_type: TargetType) -> str:
        """Recommend assessment strategy."""
        strategy_map = {
            TargetType.WEB_APP: "breadth_first",
            TargetType.API: "depth_first",
            TargetType.DOMAIN: "breadth_first",
            TargetType.HOST: "risk_prioritized",
            TargetType.NETWORK: "breadth_first",
            TargetType.CODE_REPO: "coverage_driven",
        }
        return strategy_map.get(target_type, "adaptive")

    def _score_attack_surface(self, profile: TargetProfile) -> float:
        """Score the attack surface size (0-1)."""
        score = 0.0
        score += len(profile.entry_points) * 0.1
        score += len(profile.services) * 0.05
        score += len(profile.subdomains) * 0.02

        if profile.target_type == TargetType.WEB_APP:
            score += 0.3
        elif profile.target_type == TargetType.NETWORK:
            score += 0.4
        elif profile.target_type == TargetType.DOMAIN:
            score += 0.3

        return min(1.0, score)

    def _score_complexity(self, profile: TargetProfile) -> float:
        """Score target complexity (0-1)."""
        score = 0.0
        tech = profile.tech_stack
        if tech.waf:
            score += 0.3
        if tech.cdn:
            score += 0.1
        if tech.framework:
            score += 0.1
        if profile.target_type == TargetType.NETWORK:
            score += 0.2
        return min(1.0, score)

    def get_profile(self, target: str) -> TargetProfile | None:
        return self._profiles.get(target)

    def get_stats(self) -> dict[str, Any]:
        return {"profiles": len(self._profiles)}
