"""Scope analyzer — intelligent analysis of target scope and attack surface.

Given a target, discovers and analyzes:
1. Target type identification (web app, network, API, cloud, etc.)
2. Attack surface enumeration
3. Technology stack detection
4. Entry point identification
5. Trust boundary mapping
6. Data flow analysis
7. Authentication mechanism detection
8. Risk surface scoring
"""

from __future__ import annotations

import json
import re
import time
from collections import defaultdict
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
    IP = "ip"
    IP_RANGE = "ip_range"
    CLOUD = "cloud"
    CODE_REPO = "code_repo"
    MOBILE_APP = "mobile_app"
    IOT = "iot"
    UNKNOWN = "unknown"


class EntryPointType(str, Enum):
    WEB_FORM = "web_form"
    API_ENDPOINT = "api_endpoint"
    LOGIN_PAGE = "login_page"
    FILE_UPLOAD = "file_upload"
    OPEN_PORT = "open_port"
    DNS_RECORD = "dns_record"
    SUBDOMAIN = "subdomain"
    PARAMETER = "parameter"
    HEADER = "header"
    WEBSOCKET = "websocket"


@dataclass
class EntryPoint:
    """An identified entry point in the target."""
    entry_id: str = ""
    entry_type: EntryPointType = EntryPointType.OPEN_PORT
    location: str = ""
    description: str = ""
    risk_score: float = 0.5
    authentication_required: bool = False
    parameters: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entry_id,
            "type": self.entry_type.value,
            "location": self.location[:200],
            "risk": round(self.risk_score, 2),
            "auth": self.authentication_required,
            "params": self.parameters[:5],
        }


@dataclass
class Technology:
    """A detected technology in the target stack."""
    name: str = ""
    version: str = ""
    category: str = ""  # framework, server, database, language, os
    confidence: float = 0.5
    known_vulns: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "version": self.version,
            "category": self.category,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class TrustBoundary:
    """A trust boundary in the system."""
    name: str = ""
    description: str = ""
    components_inside: list[str] = field(default_factory=list)
    components_outside: list[str] = field(default_factory=list)
    crossing_points: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "inside": self.components_inside[:5],
            "outside": self.components_outside[:5],
            "crossings": self.crossing_points[:5],
        }


@dataclass
class ScopeAnalysis:
    """Complete scope analysis result."""
    target: str = ""
    target_type: TargetType = TargetType.UNKNOWN
    technologies: list[Technology] = field(default_factory=list)
    entry_points: list[EntryPoint] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    auth_mechanisms: list[str] = field(default_factory=list)
    risk_score: float = 0.5
    attack_surface_size: str = "medium"  # small, medium, large, massive
    analysis_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "type": self.target_type.value,
            "technologies": len(self.technologies),
            "entry_points": len(self.entry_points),
            "trust_boundaries": len(self.trust_boundaries),
            "subdomains": len(self.subdomains),
            "open_ports": len(self.open_ports),
            "risk": round(self.risk_score, 2),
            "surface": self.attack_surface_size,
        }


# ── IP/URL Pattern Matching ─────────────────────────────────

IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)
CIDR_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"
)
DOMAIN_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"
)

# Known technology signatures in headers/responses
TECH_SIGNATURES: dict[str, dict[str, str]] = {
    "nginx": {"category": "server", "pattern": "nginx"},
    "apache": {"category": "server", "pattern": "apache"},
    "iis": {"category": "server", "pattern": "microsoft-iis"},
    "express": {"category": "framework", "pattern": "express"},
    "django": {"category": "framework", "pattern": "django"},
    "flask": {"category": "framework", "pattern": "flask"},
    "spring": {"category": "framework", "pattern": "spring"},
    "rails": {"category": "framework", "pattern": "ruby on rails"},
    "react": {"category": "frontend", "pattern": "react"},
    "angular": {"category": "frontend", "pattern": "angular"},
    "vue": {"category": "frontend", "pattern": "vue"},
    "wordpress": {"category": "cms", "pattern": "wordpress"},
    "drupal": {"category": "cms", "pattern": "drupal"},
    "joomla": {"category": "cms", "pattern": "joomla"},
    "mysql": {"category": "database", "pattern": "mysql"},
    "postgresql": {"category": "database", "pattern": "postgresql"},
    "mongodb": {"category": "database", "pattern": "mongodb"},
    "redis": {"category": "database", "pattern": "redis"},
    "php": {"category": "language", "pattern": "php"},
    "python": {"category": "language", "pattern": "python"},
    "java": {"category": "language", "pattern": "java"},
    "nodejs": {"category": "runtime", "pattern": "node"},
    "docker": {"category": "container", "pattern": "docker"},
    "kubernetes": {"category": "orchestration", "pattern": "kubernetes"},
    "aws": {"category": "cloud", "pattern": "amazonaws"},
    "azure": {"category": "cloud", "pattern": "azure"},
    "gcp": {"category": "cloud", "pattern": "google cloud"},
    "cloudflare": {"category": "cdn", "pattern": "cloudflare"},
}


SCOPE_ANALYZE_PROMPT = """Analyze this target for security assessment scope.

Target: {target}
Target type: {target_type}
Known information: {known_info}

Identify:
1. Likely technologies in use
2. Potential entry points for testing
3. Trust boundaries
4. Authentication mechanisms
5. Risk surface estimation

Respond as JSON:
{{
  "technologies": [
    {{"name": "tech_name", "category": "type", "confidence": 0.X}}
  ],
  "entry_points": [
    {{"type": "web_form|api_endpoint|login_page|open_port|etc",
      "location": "where", "risk": 0.X, "auth_required": true/false}}
  ],
  "trust_boundaries": [
    {{"name": "boundary_name", "inside": ["components"], "outside": ["components"]}}
  ],
  "auth_mechanisms": ["list of auth types"],
  "risk_score": 0.X,
  "attack_surface": "small|medium|large|massive"
}}"""


class ScopeAnalyzer:
    """Analyzes target scope and attack surface.

    Identifies target type, technologies, entry points,
    and trust boundaries for optimal assessment planning.
    """

    def __init__(self, model_router: ModelRouter | None = None) -> None:
        self._router = model_router
        self._analyses: list[ScopeAnalysis] = []
        self._log = logger.bind(component="scope_analyzer")

    async def analyze(
        self,
        target: str,
        known_info: dict[str, Any] | None = None,
    ) -> ScopeAnalysis:
        """Analyze a target's scope and attack surface."""
        start = time.time()

        # Identify target type
        target_type = self._identify_target_type(target)

        analysis = ScopeAnalysis(
            target=target,
            target_type=target_type,
        )

        # Static analysis based on target type
        self._static_analysis(analysis, known_info or {})

        # LLM-enhanced analysis
        if self._router:
            await self._llm_analysis(analysis, known_info or {})

        analysis.analysis_time_ms = (time.time() - start) * 1000
        self._analyses.append(analysis)

        self._log.info(
            "scope_analyzed",
            target=target,
            type=target_type.value,
            entries=len(analysis.entry_points),
            techs=len(analysis.technologies),
        )

        return analysis

    def _identify_target_type(self, target: str) -> TargetType:
        """Identify what type of target this is."""
        target_stripped = target.strip()

        # URL
        if target_stripped.startswith(("http://", "https://")):
            parsed = urlparse(target_stripped)
            if "/api/" in parsed.path or "/v1/" in parsed.path or "/v2/" in parsed.path:
                return TargetType.API
            return TargetType.WEB_APP

        # IP range (CIDR)
        if CIDR_PATTERN.match(target_stripped):
            return TargetType.IP_RANGE

        # IP address
        if IP_PATTERN.match(target_stripped):
            return TargetType.IP

        # Domain
        if DOMAIN_PATTERN.match(target_stripped):
            return TargetType.DOMAIN

        # Git URL
        if target_stripped.endswith(".git") or "github.com" in target_stripped:
            return TargetType.CODE_REPO

        # Cloud
        if any(cloud in target_stripped for cloud in ["aws", "azure", "gcp", "s3://"]):
            return TargetType.CLOUD

        return TargetType.UNKNOWN

    def _static_analysis(self, analysis: ScopeAnalysis, known: dict[str, Any]) -> None:
        """Perform static analysis based on target type."""
        if analysis.target_type == TargetType.WEB_APP:
            analysis.entry_points.extend([
                EntryPoint(entry_id="ep-1", entry_type=EntryPointType.WEB_FORM,
                           location=analysis.target, risk_score=0.6),
                EntryPoint(entry_id="ep-2", entry_type=EntryPointType.PARAMETER,
                           location=analysis.target, risk_score=0.7,
                           parameters=["id", "q", "page", "search"]),
                EntryPoint(entry_id="ep-3", entry_type=EntryPointType.HEADER,
                           location=analysis.target, risk_score=0.4,
                           parameters=["Host", "X-Forwarded-For", "Referer"]),
            ])
            analysis.attack_surface_size = "large"

        elif analysis.target_type == TargetType.API:
            analysis.entry_points.extend([
                EntryPoint(entry_id="ep-1", entry_type=EntryPointType.API_ENDPOINT,
                           location=analysis.target, risk_score=0.7,
                           methods=["GET", "POST", "PUT", "DELETE"]),
                EntryPoint(entry_id="ep-2", entry_type=EntryPointType.HEADER,
                           location=analysis.target, risk_score=0.5,
                           parameters=["Authorization", "Content-Type"]),
            ])
            analysis.attack_surface_size = "medium"

        elif analysis.target_type in (TargetType.IP, TargetType.NETWORK, TargetType.IP_RANGE):
            common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
                            143, 443, 445, 993, 995, 1433, 1521, 3306,
                            3389, 5432, 5900, 6379, 8080, 8443, 27017]
            for port in common_ports:
                analysis.entry_points.append(EntryPoint(
                    entry_id=f"ep-port-{port}",
                    entry_type=EntryPointType.OPEN_PORT,
                    location=f"{analysis.target}:{port}",
                    risk_score=0.5,
                ))
            analysis.attack_surface_size = "large"

        elif analysis.target_type == TargetType.DOMAIN:
            analysis.entry_points.extend([
                EntryPoint(entry_id="ep-1", entry_type=EntryPointType.DNS_RECORD,
                           location=analysis.target, risk_score=0.3),
                EntryPoint(entry_id="ep-2", entry_type=EntryPointType.SUBDOMAIN,
                           location=f"*.{analysis.target}", risk_score=0.5),
            ])

        # Apply known info
        for tech_name in known.get("technologies", []):
            analysis.technologies.append(Technology(
                name=tech_name, confidence=0.9, category="known",
            ))

    async def _llm_analysis(
        self,
        analysis: ScopeAnalysis,
        known: dict[str, Any],
    ) -> None:
        """Enhance analysis with LLM reasoning."""
        if not self._router:
            return

        prompt = SCOPE_ANALYZE_PROMPT.format(
            target=analysis.target,
            target_type=analysis.target_type.value,
            known_info=json.dumps(known)[:500],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=1024,
        )

        data = self._parse_json(response)

        # Merge technologies
        for tech_data in data.get("technologies", []):
            analysis.technologies.append(Technology(
                name=tech_data.get("name", ""),
                category=tech_data.get("category", ""),
                confidence=tech_data.get("confidence", 0.5),
            ))

        # Merge entry points
        ep_counter = len(analysis.entry_points)
        for ep_data in data.get("entry_points", []):
            try:
                ep_type = EntryPointType(ep_data.get("type", "parameter"))
            except ValueError:
                ep_type = EntryPointType.PARAMETER

            ep_counter += 1
            analysis.entry_points.append(EntryPoint(
                entry_id=f"ep-llm-{ep_counter}",
                entry_type=ep_type,
                location=ep_data.get("location", ""),
                risk_score=ep_data.get("risk", 0.5),
                authentication_required=ep_data.get("auth_required", False),
            ))

        # Merge trust boundaries
        for tb_data in data.get("trust_boundaries", []):
            analysis.trust_boundaries.append(TrustBoundary(
                name=tb_data.get("name", ""),
                components_inside=tb_data.get("inside", []),
                components_outside=tb_data.get("outside", []),
            ))

        # Update scores
        analysis.auth_mechanisms = data.get("auth_mechanisms", [])
        if "risk_score" in data:
            analysis.risk_score = data["risk_score"]
        if "attack_surface" in data:
            analysis.attack_surface_size = data["attack_surface"]

    def detect_technologies(self, text: str) -> list[Technology]:
        """Detect technologies from response text/headers."""
        detected = []
        text_lower = text.lower()
        for tech_name, info in TECH_SIGNATURES.items():
            if info["pattern"] in text_lower:
                detected.append(Technology(
                    name=tech_name,
                    category=info["category"],
                    confidence=0.7,
                ))
        return detected

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}

    def get_stats(self) -> dict[str, Any]:
        by_type: dict[str, int] = defaultdict(int)
        for a in self._analyses:
            by_type[a.target_type.value] += 1
        return {
            "analyses": len(self._analyses),
            "by_type": dict(by_type),
        }
