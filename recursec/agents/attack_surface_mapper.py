"""Attack surface mapper — builds a comprehensive map of the target.

Given a target, this module:
1. Identifies all entry points (ports, services, APIs, web paths)
2. Maps the technology stack (frameworks, languages, databases)
3. Identifies authentication mechanisms
4. Maps trust boundaries
5. Catalogs data flows
6. Prioritizes attack vectors by accessibility and impact
7. Generates an attack surface graph
8. Tracks surface changes over time

This feeds directly into the planning engine so the agent knows
WHERE to focus its efforts.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class EntryPointType(str, Enum):
    TCP_PORT = "tcp_port"
    UDP_PORT = "udp_port"
    HTTP_ENDPOINT = "http_endpoint"
    API_ENDPOINT = "api_endpoint"
    WEBSOCKET = "websocket"
    GRAPHQL = "graphql"
    DNS = "dns"
    EMAIL = "email"
    FILE_UPLOAD = "file_upload"
    AUTH_ENDPOINT = "auth_endpoint"
    ADMIN_PANEL = "admin_panel"
    DEBUG_ENDPOINT = "debug_endpoint"
    CLOUD_METADATA = "cloud_metadata"
    SSH = "ssh"
    RDP = "rdp"
    VPN = "vpn"
    CUSTOM = "custom"


class TechCategory(str, Enum):
    WEB_SERVER = "web_server"
    FRAMEWORK = "framework"
    LANGUAGE = "language"
    DATABASE = "database"
    CACHE = "cache"
    MESSAGE_QUEUE = "message_queue"
    CDN = "cdn"
    WAF = "waf"
    LOAD_BALANCER = "load_balancer"
    OS = "os"
    CONTAINER = "container"
    CLOUD = "cloud"
    CMS = "cms"
    AUTH_PROVIDER = "auth_provider"
    CUSTOM = "custom"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class EntryPoint:
    """A single entry point into the target."""
    ep_id: str = ""
    ep_type: EntryPointType = EntryPointType.TCP_PORT
    location: str = ""
    port: int = 0
    protocol: str = ""
    service: str = ""
    version: str = ""
    auth_required: bool = False
    auth_type: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    accessible: bool = True
    notes: str = ""
    discovered_by: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.ep_type.value[:12],
            "location": self.location[:30],
            "port": self.port,
            "service": self.service[:15],
            "risk": self.risk_level.value[:8],
            "auth": self.auth_required,
        }


@dataclass
class Technology:
    """A detected technology in the target stack."""
    name: str = ""
    category: TechCategory = TechCategory.CUSTOM
    version: str = ""
    confidence: float = 0.5
    known_vulns: list[str] = field(default_factory=list)
    cpe: str = ""
    detected_by: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:20],
            "category": self.category.value[:10],
            "version": self.version[:10],
            "vulns": len(self.known_vulns),
        }


@dataclass
class TrustBoundary:
    """A trust boundary in the architecture."""
    name: str = ""
    description: str = ""
    from_zone: str = ""
    to_zone: str = ""
    controls: list[str] = field(default_factory=list)
    bypass_risk: RiskLevel = RiskLevel.MEDIUM

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:20],
            "from": self.from_zone[:10],
            "to": self.to_zone[:10],
            "risk": self.bypass_risk.value[:8],
        }


@dataclass
class DataFlow:
    """A data flow between components."""
    name: str = ""
    source: str = ""
    destination: str = ""
    data_type: str = ""
    encrypted: bool = True
    sensitive: bool = False
    protocol: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow": f"{self.source[:8]}→{self.destination[:8]}",
            "type": self.data_type[:10],
            "encrypted": self.encrypted,
            "sensitive": self.sensitive,
        }


@dataclass
class AttackVector:
    """A prioritized attack vector."""
    name: str = ""
    entry_point_id: str = ""
    technique: str = ""
    impact: str = ""
    likelihood: float = 0.5
    complexity: str = "medium"
    prerequisites: list[str] = field(default_factory=list)
    recommended_tools: list[str] = field(default_factory=list)
    recommended_kbs: list[str] = field(default_factory=list)
    risk_score: float = 5.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:25],
            "risk": f"{self.risk_score:.1f}",
            "likelihood": f"{self.likelihood:.0%}",
            "tools": self.recommended_tools[:3],
        }


@dataclass
class AttackSurface:
    """Complete attack surface for a target."""
    target: str = ""
    entry_points: list[EntryPoint] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    data_flows: list[DataFlow] = field(default_factory=list)
    attack_vectors: list[AttackVector] = field(default_factory=list)
    scan_time: float = 0.0
    last_updated: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:20],
            "entry_points": len(self.entry_points),
            "technologies": len(self.technologies),
            "boundaries": len(self.trust_boundaries),
            "data_flows": len(self.data_flows),
            "attack_vectors": len(self.attack_vectors),
        }


# Auto-classification rules
PORT_CLASSIFICATION: dict[int, dict[str, Any]] = {
    21: {"service": "ftp", "risk": RiskLevel.HIGH, "ep_type": EntryPointType.TCP_PORT, "tech": ("FTP", TechCategory.CUSTOM)},
    22: {"service": "ssh", "risk": RiskLevel.MEDIUM, "ep_type": EntryPointType.SSH, "tech": ("SSH", TechCategory.CUSTOM)},
    23: {"service": "telnet", "risk": RiskLevel.CRITICAL, "ep_type": EntryPointType.TCP_PORT, "tech": ("Telnet", TechCategory.CUSTOM)},
    25: {"service": "smtp", "risk": RiskLevel.HIGH, "ep_type": EntryPointType.EMAIL, "tech": ("SMTP", TechCategory.CUSTOM)},
    53: {"service": "dns", "risk": RiskLevel.HIGH, "ep_type": EntryPointType.DNS, "tech": ("DNS", TechCategory.CUSTOM)},
    80: {"service": "http", "risk": RiskLevel.HIGH, "ep_type": EntryPointType.HTTP_ENDPOINT, "tech": ("HTTP", TechCategory.WEB_SERVER)},
    443: {"service": "https", "risk": RiskLevel.MEDIUM, "ep_type": EntryPointType.HTTP_ENDPOINT, "tech": ("HTTPS", TechCategory.WEB_SERVER)},
    445: {"service": "smb", "risk": RiskLevel.CRITICAL, "ep_type": EntryPointType.TCP_PORT, "tech": ("SMB", TechCategory.CUSTOM)},
    1433: {"service": "mssql", "risk": RiskLevel.CRITICAL, "ep_type": EntryPointType.TCP_PORT, "tech": ("MSSQL", TechCategory.DATABASE)},
    3306: {"service": "mysql", "risk": RiskLevel.HIGH, "ep_type": EntryPointType.TCP_PORT, "tech": ("MySQL", TechCategory.DATABASE)},
    3389: {"service": "rdp", "risk": RiskLevel.HIGH, "ep_type": EntryPointType.RDP, "tech": ("RDP", TechCategory.CUSTOM)},
    5432: {"service": "postgresql", "risk": RiskLevel.HIGH, "ep_type": EntryPointType.TCP_PORT, "tech": ("PostgreSQL", TechCategory.DATABASE)},
    6379: {"service": "redis", "risk": RiskLevel.CRITICAL, "ep_type": EntryPointType.TCP_PORT, "tech": ("Redis", TechCategory.CACHE)},
    8080: {"service": "http-proxy", "risk": RiskLevel.HIGH, "ep_type": EntryPointType.HTTP_ENDPOINT, "tech": ("HTTP Proxy", TechCategory.WEB_SERVER)},
    9200: {"service": "elasticsearch", "risk": RiskLevel.CRITICAL, "ep_type": EntryPointType.API_ENDPOINT, "tech": ("Elasticsearch", TechCategory.DATABASE)},
    27017: {"service": "mongodb", "risk": RiskLevel.CRITICAL, "ep_type": EntryPointType.TCP_PORT, "tech": ("MongoDB", TechCategory.DATABASE)},
}


class AttackSurfaceMapper:
    """Maps and prioritizes the attack surface of a target."""

    def __init__(self) -> None:
        self._surfaces: dict[str, AttackSurface] = {}
        self._ep_counter = 0
        self._log = logger.bind(component="attack_surface_mapper")

    def create_surface(self, target: str) -> AttackSurface:
        """Create a new attack surface for a target."""
        surface = AttackSurface(target=target)
        self._surfaces[target] = surface
        return surface

    def add_port_findings(self, target: str, open_ports: list[dict[str, Any]]) -> None:
        """Add entry points from port scan results."""
        surface = self._surfaces.get(target)
        if not surface:
            surface = self.create_surface(target)

        for port_info in open_ports:
            port = port_info.get("port", 0)
            classification = PORT_CLASSIFICATION.get(port, {})

            self._ep_counter += 1
            ep = EntryPoint(
                ep_id=f"ep-{self._ep_counter}",
                ep_type=classification.get("ep_type", EntryPointType.TCP_PORT),
                location=f"{target}:{port}",
                port=port,
                protocol="tcp",
                service=port_info.get("service", classification.get("service", "unknown")),
                version=port_info.get("version", ""),
                risk_level=classification.get("risk", RiskLevel.MEDIUM),
                discovered_by=port_info.get("tool", "nmap"),
            )
            surface.entry_points.append(ep)

            # Auto-detect technology
            tech_info = classification.get("tech")
            if tech_info:
                tech = Technology(
                    name=tech_info[0],
                    category=tech_info[1],
                    version=port_info.get("version", ""),
                    confidence=0.8,
                    detected_by="port_classification",
                )
                surface.technologies.append(tech)

    def add_web_findings(self, target: str, web_data: dict[str, Any]) -> None:
        """Add entry points from web scan results."""
        surface = self._surfaces.get(target)
        if not surface:
            surface = self.create_surface(target)

        # API endpoints
        for endpoint in web_data.get("endpoints", []):
            self._ep_counter += 1
            ep = EntryPoint(
                ep_id=f"ep-{self._ep_counter}",
                ep_type=EntryPointType.API_ENDPOINT,
                location=endpoint.get("path", ""),
                protocol="https",
                service="api",
                auth_required=endpoint.get("auth", False),
                risk_level=RiskLevel.HIGH if not endpoint.get("auth") else RiskLevel.MEDIUM,
                discovered_by="web_scan",
            )
            surface.entry_points.append(ep)

        # Technologies
        for tech_name in web_data.get("technologies", []):
            tech = Technology(name=tech_name, confidence=0.7, detected_by="web_scan")
            surface.technologies.append(tech)

    def generate_attack_vectors(self, target: str) -> list[AttackVector]:
        """Generate prioritized attack vectors from the surface."""
        surface = self._surfaces.get(target)
        if not surface:
            return []

        vectors = []

        # Generate vectors from entry points
        for ep in surface.entry_points:
            if ep.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                vector = self._create_vector_for_entry_point(ep)
                if vector:
                    vectors.append(vector)

        # Sort by risk score
        vectors.sort(key=lambda v: v.risk_score, reverse=True)
        surface.attack_vectors = vectors
        return vectors

    def _create_vector_for_entry_point(self, ep: EntryPoint) -> AttackVector | None:
        """Create an attack vector for a specific entry point."""
        risk_multiplier = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
        base_score = risk_multiplier.get(ep.risk_level.value, 4)

        if not ep.auth_required:
            base_score *= 1.5  # Unauthenticated = easier

        if ep.ep_type == EntryPointType.HTTP_ENDPOINT:
            return AttackVector(
                name=f"Web exploitation at {ep.location}",
                entry_point_id=ep.ep_id,
                technique="Web application attacks (injection, auth bypass, SSRF)",
                impact="Code execution, data theft",
                likelihood=0.7,
                recommended_tools=["nuclei", "sqlmap", "ffuf", "burp"],
                recommended_kbs=["web_vuln", "xss", "ssrf", "api_gateway"],
                risk_score=base_score,
            )
        elif ep.ep_type == EntryPointType.SSH:
            return AttackVector(
                name=f"SSH access at {ep.location}",
                entry_point_id=ep.ep_id,
                technique="Credential brute-force, key-based auth bypass",
                impact="Remote shell access",
                likelihood=0.3,
                recommended_tools=["hydra", "ssh-audit"],
                recommended_kbs=["network", "privesc"],
                risk_score=base_score * 0.7,
            )
        elif ep.service in ("mysql", "postgresql", "mssql", "mongodb", "redis", "elasticsearch"):
            return AttackVector(
                name=f"Database at {ep.location}",
                entry_point_id=ep.ep_id,
                technique="Default creds, SQL injection, NoSQL injection",
                impact="Data breach, command execution",
                likelihood=0.6 if not ep.auth_required else 0.3,
                recommended_tools=["nmap", "sqlmap", "metasploit"],
                recommended_kbs=["network", "web_vuln"],
                risk_score=base_score,
            )
        return None

    def build_surface_prompt(self, target: str) -> str:
        """Build LLM prompt with attack surface context."""
        surface = self._surfaces.get(target)
        if not surface:
            return ""

        lines = [f"## Attack Surface: {target}"]
        lines.append(f"Entry points: {len(surface.entry_points)}")
        lines.append(f"Technologies: {len(surface.technologies)}")
        lines.append(f"Attack vectors: {len(surface.attack_vectors)}")

        if surface.entry_points:
            lines.append("\nKey entry points:")
            for ep in sorted(surface.entry_points, key=lambda e: {"critical": 0, "high": 1, "medium": 2}.get(e.risk_level.value, 3))[:10]:
                auth = "🔒" if ep.auth_required else "🔓"
                lines.append(f"  {auth} [{ep.risk_level.value}] {ep.location} ({ep.service})")

        if surface.technologies:
            lines.append("\nTechnology stack:")
            for tech in surface.technologies[:10]:
                lines.append(f"  - {tech.name} {tech.version}")

        if surface.attack_vectors:
            lines.append("\nTop attack vectors:")
            for av in surface.attack_vectors[:5]:
                lines.append(f"  - [{av.risk_score:.0f}] {av.name}")
                lines.append(f"    Tools: {', '.join(av.recommended_tools[:3])}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_eps = sum(len(s.entry_points) for s in self._surfaces.values())
        total_techs = sum(len(s.technologies) for s in self._surfaces.values())
        total_vectors = sum(len(s.attack_vectors) for s in self._surfaces.values())
        return {
            "targets_mapped": len(self._surfaces),
            "total_entry_points": total_eps,
            "total_technologies": total_techs,
            "total_attack_vectors": total_vectors,
        }
