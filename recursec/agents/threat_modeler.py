"""Threat modeler — models threats using STRIDE and DREAD methodologies.

Implements:
1. STRIDE threat classification
2. DREAD risk scoring
3. Attack tree generation
4. Threat-asset mapping
5. Data flow analysis
6. Trust boundary identification
7. Mitigation recommendation
8. Threat prioritization
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class StrideCategory(str, Enum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


@dataclass
class DreadScore:
    """DREAD risk scoring model."""
    damage: int = 5          # 1-10
    reproducibility: int = 5  # 1-10
    exploitability: int = 5   # 1-10
    affected_users: int = 5   # 1-10
    discoverability: int = 5  # 1-10

    @property
    def total(self) -> float:
        return (self.damage + self.reproducibility + self.exploitability +
                self.affected_users + self.discoverability) / 5.0

    @property
    def risk_level(self) -> str:
        score = self.total
        if score >= 8.0:
            return "critical"
        if score >= 6.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "D": self.damage, "R": self.reproducibility,
            "E": self.exploitability, "A": self.affected_users,
            "D2": self.discoverability,
            "total": round(self.total, 1),
            "risk": self.risk_level,
        }


@dataclass
class Threat:
    """A modeled threat."""
    threat_id: str = ""
    title: str = ""
    description: str = ""
    stride: StrideCategory = StrideCategory.SPOOFING
    dread: DreadScore = field(default_factory=DreadScore)
    affected_assets: list[str] = field(default_factory=list)
    attack_vector: str = ""
    prerequisites: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    is_mitigated: bool = False
    finding_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.threat_id, "title": self.title[:60],
            "stride": self.stride.value,
            "dread": self.dread.to_dict(),
            "assets": self.affected_assets[:5],
            "mitigated": self.is_mitigated,
        }


@dataclass
class DataFlow:
    """A data flow in the system."""
    flow_id: str = ""
    source: str = ""
    destination: str = ""
    data_type: str = ""            # auth, user_data, api_call, file, config
    protocol: str = ""             # http, https, tcp, udp, grpc
    crosses_boundary: bool = False
    is_encrypted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.flow_id, "source": self.source[:30],
            "dest": self.destination[:30],
            "encrypted": self.is_encrypted,
            "boundary": self.crosses_boundary,
        }


@dataclass
class ThreatModel:
    """A complete threat model."""
    model_id: str = ""
    target: str = ""
    threats: list[Threat] = field(default_factory=list)
    data_flows: list[DataFlow] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    trust_boundaries: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.model_id, "target": self.target[:40],
            "threats": len(self.threats),
            "data_flows": len(self.data_flows),
            "assets": len(self.assets),
        }


# ── STRIDE Patterns ───────────────────────────────────────────

STRIDE_PATTERNS: dict[str, list[dict[str, Any]]] = {
    "web_app": [
        {
            "stride": "spoofing", "title": "Session Hijacking",
            "desc": "Attacker steals or forges session tokens",
            "vector": "Cookie theft, session fixation",
            "dread": {"D": 8, "R": 7, "E": 6, "A": 8, "D2": 5},
            "mitigations": ["Secure cookie flags", "Session timeout", "HTTPS only"],
        },
        {
            "stride": "spoofing", "title": "Credential Stuffing",
            "desc": "Using leaked credentials to gain access",
            "vector": "Login endpoint",
            "dread": {"D": 8, "R": 9, "E": 8, "A": 7, "D2": 8},
            "mitigations": ["MFA", "Rate limiting", "Account lockout"],
        },
        {
            "stride": "tampering", "title": "SQL Injection",
            "desc": "Modifying SQL queries through user input",
            "vector": "Input fields, URL parameters",
            "dread": {"D": 10, "R": 8, "E": 7, "A": 10, "D2": 7},
            "mitigations": ["Parameterized queries", "Input validation", "WAF"],
        },
        {
            "stride": "tampering", "title": "Cross-Site Scripting (XSS)",
            "desc": "Injecting malicious scripts into pages",
            "vector": "Input fields, URL parameters",
            "dread": {"D": 7, "R": 8, "E": 7, "A": 9, "D2": 8},
            "mitigations": ["Output encoding", "CSP", "Input sanitization"],
        },
        {
            "stride": "information_disclosure", "title": "Sensitive Data Exposure",
            "desc": "Unprotected sensitive data in transit or at rest",
            "vector": "HTTP responses, error messages, debug info",
            "dread": {"D": 9, "R": 7, "E": 5, "A": 8, "D2": 6},
            "mitigations": ["Encryption", "Data classification", "Error handling"],
        },
        {
            "stride": "denial_of_service", "title": "Application DoS",
            "desc": "Overwhelming application resources",
            "vector": "Complex queries, file uploads, API abuse",
            "dread": {"D": 7, "R": 8, "E": 7, "A": 10, "D2": 7},
            "mitigations": ["Rate limiting", "Input validation", "CDN"],
        },
        {
            "stride": "elevation_of_privilege", "title": "IDOR",
            "desc": "Accessing other users' data via ID manipulation",
            "vector": "API endpoints, URL parameters",
            "dread": {"D": 8, "R": 9, "E": 8, "A": 7, "D2": 6},
            "mitigations": ["Authorization checks", "UUID instead of sequential IDs"],
        },
        {
            "stride": "elevation_of_privilege", "title": "Privilege Escalation",
            "desc": "Gaining admin access from regular user",
            "vector": "Admin endpoints, role manipulation",
            "dread": {"D": 10, "R": 6, "E": 5, "A": 10, "D2": 4},
            "mitigations": ["RBAC", "Principle of least privilege", "Authorization checks"],
        },
    ],
    "network": [
        {
            "stride": "spoofing", "title": "ARP Spoofing",
            "desc": "Impersonating another host on the network",
            "vector": "Local network",
            "dread": {"D": 7, "R": 8, "E": 6, "A": 6, "D2": 4},
            "mitigations": ["Static ARP entries", "Network segmentation", "802.1X"],
        },
        {
            "stride": "tampering", "title": "Man-in-the-Middle",
            "desc": "Intercepting and modifying network traffic",
            "vector": "Network position",
            "dread": {"D": 9, "R": 5, "E": 5, "A": 8, "D2": 4},
            "mitigations": ["TLS", "Certificate pinning", "VPN"],
        },
        {
            "stride": "information_disclosure", "title": "Network Sniffing",
            "desc": "Capturing unencrypted network traffic",
            "vector": "Network access",
            "dread": {"D": 8, "R": 9, "E": 7, "A": 7, "D2": 5},
            "mitigations": ["Encryption", "Network segmentation", "VPN"],
        },
        {
            "stride": "denial_of_service", "title": "Network Flood",
            "desc": "Overwhelming network bandwidth",
            "vector": "Internet",
            "dread": {"D": 7, "R": 9, "E": 8, "A": 10, "D2": 8},
            "mitigations": ["DDoS protection", "Rate limiting", "CDN"],
        },
    ],
    "api": [
        {
            "stride": "spoofing", "title": "API Key Theft",
            "desc": "Stealing or leaking API keys",
            "vector": "Code repos, logs, headers",
            "dread": {"D": 8, "R": 7, "E": 7, "A": 7, "D2": 7},
            "mitigations": ["Key rotation", "Secrets management", "Scoped keys"],
        },
        {
            "stride": "tampering", "title": "API Parameter Tampering",
            "desc": "Modifying API request parameters",
            "vector": "API endpoints",
            "dread": {"D": 7, "R": 8, "E": 7, "A": 6, "D2": 7},
            "mitigations": ["Input validation", "Schema validation", "HMAC"],
        },
        {
            "stride": "information_disclosure", "title": "Excessive Data Exposure",
            "desc": "API returns more data than needed",
            "vector": "API responses",
            "dread": {"D": 6, "R": 9, "E": 5, "A": 8, "D2": 5},
            "mitigations": ["Response filtering", "GraphQL limits", "Field selection"],
        },
    ],
}


class ThreatModeler:
    """Models threats using STRIDE and DREAD methodologies.

    Generates threat models for targets based on
    their type, technologies, and discovered data.
    """

    def __init__(self) -> None:
        self._models: dict[str, ThreatModel] = {}
        self._model_counter = 0
        self._threat_counter = 0
        self._flow_counter = 0
        self._log = logger.bind(component="threat_modeler")

    def create_model(
        self,
        target: str,
        target_type: str = "web_app",
        technologies: list[str] | None = None,
        assets: list[str] | None = None,
    ) -> ThreatModel:
        """Create a threat model for a target."""
        self._model_counter += 1
        model_id = f"tm-{self._model_counter}"

        model = ThreatModel(
            model_id=model_id,
            target=target,
            assets=assets or [],
        )

        # Apply STRIDE patterns
        patterns = STRIDE_PATTERNS.get(target_type, STRIDE_PATTERNS.get("web_app", []))

        for pattern in patterns:
            self._threat_counter += 1
            threat = Threat(
                threat_id=f"threat-{self._threat_counter}",
                title=pattern["title"],
                description=pattern["desc"],
                stride=StrideCategory(pattern["stride"]),
                dread=DreadScore(**pattern.get("dread", {})),
                attack_vector=pattern.get("vector", ""),
                mitigations=pattern.get("mitigations", []),
            )

            if assets:
                threat.affected_assets = assets[:3]

            model.threats.append(threat)

        # Generate data flows
        if target_type == "web_app":
            model.data_flows = self._generate_web_flows(target)
            model.trust_boundaries = [
                "Internet → WAF",
                "WAF → Web Server",
                "Web Server → Application",
                "Application → Database",
            ]
        elif target_type == "api":
            model.data_flows = self._generate_api_flows(target)
            model.trust_boundaries = [
                "Client → API Gateway",
                "API Gateway → Service",
                "Service → Database",
            ]

        # Sort threats by risk
        model.threats.sort(key=lambda t: t.dread.total, reverse=True)

        self._models[model_id] = model
        return model

    def _generate_web_flows(self, target: str) -> list[DataFlow]:
        """Generate typical web app data flows."""
        flows = []
        flow_defs = [
            ("Client", "Web Server", "http_request", "https", True, True),
            ("Web Server", "Application", "internal", "http", False, False),
            ("Application", "Database", "sql_query", "tcp", True, False),
            ("Client", "CDN", "static_assets", "https", True, True),
            ("Application", "Cache", "cache_data", "tcp", False, False),
            ("Application", "Auth Service", "auth_token", "https", True, True),
        ]

        for src, dst, data_type, proto, crosses, encrypted in flow_defs:
            self._flow_counter += 1
            flows.append(DataFlow(
                flow_id=f"flow-{self._flow_counter}",
                source=src, destination=dst,
                data_type=data_type, protocol=proto,
                crosses_boundary=crosses, is_encrypted=encrypted,
            ))

        return flows

    def _generate_api_flows(self, target: str) -> list[DataFlow]:
        """Generate typical API data flows."""
        flows = []
        flow_defs = [
            ("Client", "API Gateway", "api_request", "https", True, True),
            ("API Gateway", "Auth Service", "auth_check", "grpc", True, True),
            ("API Gateway", "Service", "request", "grpc", False, True),
            ("Service", "Database", "query", "tcp", True, False),
        ]

        for src, dst, data_type, proto, crosses, encrypted in flow_defs:
            self._flow_counter += 1
            flows.append(DataFlow(
                flow_id=f"flow-{self._flow_counter}",
                source=src, destination=dst,
                data_type=data_type, protocol=proto,
                crosses_boundary=crosses, is_encrypted=encrypted,
            ))

        return flows

    def prioritize_threats(
        self,
        model_id: str,
    ) -> list[dict[str, Any]]:
        """Prioritize threats by DREAD score."""
        model = self._models.get(model_id)
        if not model:
            return []

        return [t.to_dict() for t in model.threats]

    def get_unmitigated(self, model_id: str) -> list[dict[str, Any]]:
        """Get unmitigated threats."""
        model = self._models.get(model_id)
        if not model:
            return []

        return [t.to_dict() for t in model.threats if not t.is_mitigated]

    def get_stats(self) -> dict[str, Any]:
        return {
            "models": len(self._models),
            "threats": self._threat_counter,
            "data_flows": self._flow_counter,
        }
