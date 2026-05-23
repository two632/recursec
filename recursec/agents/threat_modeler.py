"""Threat modeler — generates threat models for targets.

Implements:
1. STRIDE-based threat modeling
2. Attack surface enumeration
3. Threat actor profiling
4. Attack tree construction
5. Risk scoring (impact x likelihood)
6. Trust boundary analysis
7. Data flow analysis
8. Threat prioritization
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class STRIDECategory(str, Enum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class ThreatActorType(str, Enum):
    SCRIPT_KIDDIE = "script_kiddie"
    OPPORTUNISTIC = "opportunistic"
    CYBERCRIMINAL = "cybercriminal"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    NATION_STATE = "nation_state"
    APT = "apt"


class ComponentType(str, Enum):
    WEB_APP = "web_app"
    API = "api"
    DATABASE = "database"
    AUTH_SERVICE = "auth_service"
    FILE_STORAGE = "file_storage"
    MESSAGE_QUEUE = "message_queue"
    CACHE = "cache"
    CDN = "cdn"
    LOAD_BALANCER = "load_balancer"
    DNS = "dns"
    EXTERNAL_SERVICE = "external_service"


@dataclass
class SystemComponent:
    """A component in the target system."""
    component_id: str = ""
    name: str = ""
    component_type: ComponentType = ComponentType.WEB_APP
    technologies: list[str] = field(default_factory=list)
    exposed: bool = False
    trust_level: int = 0       # 0=untrusted, 1=semi, 2=trusted, 3=highly-trusted
    data_sensitivity: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.component_id,
            "name": self.name[:20],
            "type": self.component_type.value,
            "exposed": self.exposed,
            "trust": self.trust_level,
        }


@dataclass
class DataFlow:
    """Data flow between components."""
    flow_id: str = ""
    source: str = ""
    destination: str = ""
    data_type: str = ""
    protocol: str = ""
    encrypted: bool = False
    crosses_trust_boundary: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.flow_id,
            "src": self.source[:15],
            "dst": self.destination[:15],
            "encrypted": self.encrypted,
            "boundary": self.crosses_trust_boundary,
        }


@dataclass
class ThreatEntry:
    """A threat in the model."""
    threat_id: str = ""
    title: str = ""
    stride_category: STRIDECategory = STRIDECategory.SPOOFING
    component: str = ""
    description: str = ""
    attack_vector: str = ""
    impact: int = 5            # 1-10
    likelihood: int = 5        # 1-10
    mitigations: list[str] = field(default_factory=list)
    affected_data_flows: list[str] = field(default_factory=list)
    threat_actors: list[ThreatActorType] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        return self.impact * self.likelihood

    @property
    def risk_level(self) -> str:
        score = self.risk_score
        if score >= 70:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        return "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.threat_id,
            "title": self.title[:30],
            "stride": self.stride_category.value,
            "risk": self.risk_score,
            "level": self.risk_level,
            "mitigations": len(self.mitigations),
        }


@dataclass
class AttackTreeNode:
    """Node in an attack tree."""
    node_id: str = ""
    description: str = ""
    is_and: bool = False       # AND node (all children needed) vs OR node
    cost: int = 0
    difficulty: int = 0
    children: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "desc": self.description[:30],
            "type": "AND" if self.is_and else "OR",
            "children": len(self.children),
        }


@dataclass
class ThreatModel:
    """Complete threat model for a target."""
    model_id: str = ""
    target: str = ""
    components: list[SystemComponent] = field(default_factory=list)
    data_flows: list[DataFlow] = field(default_factory=list)
    threats: list[ThreatEntry] = field(default_factory=list)
    attack_trees: dict[str, AttackTreeNode] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.model_id,
            "target": self.target[:25],
            "components": len(self.components),
            "flows": len(self.data_flows),
            "threats": len(self.threats),
            "trees": len(self.attack_trees),
        }


# ── Default STRIDE Threats per Component ──────────────────────

STRIDE_THREATS: dict[str, list[dict[str, Any]]] = {
    "web_app": [
        {"stride": "spoofing", "title": "Session hijacking", "desc": "Steal/forge session tokens", "impact": 8, "likelihood": 6, "mitigations": ["Secure session management", "HTTPOnly cookies", "SameSite attribute"]},
        {"stride": "tampering", "title": "Client-side data modification", "desc": "Tamper with form data or API requests", "impact": 7, "likelihood": 7, "mitigations": ["Server-side validation", "Input sanitization"]},
        {"stride": "information_disclosure", "title": "Sensitive data in response", "desc": "API responses leak sensitive data", "impact": 8, "likelihood": 5, "mitigations": ["Response filtering", "Data minimization"]},
        {"stride": "denial_of_service", "title": "Application-layer DoS", "desc": "Resource exhaustion via expensive requests", "impact": 6, "likelihood": 5, "mitigations": ["Rate limiting", "Request size limits"]},
        {"stride": "elevation_of_privilege", "title": "IDOR access control bypass", "desc": "Access other users' data via ID manipulation", "impact": 9, "likelihood": 7, "mitigations": ["Authorization checks", "Object-level access control"]},
    ],
    "api": [
        {"stride": "spoofing", "title": "API key theft", "desc": "Steal API keys from logs/config/traffic", "impact": 9, "likelihood": 5, "mitigations": ["Key rotation", "Secrets manager", "TLS"]},
        {"stride": "tampering", "title": "Parameter pollution", "desc": "Inject extra parameters to bypass logic", "impact": 7, "likelihood": 6, "mitigations": ["Strict schema validation", "Whitelist params"]},
        {"stride": "information_disclosure", "title": "Excessive data exposure", "desc": "API returns more fields than needed", "impact": 6, "likelihood": 8, "mitigations": ["Response filtering", "GraphQL depth limiting"]},
        {"stride": "elevation_of_privilege", "title": "Broken function level auth", "desc": "Access admin endpoints without authorization", "impact": 10, "likelihood": 5, "mitigations": ["Role-based access control", "Endpoint authorization"]},
    ],
    "database": [
        {"stride": "tampering", "title": "SQL injection", "desc": "Inject SQL via application inputs", "impact": 10, "likelihood": 4, "mitigations": ["Parameterized queries", "ORM", "WAF"]},
        {"stride": "information_disclosure", "title": "Database exposure", "desc": "Database port exposed to internet", "impact": 10, "likelihood": 3, "mitigations": ["Network segmentation", "Firewall rules"]},
        {"stride": "denial_of_service", "title": "Query bomb", "desc": "Complex queries exhausting database resources", "impact": 7, "likelihood": 4, "mitigations": ["Query timeout", "Connection pooling"]},
    ],
    "auth_service": [
        {"stride": "spoofing", "title": "Credential stuffing", "desc": "Automated login attempts with leaked credentials", "impact": 8, "likelihood": 8, "mitigations": ["Rate limiting", "CAPTCHA", "MFA"]},
        {"stride": "spoofing", "title": "JWT forgery", "desc": "Forge tokens via algorithm confusion or weak keys", "impact": 10, "likelihood": 4, "mitigations": ["Strong keys", "Algorithm whitelist", "Token validation"]},
        {"stride": "elevation_of_privilege", "title": "Privilege escalation via token manipulation", "desc": "Modify role claims in tokens", "impact": 10, "likelihood": 4, "mitigations": ["Token signing verification", "Server-side role checks"]},
    ],
    "file_storage": [
        {"stride": "information_disclosure", "title": "Public bucket/blob exposure", "desc": "Cloud storage publicly readable", "impact": 9, "likelihood": 6, "mitigations": ["Private by default", "Access policies", "Monitoring"]},
        {"stride": "tampering", "title": "Malicious file upload", "desc": "Upload executable/malware via file upload", "impact": 8, "likelihood": 5, "mitigations": ["File type validation", "Virus scanning", "Content-Type enforcement"]},
    ],
    "dns": [
        {"stride": "spoofing", "title": "DNS cache poisoning", "desc": "Insert fake DNS records into resolver", "impact": 9, "likelihood": 3, "mitigations": ["DNSSEC", "Source port randomization"]},
        {"stride": "spoofing", "title": "DNS rebinding", "desc": "Change DNS resolution to access internal network", "impact": 8, "likelihood": 4, "mitigations": ["DNS pinning", "Host header validation"]},
    ],
}


class ThreatModeler:
    """Generates threat models for targets.

    Creates STRIDE-based threat models with attack surfaces,
    data flows, trust boundaries, and prioritized threats.
    """

    def __init__(self) -> None:
        self._models: dict[str, ThreatModel] = {}
        self._model_counter = 0
        self._component_counter = 0
        self._flow_counter = 0
        self._threat_counter = 0
        self._node_counter = 0
        self._log = logger.bind(component="threat_modeler")

    def create_model(self, target: str) -> ThreatModel:
        """Create a new threat model for a target."""
        self._model_counter += 1
        model = ThreatModel(
            model_id=f"tm-{self._model_counter}",
            target=target,
        )
        self._models[model.model_id] = model
        return model

    def add_component(
        self,
        model_id: str,
        name: str,
        component_type: ComponentType,
        exposed: bool = False,
        trust_level: int = 0,
        technologies: list[str] | None = None,
    ) -> SystemComponent | None:
        """Add a component to the threat model."""
        model = self._models.get(model_id)
        if not model:
            return None

        self._component_counter += 1
        component = SystemComponent(
            component_id=f"comp-{self._component_counter}",
            name=name,
            component_type=component_type,
            exposed=exposed,
            trust_level=trust_level,
            technologies=technologies or [],
        )
        model.components.append(component)

        # Auto-generate STRIDE threats for this component
        self._generate_threats(model, component)

        return component

    def add_data_flow(
        self,
        model_id: str,
        source: str,
        destination: str,
        data_type: str = "",
        protocol: str = "",
        encrypted: bool = False,
    ) -> DataFlow | None:
        """Add a data flow between components."""
        model = self._models.get(model_id)
        if not model:
            return None

        self._flow_counter += 1

        # Determine if it crosses a trust boundary
        src_comp = next((c for c in model.components if c.name == source), None)
        dst_comp = next((c for c in model.components if c.name == destination), None)
        crosses_boundary = False
        if src_comp and dst_comp:
            crosses_boundary = src_comp.trust_level != dst_comp.trust_level

        flow = DataFlow(
            flow_id=f"flow-{self._flow_counter}",
            source=source,
            destination=destination,
            data_type=data_type,
            protocol=protocol,
            encrypted=encrypted,
            crosses_trust_boundary=crosses_boundary,
        )
        model.data_flows.append(flow)

        # Add threats for unencrypted cross-boundary flows
        if crosses_boundary and not encrypted:
            self._threat_counter += 1
            model.threats.append(ThreatEntry(
                threat_id=f"th-{self._threat_counter}",
                title=f"Unencrypted data flow: {source} → {destination}",
                stride_category=STRIDECategory.INFORMATION_DISCLOSURE,
                component=f"{source}/{destination}",
                description=f"Data flow from {source} to {destination} crosses trust boundary without encryption",
                impact=7,
                likelihood=5,
                mitigations=["Enable TLS/mTLS", "Encrypt sensitive fields"],
                affected_data_flows=[flow.flow_id],
            ))

        return flow

    def _generate_threats(
        self,
        model: ThreatModel,
        component: SystemComponent,
    ) -> None:
        """Generate STRIDE threats for a component."""
        threat_templates = STRIDE_THREATS.get(component.component_type.value, [])

        for tmpl in threat_templates:
            self._threat_counter += 1

            # Adjust likelihood for exposed components
            likelihood = tmpl["likelihood"]
            if component.exposed:
                likelihood = min(10, likelihood + 2)

            model.threats.append(ThreatEntry(
                threat_id=f"th-{self._threat_counter}",
                title=tmpl["title"],
                stride_category=STRIDECategory(tmpl["stride"]),
                component=component.name,
                description=tmpl.get("desc", ""),
                impact=tmpl["impact"],
                likelihood=likelihood,
                mitigations=tmpl.get("mitigations", []),
            ))

    def build_attack_tree(
        self,
        model_id: str,
        root_goal: str,
        sub_goals: list[dict[str, Any]],
    ) -> AttackTreeNode | None:
        """Build an attack tree for a goal."""
        model = self._models.get(model_id)
        if not model:
            return None

        self._node_counter += 1
        root = AttackTreeNode(
            node_id=f"atn-{self._node_counter}",
            description=root_goal,
            is_and=False,
        )
        model.attack_trees[root.node_id] = root

        for sub in sub_goals:
            self._node_counter += 1
            child = AttackTreeNode(
                node_id=f"atn-{self._node_counter}",
                description=sub.get("desc", ""),
                cost=sub.get("cost", 0),
                difficulty=sub.get("difficulty", 0),
            )
            model.attack_trees[child.node_id] = child
            root.children.append(child.node_id)

        return root

    def prioritize_threats(self, model_id: str) -> list[ThreatEntry]:
        """Get threats sorted by risk score."""
        model = self._models.get(model_id)
        if not model:
            return []
        return sorted(model.threats, key=lambda t: t.risk_score, reverse=True)

    def get_model(self, model_id: str) -> ThreatModel | None:
        return self._models.get(model_id)

    def get_stats(self) -> dict[str, Any]:
        total_threats = sum(len(m.threats) for m in self._models.values())
        return {
            "models": len(self._models),
            "total_threats": total_threats,
            "total_components": sum(len(m.components) for m in self._models.values()),
        }
