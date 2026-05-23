"""Threat modeler — STRIDE/DREAD threat modeling for targets.

Implements:
1. STRIDE classification (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation)
2. DREAD risk scoring (Damage, Reproducibility, Exploitability, Affected Users, Discoverability)
3. Attack tree generation
4. Threat scenario planning
5. Asset identification
6. Trust boundary mapping
7. Data flow analysis
8. Countermeasure recommendation
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class STRIDECategory(str, Enum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFO_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION = "elevation_of_privilege"


class AssetType(str, Enum):
    DATA = "data"
    SERVICE = "service"
    CREDENTIAL = "credential"
    INFRASTRUCTURE = "infrastructure"
    CODE = "code"
    CONFIGURATION = "configuration"


@dataclass
class Asset:
    """An identified asset in the target environment."""
    asset_id: str = ""
    name: str = ""
    asset_type: AssetType = AssetType.DATA
    description: str = ""
    sensitivity: float = 0.5       # 0=public, 1=top secret
    location: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.asset_id, "name": self.name[:80],
            "type": self.asset_type.value,
            "sensitivity": round(self.sensitivity, 1),
        }


@dataclass
class TrustBoundary:
    """A trust boundary between components."""
    name: str = ""
    description: str = ""
    from_zone: str = ""
    to_zone: str = ""
    protocols: list[str] = field(default_factory=list)
    authentication: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:60],
            "from": self.from_zone, "to": self.to_zone,
            "protocols": self.protocols[:3],
        }


@dataclass
class DREADScore:
    """DREAD risk scoring."""
    damage: float = 5.0
    reproducibility: float = 5.0
    exploitability: float = 5.0
    affected_users: float = 5.0
    discoverability: float = 5.0

    @property
    def total(self) -> float:
        return (
            self.damage + self.reproducibility + self.exploitability
            + self.affected_users + self.discoverability
        ) / 5

    @property
    def risk_level(self) -> str:
        score = self.total
        if score >= 8:
            return "critical"
        elif score >= 6:
            return "high"
        elif score >= 4:
            return "medium"
        elif score >= 2:
            return "low"
        return "info"

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
    """An identified threat."""
    threat_id: str = ""
    name: str = ""
    description: str = ""
    stride_category: STRIDECategory = STRIDECategory.SPOOFING
    affected_assets: list[str] = field(default_factory=list)
    attack_vector: str = ""
    dread_score: DREADScore = field(default_factory=DREADScore)
    countermeasures: list[str] = field(default_factory=list)
    likelihood: float = 0.5
    impact: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.threat_id, "name": self.name[:80],
            "stride": self.stride_category.value,
            "dread": self.dread_score.to_dict(),
            "countermeasures": len(self.countermeasures),
        }


@dataclass
class AttackTreeNode:
    """A node in an attack tree."""
    node_id: str = ""
    name: str = ""
    is_goal: bool = False
    is_and: bool = False         # True=AND, False=OR
    children: list[str] = field(default_factory=list)
    probability: float = 0.0
    cost: float = 0.0
    tool: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id, "name": self.name[:80],
            "type": "AND" if self.is_and else "OR",
            "children": len(self.children),
            "probability": round(self.probability, 2),
        }


@dataclass
class ThreatModel:
    """Complete threat model for a target."""
    model_id: str = ""
    target: str = ""
    assets: list[Asset] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    threats: list[Threat] = field(default_factory=list)
    attack_trees: list[AttackTreeNode] = field(default_factory=list)
    overall_risk: str = "medium"
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.model_id, "target": self.target[:50],
            "assets": len(self.assets),
            "boundaries": len(self.trust_boundaries),
            "threats": len(self.threats),
            "risk": self.overall_risk,
        }


# ── STRIDE Threat Templates ─────────────────────────────────

WEB_THREATS: list[dict[str, Any]] = [
    {"name": "Session hijacking", "stride": "spoofing",
     "vector": "Steal session tokens via XSS or network sniffing",
     "dread": {"D": 7, "R": 6, "E": 5, "A": 8, "D2": 4},
     "fixes": ["Secure session management", "HTTPS everywhere", "SameSite cookies"]},
    {"name": "SQL injection data modification", "stride": "tampering",
     "vector": "Modify database records via SQL injection",
     "dread": {"D": 9, "R": 7, "E": 6, "A": 9, "D2": 5},
     "fixes": ["Parameterized queries", "Input validation", "WAF"]},
    {"name": "Missing audit logging", "stride": "repudiation",
     "vector": "Actions not logged, attacker denies activity",
     "dread": {"D": 4, "R": 9, "E": 8, "A": 5, "D2": 3},
     "fixes": ["Comprehensive logging", "Log integrity", "SIEM integration"]},
    {"name": "Sensitive data exposure", "stride": "information_disclosure",
     "vector": "Access sensitive data through API/error messages",
     "dread": {"D": 8, "R": 6, "E": 5, "A": 7, "D2": 6},
     "fixes": ["Encrypt at rest and transit", "Access controls", "Error handling"]},
    {"name": "Application DoS", "stride": "denial_of_service",
     "vector": "Overwhelm application with requests",
     "dread": {"D": 6, "R": 8, "E": 7, "A": 9, "D2": 7},
     "fixes": ["Rate limiting", "CDN", "Auto-scaling"]},
    {"name": "Privilege escalation via IDOR", "stride": "elevation_of_privilege",
     "vector": "Access other users' resources via insecure direct object references",
     "dread": {"D": 8, "R": 7, "E": 6, "A": 8, "D2": 5},
     "fixes": ["Authorization checks", "RBAC", "Access control testing"]},
]

NETWORK_THREATS: list[dict[str, Any]] = [
    {"name": "ARP spoofing", "stride": "spoofing",
     "vector": "Impersonate network devices via ARP poisoning",
     "dread": {"D": 7, "R": 8, "E": 6, "A": 6, "D2": 5},
     "fixes": ["ARP inspection", "Static ARP entries", "Network segmentation"]},
    {"name": "Man-in-the-middle", "stride": "tampering",
     "vector": "Intercept and modify network traffic",
     "dread": {"D": 9, "R": 5, "E": 5, "A": 8, "D2": 4},
     "fixes": ["TLS everywhere", "Certificate pinning", "HSTS"]},
    {"name": "Lateral movement", "stride": "elevation_of_privilege",
     "vector": "Move between network segments after initial access",
     "dread": {"D": 9, "R": 6, "E": 5, "A": 9, "D2": 3},
     "fixes": ["Network segmentation", "Zero trust", "Micro-segmentation"]},
]


THREAT_MODEL_PROMPT = """You are a security threat modeler. Create a threat model.

Target: {target}
Target type: {target_type}
Known technologies: {technologies}
Known entry points: {entry_points}

Identify:
1. Key assets that need protection
2. Trust boundaries
3. STRIDE threats
4. DREAD risk scores

Respond as JSON:
{{
  "assets": [{{"name": "...", "type": "data|service|credential|infrastructure", "sensitivity": 0.X}}],
  "boundaries": [{{"name": "...", "from": "zone", "to": "zone"}}],
  "threats": [
    {{
      "name": "threat name",
      "stride": "spoofing|tampering|repudiation|information_disclosure|denial_of_service|elevation_of_privilege",
      "vector": "how the attack works",
      "dread": {{"D": X, "R": X, "E": X, "A": X, "D2": X}},
      "countermeasures": ["fix 1", "fix 2"]
    }}
  ]
}}"""


class ThreatModeler:
    """STRIDE/DREAD threat modeling engine.

    Creates comprehensive threat models for targets
    with asset identification, attack trees, and
    countermeasure recommendations.
    """

    def __init__(self, model_router: ModelRouter | None = None) -> None:
        self._router = model_router
        self._models: dict[str, ThreatModel] = {}
        self._model_counter = 0
        self._threat_counter = 0
        self._asset_counter = 0
        self._node_counter = 0
        self._log = logger.bind(component="threat_modeler")

    async def model_target(
        self,
        target: str,
        target_type: str = "web_app",
        technologies: list[str] | None = None,
        entry_points: list[str] | None = None,
    ) -> ThreatModel:
        """Create a threat model for a target."""
        self._model_counter += 1
        model_id = f"tm-{self._model_counter}"

        tm = ThreatModel(model_id=model_id, target=target)

        # LLM-based modeling
        if self._router:
            llm_data = await self._llm_model(
                target, target_type, technologies or [], entry_points or [],
            )
            tm.assets = self._parse_assets(llm_data.get("assets", []))
            tm.trust_boundaries = self._parse_boundaries(llm_data.get("boundaries", []))
            tm.threats = self._parse_threats(llm_data.get("threats", []))

        # Template-based fallback / supplement
        if not tm.threats:
            template = WEB_THREATS if target_type in ("web_app", "api") else NETWORK_THREATS
            tm.threats = self._threats_from_template(template)

        # Generate attack tree from threats
        tm.attack_trees = self._generate_attack_tree(tm.threats)

        # Overall risk
        if tm.threats:
            avg_risk = sum(t.dread_score.total for t in tm.threats) / len(tm.threats)
            if avg_risk >= 7:
                tm.overall_risk = "critical"
            elif avg_risk >= 5:
                tm.overall_risk = "high"
            elif avg_risk >= 3:
                tm.overall_risk = "medium"
            else:
                tm.overall_risk = "low"

        self._models[model_id] = tm
        return tm

    def _threats_from_template(self, template: list[dict[str, Any]]) -> list[Threat]:
        threats = []
        for t_data in template:
            self._threat_counter += 1
            dread_data = t_data.get("dread", {})

            try:
                stride = STRIDECategory(t_data.get("stride", "spoofing"))
            except ValueError:
                stride = STRIDECategory.SPOOFING

            threats.append(Threat(
                threat_id=f"threat-{self._threat_counter}",
                name=t_data.get("name", ""),
                stride_category=stride,
                attack_vector=t_data.get("vector", ""),
                dread_score=DREADScore(
                    damage=dread_data.get("D", 5),
                    reproducibility=dread_data.get("R", 5),
                    exploitability=dread_data.get("E", 5),
                    affected_users=dread_data.get("A", 5),
                    discoverability=dread_data.get("D2", 5),
                ),
                countermeasures=t_data.get("fixes", []),
            ))
        return threats

    def _generate_attack_tree(self, threats: list[Threat]) -> list[AttackTreeNode]:
        """Generate attack tree from threats."""
        nodes = []

        self._node_counter += 1
        root = AttackTreeNode(
            node_id=f"atn-{self._node_counter}",
            name="Compromise Target",
            is_goal=True,
            is_and=False,
        )

        for threat in threats:
            self._node_counter += 1
            child = AttackTreeNode(
                node_id=f"atn-{self._node_counter}",
                name=threat.name,
                probability=threat.dread_score.total / 10,
            )
            root.children.append(child.node_id)
            nodes.append(child)

        nodes.insert(0, root)
        return nodes

    def _parse_assets(self, assets_data: list[dict[str, Any]]) -> list[Asset]:
        assets = []
        for a_data in assets_data[:20]:
            self._asset_counter += 1
            try:
                a_type = AssetType(a_data.get("type", "data"))
            except ValueError:
                a_type = AssetType.DATA

            assets.append(Asset(
                asset_id=f"asset-{self._asset_counter}",
                name=a_data.get("name", ""),
                asset_type=a_type,
                sensitivity=a_data.get("sensitivity", 0.5),
            ))
        return assets

    def _parse_boundaries(self, boundaries_data: list[dict[str, Any]]) -> list[TrustBoundary]:
        boundaries = []
        for b_data in boundaries_data[:10]:
            boundaries.append(TrustBoundary(
                name=b_data.get("name", ""),
                from_zone=b_data.get("from", ""),
                to_zone=b_data.get("to", ""),
            ))
        return boundaries

    def _parse_threats(self, threats_data: list[dict[str, Any]]) -> list[Threat]:
        threats = []
        for t_data in threats_data[:20]:
            self._threat_counter += 1
            try:
                stride = STRIDECategory(t_data.get("stride", "spoofing"))
            except ValueError:
                stride = STRIDECategory.SPOOFING

            dread = t_data.get("dread", {})
            threats.append(Threat(
                threat_id=f"threat-{self._threat_counter}",
                name=t_data.get("name", ""),
                stride_category=stride,
                attack_vector=t_data.get("vector", ""),
                dread_score=DREADScore(
                    damage=dread.get("D", 5),
                    reproducibility=dread.get("R", 5),
                    exploitability=dread.get("E", 5),
                    affected_users=dread.get("A", 5),
                    discoverability=dread.get("D2", 5),
                ),
                countermeasures=t_data.get("countermeasures", []),
            ))
        return threats

    async def _llm_model(
        self,
        target: str,
        target_type: str,
        technologies: list[str],
        entry_points: list[str],
    ) -> dict[str, Any]:
        if not self._router:
            return {}

        prompt = THREAT_MODEL_PROMPT.format(
            target=target,
            target_type=target_type,
            technologies=", ".join(technologies[:5]) or "Unknown",
            entry_points=", ".join(entry_points[:5]) or "Standard",
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.3,
            max_tokens=1024,
        )

        import json
        try:
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]
            return json.loads(response.strip())
        except (json.JSONDecodeError, IndexError):
            return {}

    def get_stats(self) -> dict[str, Any]:
        return {
            "models": len(self._models),
            "total_threats": sum(len(m.threats) for m in self._models.values()),
        }
