"""Threat modeling engine — STRIDE-based automated threat analysis.

Uses LLM reasoning to build threat models for targets:
1. Identify assets and trust boundaries
2. Enumerate threats using STRIDE categories
3. Rank threats by likelihood and impact
4. Map threats to MITRE ATT&CK techniques
5. Generate mitigations and test plans
6. Validate findings against threat model

STRIDE categories:
- Spoofing: Identity/authentication attacks
- Tampering: Data integrity violations
- Repudiation: Deniability of actions
- Information Disclosure: Data leaks
- Denial of Service: Availability attacks
- Elevation of Privilege: Authorization bypass
"""

from __future__ import annotations

import json
import time
import uuid
from collections import defaultdict
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
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class ThreatSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MitigationStatus(str, Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class TrustBoundary:
    """A trust boundary in the system."""
    boundary_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    description: str = ""
    components_inside: list[str] = field(default_factory=list)
    components_outside: list[str] = field(default_factory=list)
    data_flows: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.boundary_id, "name": self.name,
            "inside": self.components_inside,
            "outside": self.components_outside,
            "data_flows": len(self.data_flows),
        }


@dataclass
class Threat:
    """An identified threat."""
    threat_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    description: str = ""
    category: STRIDECategory = STRIDECategory.SPOOFING
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    affected_component: str = ""
    trust_boundary: str = ""
    attack_vector: str = ""
    mitre_technique: str = ""
    likelihood: float = 0.5  # 0.0-1.0
    impact: float = 0.5
    risk_score: float = 0.0  # likelihood * impact * severity_weight
    prerequisites: list[str] = field(default_factory=list)
    mitigations: list[dict[str, str]] = field(default_factory=list)
    mitigation_status: MitigationStatus = MitigationStatus.NOT_STARTED
    test_cases: list[str] = field(default_factory=list)
    validated: bool = False

    def calculate_risk(self) -> float:
        severity_weights = {
            ThreatSeverity.CRITICAL: 1.0, ThreatSeverity.HIGH: 0.8,
            ThreatSeverity.MEDIUM: 0.5, ThreatSeverity.LOW: 0.2,
            ThreatSeverity.INFO: 0.05,
        }
        weight = severity_weights.get(self.severity, 0.5)
        self.risk_score = self.likelihood * self.impact * weight
        return self.risk_score

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.threat_id, "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "component": self.affected_component,
            "mitre": self.mitre_technique,
            "likelihood": round(self.likelihood, 2),
            "impact": round(self.impact, 2),
            "risk": round(self.risk_score, 3),
            "mitigations": len(self.mitigations),
            "status": self.mitigation_status.value,
            "validated": self.validated,
        }


@dataclass
class ThreatModel:
    """Complete threat model for a target."""
    model_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    target: str = ""
    target_type: str = ""
    components: list[dict[str, str]] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    threats: list[Threat] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_threats_by_category(self) -> dict[str, list[Threat]]:
        by_cat: dict[str, list[Threat]] = defaultdict(list)
        for threat in self.threats:
            by_cat[threat.category.value].append(threat)
        return by_cat

    def get_top_risks(self, limit: int = 10) -> list[Threat]:
        return sorted(self.threats, key=lambda t: -t.risk_score)[:limit]

    def to_dict(self) -> dict[str, Any]:
        by_severity: dict[str, int] = defaultdict(int)
        by_category: dict[str, int] = defaultdict(int)
        for t in self.threats:
            by_severity[t.severity.value] += 1
            by_category[t.category.value] += 1
        return {
            "id": self.model_id, "target": self.target,
            "target_type": self.target_type,
            "components": len(self.components),
            "boundaries": len(self.trust_boundaries),
            "total_threats": len(self.threats),
            "by_severity": dict(by_severity),
            "by_category": dict(by_category),
            "top_risks": [t.to_dict() for t in self.get_top_risks(5)],
        }


# ── Prompt Templates ────────────────────────────────────────

IDENTIFY_COMPONENTS_PROMPT = """Identify the components and architecture of this target system.

Target: {target}
Target type: {target_type}
Known information: {known_info}

List all components, their roles, and how they communicate.

Respond as JSON:
{{
  "components": [
    {{
      "name": "component name",
      "type": "web_server|database|api|auth|cache|queue|storage|etc",
      "description": "what it does",
      "technologies": ["tech stack"],
      "exposed_ports": [80, 443],
      "data_handled": ["types of data"],
      "authentication": "none|basic|token|oauth|etc"
    }}
  ],
  "trust_boundaries": [
    {{
      "name": "boundary name",
      "inside": ["component names"],
      "outside": ["component names"],
      "data_flows": [
        {{"from": "A", "to": "B", "data": "type", "protocol": "https"}}
      ]
    }}
  ]
}}"""

ENUMERATE_THREATS_PROMPT = """Enumerate threats for this system using STRIDE methodology.

Target: {target}
Components: {components}
Trust boundaries: {boundaries}

For each STRIDE category, identify specific threats:
- Spoofing: How could identity be faked?
- Tampering: How could data be modified?
- Repudiation: How could actions be denied?
- Information Disclosure: How could data leak?
- Denial of Service: How could availability be impacted?
- Elevation of Privilege: How could authorization be bypassed?

Respond as JSON:
{{
  "threats": [
    {{
      "title": "concise threat title",
      "description": "detailed description",
      "category": "spoofing|tampering|repudiation|information_disclosure|denial_of_service|elevation_of_privilege",
      "severity": "critical|high|medium|low",
      "affected_component": "component name",
      "trust_boundary": "boundary name",
      "attack_vector": "how this would be exploited",
      "mitre_technique": "T1XXX (if applicable)",
      "likelihood": 0.X,
      "impact": 0.X,
      "prerequisites": ["what attacker needs"],
      "mitigations": [
        {{"action": "what to do", "priority": "high|medium|low"}}
      ],
      "test_cases": ["how to test for this threat"]
    }}
  ]
}}"""

VALIDATE_AGAINST_MODEL_PROMPT = """Compare these security findings against the threat model.

Threat model threats: {threats}
Actual findings: {findings}

Determine:
1. Which threats were confirmed by findings?
2. Which threats were NOT found (false negatives or properly mitigated)?
3. Which findings don't match any predicted threat (new threats)?
4. Overall coverage of the threat model

Respond as JSON:
{{
  "confirmed_threats": ["threat_ids confirmed by findings"],
  "unconfirmed_threats": ["threat_ids not found"],
  "unexpected_findings": ["findings that don't match any threat"],
  "coverage_pct": 0.X,
  "model_quality": "good|fair|poor",
  "recommendations": ["how to improve the threat model"]
}}"""


class ThreatModelEngine:
    """Automated STRIDE-based threat modeling."""

    def __init__(self, model_router: ModelRouter) -> None:
        self._router = model_router
        self._models: dict[str, ThreatModel] = {}
        self._log = logger.bind(component="threat_model")

    async def build_model(
        self,
        target: str,
        target_type: str = "",
        known_info: dict[str, Any] | None = None,
    ) -> ThreatModel:
        """Build a complete threat model for a target."""
        model = ThreatModel(target=target, target_type=target_type)

        # Step 1: Identify components and trust boundaries
        components = await self._identify_components(target, target_type, known_info or {})
        model.components = components.get("components", [])

        for boundary_data in components.get("trust_boundaries", []):
            boundary = TrustBoundary(
                name=boundary_data.get("name", ""),
                description=boundary_data.get("description", ""),
                components_inside=boundary_data.get("inside", []),
                components_outside=boundary_data.get("outside", []),
                data_flows=boundary_data.get("data_flows", []),
            )
            model.trust_boundaries.append(boundary)

        # Step 2: Enumerate threats
        threats = await self._enumerate_threats(target, model)
        for threat_data in threats.get("threats", []):
            threat = self._parse_threat(threat_data)
            threat.calculate_risk()
            model.threats.append(threat)

        # Sort by risk
        model.threats.sort(key=lambda t: -t.risk_score)

        self._models[model.model_id] = model
        self._log.info(
            "threat_model_built",
            target=target, threats=len(model.threats),
            components=len(model.components),
        )

        return model

    async def validate_findings(
        self,
        model_id: str,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Validate actual findings against the threat model."""
        model = self._models.get(model_id)
        if not model:
            return {"error": "Model not found"}

        threats_desc = json.dumps([t.to_dict() for t in model.threats[:20]])[:3000]
        findings_desc = json.dumps(findings[:20])[:3000]

        prompt = VALIDATE_AGAINST_MODEL_PROMPT.format(
            threats=threats_desc, findings=findings_desc,
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=2048,
        )

        data = self._parse_json(response)

        # Mark confirmed threats
        for threat_id in data.get("confirmed_threats", []):
            for threat in model.threats:
                if threat.threat_id == threat_id:
                    threat.validated = True

        return data

    async def _identify_components(
        self,
        target: str,
        target_type: str,
        known_info: dict[str, Any],
    ) -> dict[str, Any]:
        """Identify system components and trust boundaries."""
        prompt = IDENTIFY_COMPONENTS_PROMPT.format(
            target=target, target_type=target_type,
            known_info=json.dumps(known_info)[:2000],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=4096,
        )

        return self._parse_json(response)

    async def _enumerate_threats(
        self,
        target: str,
        model: ThreatModel,
    ) -> dict[str, Any]:
        """Enumerate STRIDE threats."""
        components_desc = json.dumps(model.components[:15])[:2000]
        boundaries_desc = json.dumps([b.to_dict() for b in model.trust_boundaries])[:1000]

        prompt = ENUMERATE_THREATS_PROMPT.format(
            target=target,
            components=components_desc,
            boundaries=boundaries_desc,
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="security",
            temperature=0.3,
            max_tokens=4096,
        )

        return self._parse_json(response)

    def _parse_threat(self, data: dict[str, Any]) -> Threat:
        """Parse a threat from JSON data."""
        try:
            category = STRIDECategory(data.get("category", "spoofing"))
        except ValueError:
            category = STRIDECategory.SPOOFING

        try:
            severity = ThreatSeverity(data.get("severity", "medium"))
        except ValueError:
            severity = ThreatSeverity.MEDIUM

        return Threat(
            title=data.get("title", ""),
            description=data.get("description", ""),
            category=category,
            severity=severity,
            affected_component=data.get("affected_component", ""),
            trust_boundary=data.get("trust_boundary", ""),
            attack_vector=data.get("attack_vector", ""),
            mitre_technique=data.get("mitre_technique", ""),
            likelihood=data.get("likelihood", 0.5),
            impact=data.get("impact", 0.5),
            prerequisites=data.get("prerequisites", []),
            mitigations=data.get("mitigations", []),
            test_cases=data.get("test_cases", []),
        )

    def get_model(self, model_id: str) -> ThreatModel | None:
        return self._models.get(model_id)

    def get_all_models(self) -> dict[str, dict[str, Any]]:
        return {mid: m.to_dict() for mid, m in self._models.items()}

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}
