"""Threat modeler — STRIDE/DREAD/PASTA threat modeling engine.

Generates threat models for targets using:
1. STRIDE classification (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation)
2. DREAD scoring (Damage, Reproducibility, Exploitability, Affected Users, Discoverability)
3. PASTA process (Process for Attack Simulation and Threat Analysis)
4. Attack tree generation
5. Mitigation recommendation per threat
6. Integration with attack surface mapper
7. LLM-assisted threat identification

This feeds the agent's planning engine so it knows
which threats to prioritize during testing.
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


class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class DREADScore:
    """DREAD risk scoring (each 1-10)."""
    damage: int = 5
    reproducibility: int = 5
    exploitability: int = 5
    affected_users: int = 5
    discoverability: int = 5

    @property
    def total(self) -> float:
        return (self.damage + self.reproducibility + self.exploitability + self.affected_users + self.discoverability) / 5.0

    @property
    def level(self) -> ThreatLevel:
        t = self.total
        if t >= 8:
            return ThreatLevel.CRITICAL
        if t >= 6:
            return ThreatLevel.HIGH
        if t >= 4:
            return ThreatLevel.MEDIUM
        if t >= 2:
            return ThreatLevel.LOW
        return ThreatLevel.NONE

    def to_dict(self) -> dict[str, Any]:
        return {
            "D": self.damage, "R": self.reproducibility,
            "E": self.exploitability, "A": self.affected_users,
            "D2": self.discoverability, "total": f"{self.total:.1f}",
            "level": self.level.value[:8],
        }


@dataclass
class Threat:
    """A single identified threat."""
    threat_id: str = ""
    title: str = ""
    description: str = ""
    stride: STRIDECategory = STRIDECategory.SPOOFING
    dread: DREADScore = field(default_factory=DREADScore)
    affected_component: str = ""
    attack_vector: str = ""
    prerequisites: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    test_cases: list[str] = field(default_factory=list)
    related_cwes: list[str] = field(default_factory=list)
    related_kbs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.threat_id[:8],
            "title": self.title[:30],
            "stride": self.stride.value[:6],
            "dread": self.dread.total,
            "level": self.dread.level.value[:8],
            "mitigations": len(self.mitigations),
            "tests": len(self.test_cases),
        }


@dataclass
class AttackTreeNode:
    """Node in an attack tree."""
    node_id: str = ""
    description: str = ""
    is_or: bool = False
    children: list[AttackTreeNode] = field(default_factory=list)
    cost: float = 0.0
    probability: float = 0.5
    tools_needed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "desc": self.description[:30],
            "type": "OR" if self.is_or else "AND",
            "children": len(self.children),
            "prob": f"{self.probability:.0%}",
        }


@dataclass
class ThreatModel:
    """Complete threat model for a target."""
    target: str = ""
    threats: list[Threat] = field(default_factory=list)
    attack_trees: list[AttackTreeNode] = field(default_factory=list)
    stride_summary: dict[str, int] = field(default_factory=dict)
    overall_risk: ThreatLevel = ThreatLevel.MEDIUM
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:20],
            "threats": len(self.threats),
            "risk": self.overall_risk.value[:8],
            "stride": self.stride_summary,
        }


# Common threat templates per component type
THREAT_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "web_application": [
        {"title": "SQL Injection", "stride": STRIDECategory.TAMPERING, "dread": DREADScore(8, 8, 7, 9, 8), "cwes": ["CWE-89"], "kbs": ["web_vuln"], "tests": ["Send ' OR 1=1 --", "Test parameterized endpoints", "UNION-based injection"]},
        {"title": "Cross-Site Scripting", "stride": STRIDECategory.INFORMATION_DISCLOSURE, "dread": DREADScore(6, 8, 7, 7, 8), "cwes": ["CWE-79"], "kbs": ["xss"], "tests": ["Inject <script>alert(1)</script>", "Test DOM-based XSS", "Stored XSS via form fields"]},
        {"title": "Broken Authentication", "stride": STRIDECategory.SPOOFING, "dread": DREADScore(9, 7, 6, 9, 6), "cwes": ["CWE-287"], "kbs": ["identity_sso"], "tests": ["Session fixation", "Credential stuffing", "JWT manipulation"]},
        {"title": "Insecure Direct Object Reference", "stride": STRIDECategory.INFORMATION_DISCLOSURE, "dread": DREADScore(7, 9, 8, 8, 7), "cwes": ["CWE-639"], "kbs": ["business_logic"], "tests": ["Increment object IDs", "Test access to other users' data", "Horizontal privilege escalation"]},
        {"title": "SSRF", "stride": STRIDECategory.INFORMATION_DISCLOSURE, "dread": DREADScore(8, 7, 6, 7, 5), "cwes": ["CWE-918"], "kbs": ["ssrf"], "tests": ["Request internal IPs", "Cloud metadata endpoint", "DNS rebinding"]},
        {"title": "CSRF", "stride": STRIDECategory.TAMPERING, "dread": DREADScore(6, 7, 5, 7, 7), "cwes": ["CWE-352"], "kbs": ["web_vuln"], "tests": ["Submit forms cross-origin", "Check CSRF token validation", "Test SameSite cookie"]},
    ],
    "api": [
        {"title": "Broken Object Level Authorization", "stride": STRIDECategory.ELEVATION_OF_PRIVILEGE, "dread": DREADScore(8, 9, 7, 8, 7), "cwes": ["CWE-284"], "kbs": ["api_gateway"], "tests": ["Access other users' objects", "Enumerate IDs"]},
        {"title": "Mass Assignment", "stride": STRIDECategory.TAMPERING, "dread": DREADScore(7, 8, 6, 6, 5), "cwes": ["CWE-915"], "kbs": ["api_gateway"], "tests": ["Add admin:true to request", "Modify read-only fields"]},
        {"title": "Rate Limiting Bypass", "stride": STRIDECategory.DENIAL_OF_SERVICE, "dread": DREADScore(5, 9, 8, 7, 8), "cwes": ["CWE-770"], "kbs": ["api_gateway"], "tests": ["Flood endpoint", "Rotate IPs", "Distributed requests"]},
    ],
    "network": [
        {"title": "Man-in-the-Middle", "stride": STRIDECategory.INFORMATION_DISCLOSURE, "dread": DREADScore(8, 5, 5, 8, 4), "cwes": ["CWE-300"], "kbs": ["network"], "tests": ["ARP spoofing", "DNS spoofing", "SSL stripping"]},
        {"title": "Unencrypted Services", "stride": STRIDECategory.INFORMATION_DISCLOSURE, "dread": DREADScore(7, 9, 9, 8, 9), "cwes": ["CWE-319"], "kbs": ["network", "crypto"], "tests": ["Capture plaintext traffic", "Check for TLS on all ports"]},
        {"title": "Default Credentials", "stride": STRIDECategory.SPOOFING, "dread": DREADScore(9, 9, 9, 8, 8), "cwes": ["CWE-798"], "kbs": ["network"], "tests": ["Try admin/admin", "Check vendor defaults", "Brute-force common creds"]},
    ],
    "cloud": [
        {"title": "Misconfigured S3 Buckets", "stride": STRIDECategory.INFORMATION_DISCLOSURE, "dread": DREADScore(8, 9, 9, 9, 8), "cwes": ["CWE-732"], "kbs": ["cloud"], "tests": ["Check ACLs", "List bucket contents", "Upload test file"]},
        {"title": "IAM Privilege Escalation", "stride": STRIDECategory.ELEVATION_OF_PRIVILEGE, "dread": DREADScore(9, 6, 5, 9, 4), "cwes": ["CWE-250"], "kbs": ["cloud"], "tests": ["Enumerate IAM policies", "Check for iam:PassRole", "Test AssumeRole chains"]},
        {"title": "Metadata Service Exploitation", "stride": STRIDECategory.INFORMATION_DISCLOSURE, "dread": DREADScore(9, 8, 7, 8, 6), "cwes": ["CWE-918"], "kbs": ["cloud", "ssrf"], "tests": ["Request 169.254.169.254", "Check for IMDSv2 enforcement"]},
    ],
}


class ThreatModeler:
    """Generates threat models for targets."""

    def __init__(self) -> None:
        self._models: dict[str, ThreatModel] = {}
        self._threat_counter = 0
        self._log = logger.bind(component="threat_modeler")

    def generate_model(
        self,
        target: str,
        component_types: list[str] | None = None,
    ) -> ThreatModel:
        """Generate a complete threat model."""
        if not component_types:
            component_types = ["web_application", "api", "network"]

        model = ThreatModel(target=target)
        stride_counts: dict[str, int] = {}

        for comp_type in component_types:
            templates = THREAT_TEMPLATES.get(comp_type, [])
            for tmpl in templates:
                self._threat_counter += 1
                threat = Threat(
                    threat_id=f"T-{self._threat_counter}",
                    title=tmpl["title"],
                    description=f"{tmpl['title']} vulnerability in {comp_type} component of {target}",
                    stride=tmpl["stride"],
                    dread=tmpl["dread"],
                    affected_component=comp_type,
                    related_cwes=tmpl.get("cwes", []),
                    related_kbs=tmpl.get("kbs", []),
                    test_cases=tmpl.get("tests", []),
                    mitigations=[f"Implement protection against {tmpl['title']}"],
                )
                model.threats.append(threat)

                stride_key = threat.stride.value
                stride_counts[stride_key] = stride_counts.get(stride_key, 0) + 1

        model.stride_summary = stride_counts

        # Calculate overall risk
        if model.threats:
            max_dread = max(t.dread.total for t in model.threats)
            if max_dread >= 8:
                model.overall_risk = ThreatLevel.CRITICAL
            elif max_dread >= 6:
                model.overall_risk = ThreatLevel.HIGH
            elif max_dread >= 4:
                model.overall_risk = ThreatLevel.MEDIUM
            else:
                model.overall_risk = ThreatLevel.LOW

        self._models[target] = model
        return model

    def build_attack_tree(self, target: str, goal: str = "Gain unauthorized access") -> AttackTreeNode:
        """Build an attack tree for a target."""
        model = self._models.get(target)
        if not model:
            model = self.generate_model(target)

        root = AttackTreeNode(
            node_id="root",
            description=goal,
            is_or=True,
        )

        # Group threats by STRIDE category
        by_stride: dict[str, list[Threat]] = {}
        for threat in model.threats:
            key = threat.stride.value
            if key not in by_stride:
                by_stride[key] = []
            by_stride[key].append(threat)

        for stride_cat, threats in by_stride.items():
            category_node = AttackTreeNode(
                node_id=f"stride-{stride_cat}",
                description=f"Via {stride_cat}",
                is_or=True,
            )
            for threat in threats:
                leaf = AttackTreeNode(
                    node_id=threat.threat_id,
                    description=threat.title,
                    probability=threat.dread.total / 10.0,
                    tools_needed=[],
                )
                category_node.children.append(leaf)
            root.children.append(category_node)

        return root

    def build_threat_model_prompt(self, target: str) -> str:
        """Build LLM prompt with threat model context."""
        model = self._models.get(target)
        if not model:
            return ""

        lines = [f"## Threat Model: {target}"]
        lines.append(f"Overall risk: {model.overall_risk.value}")
        lines.append(f"Total threats: {len(model.threats)}")
        lines.append(f"STRIDE breakdown: {model.stride_summary}")

        lines.append("\nTop threats by DREAD score:")
        sorted_threats = sorted(model.threats, key=lambda t: t.dread.total, reverse=True)
        for threat in sorted_threats[:8]:
            lines.append(f"  [{threat.dread.level.value}] {threat.title} (DREAD: {threat.dread.total:.1f})")
            lines.append(f"    STRIDE: {threat.stride.value}, CWEs: {', '.join(threat.related_cwes)}")
            if threat.test_cases:
                lines.append(f"    Tests: {', '.join(threat.test_cases[:2])}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_threats = sum(len(m.threats) for m in self._models.values())
        return {
            "models": len(self._models),
            "total_threats": total_threats,
        }
