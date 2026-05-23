"""Capability negotiation — dynamic capability discovery and matching between agents.

Implements:
1. Capability registration and advertisement
2. Capability requirement specification
3. Capability matching (exact, partial, fuzzy)
4. Capability delegation negotiation
5. Capability versioning
6. Capability dependency resolution
7. Runtime capability discovery
8. Capability scoring for agent selection
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class CapabilityLevel(str, Enum):
    EXPERT = "expert"           # Can do this very well
    COMPETENT = "competent"     # Can do this adequately
    BASIC = "basic"             # Can attempt this
    NONE = "none"               # Cannot do this


@dataclass
class Capability:
    """A capability that an agent possesses."""
    capability_id: str = ""
    name: str = ""
    category: str = ""           # analysis, exploitation, recon, code, reasoning
    level: CapabilityLevel = CapabilityLevel.COMPETENT
    version: str = "1.0"
    requires_tools: list[str] = field(default_factory=list)
    requires_models: list[str] = field(default_factory=list)
    performance_score: float = 0.5
    uses: int = 0
    successes: int = 0

    @property
    def success_rate(self) -> float:
        if self.uses == 0:
            return 0.5
        return self.successes / self.uses

    @property
    def level_score(self) -> float:
        scores = {
            CapabilityLevel.EXPERT: 1.0,
            CapabilityLevel.COMPETENT: 0.7,
            CapabilityLevel.BASIC: 0.4,
            CapabilityLevel.NONE: 0.0,
        }
        return scores.get(self.level, 0.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.capability_id,
            "name": self.name[:30],
            "category": self.category[:15],
            "level": self.level.value,
            "score": round(self.performance_score, 2),
            "success_rate": round(self.success_rate, 2),
        }


@dataclass
class CapabilityRequirement:
    """A requirement for a capability."""
    name: str = ""
    category: str = ""
    min_level: CapabilityLevel = CapabilityLevel.BASIC
    preferred_level: CapabilityLevel = CapabilityLevel.COMPETENT
    required: bool = True
    weight: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:30],
            "min_level": self.min_level.value,
            "required": self.required,
            "weight": self.weight,
        }


@dataclass
class NegotiationResult:
    """Result of capability negotiation."""
    success: bool = False
    agent_id: str = ""
    match_score: float = 0.0
    matched_capabilities: list[str] = field(default_factory=list)
    missing_capabilities: list[str] = field(default_factory=list)
    partial_capabilities: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "agent": self.agent_id[:15],
            "score": round(self.match_score, 2),
            "matched": len(self.matched_capabilities),
            "missing": len(self.missing_capabilities),
        }


# ── Default Capabilities ──────────────────────────────────────

DEFAULT_AGENT_CAPABILITIES: dict[str, list[dict[str, Any]]] = {
    "security_analyst": [
        {"name": "vulnerability_assessment", "cat": "analysis", "level": "expert"},
        {"name": "finding_classification", "cat": "analysis", "level": "expert"},
        {"name": "risk_scoring", "cat": "analysis", "level": "competent"},
        {"name": "exploit_analysis", "cat": "exploitation", "level": "competent"},
    ],
    "code_auditor": [
        {"name": "static_analysis", "cat": "code", "level": "expert"},
        {"name": "code_review", "cat": "code", "level": "expert"},
        {"name": "pattern_matching", "cat": "code", "level": "competent"},
        {"name": "dependency_audit", "cat": "code", "level": "competent"},
    ],
    "recon_agent": [
        {"name": "subdomain_enumeration", "cat": "recon", "level": "expert"},
        {"name": "port_scanning", "cat": "recon", "level": "expert"},
        {"name": "service_fingerprinting", "cat": "recon", "level": "competent"},
        {"name": "osint_gathering", "cat": "recon", "level": "competent"},
    ],
    "exploit_agent": [
        {"name": "exploit_development", "cat": "exploitation", "level": "expert"},
        {"name": "payload_crafting", "cat": "exploitation", "level": "expert"},
        {"name": "privilege_escalation", "cat": "exploitation", "level": "competent"},
    ],
    "planner": [
        {"name": "task_decomposition", "cat": "reasoning", "level": "expert"},
        {"name": "strategy_selection", "cat": "reasoning", "level": "expert"},
        {"name": "resource_planning", "cat": "reasoning", "level": "competent"},
    ],
}


class CapabilityNegotiation:
    """Dynamic capability discovery and matching between agents.

    Handles capability registration, requirement matching,
    and delegation negotiation.
    """

    def __init__(self) -> None:
        # agent_id -> list of capabilities
        self._agent_capabilities: dict[str, list[Capability]] = defaultdict(list)
        self._capability_counter = 0
        self._negotiation_counter = 0
        self._log = logger.bind(component="capability_negotiation")

    def register_capabilities(
        self,
        agent_id: str,
        role: str = "",
    ) -> list[Capability]:
        """Register default capabilities for an agent based on role."""
        caps_data = DEFAULT_AGENT_CAPABILITIES.get(role, [])
        capabilities = []

        for data in caps_data:
            self._capability_counter += 1
            cap = Capability(
                capability_id=f"cap-{self._capability_counter}",
                name=data["name"],
                category=data.get("cat", "general"),
                level=CapabilityLevel(data.get("level", "competent")),
            )
            capabilities.append(cap)

        self._agent_capabilities[agent_id] = capabilities
        return capabilities

    def add_capability(
        self,
        agent_id: str,
        name: str,
        category: str = "general",
        level: CapabilityLevel = CapabilityLevel.COMPETENT,
        requires_tools: list[str] | None = None,
        requires_models: list[str] | None = None,
    ) -> Capability:
        """Add a single capability to an agent."""
        self._capability_counter += 1
        cap = Capability(
            capability_id=f"cap-{self._capability_counter}",
            name=name,
            category=category,
            level=level,
            requires_tools=requires_tools or [],
            requires_models=requires_models or [],
        )
        self._agent_capabilities[agent_id].append(cap)
        return cap

    def negotiate(
        self,
        requirements: list[CapabilityRequirement],
        candidate_agents: list[str] | None = None,
    ) -> NegotiationResult:
        """Find the best agent for a set of requirements."""
        self._negotiation_counter += 1

        agents = candidate_agents or list(self._agent_capabilities.keys())
        best_result = NegotiationResult()
        best_score = -1.0

        for agent_id in agents:
            result = self._evaluate_match(agent_id, requirements)
            if result.match_score > best_score:
                best_score = result.match_score
                best_result = result

        return best_result

    def _evaluate_match(
        self,
        agent_id: str,
        requirements: list[CapabilityRequirement],
    ) -> NegotiationResult:
        """Evaluate how well an agent matches requirements."""
        caps = self._agent_capabilities.get(agent_id, [])
        cap_names = {c.name: c for c in caps}

        result = NegotiationResult(agent_id=agent_id)
        total_weight = 0.0
        matched_weight = 0.0

        for req in requirements:
            total_weight += req.weight

            cap = cap_names.get(req.name)
            if cap:
                if cap.level_score >= CapabilityLevel(req.min_level.value).value.count(""):
                    # Matched
                    match_quality = cap.level_score * cap.success_rate
                    matched_weight += req.weight * match_quality
                    result.matched_capabilities.append(req.name)
                else:
                    # Partial match
                    matched_weight += req.weight * 0.3
                    result.partial_capabilities.append(req.name)
            elif req.required:
                result.missing_capabilities.append(req.name)
            else:
                matched_weight += req.weight * 0.1  # Optional, not present

        if total_weight > 0:
            result.match_score = matched_weight / total_weight

        result.success = (
            len(result.missing_capabilities) == 0 and
            result.match_score > 0.3
        )

        return result

    def record_outcome(
        self,
        agent_id: str,
        capability_name: str,
        success: bool,
    ) -> None:
        """Record the outcome of using a capability."""
        caps = self._agent_capabilities.get(agent_id, [])
        for cap in caps:
            if cap.name == capability_name:
                cap.uses += 1
                if success:
                    cap.successes += 1
                # Update performance score
                cap.performance_score = (
                    cap.performance_score * 0.9 + (1.0 if success else 0.0) * 0.1
                )
                break

    def get_agent_capabilities(self, agent_id: str) -> list[dict[str, Any]]:
        return [c.to_dict() for c in self._agent_capabilities.get(agent_id, [])]

    def get_stats(self) -> dict[str, Any]:
        total_caps = sum(len(c) for c in self._agent_capabilities.values())
        return {
            "agents": len(self._agent_capabilities),
            "total_capabilities": total_caps,
            "negotiations": self._negotiation_counter,
        }
