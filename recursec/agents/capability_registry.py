"""Agent capability registry — tracks agent capabilities.

Implements:
1. Capability declaration per agent/model
2. Capability matching (task → best agent)
3. Dynamic capability discovery
4. Capability scoring and ranking
5. Capability gap analysis
6. Registry prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class CapabilityDomain(str, Enum):
    RECON = "recon"
    WEB_SECURITY = "web_security"
    NETWORK = "network"
    CODE_AUDIT = "code_audit"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    CLOUD = "cloud"
    MOBILE = "mobile"
    IOT = "iot"
    FORENSICS = "forensics"
    OSINT = "osint"
    WIRELESS = "wireless"
    CRYPTO = "crypto"
    REVERSING = "reversing"
    SOCIAL_ENG = "social_eng"
    REASONING = "reasoning"
    PLANNING = "planning"
    VALIDATION = "validation"
    REPORTING = "reporting"


@dataclass
class Capability:
    """A single capability declaration."""
    capability_id: str = ""
    domain: CapabilityDomain = CapabilityDomain.RECON
    name: str = ""
    description: str = ""
    proficiency: float = 0.5     # 0-1 (how good)
    experience: int = 0          # Number of times used
    last_used: float = 0.0
    success_rate: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain.value[:8],
            "name": self.name[:15],
            "prof": f"{self.proficiency:.2f}",
            "exp": self.experience,
        }


@dataclass
class AgentCapabilities:
    """Capabilities for a single agent/model."""
    agent_id: str = ""
    model_id: str = ""
    capabilities: list[Capability] = field(default_factory=list)
    specializations: list[str] = field(default_factory=list)
    max_context: int = 4096
    supports_tools: bool = True
    supports_code: bool = True

    def get_capability(self, domain: CapabilityDomain) -> Capability | None:
        for cap in self.capabilities:
            if cap.domain == domain:
                return cap
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id[:10],
            "model": self.model_id[:12],
            "caps": len(self.capabilities),
            "specializations": self.specializations[:3],
        }


# Pre-defined model capability profiles
MODEL_PROFILES: dict[str, dict[str, Any]] = {
    "WhiteRabbitNeo": {
        "specializations": ["security", "exploit", "pentest"],
        "capabilities": {
            CapabilityDomain.EXPLOITATION: 0.95,
            CapabilityDomain.WEB_SECURITY: 0.90,
            CapabilityDomain.NETWORK: 0.85,
            CapabilityDomain.POST_EXPLOIT: 0.90,
            CapabilityDomain.RECON: 0.80,
        },
    },
    "Qwen2.5-Coder-14B": {
        "specializations": ["code", "audit", "analysis"],
        "capabilities": {
            CapabilityDomain.CODE_AUDIT: 0.95,
            CapabilityDomain.WEB_SECURITY: 0.80,
            CapabilityDomain.REASONING: 0.85,
            CapabilityDomain.REVERSING: 0.75,
        },
    },
    "Qwen2.5-Coder-7B": {
        "specializations": ["code", "fast"],
        "capabilities": {
            CapabilityDomain.CODE_AUDIT: 0.80,
            CapabilityDomain.WEB_SECURITY: 0.70,
            CapabilityDomain.REASONING: 0.70,
        },
    },
    "DeepSeek-R1": {
        "specializations": ["reasoning", "planning", "chain-of-thought"],
        "capabilities": {
            CapabilityDomain.REASONING: 0.95,
            CapabilityDomain.PLANNING: 0.90,
            CapabilityDomain.VALIDATION: 0.85,
            CapabilityDomain.CODE_AUDIT: 0.80,
        },
    },
    "Yi-9B-200K": {
        "specializations": ["long_context", "analysis"],
        "capabilities": {
            CapabilityDomain.CODE_AUDIT: 0.85,
            CapabilityDomain.FORENSICS: 0.80,
            CapabilityDomain.REPORTING: 0.80,
            CapabilityDomain.REASONING: 0.75,
        },
    },
    "CodeLlama-13B": {
        "specializations": ["code", "exploit_dev"],
        "capabilities": {
            CapabilityDomain.CODE_AUDIT: 0.85,
            CapabilityDomain.EXPLOITATION: 0.70,
            CapabilityDomain.REVERSING: 0.75,
        },
    },
    "Hermes-4-14B": {
        "specializations": ["general", "instruction_following"],
        "capabilities": {
            CapabilityDomain.PLANNING: 0.80,
            CapabilityDomain.REASONING: 0.80,
            CapabilityDomain.REPORTING: 0.75,
            CapabilityDomain.OSINT: 0.70,
        },
    },
    "Dolphin-2.9": {
        "specializations": ["uncensored", "security"],
        "capabilities": {
            CapabilityDomain.EXPLOITATION: 0.80,
            CapabilityDomain.SOCIAL_ENG: 0.75,
            CapabilityDomain.WEB_SECURITY: 0.75,
            CapabilityDomain.RECON: 0.70,
        },
    },
    "Mistral-7B": {
        "specializations": ["fast", "general"],
        "capabilities": {
            CapabilityDomain.RECON: 0.70,
            CapabilityDomain.REPORTING: 0.70,
            CapabilityDomain.PLANNING: 0.65,
        },
    },
    "Phi-3.5-mini": {
        "specializations": ["fast", "lightweight"],
        "capabilities": {
            CapabilityDomain.RECON: 0.60,
            CapabilityDomain.PLANNING: 0.60,
            CapabilityDomain.REPORTING: 0.65,
        },
    },
    "DeepSeek-Math-7B": {
        "specializations": ["math", "crypto", "analysis"],
        "capabilities": {
            CapabilityDomain.CRYPTO: 0.90,
            CapabilityDomain.REASONING: 0.80,
            CapabilityDomain.VALIDATION: 0.75,
        },
    },
}


class CapabilityRegistry:
    """Registry of agent/model capabilities.

    Tracks capabilities, matches tasks to
    best agents, and identifies gaps.
    """

    def __init__(self) -> None:
        self._agents: dict[str, AgentCapabilities] = {}
        self._log = logger.bind(component="capability_reg")

    def register_agent(
        self,
        agent_id: str,
        model_id: str = "",
        capabilities: dict[CapabilityDomain, float] | None = None,
        specializations: list[str] | None = None,
        max_context: int = 4096,
    ) -> AgentCapabilities:
        """Register an agent with capabilities."""
        caps = []
        cap_map = capabilities or {}

        # Auto-load from model profile if available
        if not cap_map and model_id:
            for profile_key, profile in MODEL_PROFILES.items():
                if profile_key.lower() in model_id.lower():
                    cap_map = profile.get("capabilities", {})
                    specializations = specializations or profile.get("specializations", [])
                    break

        for domain, proficiency in cap_map.items():
            caps.append(Capability(
                capability_id=f"cap-{agent_id}-{domain.value}",
                domain=domain,
                name=f"{domain.value}",
                proficiency=proficiency,
            ))

        agent = AgentCapabilities(
            agent_id=agent_id,
            model_id=model_id,
            capabilities=caps,
            specializations=specializations or [],
            max_context=max_context,
        )
        self._agents[agent_id] = agent
        return agent

    def find_best_agent(self, domain: CapabilityDomain) -> str:
        """Find the best agent for a capability domain."""
        best_id = ""
        best_score = -1.0

        for agent_id, agent in self._agents.items():
            cap = agent.get_capability(domain)
            if cap and cap.proficiency > best_score:
                best_score = cap.proficiency
                best_id = agent_id

        return best_id

    def find_agents_for_task(
        self,
        domains: list[CapabilityDomain],
        min_proficiency: float = 0.5,
    ) -> list[str]:
        """Find agents that cover all required domains."""
        candidates = []

        for agent_id, agent in self._agents.items():
            covers_all = True
            total_prof = 0.0

            for domain in domains:
                cap = agent.get_capability(domain)
                if not cap or cap.proficiency < min_proficiency:
                    covers_all = False
                    break
                total_prof += cap.proficiency

            if covers_all:
                candidates.append((agent_id, total_prof))

        candidates.sort(key=lambda x: x[1], reverse=True)
        return [c[0] for c in candidates]

    def gap_analysis(self) -> dict[str, float]:
        """Find capability gaps (domains with low/no coverage)."""
        domain_max: dict[str, float] = {}

        for domain in CapabilityDomain:
            max_prof = 0.0
            for agent in self._agents.values():
                cap = agent.get_capability(domain)
                if cap:
                    max_prof = max(max_prof, cap.proficiency)
            domain_max[domain.value] = max_prof

        return {d: p for d, p in domain_max.items() if p < 0.5}

    def record_usage(
        self,
        agent_id: str,
        domain: CapabilityDomain,
        success: bool = True,
    ) -> None:
        """Record capability usage for learning."""
        agent = self._agents.get(agent_id)
        if not agent:
            return

        cap = agent.get_capability(domain)
        if not cap:
            return

        cap.experience += 1
        cap.last_used = time.time()

        # Update success rate
        total = cap.experience
        successes = cap.success_rate * (total - 1) + (1.0 if success else 0.0)
        cap.success_rate = successes / total

        # Adjust proficiency based on success rate
        if total >= 5:
            cap.proficiency = cap.proficiency * 0.9 + cap.success_rate * 0.1

    def build_registry_prompt(self) -> str:
        """Build capability context for LLM."""
        lines = ["## Agent Capabilities\n"]
        lines.append(f"Registered agents: {len(self._agents)}")

        for agent_id, agent in self._agents.items():
            top_caps = sorted(
                agent.capabilities,
                key=lambda c: c.proficiency,
                reverse=True,
            )[:3]
            cap_str = ", ".join(
                f"{c.domain.value[:8]}={c.proficiency:.0%}"
                for c in top_caps
            )
            lines.append(f"  {agent.model_id[:15]}: {cap_str}")

        gaps = self.gap_analysis()
        if gaps:
            lines.append(f"\nGaps ({len(gaps)}):")
            for domain, prof in gaps.items():
                lines.append(f"  {domain}: {prof:.0%}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "agents": len(self._agents),
            "total_capabilities": sum(
                len(a.capabilities) for a in self._agents.values()
            ),
            "gaps": self.gap_analysis(),
        }
