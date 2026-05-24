"""Agent spawner — dynamic agent creation with bounded recursion.

Implements:
1. Dynamic agent instantiation from role specs
2. Bounded recursion depth (configurable max_depth)
3. Agent lifecycle management (create/run/retire)
4. Agent pool with reuse
5. Resource budgeting per agent
6. Parent-child relationship tracking
7. Spawner prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AgentState(str, Enum):
    INITIALIZING = "initializing"
    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"      # Waiting for child
    COMPLETED = "completed"
    FAILED = "failed"
    RETIRED = "retired"


class AgentRole(str, Enum):
    COORDINATOR = "coordinator"
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    WEB_AUDIT = "web_audit"
    EXPLOIT = "exploit"
    CODE_AUDIT = "code_audit"
    NETWORK = "network"
    CLOUD = "cloud"
    MOBILE = "mobile"
    WIRELESS = "wireless"
    OSINT = "osint"
    FORENSICS = "forensics"
    VALIDATOR = "validator"
    REPORTER = "reporter"
    CUSTOM = "custom"


@dataclass
class AgentSpec:
    """Specification for creating an agent."""
    role: AgentRole = AgentRole.CUSTOM
    name: str = ""
    model_preference: str = ""     # Preferred model type
    tools: list[str] = field(default_factory=list)
    knowledge_domains: list[str] = field(default_factory=list)
    token_budget: int = 5000
    time_limit_s: float = 300.0
    max_children: int = 3
    custom_system_prompt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role.value[:10],
            "name": self.name[:15],
            "model": self.model_preference[:12],
            "budget": self.token_budget,
        }


@dataclass
class SpawnedAgent:
    """A spawned agent instance."""
    agent_id: str = ""
    parent_id: str = ""
    spec: AgentSpec = field(default_factory=AgentSpec)
    state: AgentState = AgentState.INITIALIZING
    depth: int = 0
    children: list[str] = field(default_factory=list)
    tokens_used: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def duration_s(self) -> float:
        if self.started_at == 0:
            return 0.0
        end = self.completed_at or time.time()
        return end - self.started_at

    @property
    def is_active(self) -> bool:
        return self.state in (AgentState.RUNNING, AgentState.WAITING, AgentState.IDLE)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:10],
            "role": self.spec.role.value[:8],
            "state": self.state.value[:6],
            "depth": self.depth,
            "children": len(self.children),
            "tokens": self.tokens_used,
            "findings": len(self.findings),
        }


# ── Role → Model mapping ────────────────────────────────────

ROLE_MODEL_MAP: dict[AgentRole, str] = {
    AgentRole.COORDINATOR: "DeepSeek-R1",
    AgentRole.RECON: "Mistral-7B",
    AgentRole.VULN_SCAN: "WhiteRabbitNeo",
    AgentRole.WEB_AUDIT: "WhiteRabbitNeo",
    AgentRole.EXPLOIT: "WhiteRabbitNeo",
    AgentRole.CODE_AUDIT: "Qwen2.5-Coder-14B",
    AgentRole.NETWORK: "Mistral-7B",
    AgentRole.CLOUD: "Hermes-4",
    AgentRole.MOBILE: "Qwen2.5-Coder-7B",
    AgentRole.WIRELESS: "WhiteRabbitNeo",
    AgentRole.OSINT: "Llama-3.1-8B",
    AgentRole.FORENSICS: "Yi-9B-200K",
    AgentRole.VALIDATOR: "DeepSeek-R1",
    AgentRole.REPORTER: "Phi-3.5-mini",
}

# ── Role → Knowledge mapping ────────────────────────────────

ROLE_KNOWLEDGE_MAP: dict[AgentRole, list[str]] = {
    AgentRole.COORDINATOR: ["threat_intel", "red_team"],
    AgentRole.RECON: ["network", "threat_intel"],
    AgentRole.VULN_SCAN: ["web_security", "exploitation"],
    AgentRole.WEB_AUDIT: ["web_security", "api_security", "advanced_strategy"],
    AgentRole.EXPLOIT: ["exploitation", "privilege_escalation"],
    AgentRole.CODE_AUDIT: ["code_audit"],
    AgentRole.NETWORK: ["network"],
    AgentRole.CLOUD: ["cloud"],
    AgentRole.MOBILE: ["mobile"],
    AgentRole.WIRELESS: ["wireless"],
    AgentRole.OSINT: ["threat_intel"],
    AgentRole.FORENSICS: ["forensics"],
    AgentRole.VALIDATOR: ["web_security", "exploitation"],
    AgentRole.REPORTER: [],
}


class AgentSpawner:
    """Dynamic agent creation with bounded recursion.

    Creates specialized agents on-the-fly, manages
    their lifecycle, and enforces recursion depth limits.
    """

    def __init__(
        self,
        max_depth: int = 5,
        max_total_agents: int = 50,
        max_concurrent: int = 10,
    ) -> None:
        self._agents: dict[str, SpawnedAgent] = {}
        self._max_depth = max_depth
        self._max_total = max_total_agents
        self._max_concurrent = max_concurrent
        self._counter = 0
        self._retired: list[str] = []
        self._log = logger.bind(component="agent_spawner")

    def can_spawn(self, parent_id: str = "") -> tuple[bool, str]:
        """Check if spawning is allowed."""
        # Total limit
        active = sum(1 for a in self._agents.values() if a.is_active)
        if active >= self._max_concurrent:
            return False, "max_concurrent_reached"

        if len(self._agents) >= self._max_total:
            return False, "max_total_reached"

        # Depth limit
        if parent_id:
            parent = self._agents.get(parent_id)
            if parent and parent.depth >= self._max_depth:
                return False, "max_depth_reached"

            # Children limit
            if parent and len(parent.children) >= parent.spec.max_children:
                return False, "max_children_reached"

        return True, ""

    def spawn(
        self,
        spec: AgentSpec,
        parent_id: str = "",
    ) -> SpawnedAgent | None:
        """Spawn a new agent."""
        can, reason = self.can_spawn(parent_id)
        if not can:
            self._log.warning("spawn_denied", reason=reason)
            return None

        self._counter += 1
        depth = 0
        if parent_id:
            parent = self._agents.get(parent_id)
            if parent:
                depth = parent.depth + 1

        # Auto-fill model preference if not specified
        if not spec.model_preference:
            spec.model_preference = ROLE_MODEL_MAP.get(spec.role, "Mistral-7B")

        # Auto-fill knowledge if not specified
        if not spec.knowledge_domains:
            spec.knowledge_domains = ROLE_KNOWLEDGE_MAP.get(spec.role, [])

        agent = SpawnedAgent(
            agent_id=f"agent-{self._counter}",
            parent_id=parent_id,
            spec=spec,
            state=AgentState.IDLE,
            depth=depth,
        )

        self._agents[agent.agent_id] = agent

        # Register as child of parent
        if parent_id and parent_id in self._agents:
            self._agents[parent_id].children.append(agent.agent_id)
            self._agents[parent_id].state = AgentState.WAITING

        return agent

    def start_agent(self, agent_id: str) -> bool:
        """Mark agent as started."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        agent.state = AgentState.RUNNING
        agent.started_at = time.time()
        return True

    def complete_agent(
        self,
        agent_id: str,
        findings: list[dict[str, Any]] | None = None,
        tokens_used: int = 0,
    ) -> bool:
        """Mark agent as completed."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False

        agent.state = AgentState.COMPLETED
        agent.completed_at = time.time()
        agent.findings = findings or []
        agent.tokens_used = tokens_used

        # Wake up parent if all children done
        if agent.parent_id:
            self._check_parent_ready(agent.parent_id)

        return True

    def fail_agent(self, agent_id: str, error: str = "") -> bool:
        """Mark agent as failed."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False

        agent.state = AgentState.FAILED
        agent.completed_at = time.time()
        agent.error = error

        if agent.parent_id:
            self._check_parent_ready(agent.parent_id)

        return True

    def retire_agent(self, agent_id: str) -> None:
        """Retire a completed/failed agent."""
        agent = self._agents.get(agent_id)
        if not agent:
            return
        agent.state = AgentState.RETIRED
        self._retired.append(agent_id)

    def _check_parent_ready(self, parent_id: str) -> None:
        """Check if parent should resume."""
        parent = self._agents.get(parent_id)
        if not parent:
            return

        children_done = all(
            self._agents[cid].state in (AgentState.COMPLETED, AgentState.FAILED, AgentState.RETIRED)
            for cid in parent.children
            if cid in self._agents
        )

        if children_done and parent.state == AgentState.WAITING:
            parent.state = AgentState.RUNNING

    def get_children_results(self, parent_id: str) -> list[dict[str, Any]]:
        """Get aggregated results from children."""
        parent = self._agents.get(parent_id)
        if not parent:
            return []

        results: list[dict[str, Any]] = []
        for child_id in parent.children:
            child = self._agents.get(child_id)
            if not child:
                continue
            results.append({
                "agent_id": child.agent_id,
                "role": child.spec.role.value,
                "state": child.state.value,
                "findings": child.findings,
                "tokens": child.tokens_used,
                "duration_s": round(child.duration_s, 1),
            })

        return results

    def get_agent_tree(self, root_id: str = "") -> list[dict[str, Any]]:
        """Get agent hierarchy as list."""
        if not root_id:
            roots = [a for a in self._agents.values() if not a.parent_id]
            if not roots:
                return []
            root_id = roots[0].agent_id

        tree: list[dict[str, Any]] = []

        def _walk(agent_id: str, depth: int) -> None:
            agent = self._agents.get(agent_id)
            if not agent:
                return
            tree.append({
                "depth": depth,
                "agent": agent.to_dict(),
            })
            for child_id in agent.children:
                _walk(child_id, depth + 1)

        _walk(root_id, 0)
        return tree

    def build_spawner_prompt(self) -> str:
        """Build spawner context for LLM."""
        lines = ["## Agent Hierarchy\n"]

        active = [a for a in self._agents.values() if a.is_active]
        completed = [a for a in self._agents.values() if a.state == AgentState.COMPLETED]

        lines.append(
            f"Agents: {len(self._agents)} total — "
            f"{len(active)} active, {len(completed)} completed"
        )
        lines.append(f"Max depth: {self._max_depth} | Max concurrent: {self._max_concurrent}")

        if active:
            lines.append("\nActive agents:")
            for a in active[:5]:
                lines.append(
                    f"  [{a.spec.role.value[:8]}] {a.agent_id[:10]} "
                    f"depth={a.depth} "
                    f"tokens={a.tokens_used}"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        state_counts: dict[str, int] = {}
        role_counts: dict[str, int] = {}
        for a in self._agents.values():
            s = a.state.value
            state_counts[s] = state_counts.get(s, 0) + 1
            r = a.spec.role.value
            role_counts[r] = role_counts.get(r, 0) + 1

        depths = [a.depth for a in self._agents.values()]

        return {
            "total_agents": len(self._agents),
            "retired": len(self._retired),
            "by_state": state_counts,
            "by_role": role_counts,
            "max_depth": max(depths) if depths else 0,
            "total_findings": sum(len(a.findings) for a in self._agents.values()),
        }
