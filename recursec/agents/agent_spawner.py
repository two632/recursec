"""Agent spawner — creates and manages specialist sub-agents.

Implements recursive agent creation:
1. Spawn specialist agents for specific tasks
2. Agent pool management (reuse idle agents)
3. Depth-bounded recursion (max_depth limit)
4. Token budget distribution among children
5. Result aggregation from child agents
6. Agent lifecycle management
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AgentRole(str, Enum):
    COORDINATOR = "coordinator"
    RECON = "recon"
    SCANNER = "scanner"
    WEB = "web"
    NETWORK = "network"
    EXPLOITER = "exploiter"
    CODE_AUDITOR = "code_auditor"
    ANALYST = "analyst"
    VALIDATOR = "validator"
    OSINT = "osint"
    CLOUD = "cloud"
    FORENSICS = "forensics"
    REPORTER = "reporter"
    PLANNER = "planner"


class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"


@dataclass
class SpawnedAgent:
    """A spawned specialist agent."""
    agent_id: str = ""
    role: AgentRole = AgentRole.COORDINATOR
    parent_id: str = ""
    depth: int = 0
    status: AgentStatus = AgentStatus.IDLE
    task_description: str = ""
    target: str = ""
    model_id: str = ""
    kbs: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    token_budget: int = 4096
    tokens_used: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    child_ids: list[str] = field(default_factory=list)
    started_at: float = 0.0
    completed_at: float = 0.0
    error: str = ""

    @property
    def elapsed_s(self) -> float:
        end = self.completed_at if self.completed_at else time.time()
        return end - self.started_at if self.started_at else 0.0

    @property
    def remaining_budget(self) -> int:
        return max(0, self.token_budget - self.tokens_used)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:8],
            "role": self.role.value[:10],
            "depth": self.depth,
            "status": self.status.value[:8],
            "findings": len(self.findings),
            "children": len(self.child_ids),
            "tokens": f"{self.tokens_used}/{self.token_budget}",
        }


# Role → model mapping (which model is best for each role)
ROLE_MODEL_MAP: dict[AgentRole, str] = {
    AgentRole.COORDINATOR: "deepseek-r1",
    AgentRole.RECON: "phi-3.5-mini",
    AgentRole.SCANNER: "phi-3.5-mini",
    AgentRole.WEB: "whiterabbit",
    AgentRole.NETWORK: "whiterabbit",
    AgentRole.EXPLOITER: "whiterabbit",
    AgentRole.CODE_AUDITOR: "qwen-coder-14b",
    AgentRole.ANALYST: "deepseek-r1",
    AgentRole.VALIDATOR: "deepseek-r1",
    AgentRole.OSINT: "mistral-7b",
    AgentRole.CLOUD: "hermes-4-14b",
    AgentRole.FORENSICS: "qwen-coder-14b",
    AgentRole.REPORTER: "hermes-4-14b",
    AgentRole.PLANNER: "deepseek-r1",
}

# Role → KB domains mapping
ROLE_KB_MAP: dict[AgentRole, list[str]] = {
    AgentRole.COORDINATOR: ["advanced_discovery", "threat_intel"],
    AgentRole.RECON: ["dns", "network"],
    AgentRole.SCANNER: ["network", "web_vuln"],
    AgentRole.WEB: ["web_vuln", "xss", "ssrf", "deserialization", "business_logic", "api_gateway"],
    AgentRole.NETWORK: ["network", "lateral_movement", "active_directory"],
    AgentRole.EXPLOITER: ["binary_exploitation", "privesc", "red_team"],
    AgentRole.CODE_AUDITOR: ["supply_chain", "devsecops", "advanced_discovery"],
    AgentRole.ANALYST: ["threat_intel", "advanced_discovery", "advanced_strategy"],
    AgentRole.VALIDATOR: ["advanced_discovery"],
    AgentRole.OSINT: ["dns"],
    AgentRole.CLOUD: ["cloud", "container_k8s", "serverless"],
    AgentRole.FORENSICS: ["forensics", "incident_response"],
    AgentRole.REPORTER: ["compliance", "threat_intel"],
    AgentRole.PLANNER: ["advanced_discovery", "threat_intel", "red_team"],
}

# Role → tools mapping
ROLE_TOOL_MAP: dict[AgentRole, list[str]] = {
    AgentRole.RECON: ["subfinder", "amass", "dig", "whois", "whatweb"],
    AgentRole.SCANNER: ["nmap", "masscan", "testssl"],
    AgentRole.WEB: ["nuclei", "nikto", "sqlmap", "ffuf", "gobuster"],
    AgentRole.NETWORK: ["crackmapexec", "impacket", "responder", "nmap"],
    AgentRole.EXPLOITER: ["metasploit", "sqlmap", "hydra"],
    AgentRole.CODE_AUDITOR: ["semgrep", "bandit", "gitleaks", "codeql"],
    AgentRole.OSINT: ["theHarvester", "sherlock", "subfinder"],
    AgentRole.CLOUD: ["prowler", "scoutsuite", "trivy"],
    AgentRole.FORENSICS: ["volatility", "autopsy", "binwalk"],
}


class AgentSpawner:
    """Manages spawning and lifecycle of specialist agents."""

    def __init__(self, max_depth: int = 5, max_agents: int = 20) -> None:
        self._agents: dict[str, SpawnedAgent] = {}
        self._agent_counter = 0
        self._max_depth = max_depth
        self._max_agents = max_agents
        self._log = logger.bind(component="agent_spawner")

    def spawn(
        self,
        role: AgentRole,
        task_description: str,
        target: str = "",
        parent_id: str = "",
        depth: int = 0,
        token_budget: int = 4096,
    ) -> SpawnedAgent | None:
        """Spawn a new specialist agent."""
        if depth >= self._max_depth:
            self._log.warning("max_depth_exceeded", depth=depth, max=self._max_depth)
            return None

        if len(self._agents) >= self._max_agents:
            # Try to reclaim completed agents
            self._cleanup_completed()
            if len(self._agents) >= self._max_agents:
                self._log.warning("max_agents_exceeded", count=len(self._agents))
                return None

        self._agent_counter += 1
        agent = SpawnedAgent(
            agent_id=f"agent-{self._agent_counter}",
            role=role,
            parent_id=parent_id,
            depth=depth,
            status=AgentStatus.IDLE,
            task_description=task_description,
            target=target,
            model_id=ROLE_MODEL_MAP.get(role, "mistral-7b"),
            kbs=ROLE_KB_MAP.get(role, []),
            tools=ROLE_TOOL_MAP.get(role, []),
            token_budget=token_budget,
            started_at=time.time(),
        )

        self._agents[agent.agent_id] = agent

        # Register as child of parent
        if parent_id and parent_id in self._agents:
            self._agents[parent_id].child_ids.append(agent.agent_id)

        return agent

    def get_agent(self, agent_id: str) -> SpawnedAgent | None:
        """Get an agent by ID."""
        return self._agents.get(agent_id)

    def update_status(self, agent_id: str, status: AgentStatus) -> None:
        """Update agent status."""
        agent = self._agents.get(agent_id)
        if agent:
            agent.status = status
            if status in (AgentStatus.COMPLETED, AgentStatus.FAILED, AgentStatus.TERMINATED):
                agent.completed_at = time.time()

    def add_finding(self, agent_id: str, finding: dict[str, Any]) -> None:
        """Add a finding to an agent."""
        agent = self._agents.get(agent_id)
        if agent:
            agent.findings.append(finding)

    def aggregate_findings(self, agent_id: str) -> list[dict[str, Any]]:
        """Aggregate findings from agent and all children recursively."""
        agent = self._agents.get(agent_id)
        if not agent:
            return []

        findings = list(agent.findings)
        for child_id in agent.child_ids:
            findings.extend(self.aggregate_findings(child_id))
        return findings

    def get_agent_tree(self, root_id: str) -> dict[str, Any]:
        """Get the agent hierarchy tree."""
        agent = self._agents.get(root_id)
        if not agent:
            return {}

        tree = agent.to_dict()
        tree["children"] = [
            self.get_agent_tree(child_id)
            for child_id in agent.child_ids
        ]
        return tree

    def distribute_budget(
        self,
        parent_id: str,
        child_count: int,
    ) -> int:
        """Calculate token budget for each child agent."""
        parent = self._agents.get(parent_id)
        if not parent:
            return 2048

        available = parent.remaining_budget
        # Reserve 20% for parent's own reasoning
        distributable = int(available * 0.8)
        return max(1024, distributable // max(1, child_count))

    def _cleanup_completed(self) -> None:
        """Remove completed agents to free slots."""
        to_remove = [
            aid for aid, agent in self._agents.items()
            if agent.status in (AgentStatus.COMPLETED, AgentStatus.FAILED, AgentStatus.TERMINATED)
            and agent.elapsed_s > 300  # Keep for 5 min for aggregation
        ]
        for aid in to_remove:
            del self._agents[aid]

    def get_active_agents(self) -> list[SpawnedAgent]:
        """Get all currently active agents."""
        return [
            a for a in self._agents.values()
            if a.status in (AgentStatus.IDLE, AgentStatus.RUNNING, AgentStatus.WAITING)
        ]

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        role_counts: dict[str, int] = {}
        for a in self._agents.values():
            status_counts[a.status.value] = status_counts.get(a.status.value, 0) + 1
            role_counts[a.role.value] = role_counts.get(a.role.value, 0) + 1
        return {
            "total_agents": len(self._agents),
            "active": len(self.get_active_agents()),
            "by_status": status_counts,
            "by_role": role_counts,
            "max_depth_seen": max((a.depth for a in self._agents.values()), default=0),
        }

    def build_spawner_prompt(self) -> str:
        """Build LLM prompt with agent hierarchy info."""
        stats = self.get_stats()
        lines = ["## Agent Hierarchy"]
        lines.append(f"Total: {stats['total_agents']} (active: {stats['active']})")
        lines.append(f"Max depth: {stats['max_depth_seen']}")
        if stats["by_role"]:
            lines.append("Roles: " + ", ".join(f"{r}={c}" for r, c in stats["by_role"].items()))
        return "\n".join(lines)
