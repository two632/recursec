"""Recursive agent spawner — core spawning with depth control.

Implements:
1. Agent spawning with depth limits
2. Budget inheritance (parent → child)
3. Context propagation down the tree
4. Result aggregation up the tree
5. Spawn policies (parallel/sequential/conditional)
6. Agent tree visualization prompt
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class SpawnPolicy(str, Enum):
    PARALLEL = "parallel"         # All children run simultaneously
    SEQUENTIAL = "sequential"     # One after another
    CONDITIONAL = "conditional"   # Next child depends on previous result
    ADAPTIVE = "adaptive"         # System decides based on results


class AgentRole(str, Enum):
    COORDINATOR = "coordinator"
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    WEB_AUDIT = "web_audit"
    EXPLOIT = "exploit"
    CODE_AUDIT = "code_audit"
    NETWORK = "network"
    CLOUD = "cloud"
    FORENSICS = "forensics"
    VALIDATOR = "validator"
    REPORTER = "reporter"
    OSINT = "osint"
    WIRELESS = "wireless"
    MOBILE = "mobile"
    IOT = "iot"


class SpawnStatus(str, Enum):
    SPAWNED = "spawned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


@dataclass
class AgentBudget:
    """Resource budget for an agent."""
    max_tokens: int = 50000
    tokens_used: int = 0
    max_steps: int = 50
    steps_used: int = 0
    max_tools: int = 20
    tools_used: int = 0
    timeout_s: float = 600.0
    started_at: float = field(default_factory=time.time)

    @property
    def tokens_remaining(self) -> int:
        return max(0, self.max_tokens - self.tokens_used)

    @property
    def steps_remaining(self) -> int:
        return max(0, self.max_steps - self.steps_used)

    @property
    def time_remaining(self) -> float:
        elapsed = time.time() - self.started_at
        return max(0.0, self.timeout_s - elapsed)

    @property
    def is_exhausted(self) -> bool:
        return (
            self.tokens_remaining <= 0
            or self.steps_remaining <= 0
            or self.time_remaining <= 0
        )

    def allocate_child(self, fraction: float = 0.3) -> "AgentBudget":
        """Create a child budget from remaining resources."""
        return AgentBudget(
            max_tokens=int(self.tokens_remaining * fraction),
            max_steps=int(self.steps_remaining * fraction),
            max_tools=self.max_tools,
            timeout_s=self.time_remaining * fraction,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tokens": f"{self.tokens_used}/{self.max_tokens}",
            "steps": f"{self.steps_used}/{self.max_steps}",
            "time_left": f"{self.time_remaining:.0f}s",
        }


@dataclass
class SpawnedAgent:
    """A spawned agent instance."""
    agent_id: str = ""
    parent_id: str = ""
    role: AgentRole = AgentRole.COORDINATOR
    task: str = ""
    depth: int = 0
    status: SpawnStatus = SpawnStatus.SPAWNED
    budget: AgentBudget = field(default_factory=AgentBudget)
    children: list[str] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)
    findings_count: int = 0
    model_id: str = ""
    context: str = ""
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def duration_s(self) -> float:
        end = self.completed_at if self.completed_at > 0 else time.time()
        return end - self.created_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:10],
            "role": self.role.value[:8],
            "depth": self.depth,
            "status": self.status.value[:6],
            "children": len(self.children),
            "findings": self.findings_count,
        }


class RecursiveSpawner:
    """Core recursive agent spawning engine.

    Manages the agent tree with depth control,
    budget inheritance, context propagation,
    and result aggregation.
    """

    def __init__(
        self,
        max_depth: int = 5,
        max_agents: int = 50,
        default_budget: AgentBudget | None = None,
    ) -> None:
        self._agents: dict[str, SpawnedAgent] = {}
        self._agent_counter = 0
        self._max_depth = max_depth
        self._max_agents = max_agents
        self._default_budget = default_budget or AgentBudget()
        self._log = logger.bind(component="spawner")

    def spawn(
        self,
        role: AgentRole,
        task: str,
        parent_id: str = "",
        budget: AgentBudget | None = None,
        model_id: str = "",
        context: str = "",
    ) -> SpawnedAgent | None:
        """Spawn a new agent."""
        # Check limits
        if len(self._agents) >= self._max_agents:
            self._log.warning("max_agents_reached")
            return None

        # Calculate depth
        depth = 0
        if parent_id and parent_id in self._agents:
            depth = self._agents[parent_id].depth + 1

        if depth > self._max_depth:
            self._log.warning("max_depth_reached", depth=depth)
            return None

        # Create budget
        if budget is None:
            if parent_id and parent_id in self._agents:
                parent = self._agents[parent_id]
                budget = parent.budget.allocate_child()
            else:
                budget = AgentBudget(
                    max_tokens=self._default_budget.max_tokens,
                    max_steps=self._default_budget.max_steps,
                    max_tools=self._default_budget.max_tools,
                    timeout_s=self._default_budget.timeout_s,
                )

        self._agent_counter += 1
        agent = SpawnedAgent(
            agent_id=f"agent-{self._agent_counter}",
            parent_id=parent_id,
            role=role,
            task=task,
            depth=depth,
            budget=budget,
            model_id=model_id,
            context=context,
        )

        self._agents[agent.agent_id] = agent

        # Register as child of parent
        if parent_id and parent_id in self._agents:
            self._agents[parent_id].children.append(agent.agent_id)

        return agent

    def spawn_team(
        self,
        parent_id: str,
        roles: list[tuple[AgentRole, str]],
        policy: SpawnPolicy = SpawnPolicy.PARALLEL,
    ) -> list[SpawnedAgent]:
        """Spawn a team of agents."""
        agents = []
        for role, task in roles:
            agent = self.spawn(role=role, task=task, parent_id=parent_id)
            if agent:
                agents.append(agent)
        return agents

    def complete_agent(
        self,
        agent_id: str,
        results: list[dict[str, Any]] | None = None,
        findings_count: int = 0,
        status: SpawnStatus = SpawnStatus.COMPLETED,
    ) -> bool:
        """Mark an agent as completed."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False

        agent.status = status
        agent.completed_at = time.time()
        agent.findings_count = findings_count
        if results:
            agent.results = results

        return True

    def aggregate_results(self, agent_id: str) -> list[dict[str, Any]]:
        """Aggregate results from agent and all children."""
        agent = self._agents.get(agent_id)
        if not agent:
            return []

        all_results = list(agent.results)

        for child_id in agent.children:
            child_results = self.aggregate_results(child_id)
            all_results.extend(child_results)

        return all_results

    def get_tree(self, root_id: str = "") -> dict[str, Any]:
        """Get agent tree structure."""
        if not root_id:
            roots = [a for a in self._agents.values() if not a.parent_id]
            if not roots:
                return {}
            root_id = roots[0].agent_id

        agent = self._agents.get(root_id)
        if not agent:
            return {}

        tree: dict[str, Any] = {
            "id": agent.agent_id,
            "role": agent.role.value,
            "status": agent.status.value,
            "depth": agent.depth,
            "findings": agent.findings_count,
            "children": [],
        }

        for child_id in agent.children:
            child_tree = self.get_tree(child_id)
            if child_tree:
                tree["children"].append(child_tree)

        return tree

    def get_active_agents(self) -> list[SpawnedAgent]:
        """Get all running agents."""
        return [
            a for a in self._agents.values()
            if a.status in (SpawnStatus.SPAWNED, SpawnStatus.RUNNING)
        ]

    def get_agents_at_depth(self, depth: int) -> list[SpawnedAgent]:
        """Get agents at a specific depth."""
        return [a for a in self._agents.values() if a.depth == depth]

    def build_spawner_prompt(self, agent_id: str = "") -> str:
        """Build agent tree context for LLM."""
        lines = ["## Agent Tree\n"]

        lines.append(f"Total agents: {len(self._agents)}")
        lines.append(f"Max depth: {self._max_depth}")

        active = self.get_active_agents()
        lines.append(f"Active: {len(active)}")

        if agent_id and agent_id in self._agents:
            agent = self._agents[agent_id]
            lines.append(f"\nCurrent: {agent.role.value} (depth={agent.depth})")
            lines.append(f"Budget: {agent.budget.to_dict()}")
            lines.append(f"Children: {len(agent.children)}")

        # Tree visualization
        roots = [a for a in self._agents.values() if not a.parent_id]
        for root in roots[:2]:
            lines.append(f"\n{self._format_tree(root.agent_id, 0)}")

        return "\n".join(lines)

    def _format_tree(self, agent_id: str, indent: int) -> str:
        """Format agent tree for display."""
        agent = self._agents.get(agent_id)
        if not agent:
            return ""

        prefix = "  " * indent
        status_icon = {
            SpawnStatus.COMPLETED: "[done]",
            SpawnStatus.RUNNING: "[>>>]",
            SpawnStatus.SPAWNED: "[   ]",
            SpawnStatus.FAILED: "[ERR]",
        }.get(agent.status, "[?]")

        line = f"{prefix}{status_icon} {agent.role.value} (f={agent.findings_count})"
        lines = [line]

        for child_id in agent.children:
            lines.append(self._format_tree(child_id, indent + 1))

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for a in self._agents.values():
            s = a.status.value
            status_counts[s] = status_counts.get(s, 0) + 1

        depth_counts: dict[int, int] = {}
        for a in self._agents.values():
            depth_counts[a.depth] = depth_counts.get(a.depth, 0) + 1

        return {
            "total": len(self._agents),
            "by_status": status_counts,
            "by_depth": depth_counts,
            "total_findings": sum(a.findings_count for a in self._agents.values()),
        }
