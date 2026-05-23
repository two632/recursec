"""Recursive agent spawner — creates and manages hierarchical agent trees.

Implements the core recursive agent architecture:
1. Parent agents decompose tasks and spawn children
2. Children can spawn grandchildren (bounded depth)
3. Results flow back up through the hierarchy
4. Failed children can be respawned or replaced
5. Resource budgets cascade with diminishing allocation
6. Context is inherited and narrowed at each level
7. Coordination between sibling agents
8. Dynamic depth adjustment based on complexity
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AgentState(str, Enum):
    PENDING = "pending"
    SPAWNING = "spawning"
    RUNNING = "running"
    WAITING = "waiting"
    AGGREGATING = "aggregating"
    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"


@dataclass
class SpawnedAgent:
    """A spawned agent in the hierarchy."""
    agent_id: str = ""
    role: str = ""
    parent_id: str = ""
    depth: int = 0
    state: AgentState = AgentState.PENDING

    # Task
    task: str = ""
    target: str = ""
    tools: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    # Budgets
    token_budget: int = 50000
    tokens_used: int = 0
    step_budget: int = 100
    steps_taken: int = 0
    time_budget_s: float = 300.0

    # Results
    findings: list[dict[str, Any]] = field(default_factory=list)
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    # Children
    children: list[str] = field(default_factory=list)
    max_children: int = 5

    # Timing
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def is_active(self) -> bool:
        return self.state in (AgentState.RUNNING, AgentState.WAITING, AgentState.AGGREGATING)

    @property
    def duration_s(self) -> float:
        end = self.completed_at or time.time()
        start = self.started_at or self.created_at
        return end - start

    @property
    def budget_used_pct(self) -> float:
        if self.token_budget == 0:
            return 0.0
        return self.tokens_used / self.token_budget

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id,
            "role": self.role,
            "parent": self.parent_id,
            "depth": self.depth,
            "state": self.state.value,
            "task": self.task[:80],
            "children": len(self.children),
            "findings": len(self.findings),
            "budget": f"{self.budget_used_pct:.0%}",
        }


@dataclass
class SpawnRequest:
    """Request to spawn a child agent."""
    role: str = ""
    task: str = ""
    target: str = ""
    tools: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    token_budget: int = 0      # 0 = auto-allocate from parent
    step_budget: int = 0
    time_budget_s: float = 0.0
    priority: int = 5


class RecursiveSpawner:
    """Creates and manages hierarchical agent trees.

    Spawns child agents with cascading budgets and context,
    tracks the full tree, and aggregates results.
    """

    def __init__(
        self,
        max_depth: int = 4,
        max_total_agents: int = 50,
        budget_cascade_factor: float = 0.6,
    ) -> None:
        self._max_depth = max_depth
        self._max_total = max_total_agents
        self._cascade_factor = budget_cascade_factor

        self._agents: dict[str, SpawnedAgent] = {}
        self._tree: dict[str, list[str]] = defaultdict(list)  # parent → [children]
        self._agent_counter = 0
        self._log = logger.bind(component="recursive_spawner")

    def create_root(
        self,
        role: str = "coordinator",
        task: str = "",
        target: str = "",
        token_budget: int = 100000,
        step_budget: int = 200,
        time_budget_s: float = 600.0,
    ) -> SpawnedAgent:
        """Create the root agent."""
        self._agent_counter += 1
        agent_id = f"agent-{self._agent_counter}"

        agent = SpawnedAgent(
            agent_id=agent_id,
            role=role,
            depth=0,
            task=task,
            target=target,
            token_budget=token_budget,
            step_budget=step_budget,
            time_budget_s=time_budget_s,
        )

        self._agents[agent_id] = agent
        return agent

    def spawn_child(
        self,
        parent_id: str,
        request: SpawnRequest,
    ) -> SpawnedAgent | None:
        """Spawn a child agent."""
        parent = self._agents.get(parent_id)
        if not parent:
            self._log.warning("parent_not_found", parent_id=parent_id)
            return None

        # Check depth
        child_depth = parent.depth + 1
        if child_depth > self._max_depth:
            self._log.warning("max_depth_reached", depth=child_depth)
            return None

        # Check total agents
        if len(self._agents) >= self._max_total:
            self._log.warning("max_agents_reached", total=len(self._agents))
            return None

        # Check parent children limit
        if len(parent.children) >= parent.max_children:
            self._log.warning("max_children_reached", parent=parent_id)
            return None

        # Allocate budgets
        if request.token_budget == 0:
            request.token_budget = int(
                (parent.token_budget - parent.tokens_used) * self._cascade_factor
                / max(1, parent.max_children - len(parent.children))
            )
        if request.step_budget == 0:
            request.step_budget = int(
                (parent.step_budget - parent.steps_taken) * self._cascade_factor
                / max(1, parent.max_children - len(parent.children))
            )
        if request.time_budget_s == 0:
            remaining = parent.time_budget_s - parent.duration_s
            request.time_budget_s = (
                remaining * self._cascade_factor
                / max(1, parent.max_children - len(parent.children))
            )

        # Create child
        self._agent_counter += 1
        agent_id = f"agent-{self._agent_counter}"

        # Inherit and narrow context
        child_context = dict(parent.context)
        child_context.update(request.context)
        child_context["parent_task"] = parent.task[:100]
        child_context["parent_role"] = parent.role

        child = SpawnedAgent(
            agent_id=agent_id,
            role=request.role,
            parent_id=parent_id,
            depth=child_depth,
            task=request.task,
            target=request.target or parent.target,
            tools=request.tools,
            context=child_context,
            token_budget=request.token_budget,
            step_budget=request.step_budget,
            time_budget_s=request.time_budget_s,
            max_children=max(1, parent.max_children - 1),
        )

        self._agents[agent_id] = child
        self._tree[parent_id].append(agent_id)
        parent.children.append(agent_id)

        self._log.info(
            "child_spawned",
            child=agent_id, parent=parent_id,
            role=request.role, depth=child_depth,
        )

        return child

    def start_agent(self, agent_id: str) -> bool:
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
        result: dict[str, Any] | None = None,
    ) -> None:
        """Mark agent as completed."""
        agent = self._agents.get(agent_id)
        if not agent:
            return
        agent.state = AgentState.COMPLETED
        agent.completed_at = time.time()
        agent.findings = findings or []
        agent.result = result or {}

        # Propagate findings up
        if agent.parent_id:
            parent = self._agents.get(agent.parent_id)
            if parent:
                parent.findings.extend(agent.findings)

    def fail_agent(self, agent_id: str, error: str = "") -> None:
        agent = self._agents.get(agent_id)
        if not agent:
            return
        agent.state = AgentState.FAILED
        agent.completed_at = time.time()
        agent.error = error

    def terminate_agent(self, agent_id: str) -> None:
        """Terminate an agent and its children."""
        agent = self._agents.get(agent_id)
        if not agent:
            return
        agent.state = AgentState.TERMINATED
        agent.completed_at = time.time()

        # Terminate children recursively
        for child_id in agent.children:
            self.terminate_agent(child_id)

    def respawn_failed(self, agent_id: str) -> SpawnedAgent | None:
        """Respawn a failed agent."""
        original = self._agents.get(agent_id)
        if not original or original.state != AgentState.FAILED:
            return None

        if not original.parent_id:
            return None

        request = SpawnRequest(
            role=original.role,
            task=original.task,
            target=original.target,
            tools=original.tools,
            context=original.context,
        )

        return self.spawn_child(original.parent_id, request)

    def get_agent(self, agent_id: str) -> SpawnedAgent | None:
        return self._agents.get(agent_id)

    def get_children(self, agent_id: str) -> list[SpawnedAgent]:
        child_ids = self._tree.get(agent_id, [])
        return [self._agents[cid] for cid in child_ids if cid in self._agents]

    def get_active_agents(self) -> list[SpawnedAgent]:
        return [a for a in self._agents.values() if a.is_active]

    def get_tree(self, root_id: str = "") -> dict[str, Any]:
        """Get the agent tree structure."""
        if not root_id:
            roots = [a for a in self._agents.values() if not a.parent_id]
            if not roots:
                return {}
            root_id = roots[0].agent_id

        return self._build_tree(root_id)

    def _build_tree(self, agent_id: str) -> dict[str, Any]:
        agent = self._agents.get(agent_id)
        if not agent:
            return {}
        return {
            "agent": agent.to_dict(),
            "children": [
                self._build_tree(cid) for cid in agent.children
            ],
        }

    def aggregate_findings(self, root_id: str = "") -> list[dict[str, Any]]:
        """Aggregate findings from all agents."""
        findings = []
        for agent in self._agents.values():
            if root_id and not self._is_descendant(agent.agent_id, root_id):
                continue
            findings.extend(agent.findings)
        return findings

    def _is_descendant(self, agent_id: str, ancestor_id: str) -> bool:
        if agent_id == ancestor_id:
            return True
        agent = self._agents.get(agent_id)
        if not agent or not agent.parent_id:
            return False
        return self._is_descendant(agent.parent_id, ancestor_id)

    def get_stats(self) -> dict[str, Any]:
        by_state: dict[str, int] = defaultdict(int)
        by_role: dict[str, int] = defaultdict(int)
        max_depth = 0
        for a in self._agents.values():
            by_state[a.state.value] += 1
            by_role[a.role] += 1
            max_depth = max(max_depth, a.depth)
        return {
            "total_agents": len(self._agents),
            "active": len(self.get_active_agents()),
            "max_depth": max_depth,
            "by_state": dict(by_state),
            "by_role": dict(by_role),
            "total_findings": sum(len(a.findings) for a in self._agents.values()),
        }
