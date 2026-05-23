"""Recursive agent spawner — dynamic agent creation and delegation.

Implements:
1. Recursive agent hierarchy with depth limits
2. Dynamic agent instantiation based on task type
3. Parent-child relationship tracking
4. Result aggregation from child agents
5. Budget inheritance and splitting
6. Context passing between levels
7. Agent pool reuse for efficiency
8. Bounded execution with convergence checks
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AgentRole(str, Enum):
    COORDINATOR = "coordinator"
    RECON = "recon"
    SCANNER = "scanner"
    ANALYZER = "analyzer"
    EXPLOITER = "exploiter"
    VALIDATOR = "validator"
    REPORTER = "reporter"
    PLANNER = "planner"
    RESEARCHER = "researcher"


class SpawnReason(str, Enum):
    TASK_DECOMPOSITION = "task_decomposition"
    PARALLEL_EXECUTION = "parallel_execution"
    SPECIALIST_NEEDED = "specialist_needed"
    VALIDATION_REQUIRED = "validation_required"
    DEPTH_EXPANSION = "depth_expansion"
    RETRY_WITH_DIFFERENT = "retry_with_different"


class AgentStatus(str, Enum):
    INITIALIZING = "initializing"
    RUNNING = "running"
    WAITING_CHILDREN = "waiting_children"
    AGGREGATING = "aggregating"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class SpawnedAgent:
    """A dynamically spawned agent."""
    agent_id: str = ""
    role: AgentRole = AgentRole.SCANNER
    task: str = ""
    parent_id: str = ""
    depth: int = 0
    status: AgentStatus = AgentStatus.INITIALIZING
    model_assigned: str = ""
    token_budget: int = 4096
    tokens_used: int = 0
    context: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)
    children: list[str] = field(default_factory=list)
    spawn_reason: SpawnReason = SpawnReason.TASK_DECOMPOSITION
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def elapsed_s(self) -> float:
        end = self.completed_at if self.completed_at else time.time()
        return end - self.created_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id,
            "role": self.role.value,
            "task": self.task[:30],
            "parent": self.parent_id[:10] if self.parent_id else None,
            "depth": self.depth,
            "status": self.status.value,
            "model": self.model_assigned[:15],
            "children": len(self.children),
            "tokens": self.tokens_used,
        }


@dataclass
class SpawnConfig:
    """Configuration for agent spawning."""
    max_depth: int = 5
    max_agents_per_level: int = 8
    max_total_agents: int = 50
    default_token_budget: int = 4096
    budget_decay_factor: float = 0.7    # Each level gets 70% of parent budget
    timeout_per_agent_s: int = 300
    reuse_pool: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_depth": self.max_depth,
            "max_per_level": self.max_agents_per_level,
            "max_total": self.max_total_agents,
            "budget_decay": self.budget_decay_factor,
        }


@dataclass
class AggregationResult:
    """Aggregated results from child agents."""
    parent_id: str = ""
    children_completed: int = 0
    children_failed: int = 0
    merged_findings: list[dict[str, Any]] = field(default_factory=list)
    total_tokens: int = 0
    total_time_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "parent": self.parent_id[:10],
            "completed": self.children_completed,
            "failed": self.children_failed,
            "findings": len(self.merged_findings),
            "tokens": self.total_tokens,
        }


# ── Role to Model Mapping ─────────────────────────────────────

ROLE_MODEL_PREFERENCES: dict[AgentRole, list[str]] = {
    AgentRole.COORDINATOR: ["hermes-4-14b", "llama-3.1-8b", "mistral-7b"],
    AgentRole.RECON: ["whiterabbitneo-7b", "mistral-7b", "llama-3.1-8b"],
    AgentRole.SCANNER: ["whiterabbitneo-7b", "qwen2.5-coder-7b"],
    AgentRole.ANALYZER: ["qwen2.5-coder-14b", "yi-9b-200k", "deepseek-r1-7b"],
    AgentRole.EXPLOITER: ["whiterabbitneo-7b", "dolphin-2.9", "qwen2.5-coder-14b"],
    AgentRole.VALIDATOR: ["deepseek-r1-7b", "hermes-4-14b"],
    AgentRole.REPORTER: ["mistral-7b", "llama-3.1-8b"],
    AgentRole.PLANNER: ["deepseek-r1-7b", "hermes-4-14b"],
    AgentRole.RESEARCHER: ["yi-9b-200k", "qwen2.5-coder-14b"],
}

# ── Task Type to Role Mapping ─────────────────────────────────

TASK_ROLE_MAP: dict[str, AgentRole] = {
    "reconnaissance": AgentRole.RECON,
    "port_scan": AgentRole.SCANNER,
    "web_scan": AgentRole.SCANNER,
    "code_analysis": AgentRole.ANALYZER,
    "vuln_analysis": AgentRole.ANALYZER,
    "exploitation": AgentRole.EXPLOITER,
    "validation": AgentRole.VALIDATOR,
    "report": AgentRole.REPORTER,
    "planning": AgentRole.PLANNER,
    "research": AgentRole.RESEARCHER,
}


class RecursiveSpawner:
    """Dynamic agent creation and delegation with recursive hierarchy.

    Manages a tree of agents that decompose tasks, spawn children,
    and aggregate results back up the hierarchy.
    """

    def __init__(self, config: SpawnConfig | None = None) -> None:
        self._config = config or SpawnConfig()
        self._agents: dict[str, SpawnedAgent] = {}
        self._pool: dict[AgentRole, list[str]] = defaultdict(list)
        self._agent_counter = 0
        self._level_counts: dict[int, int] = defaultdict(int)
        self._log = logger.bind(component="recursive_spawner")

    def spawn(
        self,
        role: AgentRole,
        task: str,
        parent_id: str = "",
        context: dict[str, Any] | None = None,
        reason: SpawnReason = SpawnReason.TASK_DECOMPOSITION,
    ) -> SpawnedAgent | None:
        """Spawn a new agent."""
        parent = self._agents.get(parent_id) if parent_id else None
        depth = (parent.depth + 1) if parent else 0

        # Check depth limit
        if depth > self._config.max_depth:
            self._log.warning("depth_limit_reached", depth=depth, task=task[:30])
            return None

        # Check per-level limit
        if self._level_counts[depth] >= self._config.max_agents_per_level:
            self._log.warning("level_limit_reached", depth=depth)
            return None

        # Check total limit
        active = sum(
            1 for a in self._agents.values()
            if a.status in (AgentStatus.INITIALIZING, AgentStatus.RUNNING, AgentStatus.WAITING_CHILDREN)
        )
        if active >= self._config.max_total_agents:
            self._log.warning("total_limit_reached", active=active)
            return None

        # Try pool reuse
        reused_id = None
        if self._config.reuse_pool and self._pool[role]:
            reused_id = self._pool[role].pop()
            existing = self._agents.get(reused_id)
            if existing and existing.status in (AgentStatus.COMPLETED, AgentStatus.FAILED):
                existing.task = task
                existing.parent_id = parent_id
                existing.depth = depth
                existing.status = AgentStatus.INITIALIZING
                existing.context = context or {}
                existing.result = {}
                existing.children = []
                existing.spawn_reason = reason
                existing.created_at = time.time()
                existing.completed_at = 0.0
                existing.tokens_used = 0

                if parent:
                    parent.children.append(existing.agent_id)

                self._level_counts[depth] += 1
                return existing

        # Create new agent
        self._agent_counter += 1
        agent_id = f"agent-{self._agent_counter}"

        # Calculate budget
        if parent:
            token_budget = int(parent.token_budget * self._config.budget_decay_factor)
        else:
            token_budget = self._config.default_token_budget

        # Select model
        model = self._select_model(role)

        agent = SpawnedAgent(
            agent_id=agent_id,
            role=role,
            task=task,
            parent_id=parent_id,
            depth=depth,
            model_assigned=model,
            token_budget=token_budget,
            context=context or {},
            spawn_reason=reason,
        )

        self._agents[agent_id] = agent
        self._level_counts[depth] += 1

        if parent:
            parent.children.append(agent_id)
            parent.status = AgentStatus.WAITING_CHILDREN

        return agent

    def spawn_for_task(
        self,
        task_type: str,
        task: str,
        parent_id: str = "",
        context: dict[str, Any] | None = None,
    ) -> SpawnedAgent | None:
        """Spawn an agent based on task type."""
        role = TASK_ROLE_MAP.get(task_type, AgentRole.SCANNER)
        return self.spawn(role, task, parent_id, context)

    def complete_agent(
        self,
        agent_id: str,
        result: dict[str, Any] | None = None,
        tokens_used: int = 0,
    ) -> None:
        """Mark an agent as completed."""
        agent = self._agents.get(agent_id)
        if not agent:
            return

        agent.status = AgentStatus.COMPLETED
        agent.completed_at = time.time()
        agent.result = result or {}
        agent.tokens_used = tokens_used

        # Return to pool
        if self._config.reuse_pool:
            self._pool[agent.role].append(agent_id)

        # Check if parent can aggregate
        if agent.parent_id:
            parent = self._agents.get(agent.parent_id)
            if parent and parent.status == AgentStatus.WAITING_CHILDREN:
                all_done = all(
                    self._agents[cid].status in (AgentStatus.COMPLETED, AgentStatus.FAILED)
                    for cid in parent.children
                    if cid in self._agents
                )
                if all_done:
                    parent.status = AgentStatus.AGGREGATING

    def fail_agent(
        self,
        agent_id: str,
        error: str = "",
    ) -> None:
        """Mark an agent as failed."""
        agent = self._agents.get(agent_id)
        if not agent:
            return

        agent.status = AgentStatus.FAILED
        agent.completed_at = time.time()
        agent.result = {"error": error}

        if self._config.reuse_pool:
            self._pool[agent.role].append(agent_id)

    def aggregate_children(self, parent_id: str) -> AggregationResult:
        """Aggregate results from all children of a parent."""
        parent = self._agents.get(parent_id)
        if not parent:
            return AggregationResult(parent_id=parent_id)

        result = AggregationResult(parent_id=parent_id)

        for child_id in parent.children:
            child = self._agents.get(child_id)
            if not child:
                continue

            if child.status == AgentStatus.COMPLETED:
                result.children_completed += 1
                # Merge findings
                findings = child.result.get("findings", [])
                if isinstance(findings, list):
                    result.merged_findings.extend(findings)
            else:
                result.children_failed += 1

            result.total_tokens += child.tokens_used
            result.total_time_s += child.elapsed_s

        parent.status = AgentStatus.COMPLETED
        parent.completed_at = time.time()
        parent.result = {
            "aggregated": True,
            "findings": result.merged_findings,
            "children_completed": result.children_completed,
            "children_failed": result.children_failed,
        }

        return result

    def get_agent(self, agent_id: str) -> SpawnedAgent | None:
        return self._agents.get(agent_id)

    def get_children(self, parent_id: str) -> list[SpawnedAgent]:
        parent = self._agents.get(parent_id)
        if not parent:
            return []
        return [
            self._agents[cid]
            for cid in parent.children
            if cid in self._agents
        ]

    def get_tree(self, root_id: str) -> dict[str, Any]:
        """Get the agent tree from a root."""
        agent = self._agents.get(root_id)
        if not agent:
            return {}

        tree = agent.to_dict()
        tree["children_data"] = []
        for child_id in agent.children:
            tree["children_data"].append(self.get_tree(child_id))
        return tree

    @staticmethod
    def _select_model(role: AgentRole) -> str:
        """Select the best model for a role."""
        preferences = ROLE_MODEL_PREFERENCES.get(role, ["mistral-7b"])
        return preferences[0] if preferences else "mistral-7b"

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        role_counts: dict[str, int] = defaultdict(int)
        for agent in self._agents.values():
            status_counts[agent.status.value] += 1
            role_counts[agent.role.value] += 1
        return {
            "total_agents": len(self._agents),
            "by_status": dict(status_counts),
            "by_role": dict(role_counts),
            "pool_sizes": {r.value: len(ids) for r, ids in self._pool.items() if ids},
            "depth_counts": dict(self._level_counts),
        }
