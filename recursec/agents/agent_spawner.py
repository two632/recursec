"""Agent spawner — recursive child agent creation with bounded depth.

Implements:
1. Child agent creation with role assignment
2. Depth-bounded recursion (max 5 levels)
3. Budget inheritance with decay (70%)
4. Agent lifecycle management
5. Parent-child relationship tracking
6. Agent pool for reuse
7. Spawn strategy based on task type
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class SpawnedAgentState(str, Enum):
    CREATED = "created"
    INITIALIZING = "initializing"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    RECYCLED = "recycled"


class SpawnedAgentRole(str, Enum):
    COORDINATOR = "coordinator"
    RECON = "recon"
    SCANNER = "scanner"
    EXPLOITER = "exploiter"
    CODE_AUDITOR = "code_auditor"
    VALIDATOR = "validator"
    ANALYST = "analyst"
    PLANNER = "planner"
    OSINT = "osint"
    FUZZER = "fuzzer"
    CLOUD = "cloud"
    WIRELESS = "wireless"
    FORENSICS = "forensics"


@dataclass
class SpawnedAgent:
    """A spawned child agent."""
    agent_id: str = ""
    role: SpawnedAgentRole = SpawnedAgentRole.SCANNER
    state: SpawnedAgentState = SpawnedAgentState.CREATED
    parent_id: str = ""
    depth: int = 0
    model_id: str = ""
    task_description: str = ""
    token_budget: int = 10000
    tokens_used: int = 0
    time_budget_s: float = 600.0
    findings_count: int = 0
    children: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    result: str = ""

    @property
    def duration_s(self) -> float:
        if self.completed_at:
            return self.completed_at - self.created_at
        return time.time() - self.created_at

    @property
    def budget_remaining(self) -> int:
        return max(0, self.token_budget - self.tokens_used)

    @property
    def is_active(self) -> bool:
        return self.state in (
            SpawnedAgentState.CREATED,
            SpawnedAgentState.INITIALIZING,
            SpawnedAgentState.RUNNING,
            SpawnedAgentState.WAITING,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:10],
            "role": self.role.value,
            "state": self.state.value,
            "depth": self.depth,
            "tokens": f"{self.tokens_used}/{self.token_budget}",
            "findings": self.findings_count,
            "children": len(self.children),
        }


# ── Spawn strategies ─────────────────────────────────────────

ROLE_FOR_TASK: dict[str, SpawnedAgentRole] = {
    "subdomain_enum": SpawnedAgentRole.RECON,
    "port_scan": SpawnedAgentRole.SCANNER,
    "web_vuln_scan": SpawnedAgentRole.SCANNER,
    "sqli_test": SpawnedAgentRole.EXPLOITER,
    "code_audit": SpawnedAgentRole.CODE_AUDITOR,
    "validate_finding": SpawnedAgentRole.VALIDATOR,
    "analyze_results": SpawnedAgentRole.ANALYST,
    "osint_gather": SpawnedAgentRole.OSINT,
    "fuzz_target": SpawnedAgentRole.FUZZER,
    "cloud_audit": SpawnedAgentRole.CLOUD,
    "wifi_test": SpawnedAgentRole.WIRELESS,
    "forensic_analysis": SpawnedAgentRole.FORENSICS,
    "plan_phase": SpawnedAgentRole.PLANNER,
    "exploit_vuln": SpawnedAgentRole.EXPLOITER,
}

# Model preference by role
ROLE_MODEL_PREFERENCE: dict[str, list[str]] = {
    "coordinator": ["deepseek-r1-7b", "hermes-14b"],
    "recon": ["mistral-7b", "llama-3.1-8b"],
    "scanner": ["qwen-coder-7b", "mistral-7b"],
    "exploiter": ["whiterabbitneo-7b", "dolphin-8b"],
    "code_auditor": ["qwen-coder-14b", "codellama-13b"],
    "validator": ["deepseek-r1-7b", "qwen-coder-14b"],
    "analyst": ["hermes-14b", "deepseek-r1-7b"],
    "planner": ["deepseek-r1-7b", "hermes-14b"],
    "osint": ["llama-3.1-8b", "mistral-7b"],
    "fuzzer": ["whiterabbitneo-7b", "codellama-7b"],
    "cloud": ["qwen-coder-14b", "hermes-14b"],
    "wireless": ["whiterabbitneo-7b", "dolphin-8b"],
    "forensics": ["yi-9b-200k", "qwen-coder-14b"],
}

MAX_DEPTH = 5
BUDGET_DECAY = 0.7
MAX_CHILDREN_PER_AGENT = 8


class AgentSpawner:
    """Creates and manages child agents recursively.

    Spawns specialized agents with bounded depth,
    budget decay, and role-based model selection.
    Tracks agent hierarchy and lifecycle.
    """

    def __init__(self, max_depth: int = MAX_DEPTH) -> None:
        self._agents: dict[str, SpawnedAgent] = {}
        self._max_depth = max_depth
        self._counter = 0
        self._pool: dict[str, list[str]] = {}  # role → [recycled agent_ids]
        self._log = logger.bind(component="agent_spawner")

    def spawn(
        self,
        role: SpawnedAgentRole,
        task_description: str,
        parent_id: str = "",
        token_budget: int = 0,
        time_budget_s: float = 0.0,
        model_id: str = "",
    ) -> SpawnedAgent | None:
        """Spawn a new child agent."""
        # Determine depth
        depth = 0
        if parent_id:
            parent = self._agents.get(parent_id)
            if not parent:
                return None
            depth = parent.depth + 1
            if depth > self._max_depth:
                self._log.warning("max_depth_exceeded", parent=parent_id[:10], depth=depth)
                return None
            if len(parent.children) >= MAX_CHILDREN_PER_AGENT:
                self._log.warning("max_children_exceeded", parent=parent_id[:10])
                return None

        # Check pool for recycled agent
        recycled = self._try_recycle(role)
        if recycled:
            recycled.state = SpawnedAgentState.INITIALIZING
            recycled.parent_id = parent_id
            recycled.depth = depth
            recycled.task_description = task_description
            recycled.tokens_used = 0
            recycled.findings_count = 0
            recycled.result = ""
            recycled.created_at = time.time()
            recycled.completed_at = 0.0
            if parent_id and parent_id in self._agents:
                self._agents[parent_id].children.append(recycled.agent_id)
            return recycled

        # Calculate budget with decay
        if token_budget == 0:
            if parent_id and parent_id in self._agents:
                parent_budget = self._agents[parent_id].budget_remaining
                token_budget = int(parent_budget * BUDGET_DECAY)
            else:
                token_budget = 100000

        if time_budget_s == 0:
            time_budget_s = 600.0

        # Select model by role preference
        if not model_id:
            prefs = ROLE_MODEL_PREFERENCE.get(role.value, [])
            model_id = prefs[0] if prefs else "mistral-7b"

        self._counter += 1
        agent = SpawnedAgent(
            agent_id=f"agent-{self._counter}",
            role=role,
            state=SpawnedAgentState.INITIALIZING,
            parent_id=parent_id,
            depth=depth,
            model_id=model_id,
            task_description=task_description,
            token_budget=token_budget,
            time_budget_s=time_budget_s,
        )

        self._agents[agent.agent_id] = agent

        if parent_id and parent_id in self._agents:
            self._agents[parent_id].children.append(agent.agent_id)

        return agent

    def spawn_for_task(
        self,
        task_type: str,
        task_description: str,
        parent_id: str = "",
    ) -> SpawnedAgent | None:
        """Spawn an agent based on task type."""
        role = ROLE_FOR_TASK.get(task_type, SpawnedAgentRole.SCANNER)
        return self.spawn(role=role, task_description=task_description, parent_id=parent_id)

    def complete_agent(
        self,
        agent_id: str,
        result: str = "",
        findings_count: int = 0,
    ) -> bool:
        """Mark an agent as completed."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False

        agent.state = SpawnedAgentState.COMPLETED
        agent.result = result
        agent.findings_count = findings_count
        agent.completed_at = time.time()

        return True

    def fail_agent(self, agent_id: str, error: str = "") -> bool:
        """Mark an agent as failed."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        agent.state = SpawnedAgentState.FAILED
        agent.result = error
        agent.completed_at = time.time()
        return True

    def recycle_agent(self, agent_id: str) -> bool:
        """Return an agent to the pool for reuse."""
        agent = self._agents.get(agent_id)
        if not agent or agent.is_active:
            return False

        agent.state = SpawnedAgentState.RECYCLED
        self._pool.setdefault(agent.role.value, []).append(agent_id)
        return True

    def get_active_agents(self) -> list[SpawnedAgent]:
        """Get all active agents."""
        return [a for a in self._agents.values() if a.is_active]

    def get_children(self, parent_id: str) -> list[SpawnedAgent]:
        """Get child agents of a parent."""
        parent = self._agents.get(parent_id)
        if not parent:
            return []
        return [
            self._agents[cid]
            for cid in parent.children
            if cid in self._agents
        ]

    def get_agent_tree(self, root_id: str = "") -> list[tuple[int, SpawnedAgent]]:
        """Get agent hierarchy as flat list."""
        result: list[tuple[int, SpawnedAgent]] = []

        if root_id:
            roots = [self._agents[root_id]] if root_id in self._agents else []
        else:
            roots = [a for a in self._agents.values() if not a.parent_id]

        def _traverse(agent: SpawnedAgent) -> None:
            result.append((agent.depth, agent))
            for child_id in agent.children:
                child = self._agents.get(child_id)
                if child:
                    _traverse(child)

        for root in roots:
            _traverse(root)
        return result

    def build_spawn_prompt(self, parent_id: str = "") -> str:
        """Build agent hierarchy context for LLM."""
        lines = ["## Agent Hierarchy\n"]

        tree = self.get_agent_tree(parent_id)
        for depth, agent in tree[:15]:
            indent = "  " * depth
            state_icon = {
                "created": "[ ]", "initializing": "[~]",
                "running": "[>]", "waiting": "[.]",
                "completed": "[x]", "failed": "[!]",
                "timed_out": "[T]", "recycled": "[-]",
            }.get(agent.state.value, "[ ]")

            lines.append(
                f"{indent}{state_icon} {agent.role.value}:{agent.agent_id[:8]} "
                f"({agent.findings_count} findings)"
            )

        active = self.get_active_agents()
        lines.append(f"\nActive agents: {len(active)}/{len(self._agents)}")

        return "\n".join(lines)

    def _try_recycle(self, role: SpawnedAgentRole) -> SpawnedAgent | None:
        """Try to get a recycled agent from the pool."""
        pool = self._pool.get(role.value, [])
        if pool:
            agent_id = pool.pop()
            return self._agents.get(agent_id)
        return None

    def get_stats(self) -> dict[str, Any]:
        state_counts: dict[str, int] = {}
        role_counts: dict[str, int] = {}
        for a in self._agents.values():
            state_counts[a.state.value] = state_counts.get(a.state.value, 0) + 1
            role_counts[a.role.value] = role_counts.get(a.role.value, 0) + 1

        return {
            "total_agents": len(self._agents),
            "active": len(self.get_active_agents()),
            "max_depth": max((a.depth for a in self._agents.values()), default=0),
            "by_state": state_counts,
            "by_role": role_counts,
            "pool_size": sum(len(v) for v in self._pool.values()),
        }
