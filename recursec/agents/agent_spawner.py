"""Agent spawner — dynamic recursive agent creation and lifecycle management.

The heart of the recursive multi-agent system. Implements:
1. Dynamic agent instantiation based on task requirements
2. Recursive spawning with depth limits
3. Agent pool management and reuse
4. Parent-child context inheritance
5. Result aggregation from child agents
6. Agent retirement and cleanup
7. Spawn budget tracking
8. Agent lineage tracking
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class SpawnReason(str, Enum):
    DECOMPOSITION = "decomposition"    # Parent decomposed task
    SPECIALIZATION = "specialization"  # Need specialized capability
    VALIDATION = "validation"          # Cross-validate findings
    EXPLORATION = "exploration"        # Explore alternative approach
    ESCALATION = "escalation"          # Escalate to more capable model
    RETRY = "retry"                    # Retry with different config


class AgentLifecycle(str, Enum):
    SPAWNING = "spawning"
    INITIALIZING = "initializing"
    RUNNING = "running"
    WAITING_CHILDREN = "waiting_children"
    AGGREGATING = "aggregating"
    COMPLETED = "completed"
    FAILED = "failed"
    RETIRED = "retired"


@dataclass
class SpawnedAgent:
    """A dynamically spawned agent."""
    agent_id: str = ""
    parent_id: str = ""
    depth: int = 0
    role: str = ""
    model_hint: str = ""
    task: str = ""
    spawn_reason: SpawnReason = SpawnReason.DECOMPOSITION
    lifecycle: AgentLifecycle = AgentLifecycle.SPAWNING
    children_ids: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)
    tokens_used: int = 0
    spawned_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def duration_s(self) -> float:
        end = self.completed_at or time.time()
        return end - self.spawned_at

    @property
    def is_active(self) -> bool:
        return self.lifecycle in (
            AgentLifecycle.SPAWNING, AgentLifecycle.INITIALIZING,
            AgentLifecycle.RUNNING, AgentLifecycle.WAITING_CHILDREN,
            AgentLifecycle.AGGREGATING,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id,
            "parent": self.parent_id[:15],
            "depth": self.depth,
            "role": self.role[:20],
            "model": self.model_hint[:15],
            "lifecycle": self.lifecycle.value,
            "children": len(self.children_ids),
            "tokens": self.tokens_used,
            "duration_s": round(self.duration_s, 1),
        }


@dataclass
class SpawnRequest:
    """A request to spawn a new agent."""
    request_id: str = ""
    parent_id: str = ""
    role: str = ""
    task: str = ""
    model_hint: str = ""
    spawn_reason: SpawnReason = SpawnReason.DECOMPOSITION
    context: dict[str, Any] = field(default_factory=dict)
    priority: int = 5
    max_tokens: int = 4096

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.request_id,
            "parent": self.parent_id[:15],
            "role": self.role[:20],
            "task": self.task[:40],
            "reason": self.spawn_reason.value,
        }


@dataclass
class AggregatedResult:
    """Result aggregated from child agents."""
    parent_id: str = ""
    children_results: list[dict[str, Any]] = field(default_factory=list)
    merged_findings: list[dict[str, Any]] = field(default_factory=list)
    total_tokens: int = 0
    total_duration_s: float = 0.0
    success_count: int = 0
    failure_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "parent": self.parent_id[:15],
            "children": len(self.children_results),
            "findings": len(self.merged_findings),
            "tokens": self.total_tokens,
            "success": self.success_count,
            "failures": self.failure_count,
        }


# ── Role → Model Recommendations ──────────────────────────────

ROLE_MODEL_RECOMMENDATIONS: dict[str, list[str]] = {
    "security_analyst": ["whiterabbitneo-7b", "hermes-14b", "dolphin-8b"],
    "code_auditor": ["qwen-coder-14b", "qwen-coder-7b", "codellama-13b"],
    "recon_agent": ["mistral-7b", "llama-8b", "phi-3.5"],
    "exploit_analyst": ["whiterabbitneo-7b", "dolphin-8b"],
    "planner": ["deepseek-r1-7b", "hermes-14b"],
    "validator": ["hermes-14b", "qwen-coder-7b"],
    "reasoning": ["deepseek-r1-7b", "deepseek-math-7b"],
    "long_context": ["yi-9b-200k"],
    "fast_router": ["functiongemma-270m", "phi-3.5"],
    "safety_filter": ["llama-guard-3-1b"],
}


class AgentSpawner:
    """Dynamic recursive agent creation and lifecycle management.

    The core of the recursive multi-agent system.
    Spawns, manages, and retires agents with depth
    limits, budget tracking, and result aggregation.
    """

    def __init__(
        self,
        max_depth: int = 5,
        max_concurrent: int = 20,
        max_total_spawns: int = 200,
        token_budget: int = 500000,
    ) -> None:
        self._agents: dict[str, SpawnedAgent] = {}
        self._request_queue: list[SpawnRequest] = []
        self._spawn_counter = 0
        self._request_counter = 0
        self._max_depth = max_depth
        self._max_concurrent = max_concurrent
        self._max_total_spawns = max_total_spawns
        self._token_budget = token_budget
        self._tokens_used = 0
        self._log = logger.bind(component="agent_spawner")

    def request_spawn(
        self,
        parent_id: str,
        role: str,
        task: str,
        model_hint: str = "",
        spawn_reason: SpawnReason = SpawnReason.DECOMPOSITION,
        context: dict[str, Any] | None = None,
        priority: int = 5,
        max_tokens: int = 4096,
    ) -> SpawnRequest:
        """Request to spawn a new agent."""
        self._request_counter += 1
        request = SpawnRequest(
            request_id=f"sr-{self._request_counter}",
            parent_id=parent_id,
            role=role,
            task=task,
            model_hint=model_hint or self._recommend_model(role),
            spawn_reason=spawn_reason,
            context=context or {},
            priority=priority,
            max_tokens=max_tokens,
        )

        self._request_queue.append(request)
        self._request_queue.sort(key=lambda r: r.priority, reverse=True)

        return request

    def spawn(self, request: SpawnRequest) -> SpawnedAgent | None:
        """Spawn a new agent from a request."""
        # Check depth limit
        parent = self._agents.get(request.parent_id)
        depth = (parent.depth + 1) if parent else 0

        if depth > self._max_depth:
            self._log.warning("max_depth_reached", depth=depth, max=self._max_depth)
            return None

        # Check concurrent limit
        active = sum(1 for a in self._agents.values() if a.is_active)
        if active >= self._max_concurrent:
            self._log.warning("max_concurrent_reached", active=active)
            return None

        # Check total spawn limit
        if self._spawn_counter >= self._max_total_spawns:
            self._log.warning("max_total_spawns_reached", total=self._spawn_counter)
            return None

        # Check token budget
        if self._tokens_used >= self._token_budget:
            self._log.warning("token_budget_exhausted")
            return None

        self._spawn_counter += 1
        agent_id = f"sa-{self._spawn_counter}"

        # Inherit context from parent
        inherited_context = {}
        if parent:
            # Selective inheritance
            for key in ("target", "scope", "findings", "phase"):
                if key in parent.context:
                    inherited_context[key] = parent.context[key]

        inherited_context.update(request.context)

        agent = SpawnedAgent(
            agent_id=agent_id,
            parent_id=request.parent_id,
            depth=depth,
            role=request.role,
            model_hint=request.model_hint,
            task=request.task,
            spawn_reason=request.spawn_reason,
            lifecycle=AgentLifecycle.INITIALIZING,
            context=inherited_context,
        )

        self._agents[agent_id] = agent

        # Link to parent
        if parent:
            parent.children_ids.append(agent_id)

        return agent

    def process_queue(self, max_spawns: int = 5) -> list[SpawnedAgent]:
        """Process pending spawn requests."""
        spawned = []
        while self._request_queue and len(spawned) < max_spawns:
            request = self._request_queue.pop(0)
            agent = self.spawn(request)
            if agent:
                spawned.append(agent)
        return spawned

    def complete_agent(
        self,
        agent_id: str,
        result: dict[str, Any],
        tokens_used: int = 0,
        success: bool = True,
    ) -> None:
        """Mark an agent as completed."""
        agent = self._agents.get(agent_id)
        if not agent:
            return

        agent.result = result
        agent.tokens_used = tokens_used
        agent.completed_at = time.time()
        agent.lifecycle = AgentLifecycle.COMPLETED if success else AgentLifecycle.FAILED

        self._tokens_used += tokens_used

        # Check if parent can aggregate
        if agent.parent_id:
            parent = self._agents.get(agent.parent_id)
            if parent and parent.lifecycle == AgentLifecycle.WAITING_CHILDREN:
                all_done = all(
                    not self._agents[cid].is_active
                    for cid in parent.children_ids
                    if cid in self._agents
                )
                if all_done:
                    parent.lifecycle = AgentLifecycle.AGGREGATING

    def aggregate_results(self, parent_id: str) -> AggregatedResult:
        """Aggregate results from all children of a parent."""
        parent = self._agents.get(parent_id)
        if not parent:
            return AggregatedResult()

        result = AggregatedResult(parent_id=parent_id)

        for child_id in parent.children_ids:
            child = self._agents.get(child_id)
            if not child:
                continue

            result.children_results.append(child.result)
            result.total_tokens += child.tokens_used
            result.total_duration_s += child.duration_s

            if child.lifecycle == AgentLifecycle.COMPLETED:
                result.success_count += 1
            elif child.lifecycle == AgentLifecycle.FAILED:
                result.failure_count += 1

            # Extract findings from children
            for finding in child.result.get("findings", []):
                result.merged_findings.append(finding)

        parent.lifecycle = AgentLifecycle.COMPLETED
        parent.completed_at = time.time()

        return result

    def get_lineage(self, agent_id: str) -> list[str]:
        """Get the full lineage (root → ... → agent)."""
        lineage = []
        current = self._agents.get(agent_id)
        while current:
            lineage.append(current.agent_id)
            current = self._agents.get(current.parent_id) if current.parent_id else None
        lineage.reverse()
        return lineage

    def _recommend_model(self, role: str) -> str:
        """Recommend a model for a role."""
        models = ROLE_MODEL_RECOMMENDATIONS.get(role, ["mistral-7b"])
        return models[0]

    def retire_completed(self) -> int:
        """Retire completed agents to free resources."""
        retired = 0
        for agent in self._agents.values():
            if agent.lifecycle in (AgentLifecycle.COMPLETED, AgentLifecycle.FAILED):
                agent.lifecycle = AgentLifecycle.RETIRED
                retired += 1
        return retired

    def get_active(self) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._agents.values() if a.is_active]

    def get_stats(self) -> dict[str, Any]:
        lifecycle_counts: dict[str, int] = defaultdict(int)
        for agent in self._agents.values():
            lifecycle_counts[agent.lifecycle.value] += 1

        return {
            "total_spawned": self._spawn_counter,
            "active": sum(1 for a in self._agents.values() if a.is_active),
            "lifecycle": dict(lifecycle_counts),
            "tokens_used": self._tokens_used,
            "token_budget": self._token_budget,
            "queue": len(self._request_queue),
            "max_depth": self._max_depth,
        }
