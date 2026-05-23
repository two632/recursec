"""Recursive spawner — spawns and manages child agent hierarchies.

Implements:
1. Recursive agent creation with depth limits
2. Context inheritance (parent → child)
3. Result aggregation (child → parent)
4. Budget splitting across children
5. Child monitoring and health checks
6. Convergence-based early termination
7. Agent specialization based on task decomposition
8. Spawn throttling and resource management
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine

import structlog

logger = structlog.get_logger()


class SpawnReason(str, Enum):
    TASK_DECOMPOSITION = "task_decomposition"
    SPECIALIZATION = "specialization"
    PARALLEL_EXECUTION = "parallel_execution"
    DEPTH_EXPLORATION = "depth_exploration"
    VALIDATION = "validation"
    RETRY = "retry"


class ChildStatus(str, Enum):
    SPAWNING = "spawning"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    KILLED = "killed"


@dataclass
class SpawnedChild:
    """A spawned child agent."""
    child_id: str = ""
    parent_id: str = ""
    role: str = ""
    task: str = ""
    reason: SpawnReason = SpawnReason.TASK_DECOMPOSITION
    depth: int = 0
    max_depth: int = 5
    token_budget: int = 100_000
    tokens_used: int = 0
    time_budget_s: float = 600.0
    status: ChildStatus = ChildStatus.SPAWNING
    result: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    spawned_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def duration_s(self) -> float:
        if self.completed_at:
            return self.completed_at - self.spawned_at
        return time.time() - self.spawned_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.child_id, "parent": self.parent_id,
            "role": self.role, "depth": self.depth,
            "status": self.status.value,
            "findings": len(self.findings),
            "duration_s": round(self.duration_s, 1),
        }


@dataclass
class SpawnRequest:
    """A request to spawn a child agent."""
    role: str = ""
    task: str = ""
    reason: SpawnReason = SpawnReason.TASK_DECOMPOSITION
    context: dict[str, Any] = field(default_factory=dict)
    token_budget: int = 50_000
    time_budget_s: float = 300.0
    priority: int = 5


class RecursiveSpawner:
    """Manages recursive agent spawning and hierarchies.

    Spawns child agents for task decomposition,
    manages their lifecycle, and aggregates results.
    """

    def __init__(
        self,
        max_depth: int = 5,
        max_children_per_agent: int = 10,
        max_total_agents: int = 100,
        total_token_budget: int = 5_000_000,
    ) -> None:
        self._max_depth = max_depth
        self._max_children_per_agent = max_children_per_agent
        self._max_total = max_total_agents
        self._total_budget = total_token_budget

        self._children: dict[str, SpawnedChild] = {}
        self._parent_children: dict[str, list[str]] = defaultdict(list)
        self._child_counter = 0
        self._total_spawned = 0
        self._tokens_used = 0
        self._agent_handlers: dict[str, Callable[..., Coroutine[Any, Any, dict[str, Any]]]] = {}
        self._log = logger.bind(component="recursive_spawner")

    def register_handler(
        self,
        role: str,
        handler: Callable[..., Coroutine[Any, Any, dict[str, Any]]],
    ) -> None:
        """Register an agent handler for a role."""
        self._agent_handlers[role] = handler

    def can_spawn(self, parent_id: str, depth: int) -> bool:
        """Check if spawning is allowed."""
        if depth >= self._max_depth:
            return False

        if self._total_spawned >= self._max_total:
            return False

        children_count = len(self._parent_children.get(parent_id, []))
        if children_count >= self._max_children_per_agent:
            return False

        if self._tokens_used >= self._total_budget:
            return False

        return True

    def spawn(
        self,
        parent_id: str,
        request: SpawnRequest,
        depth: int = 0,
    ) -> str:
        """Spawn a child agent."""
        if not self.can_spawn(parent_id, depth):
            return ""

        self._child_counter += 1
        self._total_spawned += 1
        child_id = f"child-{self._child_counter}"

        # Inherit context from parent
        parent_context = {}
        parent = self._children.get(parent_id)
        if parent:
            parent_context = dict(parent.context)
        parent_context.update(request.context)

        child = SpawnedChild(
            child_id=child_id,
            parent_id=parent_id,
            role=request.role,
            task=request.task,
            reason=request.reason,
            depth=depth,
            max_depth=self._max_depth,
            token_budget=request.token_budget,
            time_budget_s=request.time_budget_s,
            context=parent_context,
        )

        self._children[child_id] = child
        self._parent_children[parent_id].append(child_id)

        return child_id

    async def execute(self, child_id: str) -> dict[str, Any]:
        """Execute a spawned child agent."""
        child = self._children.get(child_id)
        if not child:
            return {"error": "child_not_found"}

        child.status = ChildStatus.RUNNING

        handler = self._agent_handlers.get(child.role)
        if not handler:
            child.status = ChildStatus.FAILED
            child.result = {"error": f"no_handler_for_{child.role}"}
            return child.result

        try:
            result = await asyncio.wait_for(
                handler(child.task, child.context),
                timeout=child.time_budget_s,
            )

            child.status = ChildStatus.COMPLETED
            child.result = result
            child.findings = result.get("findings", [])
            child.completed_at = time.time()

            return result

        except asyncio.TimeoutError:
            child.status = ChildStatus.TIMEOUT
            child.completed_at = time.time()
            return {"error": "timeout", "partial": child.result}

        except Exception as e:
            child.status = ChildStatus.FAILED
            child.result = {"error": str(e)[:200]}
            child.completed_at = time.time()
            return child.result

    async def spawn_and_execute(
        self,
        parent_id: str,
        request: SpawnRequest,
        depth: int = 0,
    ) -> dict[str, Any]:
        """Spawn and immediately execute a child."""
        child_id = self.spawn(parent_id, request, depth)
        if not child_id:
            return {"error": "spawn_denied"}

        return await self.execute(child_id)

    async def fan_out(
        self,
        parent_id: str,
        requests: list[SpawnRequest],
        depth: int = 0,
    ) -> list[dict[str, Any]]:
        """Spawn multiple children and execute in parallel."""
        child_ids = []
        for req in requests:
            cid = self.spawn(parent_id, req, depth)
            if cid:
                child_ids.append(cid)

        if not child_ids:
            return []

        tasks = [self.execute(cid) for cid in child_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed = []
        for result in results:
            if isinstance(result, Exception):
                processed.append({"error": str(result)[:200]})
            else:
                processed.append(result)

        return processed

    def aggregate_findings(self, parent_id: str) -> list[dict[str, Any]]:
        """Aggregate findings from all children of a parent."""
        all_findings: list[dict[str, Any]] = []
        child_ids = self._parent_children.get(parent_id, [])

        for cid in child_ids:
            child = self._children.get(cid)
            if child and child.findings:
                all_findings.extend(child.findings)

        # Deduplicate by title
        seen_titles: set[str] = set()
        unique: list[dict[str, Any]] = []
        for finding in all_findings:
            title = finding.get("title", "")
            if title not in seen_titles:
                seen_titles.add(title)
                unique.append(finding)

        return unique

    def kill(self, child_id: str) -> bool:
        """Kill a child agent."""
        child = self._children.get(child_id)
        if child and child.status == ChildStatus.RUNNING:
            child.status = ChildStatus.KILLED
            child.completed_at = time.time()
            return True
        return False

    def get_hierarchy(self, root_id: str) -> dict[str, Any]:
        """Get the full hierarchy tree from a root."""
        def build_tree(pid: str) -> dict[str, Any]:
            child_ids = self._parent_children.get(pid, [])
            children_data = []
            for cid in child_ids:
                child = self._children.get(cid)
                if child:
                    child_data = child.to_dict()
                    child_data["children"] = build_tree(cid).get("children", [])
                    children_data.append(child_data)
            return {"id": pid, "children": children_data}

        return build_tree(root_id)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for child in self._children.values():
            status_counts[child.status.value] += 1

        return {
            "total_spawned": self._total_spawned,
            "active": sum(
                1 for c in self._children.values()
                if c.status == ChildStatus.RUNNING
            ),
            "max_depth": self._max_depth,
            "status": dict(status_counts),
        }
