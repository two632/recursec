"""Agent spawner — dynamic creation, delegation, and lifecycle management of child agents.

The recursive heart of the multi-agent system. Parent agents can:
1. Spawn child agents for subtasks
2. Delegate work with full context propagation
3. Monitor child progress and collect results
4. Handle child failures (retry, reassign, escalate)
5. Manage recursion depth limits
6. Pool and reuse idle agents
7. Fan-out parallel subtasks

Agent types:
- Ephemeral: Created for a single task, destroyed after
- Persistent: Long-lived, reusable across tasks
- Pooled: Pre-created pool of agents for common tasks

Delegation patterns:
- Fire-and-forget: Parent doesn't wait for result
- Await-result: Parent blocks until child completes
- Stream-results: Child streams partial results to parent
- Collaborative: Multiple children collaborate on a task
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Coroutine

import structlog

if TYPE_CHECKING:
    pass

logger = structlog.get_logger()


class AgentLifecycle(str, Enum):
    EPHEMERAL = "ephemeral"
    PERSISTENT = "persistent"
    POOLED = "pooled"


class DelegationPattern(str, Enum):
    AWAIT_RESULT = "await_result"
    FIRE_AND_FORGET = "fire_and_forget"
    STREAM_RESULTS = "stream_results"
    COLLABORATIVE = "collaborative"


class SpawnResult(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    DEPTH_EXCEEDED = "depth_exceeded"
    CAPACITY_EXCEEDED = "capacity_exceeded"


@dataclass
class AgentSpec:
    """Specification for spawning an agent."""
    role: str                    # Agent role (recon, vuln_scan, exploit, etc.)
    goal: str                    # What the agent should accomplish
    tools: list[str] = field(default_factory=list)
    model_preference: str = ""   # Preferred LLM type
    context: dict[str, Any] = field(default_factory=dict)
    budget_tokens: int = 50000
    budget_time_s: float = 300.0
    budget_steps: int = 50
    max_children: int = 3        # How many children this agent can spawn
    lifecycle: AgentLifecycle = AgentLifecycle.EPHEMERAL
    priority: int = 5            # 1=highest, 10=lowest
    parent_id: str = ""
    depth: int = 0
    tags: list[str] = field(default_factory=list)


@dataclass
class SpawnedAgent:
    """A spawned agent instance."""
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    spec: AgentSpec = field(default_factory=AgentSpec)
    parent_id: str = ""
    children: list[str] = field(default_factory=list)
    status: str = "created"  # created, running, completed, failed, timeout
    result: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    started_at: float = 0.0
    completed_at: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id, "role": self.spec.role,
            "goal": self.spec.goal[:100], "parent": self.parent_id,
            "children": len(self.children), "status": self.status,
            "findings": len(self.findings), "depth": self.spec.depth,
            "elapsed_s": round(time.time() - self.started_at, 1) if self.started_at else 0,
        }


# Type for agent execution functions
AgentExecutor = Callable[[SpawnedAgent], Coroutine[Any, Any, dict[str, Any]]]


class AgentSpawner:
    """Manages dynamic creation and lifecycle of child agents.

    The core recursive mechanism: parent agents create child agents
    to handle subtasks, with full context propagation and result collection.
    """

    def __init__(
        self,
        max_depth: int = 5,
        max_total_agents: int = 50,
        max_concurrent: int = 10,
        default_timeout_s: float = 300.0,
    ) -> None:
        self._max_depth = max_depth
        self._max_total = max_total_agents
        self._max_concurrent = max_concurrent
        self._default_timeout = default_timeout_s

        self._agents: dict[str, SpawnedAgent] = {}
        self._active_count = 0
        self._pool: dict[str, list[SpawnedAgent]] = defaultdict(list)
        self._executor: AgentExecutor | None = None
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._log = logger.bind(component="spawner")

    def set_executor(self, executor: AgentExecutor) -> None:
        """Set the function that actually runs an agent."""
        self._executor = executor

    async def spawn(
        self,
        spec: AgentSpec,
        parent_id: str = "",
        delegation: DelegationPattern = DelegationPattern.AWAIT_RESULT,
    ) -> SpawnedAgent:
        """Spawn a new child agent."""
        # Check depth limit
        if spec.depth >= self._max_depth:
            self._log.warning("depth_exceeded", depth=spec.depth, max=self._max_depth)
            agent = SpawnedAgent(spec=spec, parent_id=parent_id, status="failed", error="Max depth exceeded")
            return agent

        # Check capacity
        if len(self._agents) >= self._max_total:
            self._log.warning("capacity_exceeded", total=len(self._agents), max=self._max_total)
            agent = SpawnedAgent(spec=spec, parent_id=parent_id, status="failed", error="Max agents exceeded")
            return agent

        # Try to reuse from pool
        if spec.lifecycle == AgentLifecycle.POOLED:
            pooled = self._get_from_pool(spec.role)
            if pooled:
                pooled.spec = spec
                pooled.parent_id = parent_id
                pooled.status = "created"
                pooled.result = {}
                pooled.findings = []
                pooled.error = ""
                agent = pooled
            else:
                agent = SpawnedAgent(spec=spec, parent_id=parent_id)
        else:
            agent = SpawnedAgent(spec=spec, parent_id=parent_id)

        spec.parent_id = parent_id
        self._agents[agent.agent_id] = agent

        # Register as child of parent
        if parent_id and parent_id in self._agents:
            self._agents[parent_id].children.append(agent.agent_id)

        self._log.info(
            "agent_spawned",
            agent=agent.agent_id, role=spec.role,
            depth=spec.depth, parent=parent_id,
        )

        # Execute based on delegation pattern
        if delegation == DelegationPattern.FIRE_AND_FORGET:
            asyncio.create_task(self._execute_agent(agent))
            return agent
        elif delegation == DelegationPattern.AWAIT_RESULT:
            await self._execute_agent(agent)
            return agent
        elif delegation == DelegationPattern.COLLABORATIVE:
            # Don't execute yet — parent will coordinate
            return agent
        else:
            await self._execute_agent(agent)
            return agent

    async def spawn_parallel(
        self,
        specs: list[AgentSpec],
        parent_id: str = "",
    ) -> list[SpawnedAgent]:
        """Spawn multiple agents in parallel and wait for all to complete."""
        tasks = []
        for spec in specs:
            spec.depth = spec.depth or (self._agents.get(parent_id, SpawnedAgent()).spec.depth + 1)
            tasks.append(self.spawn(spec, parent_id=parent_id))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        agents = []
        for result in results:
            if isinstance(result, SpawnedAgent):
                agents.append(result)
            else:
                self._log.error("parallel_spawn_error", error=str(result))
        return agents

    async def _execute_agent(self, agent: SpawnedAgent) -> None:
        """Execute an agent with the registered executor."""
        if not self._executor:
            agent.status = "failed"
            agent.error = "No executor registered"
            return

        async with self._semaphore:
            agent.status = "running"
            agent.started_at = time.time()
            self._active_count += 1

            try:
                result = await asyncio.wait_for(
                    self._executor(agent),
                    timeout=agent.spec.budget_time_s or self._default_timeout,
                )
                agent.result = result or {}
                agent.findings = result.get("findings", []) if result else []
                agent.status = "completed"

            except asyncio.TimeoutError:
                agent.status = "timeout"
                agent.error = f"Timed out after {agent.spec.budget_time_s}s"
                self._log.warning("agent_timeout", agent=agent.agent_id)

            except Exception as e:
                agent.status = "failed"
                agent.error = str(e)
                self._log.error("agent_error", agent=agent.agent_id, error=str(e))

            finally:
                agent.completed_at = time.time()
                self._active_count -= 1

                # Return to pool if pooled
                if agent.spec.lifecycle == AgentLifecycle.POOLED and agent.status != "failed":
                    self._return_to_pool(agent)

    def collect_results(self, parent_id: str) -> dict[str, Any]:
        """Collect results from all children of a parent agent."""
        parent = self._agents.get(parent_id)
        if not parent:
            return {}

        children_results = []
        all_findings: list[dict[str, Any]] = []
        for child_id in parent.children:
            child = self._agents.get(child_id)
            if child:
                children_results.append({
                    "agent": child.agent_id,
                    "role": child.spec.role,
                    "status": child.status,
                    "findings": len(child.findings),
                    "result": child.result,
                })
                all_findings.extend(child.findings)

        return {
            "parent": parent_id,
            "children_count": len(parent.children),
            "completed": sum(1 for c in children_results if c["status"] == "completed"),
            "failed": sum(1 for c in children_results if c["status"] == "failed"),
            "total_findings": len(all_findings),
            "children": children_results,
            "findings": all_findings,
        }

    def get_agent(self, agent_id: str) -> SpawnedAgent | None:
        return self._agents.get(agent_id)

    def get_children(self, parent_id: str) -> list[SpawnedAgent]:
        parent = self._agents.get(parent_id)
        if not parent:
            return []
        return [
            self._agents[cid] for cid in parent.children
            if cid in self._agents
        ]

    def get_lineage(self, agent_id: str) -> list[str]:
        """Get the full ancestry chain of an agent."""
        lineage = []
        current = agent_id
        while current:
            lineage.append(current)
            agent = self._agents.get(current)
            if agent:
                current = agent.parent_id
            else:
                break
        return list(reversed(lineage))

    # ── Pool Management ──────────────────────────────────

    def _get_from_pool(self, role: str) -> SpawnedAgent | None:
        pool = self._pool.get(role, [])
        if pool:
            return pool.pop(0)
        return None

    def _return_to_pool(self, agent: SpawnedAgent) -> None:
        pool = self._pool[agent.spec.role]
        if len(pool) < 5:  # Max pool size per role
            agent.status = "pooled"
            pool.append(agent)

    # ── Reporting ────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        by_status: dict[str, int] = defaultdict(int)
        by_role: dict[str, int] = defaultdict(int)
        by_depth: dict[int, int] = defaultdict(int)
        for agent in self._agents.values():
            by_status[agent.status] += 1
            by_role[agent.spec.role] += 1
            by_depth[agent.spec.depth] += 1
        return {
            "total_agents": len(self._agents),
            "active": self._active_count,
            "max_concurrent": self._max_concurrent,
            "by_status": dict(by_status),
            "by_role": dict(by_role),
            "by_depth": dict(by_depth),
            "pool_sizes": {role: len(pool) for role, pool in self._pool.items()},
        }

    def get_tree(self, root_id: str = "") -> dict[str, Any]:
        """Get the agent tree structure."""
        if not root_id:
            roots = [a for a in self._agents.values() if not a.parent_id]
            return {"roots": [self._build_tree(r.agent_id) for r in roots]}
        return self._build_tree(root_id)

    def _build_tree(self, agent_id: str) -> dict[str, Any]:
        agent = self._agents.get(agent_id)
        if not agent:
            return {}
        return {
            "id": agent.agent_id,
            "role": agent.spec.role,
            "status": agent.status,
            "depth": agent.spec.depth,
            "findings": len(agent.findings),
            "children": [self._build_tree(cid) for cid in agent.children],
        }
