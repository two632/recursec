"""Agent lifecycle manager — manages agent creation, monitoring, and teardown.

Handles:
1. Agent creation with proper initialization
2. Health monitoring and heartbeat checking
3. Resource tracking (tokens, time, memory)
4. Graceful shutdown and cleanup
5. Agent restart on failure
6. Agent pooling for reuse
7. Agent hierarchies (parent-child)
8. Lifecycle hooks (on_create, on_start, on_complete, on_error, on_destroy)
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
    CREATED = "created"
    INITIALIZING = "initializing"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETING = "completing"
    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"
    POOLED = "pooled"


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    DEAD = "dead"


@dataclass
class AgentInfo:
    """Information about a managed agent."""
    agent_id: str = ""
    role: str = ""
    goal: str = ""
    state: AgentState = AgentState.CREATED
    parent_id: str = ""
    children: list[str] = field(default_factory=list)
    depth: int = 0

    # Resource tracking
    tokens_used: int = 0
    tokens_budget: int = 50000
    time_elapsed_s: float = 0.0
    time_budget_s: float = 300.0
    steps_taken: int = 0
    steps_budget: int = 100
    tools_invoked: int = 0
    findings_generated: int = 0

    # Health
    last_heartbeat: float = field(default_factory=time.time)
    heartbeat_interval_s: float = 30.0
    health: HealthStatus = HealthStatus.HEALTHY
    consecutive_errors: int = 0
    max_consecutive_errors: int = 5

    # Timestamps
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0

    # Result
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    exit_reason: str = ""

    @property
    def alive(self) -> bool:
        return self.state in (AgentState.READY, AgentState.RUNNING, AgentState.PAUSED)

    @property
    def token_utilization(self) -> float:
        return self.tokens_used / max(1, self.tokens_budget)

    @property
    def time_utilization(self) -> float:
        return self.time_elapsed_s / max(1, self.time_budget_s)

    @property
    def time_remaining_s(self) -> float:
        return max(0, self.time_budget_s - self.time_elapsed_s)

    @property
    def tokens_remaining(self) -> int:
        return max(0, self.tokens_budget - self.tokens_used)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id, "role": self.role,
            "state": self.state.value, "health": self.health.value,
            "depth": self.depth,
            "tokens": f"{self.tokens_used}/{self.tokens_budget}",
            "time_s": f"{self.time_elapsed_s:.0f}/{self.time_budget_s:.0f}",
            "steps": f"{self.steps_taken}/{self.steps_budget}",
            "findings": self.findings_generated,
            "children": len(self.children),
        }


@dataclass
class LifecycleEvent:
    """A lifecycle event."""
    event_type: str = ""
    agent_id: str = ""
    timestamp: float = field(default_factory=time.time)
    data: dict[str, Any] = field(default_factory=dict)


class AgentLifecycleManager:
    """Manages agent lifecycle from creation to destruction.

    Provides centralized tracking, health monitoring,
    and resource management for all agents.
    """

    def __init__(
        self,
        heartbeat_timeout_s: float = 60.0,
        max_agents: int = 100,
    ) -> None:
        self._agents: dict[str, AgentInfo] = {}
        self._pool: dict[str, list[AgentInfo]] = defaultdict(list)
        self._events: list[LifecycleEvent] = []
        self._heartbeat_timeout = heartbeat_timeout_s
        self._max_agents = max_agents
        self._log = logger.bind(component="lifecycle")

    def create_agent(
        self,
        agent_id: str,
        role: str,
        goal: str = "",
        parent_id: str = "",
        tokens_budget: int = 50000,
        time_budget_s: float = 300.0,
        steps_budget: int = 100,
    ) -> AgentInfo:
        """Create and register a new agent."""
        if len(self._agents) >= self._max_agents:
            self._log.warning("max_agents_reached", max=self._max_agents)
            # Try to reclaim pooled agents
            self._cleanup_pool()

        parent = self._agents.get(parent_id)
        depth = parent.depth + 1 if parent else 0

        agent = AgentInfo(
            agent_id=agent_id,
            role=role,
            goal=goal,
            parent_id=parent_id,
            depth=depth,
            tokens_budget=tokens_budget,
            time_budget_s=time_budget_s,
            steps_budget=steps_budget,
        )

        self._agents[agent_id] = agent

        # Track parent-child
        if parent:
            parent.children.append(agent_id)

        self._emit("agent_created", agent_id, {"role": role, "depth": depth})
        return agent

    def start_agent(self, agent_id: str) -> bool:
        """Transition agent to running state."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False

        if agent.state not in (AgentState.CREATED, AgentState.READY, AgentState.POOLED):
            return False

        agent.state = AgentState.RUNNING
        agent.started_at = time.time()
        agent.last_heartbeat = time.time()
        self._emit("agent_started", agent_id)
        return True

    def heartbeat(self, agent_id: str) -> None:
        """Record a heartbeat from an agent."""
        agent = self._agents.get(agent_id)
        if agent:
            agent.last_heartbeat = time.time()
            agent.health = HealthStatus.HEALTHY

    def record_tokens(self, agent_id: str, tokens: int) -> bool:
        """Record token usage. Returns False if budget exceeded."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        agent.tokens_used += tokens
        if agent.tokens_used >= agent.tokens_budget:
            self._emit("budget_exceeded", agent_id, {"type": "tokens"})
            return False
        return True

    def record_step(self, agent_id: str) -> bool:
        """Record a step. Returns False if step budget exceeded."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        agent.steps_taken += 1
        agent.time_elapsed_s = time.time() - agent.started_at if agent.started_at else 0
        if agent.steps_taken >= agent.steps_budget:
            self._emit("budget_exceeded", agent_id, {"type": "steps"})
            return False
        if agent.time_elapsed_s >= agent.time_budget_s:
            self._emit("budget_exceeded", agent_id, {"type": "time"})
            return False
        return True

    def record_tool_use(self, agent_id: str) -> None:
        agent = self._agents.get(agent_id)
        if agent:
            agent.tools_invoked += 1

    def record_finding(self, agent_id: str) -> None:
        agent = self._agents.get(agent_id)
        if agent:
            agent.findings_generated += 1

    def record_error(self, agent_id: str, error: str) -> bool:
        """Record an error. Returns False if max errors exceeded."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        agent.consecutive_errors += 1
        agent.health = HealthStatus.DEGRADED
        self._emit("agent_error", agent_id, {"error": error[:200]})
        if agent.consecutive_errors >= agent.max_consecutive_errors:
            agent.health = HealthStatus.UNHEALTHY
            return False
        return True

    def clear_errors(self, agent_id: str) -> None:
        agent = self._agents.get(agent_id)
        if agent:
            agent.consecutive_errors = 0
            agent.health = HealthStatus.HEALTHY

    def complete_agent(
        self,
        agent_id: str,
        result: dict[str, Any] | None = None,
    ) -> None:
        """Mark agent as completed."""
        agent = self._agents.get(agent_id)
        if not agent:
            return

        agent.state = AgentState.COMPLETED
        agent.completed_at = time.time()
        agent.time_elapsed_s = agent.completed_at - (agent.started_at or agent.created_at)
        agent.result = result or {}
        agent.exit_reason = "completed"

        self._emit("agent_completed", agent_id, {
            "findings": agent.findings_generated,
            "tokens": agent.tokens_used,
            "duration_s": round(agent.time_elapsed_s, 1),
        })

    def fail_agent(self, agent_id: str, error: str = "") -> None:
        """Mark agent as failed."""
        agent = self._agents.get(agent_id)
        if not agent:
            return

        agent.state = AgentState.FAILED
        agent.completed_at = time.time()
        agent.error = error
        agent.exit_reason = "failed"
        agent.health = HealthStatus.DEAD

        self._emit("agent_failed", agent_id, {"error": error[:200]})

    def terminate_agent(self, agent_id: str, reason: str = "") -> None:
        """Forcefully terminate an agent."""
        agent = self._agents.get(agent_id)
        if not agent:
            return

        agent.state = AgentState.TERMINATED
        agent.completed_at = time.time()
        agent.exit_reason = f"terminated: {reason}"

        # Terminate children too
        for child_id in agent.children:
            self.terminate_agent(child_id, reason="parent terminated")

        self._emit("agent_terminated", agent_id, {"reason": reason})

    def pool_agent(self, agent_id: str) -> None:
        """Return an agent to the pool for reuse."""
        agent = self._agents.get(agent_id)
        if not agent:
            return

        agent.state = AgentState.POOLED
        agent.goal = ""
        agent.result = {}
        agent.error = ""
        agent.tokens_used = 0
        agent.steps_taken = 0
        agent.time_elapsed_s = 0
        agent.findings_generated = 0
        agent.consecutive_errors = 0
        agent.health = HealthStatus.HEALTHY

        self._pool[agent.role].append(agent)

    def get_pooled(self, role: str) -> AgentInfo | None:
        """Get a pooled agent of the given role."""
        pool = self._pool.get(role, [])
        if pool:
            agent = pool.pop()
            agent.state = AgentState.READY
            return agent
        return None

    # ── Health Monitoring ────────────────────────────────

    def check_health(self) -> list[dict[str, Any]]:
        """Check health of all running agents."""
        now = time.time()
        unhealthy: list[dict[str, Any]] = []

        for agent in self._agents.values():
            if not agent.alive:
                continue

            # Check heartbeat timeout
            if now - agent.last_heartbeat > self._heartbeat_timeout:
                agent.health = HealthStatus.UNHEALTHY
                unhealthy.append({
                    "agent": agent.agent_id,
                    "issue": "heartbeat_timeout",
                    "last_seen": round(now - agent.last_heartbeat, 1),
                })

            # Check budget
            if agent.token_utilization > 0.9:
                unhealthy.append({
                    "agent": agent.agent_id,
                    "issue": "token_budget_near_limit",
                    "usage": round(agent.token_utilization, 2),
                })

            if agent.time_utilization > 0.9:
                unhealthy.append({
                    "agent": agent.agent_id,
                    "issue": "time_budget_near_limit",
                    "usage": round(agent.time_utilization, 2),
                })

        return unhealthy

    # ── Queries ──────────────────────────────────────────

    def get_agent(self, agent_id: str) -> AgentInfo | None:
        return self._agents.get(agent_id)

    def get_running_agents(self) -> list[AgentInfo]:
        return [a for a in self._agents.values() if a.alive]

    def get_hierarchy(self, root_id: str = "") -> dict[str, Any]:
        """Get agent hierarchy starting from root."""
        roots = [a for a in self._agents.values() if not a.parent_id]
        if root_id:
            roots = [a for a in self._agents.values() if a.agent_id == root_id]

        def build_tree(agent: AgentInfo) -> dict[str, Any]:
            return {
                "agent": agent.to_dict(),
                "children": [
                    build_tree(self._agents[cid])
                    for cid in agent.children
                    if cid in self._agents
                ],
            }

        return {"roots": [build_tree(r) for r in roots]}

    def get_events(self, agent_id: str = "", limit: int = 50) -> list[dict[str, Any]]:
        events = self._events
        if agent_id:
            events = [e for e in events if e.agent_id == agent_id]
        return [
            {"type": e.event_type, "agent": e.agent_id, "data": e.data}
            for e in events[-limit:]
        ]

    # ── Internal ─────────────────────────────────────────

    def _emit(self, event_type: str, agent_id: str, data: dict[str, Any] | None = None) -> None:
        self._events.append(LifecycleEvent(
            event_type=event_type,
            agent_id=agent_id,
            data=data or {},
        ))
        if len(self._events) > 5000:
            self._events = self._events[-5000:]

    def _cleanup_pool(self) -> None:
        for role in list(self._pool.keys()):
            old = [a for a in self._pool[role] if time.time() - a.completed_at > 600]
            for a in old:
                del self._agents[a.agent_id]
            self._pool[role] = [a for a in self._pool[role] if a not in old]

    def get_stats(self) -> dict[str, Any]:
        by_state: dict[str, int] = defaultdict(int)
        by_role: dict[str, int] = defaultdict(int)
        for a in self._agents.values():
            by_state[a.state.value] += 1
            by_role[a.role] += 1
        return {
            "total_agents": len(self._agents),
            "running": sum(1 for a in self._agents.values() if a.alive),
            "pooled": sum(len(p) for p in self._pool.values()),
            "by_state": dict(by_state),
            "by_role": dict(by_role),
            "total_events": len(self._events),
        }
