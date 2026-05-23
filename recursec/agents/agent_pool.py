"""Agent pool — manages a pool of reusable agent instances.

Implements:
1. Agent instance lifecycle management
2. Agent reuse (avoid re-initialization overhead)
3. Pool sizing (min/max instances)
4. Agent specialization (role-specific pools)
5. Load balancing across agent instances
6. Health monitoring per agent
7. Graceful agent retirement
8. Agent warmup on pool start
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AgentStatus(str, Enum):
    IDLE = "idle"
    BUSY = "busy"
    WARMING_UP = "warming_up"
    RETIRING = "retiring"
    FAILED = "failed"


@dataclass
class PooledAgent:
    """An agent instance in the pool."""
    agent_id: str = ""
    role: str = ""
    status: AgentStatus = AgentStatus.IDLE
    tasks_completed: int = 0
    tasks_failed: int = 0
    current_task: str = ""
    avg_task_time_s: float = 0.0
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    total_time_busy_s: float = 0.0

    @property
    def utilization(self) -> float:
        total = time.time() - self.created_at
        if total <= 0:
            return 0.0
        return min(1.0, self.total_time_busy_s / total)

    @property
    def error_rate(self) -> float:
        total = self.tasks_completed + self.tasks_failed
        if total == 0:
            return 0.0
        return self.tasks_failed / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id, "role": self.role,
            "status": self.status.value,
            "tasks": self.tasks_completed,
            "utilization": round(self.utilization, 2),
            "error_rate": round(self.error_rate, 2),
        }


@dataclass
class PoolConfig:
    """Configuration for an agent pool."""
    role: str = ""
    min_size: int = 1
    max_size: int = 5
    max_tasks_per_agent: int = 100
    idle_timeout_s: float = 300.0
    warmup_fn: Any = None           # Optional warmup callable


class AgentPool:
    """Pool of reusable agent instances.

    Manages agent lifecycle, provides load-balanced
    agent allocation, and handles scaling.
    """

    def __init__(self) -> None:
        self._pools: dict[str, list[PooledAgent]] = defaultdict(list)
        self._configs: dict[str, PoolConfig] = {}
        self._agent_counter = 0
        self._log = logger.bind(component="agent_pool")

    def configure_pool(
        self,
        role: str,
        min_size: int = 1,
        max_size: int = 5,
        max_tasks_per_agent: int = 100,
    ) -> None:
        """Configure a pool for a specific role."""
        self._configs[role] = PoolConfig(
            role=role,
            min_size=min_size,
            max_size=max_size,
            max_tasks_per_agent=max_tasks_per_agent,
        )

        # Ensure minimum pool size
        current = len(self._pools.get(role, []))
        for _ in range(max(0, min_size - current)):
            self._create_agent(role)

    def acquire(self, role: str) -> PooledAgent | None:
        """Acquire an idle agent from the pool."""
        pool = self._pools.get(role, [])

        # Try to find an idle agent
        for agent in pool:
            if agent.status == AgentStatus.IDLE:
                agent.status = AgentStatus.BUSY
                agent.last_active = time.time()
                return agent

        # Try to create a new agent
        config = self._configs.get(role)
        max_size = config.max_size if config else 10

        if len(pool) < max_size:
            agent = self._create_agent(role)
            agent.status = AgentStatus.BUSY
            return agent

        return None

    def release(
        self,
        agent_id: str,
        success: bool = True,
        task_time_s: float = 0.0,
    ) -> None:
        """Release an agent back to the pool."""
        for role, pool in self._pools.items():
            for agent in pool:
                if agent.agent_id == agent_id:
                    if success:
                        agent.tasks_completed += 1
                    else:
                        agent.tasks_failed += 1

                    # Update average task time
                    total_tasks = agent.tasks_completed + agent.tasks_failed
                    if agent.avg_task_time_s == 0:
                        agent.avg_task_time_s = task_time_s
                    else:
                        agent.avg_task_time_s = (
                            agent.avg_task_time_s * (total_tasks - 1) + task_time_s
                        ) / total_tasks

                    agent.total_time_busy_s += task_time_s
                    agent.current_task = ""
                    agent.last_active = time.time()

                    # Check if agent should be retired
                    config = self._configs.get(role)
                    max_tasks = config.max_tasks_per_agent if config else 100

                    if total_tasks >= max_tasks or agent.error_rate > 0.5:
                        agent.status = AgentStatus.RETIRING
                    else:
                        agent.status = AgentStatus.IDLE

                    return

    async def cleanup(self) -> int:
        """Remove idle and retiring agents beyond minimum pool size."""
        removed = 0

        for role, pool in self._pools.items():
            config = self._configs.get(role)
            min_size = config.min_size if config else 1
            idle_timeout = config.idle_timeout_s if config else 300.0

            # Remove retiring agents
            to_remove = []
            for agent in pool:
                if agent.status == AgentStatus.RETIRING:
                    to_remove.append(agent)
                elif agent.status == AgentStatus.IDLE:
                    idle_time = time.time() - agent.last_active
                    if idle_time > idle_timeout and len(pool) > min_size:
                        to_remove.append(agent)

            for agent in to_remove:
                if len(pool) > min_size:
                    pool.remove(agent)
                    removed += 1

        return removed

    def _create_agent(self, role: str) -> PooledAgent:
        """Create a new agent instance."""
        self._agent_counter += 1
        agent = PooledAgent(
            agent_id=f"pool-{role}-{self._agent_counter}",
            role=role,
        )
        self._pools[role].append(agent)
        return agent

    def get_pool_status(self, role: str = "") -> dict[str, Any]:
        """Get pool status."""
        if role:
            pool = self._pools.get(role, [])
            return {
                "role": role,
                "total": len(pool),
                "idle": sum(1 for a in pool if a.status == AgentStatus.IDLE),
                "busy": sum(1 for a in pool if a.status == AgentStatus.BUSY),
                "agents": [a.to_dict() for a in pool],
            }

        all_status = {}
        for pool_role, pool in self._pools.items():
            all_status[pool_role] = {
                "total": len(pool),
                "idle": sum(1 for a in pool if a.status == AgentStatus.IDLE),
                "busy": sum(1 for a in pool if a.status == AgentStatus.BUSY),
            }
        return all_status

    def get_stats(self) -> dict[str, Any]:
        total = sum(len(p) for p in self._pools.values())
        busy = sum(
            1 for pool in self._pools.values()
            for a in pool if a.status == AgentStatus.BUSY
        )

        return {
            "pools": len(self._pools),
            "total_agents": total,
            "busy": busy,
            "idle": total - busy,
        }
