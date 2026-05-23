"""Agent lifecycle manager — manages the complete lifecycle of agent instances.

Implements:
1. Agent creation with configuration
2. Agent initialization and warm-up
3. Health monitoring and heartbeat
4. Graceful shutdown
5. Agent restart and recovery
6. Pool management (min/max instances)
7. Load-based scaling
8. Agent metrics collection
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AgentPhase(str, Enum):
    CREATED = "created"
    INITIALIZING = "initializing"
    READY = "ready"
    BUSY = "busy"
    IDLE = "idle"
    DRAINING = "draining"
    SHUTTING_DOWN = "shutting_down"
    TERMINATED = "terminated"
    ERROR = "error"


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class AgentInstance:
    """A managed agent instance."""
    instance_id: str = ""
    agent_type: str = ""
    role: str = ""
    model_id: str = ""
    phase: AgentPhase = AgentPhase.CREATED
    health: HealthStatus = HealthStatus.UNKNOWN
    current_task: str = ""
    tasks_completed: int = 0
    tasks_failed: int = 0
    tokens_used: int = 0
    last_heartbeat: float = 0.0
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    error_count: int = 0
    config: dict[str, Any] = field(default_factory=dict)

    @property
    def uptime_s(self) -> float:
        if self.started_at == 0:
            return 0.0
        return time.time() - self.started_at

    @property
    def is_available(self) -> bool:
        return self.phase in (AgentPhase.READY, AgentPhase.IDLE)

    @property
    def success_rate(self) -> float:
        total = self.tasks_completed + self.tasks_failed
        if total == 0:
            return 1.0
        return self.tasks_completed / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.instance_id,
            "type": self.agent_type[:15],
            "role": self.role[:10],
            "phase": self.phase.value,
            "health": self.health.value,
            "tasks": self.tasks_completed,
            "uptime_m": round(self.uptime_s / 60, 1),
        }


@dataclass
class PoolConfig:
    """Configuration for an agent pool."""
    agent_type: str = ""
    min_instances: int = 1
    max_instances: int = 5
    target_utilization: float = 0.7
    scale_up_threshold: float = 0.8
    scale_down_threshold: float = 0.3
    cooldown_s: int = 60

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.agent_type[:15],
            "min": self.min_instances,
            "max": self.max_instances,
            "target_util": self.target_utilization,
        }


@dataclass
class ScaleEvent:
    """A scaling event."""
    direction: str = ""
    agent_type: str = ""
    from_count: int = 0
    to_count: int = 0
    reason: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dir": self.direction[:4],
            "type": self.agent_type[:15],
            "from": self.from_count,
            "to": self.to_count,
            "reason": self.reason[:25],
        }


# ── Default Agent Types ───────────────────────────────────────

DEFAULT_POOL_CONFIGS: list[dict[str, Any]] = [
    {"type": "coordinator", "min": 1, "max": 1},
    {"type": "recon", "min": 1, "max": 3},
    {"type": "scanner", "min": 1, "max": 4},
    {"type": "analyzer", "min": 1, "max": 3},
    {"type": "exploiter", "min": 0, "max": 2},
    {"type": "validator", "min": 1, "max": 2},
    {"type": "reporter", "min": 0, "max": 1},
]


class AgentLifecycle:
    """Manages the complete lifecycle of agent instances.

    Handles creation, health monitoring, scaling,
    and shutdown of agent instances.
    """

    def __init__(
        self,
        heartbeat_timeout: int = 120,
    ) -> None:
        self._instances: dict[str, AgentInstance] = {}
        self._pools: dict[str, PoolConfig] = {}
        self._scale_events: list[ScaleEvent] = []
        self._instance_counter = 0
        self._heartbeat_timeout = heartbeat_timeout
        self._log = logger.bind(component="agent_lifecycle")

        self._initialize_pools()

    def _initialize_pools(self) -> None:
        """Initialize default pool configs."""
        for data in DEFAULT_POOL_CONFIGS:
            self._pools[data["type"]] = PoolConfig(
                agent_type=data["type"],
                min_instances=data["min"],
                max_instances=data["max"],
            )

    def create_agent(
        self,
        agent_type: str,
        role: str = "",
        model_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> AgentInstance:
        """Create a new agent instance."""
        # Check pool limits
        pool = self._pools.get(agent_type)
        if pool:
            current_count = self._count_type(agent_type)
            if current_count >= pool.max_instances:
                self._log.warning("pool_limit", type=agent_type)
                return self._get_idle_agent(agent_type) or AgentInstance()

        self._instance_counter += 1
        instance = AgentInstance(
            instance_id=f"agent-{self._instance_counter}",
            agent_type=agent_type,
            role=role or agent_type,
            model_id=model_id,
            config=config or {},
        )

        self._instances[instance.instance_id] = instance
        return instance

    def initialize_agent(self, instance_id: str) -> bool:
        """Initialize an agent (warm-up phase)."""
        instance = self._instances.get(instance_id)
        if not instance:
            return False

        instance.phase = AgentPhase.INITIALIZING
        instance.started_at = time.time()
        instance.last_heartbeat = time.time()
        instance.health = HealthStatus.HEALTHY
        instance.phase = AgentPhase.READY
        return True

    def assign_task(self, instance_id: str, task_id: str) -> bool:
        """Assign a task to an agent."""
        instance = self._instances.get(instance_id)
        if not instance or not instance.is_available:
            return False

        instance.phase = AgentPhase.BUSY
        instance.current_task = task_id
        return True

    def complete_task(
        self,
        instance_id: str,
        success: bool = True,
        tokens_used: int = 0,
    ) -> None:
        """Mark agent's current task as complete."""
        instance = self._instances.get(instance_id)
        if not instance:
            return

        if success:
            instance.tasks_completed += 1
        else:
            instance.tasks_failed += 1

        instance.tokens_used += tokens_used
        instance.current_task = ""
        instance.phase = AgentPhase.IDLE

    def heartbeat(self, instance_id: str) -> None:
        """Record heartbeat from an agent."""
        instance = self._instances.get(instance_id)
        if instance:
            instance.last_heartbeat = time.time()

    def check_health(self) -> dict[str, list[str]]:
        """Check health of all agents."""
        issues: dict[str, list[str]] = defaultdict(list)
        now = time.time()

        for instance in self._instances.values():
            if instance.phase in (AgentPhase.TERMINATED, AgentPhase.SHUTTING_DOWN):
                continue

            # Heartbeat check
            if instance.last_heartbeat > 0:
                gap = now - instance.last_heartbeat
                if gap > self._heartbeat_timeout:
                    instance.health = HealthStatus.UNHEALTHY
                    issues["heartbeat_timeout"].append(instance.instance_id)
                elif gap > self._heartbeat_timeout / 2:
                    instance.health = HealthStatus.DEGRADED

            # Error rate check
            if instance.success_rate < 0.5 and instance.tasks_completed + instance.tasks_failed > 5:
                instance.health = HealthStatus.DEGRADED
                issues["high_error_rate"].append(instance.instance_id)

        return dict(issues)

    def autoscale(self) -> list[ScaleEvent]:
        """Auto-scale agent pools based on utilization."""
        events = []

        for agent_type, pool in self._pools.items():
            instances = self._get_type_instances(agent_type)
            active = [i for i in instances if i.phase not in (AgentPhase.TERMINATED,)]
            busy = [i for i in active if i.phase == AgentPhase.BUSY]

            count = len(active)
            utilization = len(busy) / max(1, count)

            # Scale up
            if utilization > pool.scale_up_threshold and count < pool.max_instances:
                event = ScaleEvent(
                    direction="up",
                    agent_type=agent_type,
                    from_count=count,
                    to_count=count + 1,
                    reason=f"utilization {utilization:.0%}",
                )
                self._scale_events.append(event)
                events.append(event)
                self.create_agent(agent_type)

            # Scale down
            elif utilization < pool.scale_down_threshold and count > pool.min_instances:
                idle = [i for i in active if i.phase == AgentPhase.IDLE]
                if idle:
                    event = ScaleEvent(
                        direction="down",
                        agent_type=agent_type,
                        from_count=count,
                        to_count=count - 1,
                        reason=f"utilization {utilization:.0%}",
                    )
                    self._scale_events.append(event)
                    events.append(event)
                    self.shutdown_agent(idle[0].instance_id)

        return events

    def shutdown_agent(self, instance_id: str) -> None:
        """Gracefully shut down an agent."""
        instance = self._instances.get(instance_id)
        if not instance:
            return

        if instance.phase == AgentPhase.BUSY:
            instance.phase = AgentPhase.DRAINING
        else:
            instance.phase = AgentPhase.TERMINATED

    def restart_agent(self, instance_id: str) -> AgentInstance | None:
        """Restart an agent (terminate + create new)."""
        old = self._instances.get(instance_id)
        if not old:
            return None

        self.shutdown_agent(instance_id)
        return self.create_agent(
            agent_type=old.agent_type,
            role=old.role,
            model_id=old.model_id,
            config=old.config,
        )

    def _count_type(self, agent_type: str) -> int:
        return sum(
            1 for i in self._instances.values()
            if i.agent_type == agent_type and i.phase != AgentPhase.TERMINATED
        )

    def _get_type_instances(self, agent_type: str) -> list[AgentInstance]:
        return [
            i for i in self._instances.values()
            if i.agent_type == agent_type
        ]

    def _get_idle_agent(self, agent_type: str) -> AgentInstance | None:
        for inst in self._instances.values():
            if inst.agent_type == agent_type and inst.is_available:
                return inst
        return None

    def get_stats(self) -> dict[str, Any]:
        phase_counts: dict[str, int] = defaultdict(int)
        for inst in self._instances.values():
            phase_counts[inst.phase.value] += 1
        return {
            "instances": len(self._instances),
            "phases": dict(phase_counts),
            "pools": len(self._pools),
            "scale_events": len(self._scale_events),
        }
