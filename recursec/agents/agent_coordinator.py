"""Agent coordinator — coordinates multiple specialized agents.

Implements:
1. Agent registration and role assignment
2. Task routing to best-fit agents
3. Agent collaboration protocols
4. Work stealing for load balancing
5. Agent lifecycle management
6. Inter-agent dependency resolution
7. Agent performance monitoring
8. Dynamic agent scaling (spawn/retire)
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
    PLANNER = "planner"
    RECON = "recon"
    ANALYZER = "analyzer"
    EXPLOITER = "exploiter"
    VALIDATOR = "validator"
    REPORTER = "reporter"
    COORDINATOR = "coordinator"
    SPECIALIST = "specialist"


class AgentStatus(str, Enum):
    IDLE = "idle"
    BUSY = "busy"
    WAITING = "waiting"
    ERROR = "error"
    RETIRED = "retired"


@dataclass
class AgentInfo:
    """Information about a registered agent."""
    agent_id: str = ""
    role: AgentRole = AgentRole.SPECIALIST
    model_hint: str = ""          # Preferred model for this agent
    capabilities: list[str] = field(default_factory=list)
    status: AgentStatus = AgentStatus.IDLE
    current_task: str = ""
    tasks_completed: int = 0
    tasks_failed: int = 0
    total_tokens_used: int = 0
    avg_task_duration_s: float = 0.0
    spawned_at: float = field(default_factory=time.time)
    last_active_at: float = field(default_factory=time.time)
    parent_id: str = ""           # Coordinator that spawned this agent

    @property
    def success_rate(self) -> float:
        total = self.tasks_completed + self.tasks_failed
        if total == 0:
            return 0.0
        return self.tasks_completed / total

    @property
    def is_available(self) -> bool:
        return self.status == AgentStatus.IDLE

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id, "role": self.role.value,
            "model": self.model_hint[:15],
            "status": self.status.value,
            "completed": self.tasks_completed,
            "success_rate": round(self.success_rate, 2),
            "tokens": self.total_tokens_used,
        }


@dataclass
class TaskAssignment:
    """A task assigned to an agent."""
    task_id: str = ""
    agent_id: str = ""
    description: str = ""
    priority: int = 5              # 1-10
    assigned_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    result: dict[str, Any] = field(default_factory=dict)
    success: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task_id, "agent": self.agent_id[:15],
            "priority": self.priority,
            "success": self.success,
        }


@dataclass
class CollaborationRequest:
    """A request for inter-agent collaboration."""
    request_id: str = ""
    from_agent: str = ""
    to_agent: str = ""
    request_type: str = ""         # help, validate, share_findings, delegate
    payload: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"        # pending, accepted, completed, rejected
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.request_id,
            "from": self.from_agent[:15],
            "to": self.to_agent[:15],
            "type": self.request_type,
            "status": self.status,
        }


# ── Role → Model Mapping ──────────────────────────────────────

ROLE_MODEL_MAP: dict[str, list[str]] = {
    "planner": ["deepseek-r1", "hermes-14b"],
    "recon": ["mistral-7b", "llama-8b"],
    "analyzer": ["qwen-coder-14b", "deepseek-r1"],
    "exploiter": ["whiterabbit", "dolphin"],
    "validator": ["hermes-14b", "qwen-coder-7b"],
    "reporter": ["mistral-7b", "llama-8b"],
    "coordinator": ["hermes-14b", "deepseek-r1"],
    "specialist": ["whiterabbit", "qwen-coder-14b"],
}


class AgentCoordinator:
    """Coordinates multiple specialized agents.

    Manages agent registration, task routing,
    collaboration, load balancing, and lifecycle.
    """

    def __init__(self, max_agents: int = 50) -> None:
        self._agents: dict[str, AgentInfo] = {}
        self._tasks: dict[str, TaskAssignment] = {}
        self._task_queue: list[TaskAssignment] = []
        self._collaborations: list[CollaborationRequest] = []
        self._agent_counter = 0
        self._task_counter = 0
        self._collab_counter = 0
        self._max_agents = max_agents
        self._log = logger.bind(component="agent_coordinator")

    def register_agent(
        self,
        role: AgentRole,
        model_hint: str = "",
        capabilities: list[str] | None = None,
        parent_id: str = "",
    ) -> AgentInfo:
        """Register a new agent."""
        if len(self._agents) >= self._max_agents:
            # Retire idle agents to make room
            self._retire_idle()

        self._agent_counter += 1
        agent_id = f"agent-{self._agent_counter}"

        if not model_hint:
            model_hint = self._suggest_model(role)

        agent = AgentInfo(
            agent_id=agent_id,
            role=role,
            model_hint=model_hint,
            capabilities=capabilities or [],
            parent_id=parent_id,
        )

        self._agents[agent_id] = agent
        return agent

    def assign_task(
        self,
        description: str,
        preferred_role: AgentRole | None = None,
        priority: int = 5,
    ) -> TaskAssignment | None:
        """Assign a task to the best available agent."""
        self._task_counter += 1
        task_id = f"task-{self._task_counter}"

        # Find best agent
        agent = self._find_best_agent(preferred_role)

        if not agent:
            # Queue the task
            assignment = TaskAssignment(
                task_id=task_id,
                description=description,
                priority=priority,
            )
            self._task_queue.append(assignment)
            self._task_queue.sort(key=lambda t: t.priority, reverse=True)
            return assignment

        assignment = TaskAssignment(
            task_id=task_id,
            agent_id=agent.agent_id,
            description=description,
            priority=priority,
        )

        agent.status = AgentStatus.BUSY
        agent.current_task = task_id
        agent.last_active_at = time.time()

        self._tasks[task_id] = assignment
        return assignment

    def complete_task(
        self,
        task_id: str,
        result: dict[str, Any],
        success: bool = True,
        tokens_used: int = 0,
    ) -> None:
        """Mark a task as completed."""
        assignment = self._tasks.get(task_id)
        if not assignment:
            return

        assignment.completed_at = time.time()
        assignment.result = result
        assignment.success = success

        agent = self._agents.get(assignment.agent_id)
        if agent:
            agent.status = AgentStatus.IDLE
            agent.current_task = ""
            agent.total_tokens_used += tokens_used

            duration = assignment.completed_at - assignment.assigned_at
            if agent.avg_task_duration_s == 0:
                agent.avg_task_duration_s = duration
            else:
                agent.avg_task_duration_s = agent.avg_task_duration_s * 0.8 + duration * 0.2

            if success:
                agent.tasks_completed += 1
            else:
                agent.tasks_failed += 1

        # Process queued tasks
        self._process_queue()

    def request_collaboration(
        self,
        from_agent: str,
        to_agent: str,
        request_type: str,
        payload: dict[str, Any] | None = None,
    ) -> CollaborationRequest:
        """Create an inter-agent collaboration request."""
        self._collab_counter += 1
        req = CollaborationRequest(
            request_id=f"collab-{self._collab_counter}",
            from_agent=from_agent,
            to_agent=to_agent,
            request_type=request_type,
            payload=payload or {},
        )
        self._collaborations.append(req)
        return req

    def work_steal(self) -> TaskAssignment | None:
        """Steal a task from the queue for an idle agent."""
        if not self._task_queue:
            return None

        idle = [a for a in self._agents.values() if a.is_available]
        if not idle:
            return None

        task = self._task_queue.pop(0)
        agent = idle[0]

        task.agent_id = agent.agent_id
        agent.status = AgentStatus.BUSY
        agent.current_task = task.task_id
        self._tasks[task.task_id] = task

        return task

    def _find_best_agent(
        self,
        preferred_role: AgentRole | None = None,
    ) -> AgentInfo | None:
        """Find the best available agent for a task."""
        available = [a for a in self._agents.values() if a.is_available]

        if not available:
            return None

        if preferred_role:
            role_match = [a for a in available if a.role == preferred_role]
            if role_match:
                return max(role_match, key=lambda a: a.success_rate)

        return max(available, key=lambda a: a.success_rate)

    def _suggest_model(self, role: AgentRole) -> str:
        """Suggest a model for a role."""
        models = ROLE_MODEL_MAP.get(role.value, ["mistral-7b"])
        return models[0] if models else "mistral-7b"

    def _retire_idle(self) -> None:
        """Retire oldest idle agents."""
        idle = [
            a for a in self._agents.values()
            if a.status == AgentStatus.IDLE
        ]
        idle.sort(key=lambda a: a.last_active_at)

        for agent in idle[:5]:
            agent.status = AgentStatus.RETIRED

    def _process_queue(self) -> None:
        """Process queued tasks."""
        while self._task_queue:
            idle = [a for a in self._agents.values() if a.is_available]
            if not idle:
                break

            task = self._task_queue.pop(0)
            agent = idle[0]
            task.agent_id = agent.agent_id
            agent.status = AgentStatus.BUSY
            agent.current_task = task.task_id
            self._tasks[task.task_id] = task

    def get_agent_status(self) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._agents.values()]

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for agent in self._agents.values():
            status_counts[agent.status.value] += 1

        return {
            "total_agents": len(self._agents),
            "status": dict(status_counts),
            "tasks_completed": sum(a.tasks_completed for a in self._agents.values()),
            "queued": len(self._task_queue),
            "collaborations": len(self._collaborations),
        }
