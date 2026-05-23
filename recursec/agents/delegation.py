"""Delegation engine — intelligent task assignment to specialized agents.

Handles:
1. Capability matching: Match tasks to agents with right skills
2. Load balancing: Distribute work evenly across agents
3. Expertise weighting: Prefer specialists for domain tasks
4. Failure recovery: Reassign failed tasks to alternative agents
5. Priority ordering: High-priority tasks get best agents
6. Dependency tracking: Tasks that depend on others wait
7. Result aggregation: Collect and merge results from delegated tasks
8. Performance tracking: Learn which agents are best at what

Delegation patterns:
- Single: One task → one agent
- Fan-out: One task → multiple agents (parallel exploration)
- Pipeline: Task chain → agent sequence
- Round-robin: Distribute evenly
- Expertise-weighted: Best match wins
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DelegationStrategy(str, Enum):
    BEST_MATCH = "best_match"
    ROUND_ROBIN = "round_robin"
    LEAST_LOADED = "least_loaded"
    EXPERTISE_WEIGHTED = "expertise_weighted"
    RANDOM = "random"


class TaskState(str, Enum):
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REASSIGNED = "reassigned"


@dataclass
class AgentCapability:
    """Represents an agent's capabilities and current state."""
    agent_id: str = ""
    role: str = ""
    specialties: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    max_concurrent_tasks: int = 3
    current_tasks: int = 0
    total_completed: int = 0
    total_failed: int = 0
    avg_completion_time_s: float = 60.0
    performance_scores: dict[str, float] = field(default_factory=dict)

    @property
    def available_capacity(self) -> int:
        return max(0, self.max_concurrent_tasks - self.current_tasks)

    @property
    def success_rate(self) -> float:
        total = self.total_completed + self.total_failed
        return self.total_completed / max(1, total)

    def get_expertise(self, domain: str) -> float:
        """Get expertise score for a domain (0-1)."""
        if domain in self.specialties:
            return self.performance_scores.get(domain, 0.8)
        return self.performance_scores.get(domain, 0.3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id, "role": self.role,
            "specialties": self.specialties,
            "capacity": self.available_capacity,
            "success_rate": round(self.success_rate, 2),
            "completed": self.total_completed,
        }


@dataclass
class DelegatedTask:
    """A task that has been delegated to an agent."""
    task_id: str = ""
    name: str = ""
    description: str = ""
    required_capabilities: list[str] = field(default_factory=list)
    required_tools: list[str] = field(default_factory=list)
    priority: int = 5
    state: TaskState = TaskState.PENDING
    assigned_agent: str = ""
    reassigned_from: str = ""
    dependencies: list[str] = field(default_factory=list)
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    max_retries: int = 2
    retry_count: int = 0

    @property
    def duration_s(self) -> float:
        if self.completed_at and self.started_at:
            return self.completed_at - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id, "name": self.name[:100],
            "state": self.state.value,
            "agent": self.assigned_agent,
            "priority": self.priority,
            "retries": self.retry_count,
            "duration_s": round(self.duration_s, 1),
        }


@dataclass
class DelegationResult:
    """Result of a delegation decision."""
    task_id: str = ""
    assigned_agent: str = ""
    strategy_used: str = ""
    match_score: float = 0.0
    alternatives_considered: list[str] = field(default_factory=list)
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task_id,
            "agent": self.assigned_agent,
            "strategy": self.strategy_used,
            "score": round(self.match_score, 3),
            "alternatives": self.alternatives_considered[:3],
        }


class DelegationEngine:
    """Intelligent task delegation to specialized agents.

    Matches tasks to the most capable agents based on
    expertise, capacity, and performance history.
    """

    def __init__(
        self,
        strategy: DelegationStrategy = DelegationStrategy.EXPERTISE_WEIGHTED,
    ) -> None:
        self._strategy = strategy
        self._agents: dict[str, AgentCapability] = {}
        self._tasks: dict[str, DelegatedTask] = {}
        self._delegation_log: list[DelegationResult] = []
        self._round_robin_idx = 0
        self._log = logger.bind(component="delegation")

    def register_agent(self, capability: AgentCapability) -> None:
        """Register an agent's capabilities."""
        self._agents[capability.agent_id] = capability

    def unregister_agent(self, agent_id: str) -> None:
        """Remove an agent."""
        self._agents.pop(agent_id, None)

    def delegate(self, task: DelegatedTask) -> DelegationResult:
        """Delegate a task to the best available agent."""
        self._tasks[task.task_id] = task

        # Check dependencies
        for dep_id in task.dependencies:
            dep_task = self._tasks.get(dep_id)
            if dep_task and dep_task.state != TaskState.COMPLETED:
                return DelegationResult(
                    task_id=task.task_id,
                    reasoning=f"Waiting for dependency: {dep_id}",
                )

        # Find best agent
        available = [a for a in self._agents.values() if a.available_capacity > 0]
        if not available:
            return DelegationResult(
                task_id=task.task_id,
                reasoning="No agents with available capacity",
            )

        # Score each agent
        scored: list[tuple[AgentCapability, float]] = []
        for agent in available:
            score = self._score_match(agent, task)
            scored.append((agent, score))

        scored.sort(key=lambda x: -x[1])

        # Select based on strategy
        if self._strategy == DelegationStrategy.BEST_MATCH:
            selected = scored[0][0]
        elif self._strategy == DelegationStrategy.ROUND_ROBIN:
            self._round_robin_idx = (self._round_robin_idx + 1) % len(available)
            selected = available[self._round_robin_idx]
        elif self._strategy == DelegationStrategy.LEAST_LOADED:
            selected = min(available, key=lambda a: a.current_tasks)
        elif self._strategy == DelegationStrategy.EXPERTISE_WEIGHTED:
            selected = scored[0][0]
        else:
            selected = scored[0][0]

        # Assign
        task.assigned_agent = selected.agent_id
        task.state = TaskState.ASSIGNED
        task.started_at = time.time()
        selected.current_tasks += 1

        result = DelegationResult(
            task_id=task.task_id,
            assigned_agent=selected.agent_id,
            strategy_used=self._strategy.value,
            match_score=scored[0][1],
            alternatives_considered=[a.agent_id for a, _ in scored[1:4]],
            reasoning=f"Best match by {self._strategy.value}",
        )

        self._delegation_log.append(result)
        return result

    def delegate_batch(self, tasks: list[DelegatedTask]) -> list[DelegationResult]:
        """Delegate multiple tasks, considering load balance."""
        # Sort by priority (highest first)
        tasks.sort(key=lambda t: -t.priority)
        return [self.delegate(task) for task in tasks]

    def complete_task(self, task_id: str, result: dict[str, Any]) -> None:
        """Mark a task as completed."""
        task = self._tasks.get(task_id)
        if not task:
            return

        task.state = TaskState.COMPLETED
        task.completed_at = time.time()
        task.result = result

        # Update agent stats
        agent = self._agents.get(task.assigned_agent)
        if agent:
            agent.current_tasks = max(0, agent.current_tasks - 1)
            agent.total_completed += 1
            n = agent.total_completed
            agent.avg_completion_time_s = (
                agent.avg_completion_time_s * (n - 1) + task.duration_s
            ) / n

            # Update performance for domain
            for cap in task.required_capabilities:
                current = agent.performance_scores.get(cap, 0.5)
                agent.performance_scores[cap] = current * 0.9 + 0.1 * 1.0

    def fail_task(self, task_id: str, error: str = "") -> DelegationResult | None:
        """Mark a task as failed and optionally reassign."""
        task = self._tasks.get(task_id)
        if not task:
            return None

        task.state = TaskState.FAILED
        task.error = error

        # Update agent stats
        agent = self._agents.get(task.assigned_agent)
        if agent:
            agent.current_tasks = max(0, agent.current_tasks - 1)
            agent.total_failed += 1
            for cap in task.required_capabilities:
                current = agent.performance_scores.get(cap, 0.5)
                agent.performance_scores[cap] = current * 0.9 + 0.1 * 0.0

        # Try to reassign
        if task.retry_count < task.max_retries:
            task.retry_count += 1
            task.reassigned_from = task.assigned_agent
            task.assigned_agent = ""
            task.state = TaskState.PENDING
            return self.delegate(task)

        return None

    def get_pending_tasks(self) -> list[DelegatedTask]:
        return [t for t in self._tasks.values() if t.state == TaskState.PENDING]

    def get_running_tasks(self) -> list[DelegatedTask]:
        return [t for t in self._tasks.values() if t.state in (TaskState.ASSIGNED, TaskState.RUNNING)]

    # ── Scoring ──────────────────────────────────────────

    def _score_match(self, agent: AgentCapability, task: DelegatedTask) -> float:
        """Score how well an agent matches a task."""
        score = 0.0

        # Capability match (most important)
        if task.required_capabilities:
            matched = sum(
                1 for cap in task.required_capabilities
                if cap in agent.specialties
            )
            score += (matched / len(task.required_capabilities)) * 0.4

        # Tool availability
        if task.required_tools:
            tool_match = sum(
                1 for tool in task.required_tools
                if tool in agent.tools
            )
            score += (tool_match / len(task.required_tools)) * 0.2

        # Expertise weighting
        for cap in task.required_capabilities:
            score += agent.get_expertise(cap) * 0.1

        # Capacity bonus (prefer less loaded agents)
        capacity_ratio = agent.available_capacity / max(1, agent.max_concurrent_tasks)
        score += capacity_ratio * 0.15

        # Success rate bonus
        score += agent.success_rate * 0.15

        return min(1.0, score)

    def get_agent_workload(self) -> dict[str, dict[str, Any]]:
        """Get current workload for all agents."""
        return {
            agent_id: {
                "current": agent.current_tasks,
                "max": agent.max_concurrent_tasks,
                "utilization": round(agent.current_tasks / max(1, agent.max_concurrent_tasks), 2),
                "completed": agent.total_completed,
                "failed": agent.total_failed,
            }
            for agent_id, agent in self._agents.items()
        }

    def get_stats(self) -> dict[str, Any]:
        by_state: dict[str, int] = defaultdict(int)
        for task in self._tasks.values():
            by_state[task.state.value] += 1
        return {
            "total_tasks": len(self._tasks),
            "by_state": dict(by_state),
            "agents": len(self._agents),
            "delegations": len(self._delegation_log),
        }
