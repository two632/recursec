"""Multi-task coordinator — manages concurrent tasks with shared resources.

Implements:
1. Concurrent task management
2. Resource allocation across tasks
3. Inter-task dependency management
4. Task priority scheduling
5. Result merging from concurrent tasks
6. Deadlock detection and resolution
7. Task migration (move to better agent)
8. Progress tracking across all tasks
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"
    BACKGROUND = "background"


class TaskState(str, Enum):
    QUEUED = "queued"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    MIGRATING = "migrating"


@dataclass
class ManagedTask:
    """A task managed by the coordinator."""
    task_id: str = ""
    name: str = ""
    target: str = ""
    priority: TaskPriority = TaskPriority.NORMAL
    state: TaskState = TaskState.QUEUED
    assigned_agent: str = ""
    required_resources: dict[str, int] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    progress: float = 0.0
    result: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    tokens_budget: int = 10000
    tokens_used: int = 0
    retries: int = 0
    max_retries: int = 3

    @property
    def is_active(self) -> bool:
        return self.state in (TaskState.RUNNING, TaskState.WAITING, TaskState.MIGRATING)

    @property
    def can_start(self) -> bool:
        return self.state == TaskState.QUEUED and not self.dependencies

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id,
            "name": self.name[:25],
            "priority": self.priority.value,
            "state": self.state.value,
            "agent": self.assigned_agent[:15],
            "progress": round(self.progress, 2),
            "deps": len(self.dependencies),
        }


@dataclass
class ResourcePool:
    """A pool of shared resources."""
    name: str = ""
    total: int = 0
    available: int = 0
    reservations: dict[str, int] = field(default_factory=dict)

    def reserve(self, task_id: str, amount: int) -> bool:
        if amount > self.available:
            return False
        self.reservations[task_id] = amount
        self.available -= amount
        return True

    def release(self, task_id: str) -> None:
        amount = self.reservations.pop(task_id, 0)
        self.available += amount

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:15],
            "total": self.total,
            "available": self.available,
            "reservations": len(self.reservations),
        }


# ── Priority Weights ──────────────────────────────────────────

PRIORITY_WEIGHTS: dict[TaskPriority, int] = {
    TaskPriority.CRITICAL: 100,
    TaskPriority.HIGH: 50,
    TaskPriority.NORMAL: 20,
    TaskPriority.LOW: 5,
    TaskPriority.BACKGROUND: 1,
}


class MultiTaskCoordinator:
    """Manages concurrent tasks with shared resources.

    Handles scheduling, resource allocation, dependency
    management, and progress tracking across all tasks.
    """

    def __init__(
        self,
        max_concurrent: int = 10,
    ) -> None:
        self._tasks: dict[str, ManagedTask] = {}
        self._resources: dict[str, ResourcePool] = {}
        self._task_counter = 0
        self._max_concurrent = max_concurrent
        self._log = logger.bind(component="multi_task_coordinator")

        # Initialize default resource pools
        self._resources["tokens"] = ResourcePool(
            name="tokens", total=500000, available=500000
        )
        self._resources["model_slots"] = ResourcePool(
            name="model_slots", total=16, available=16
        )
        self._resources["tool_slots"] = ResourcePool(
            name="tool_slots", total=10, available=10
        )

    def submit(
        self,
        name: str,
        target: str = "",
        priority: TaskPriority = TaskPriority.NORMAL,
        dependencies: list[str] | None = None,
        tokens_budget: int = 10000,
        resources: dict[str, int] | None = None,
    ) -> ManagedTask:
        """Submit a new task."""
        self._task_counter += 1
        task = ManagedTask(
            task_id=f"mt-{self._task_counter}",
            name=name,
            target=target,
            priority=priority,
            dependencies=dependencies or [],
            tokens_budget=tokens_budget,
            required_resources=resources or {},
        )

        self._tasks[task.task_id] = task
        return task

    def schedule(self) -> list[ManagedTask]:
        """Schedule ready tasks based on priority and resources."""
        # Count currently active tasks
        active_count = sum(1 for t in self._tasks.values() if t.is_active)
        slots = self._max_concurrent - active_count

        if slots <= 0:
            return []

        # Get schedulable tasks (queued, deps met)
        schedulable = []
        for task in self._tasks.values():
            if not task.can_start:
                continue

            # Check dependencies
            deps_met = True
            for dep_id in task.dependencies:
                dep = self._tasks.get(dep_id)
                if dep and dep.state != TaskState.COMPLETED:
                    deps_met = False
                    break

            if deps_met:
                task.dependencies = []  # Clear resolved deps
                schedulable.append(task)

        # Sort by priority
        schedulable.sort(
            key=lambda t: PRIORITY_WEIGHTS.get(t.priority, 0),
            reverse=True,
        )

        # Schedule up to available slots
        scheduled = []
        for task in schedulable[:slots]:
            # Try to reserve resources
            reserved = self._try_reserve_resources(task)
            if reserved:
                task.state = TaskState.SCHEDULED
                task.started_at = time.time()
                scheduled.append(task)

        return scheduled

    def start_task(self, task_id: str, agent_id: str = "") -> bool:
        """Mark a task as started."""
        task = self._tasks.get(task_id)
        if not task or task.state not in (TaskState.SCHEDULED, TaskState.QUEUED):
            return False

        task.state = TaskState.RUNNING
        task.assigned_agent = agent_id
        if not task.started_at:
            task.started_at = time.time()
        return True

    def update_progress(
        self,
        task_id: str,
        progress: float,
        tokens_used: int = 0,
    ) -> None:
        """Update task progress."""
        task = self._tasks.get(task_id)
        if task:
            task.progress = min(1.0, progress)
            task.tokens_used += tokens_used

    def complete_task(
        self,
        task_id: str,
        result: dict[str, Any],
        success: bool = True,
    ) -> list[ManagedTask]:
        """Complete a task and unblock dependents."""
        task = self._tasks.get(task_id)
        if not task:
            return []

        task.state = TaskState.COMPLETED if success else TaskState.FAILED
        task.result = result
        task.progress = 1.0 if success else task.progress
        task.completed_at = time.time()

        # Release resources
        self._release_resources(task)

        # Handle failure with retry
        if not success and task.retries < task.max_retries:
            task.retries += 1
            task.state = TaskState.QUEUED
            task.progress = 0.0
            return []

        # Unblock dependent tasks
        unblocked = []
        for other in self._tasks.values():
            if task_id in other.dependencies:
                other.dependencies.remove(task_id)
                if other.can_start:
                    unblocked.append(other)

        return unblocked

    def cancel_task(self, task_id: str) -> None:
        """Cancel a task."""
        task = self._tasks.get(task_id)
        if task:
            task.state = TaskState.CANCELLED
            self._release_resources(task)

    def detect_deadlocks(self) -> list[list[str]]:
        """Detect circular dependencies (deadlocks)."""
        # Build dependency graph
        graph: dict[str, list[str]] = defaultdict(list)
        for task in self._tasks.values():
            if task.state in (TaskState.QUEUED, TaskState.WAITING):
                for dep_id in task.dependencies:
                    graph[task.task_id].append(dep_id)

        # Find cycles using DFS
        cycles = []
        visited: set[str] = set()
        in_stack: set[str] = set()
        path: list[str] = []

        def dfs(node: str) -> None:
            visited.add(node)
            in_stack.add(node)
            path.append(node)

            for neighbor in graph.get(node, []):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in in_stack:
                    # Found cycle
                    cycle_start = path.index(neighbor)
                    cycles.append(path[cycle_start:])

            path.pop()
            in_stack.discard(node)

        for node in graph:
            if node not in visited:
                dfs(node)

        return cycles

    def _try_reserve_resources(self, task: ManagedTask) -> bool:
        """Try to reserve all required resources."""
        for resource_name, amount in task.required_resources.items():
            pool = self._resources.get(resource_name)
            if not pool or not pool.reserve(task.task_id, amount):
                # Rollback any reservations
                for rname in task.required_resources:
                    pool = self._resources.get(rname)
                    if pool:
                        pool.release(task.task_id)
                return False
        return True

    def _release_resources(self, task: ManagedTask) -> None:
        """Release all resources held by a task."""
        for resource_name in task.required_resources:
            pool = self._resources.get(resource_name)
            if pool:
                pool.release(task.task_id)

    def get_progress(self) -> dict[str, Any]:
        """Get overall progress."""
        total = len(self._tasks)
        completed = sum(1 for t in self._tasks.values() if t.state == TaskState.COMPLETED)
        failed = sum(1 for t in self._tasks.values() if t.state == TaskState.FAILED)

        return {
            "total": total,
            "completed": completed,
            "failed": failed,
            "active": sum(1 for t in self._tasks.values() if t.is_active),
            "queued": sum(1 for t in self._tasks.values() if t.state == TaskState.QUEUED),
            "progress": round(completed / max(1, total), 2),
        }

    def get_stats(self) -> dict[str, Any]:
        return self.get_progress()
