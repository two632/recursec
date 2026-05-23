"""Task DAG planner — directed acyclic graph for task decomposition.

Implements:
1. Task node creation with dependencies
2. Topological ordering for execution
3. Parallel task scheduling
4. Dependency resolution
5. Budget propagation through task tree
6. Task status tracking
7. Critical path analysis
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"           # All dependencies met
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"       # Dependency failed


class TaskPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class TaskNode:
    """A task in the DAG."""
    task_id: str = ""
    name: str = ""
    description: str = ""
    agent_role: str = ""
    tool: str = ""
    priority: TaskPriority = TaskPriority.MEDIUM
    status: TaskStatus = TaskStatus.PENDING
    dependencies: list[str] = field(default_factory=list)
    dependents: list[str] = field(default_factory=list)
    token_budget: int = 0
    time_budget_s: float = 0.0
    tokens_used: int = 0
    duration_s: float = 0.0
    result: str = ""
    findings: int = 0
    started_at: float = 0.0
    completed_at: float = 0.0
    retries: int = 0
    max_retries: int = 2

    @property
    def is_terminal(self) -> bool:
        return self.status in (
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.SKIPPED,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:10],
            "name": self.name[:20],
            "status": self.status.value,
            "deps": len(self.dependencies),
            "findings": self.findings,
        }


@dataclass
class DAGExecutionPlan:
    """Execution plan from the DAG."""
    levels: list[list[str]] = field(default_factory=list)
    critical_path: list[str] = field(default_factory=list)
    total_tasks: int = 0
    parallelizable: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "levels": len(self.levels),
            "tasks": self.total_tasks,
            "parallelizable": self.parallelizable,
            "critical_path": len(self.critical_path),
        }


class TaskDAG:
    """Directed acyclic graph for task planning.

    Decomposes assessment objectives into
    tasks with dependencies, computes execution
    order, and identifies parallel opportunities.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, TaskNode] = {}
        self._counter = 0
        self._log = logger.bind(component="task_dag")

    def add_task(
        self,
        name: str,
        description: str = "",
        agent_role: str = "",
        tool: str = "",
        priority: TaskPriority = TaskPriority.MEDIUM,
        dependencies: list[str] | None = None,
        token_budget: int = 0,
        time_budget_s: float = 0.0,
    ) -> TaskNode:
        """Add a task to the DAG."""
        self._counter += 1
        task = TaskNode(
            task_id=f"task-{self._counter}",
            name=name,
            description=description,
            agent_role=agent_role,
            tool=tool,
            priority=priority,
            dependencies=dependencies or [],
            token_budget=token_budget,
            time_budget_s=time_budget_s,
        )
        self._tasks[task.task_id] = task

        # Register as dependent on each dependency
        for dep_id in task.dependencies:
            dep = self._tasks.get(dep_id)
            if dep:
                dep.dependents.append(task.task_id)

        return task

    def mark_ready(self, task_id: str) -> bool:
        """Check and mark task as ready if all deps are complete."""
        task = self._tasks.get(task_id)
        if not task or task.status != TaskStatus.PENDING:
            return False

        for dep_id in task.dependencies:
            dep = self._tasks.get(dep_id)
            if not dep or dep.status != TaskStatus.COMPLETED:
                return False

        task.status = TaskStatus.READY
        return True

    def start_task(self, task_id: str) -> bool:
        """Mark task as running."""
        task = self._tasks.get(task_id)
        if not task or task.status not in (TaskStatus.READY, TaskStatus.PENDING):
            return False

        task.status = TaskStatus.RUNNING
        task.started_at = time.time()
        return True

    def complete_task(
        self,
        task_id: str,
        result: str = "",
        findings: int = 0,
        tokens_used: int = 0,
    ) -> list[str]:
        """Complete a task and return newly ready tasks."""
        task = self._tasks.get(task_id)
        if not task:
            return []

        task.status = TaskStatus.COMPLETED
        task.completed_at = time.time()
        task.duration_s = task.completed_at - task.started_at
        task.result = result
        task.findings = findings
        task.tokens_used = tokens_used

        # Check which dependents are now ready
        newly_ready = []
        for dep_id in task.dependents:
            if self.mark_ready(dep_id):
                newly_ready.append(dep_id)

        return newly_ready

    def fail_task(self, task_id: str, reason: str = "") -> list[str]:
        """Fail a task and cascade to dependents."""
        task = self._tasks.get(task_id)
        if not task:
            return []

        # Check for retries
        if task.retries < task.max_retries:
            task.retries += 1
            task.status = TaskStatus.READY
            return [task_id]

        task.status = TaskStatus.FAILED
        task.result = reason

        # Cascade failure to dependents
        blocked = []
        for dep_id in task.dependents:
            dep = self._tasks.get(dep_id)
            if dep and dep.status == TaskStatus.PENDING:
                dep.status = TaskStatus.BLOCKED
                blocked.append(dep_id)

        return blocked

    def get_ready_tasks(self) -> list[TaskNode]:
        """Get all tasks that are ready to execute."""
        ready = []
        for task in self._tasks.values():
            if task.status == TaskStatus.READY:
                ready.append(task)
            elif task.status == TaskStatus.PENDING:
                self.mark_ready(task.task_id)
                if task.status == TaskStatus.READY:
                    ready.append(task)

        # Sort by priority
        priority_order = {
            TaskPriority.CRITICAL: 0,
            TaskPriority.HIGH: 1,
            TaskPriority.MEDIUM: 2,
            TaskPriority.LOW: 3,
        }
        ready.sort(key=lambda t: priority_order.get(t.priority, 2))
        return ready

    def topological_sort(self) -> list[list[str]]:
        """Compute topological ordering (level-based)."""
        in_degree: dict[str, int] = {}
        for task_id, task in self._tasks.items():
            in_degree[task_id] = len(task.dependencies)

        levels: list[list[str]] = []
        remaining = set(self._tasks.keys())

        while remaining:
            # Find all tasks with no remaining dependencies
            level = [
                tid for tid in remaining
                if in_degree.get(tid, 0) == 0
            ]

            if not level:
                break  # Cycle detected

            levels.append(level)

            for tid in level:
                remaining.discard(tid)
                task = self._tasks.get(tid)
                if task:
                    for dep_id in task.dependents:
                        if dep_id in in_degree:
                            in_degree[dep_id] -= 1

        return levels

    def get_critical_path(self) -> list[str]:
        """Find the critical path (longest dependency chain)."""
        dist: dict[str, int] = {}
        pred: dict[str, str] = {}

        for task_id in self._tasks:
            dist[task_id] = 0
            pred[task_id] = ""

        levels = self.topological_sort()
        for level in levels:
            for task_id in level:
                task = self._tasks.get(task_id)
                if task:
                    for dep_id in task.dependents:
                        if dist.get(dep_id, 0) < dist.get(task_id, 0) + 1:
                            dist[dep_id] = dist.get(task_id, 0) + 1
                            pred[dep_id] = task_id

        if not dist:
            return []

        # Find the endpoint of the longest path
        end_id = max(dist, key=lambda x: dist[x])
        path = [end_id]
        current = end_id
        while pred.get(current, ""):
            current = pred[current]
            path.append(current)

        path.reverse()
        return path

    def build_execution_plan(self) -> DAGExecutionPlan:
        """Build a full execution plan."""
        levels = self.topological_sort()
        critical = self.get_critical_path()
        parallelizable = sum(len(level) - 1 for level in levels if len(level) > 1)

        return DAGExecutionPlan(
            levels=levels,
            critical_path=critical,
            total_tasks=len(self._tasks),
            parallelizable=parallelizable,
        )

    def build_dag_prompt(self) -> str:
        """Build DAG visualization for LLM context."""
        lines = ["## Task DAG\n"]
        plan = self.build_execution_plan()

        lines.append(f"Tasks: {plan.total_tasks}, "
                      f"Levels: {len(plan.levels)}, "
                      f"Parallelizable: {plan.parallelizable}")

        for idx, level in enumerate(plan.levels):
            task_names = []
            for tid in level:
                task = self._tasks.get(tid)
                if task:
                    task_names.append(f"{task.name} [{task.status.value}]")
            lines.append(f"Level {idx}: {', '.join(task_names)}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for task in self._tasks.values():
            status_counts[task.status.value] += 1

        return {
            "total_tasks": len(self._tasks),
            "by_status": dict(status_counts),
            "total_findings": sum(t.findings for t in self._tasks.values()),
        }
