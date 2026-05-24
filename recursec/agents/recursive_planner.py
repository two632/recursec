"""Recursive task planner — decomposes tasks into sub-tasks.

Implements:
1. Task decomposition tree
2. Depth-limited recursive planning
3. Dependency tracking between sub-tasks
4. Progress aggregation up the tree
5. Parallel execution identification
6. Planner prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskStatus(str, Enum):
    PENDING = "pending"
    PLANNING = "planning"
    IN_PROGRESS = "in_progress"
    WAITING = "waiting"       # Waiting for sub-tasks
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class TaskPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


PRIORITY_VALUES: dict[TaskPriority, int] = {
    TaskPriority.CRITICAL: 4,
    TaskPriority.HIGH: 3,
    TaskPriority.MEDIUM: 2,
    TaskPriority.LOW: 1,
}


@dataclass
class PlanTask:
    """A task in the recursive plan."""
    task_id: str = ""
    parent_id: str = ""
    depth: int = 0
    description: str = ""
    task_type: str = ""
    status: TaskStatus = TaskStatus.PENDING
    priority: TaskPriority = TaskPriority.MEDIUM
    agent_role: str = ""
    model_preference: str = ""
    dependencies: list[str] = field(default_factory=list)
    children: list[str] = field(default_factory=list)
    result: dict[str, Any] = field(default_factory=dict)
    findings_count: int = 0
    started_at: float = 0.0
    completed_at: float = 0.0
    estimated_steps: int = 1
    actual_steps: int = 0
    can_parallelize: bool = False

    @property
    def duration_s(self) -> float:
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:10],
            "desc": self.description[:20],
            "status": self.status.value[:8],
            "depth": self.depth,
            "children": len(self.children),
        }


class RecursivePlanner:
    """Recursive task decomposition and planning.

    Decomposes complex tasks into hierarchical
    sub-tasks with dependency tracking.
    """

    def __init__(
        self,
        max_depth: int = 4,
        max_children: int = 8,
        max_tasks: int = 200,
    ) -> None:
        self._tasks: dict[str, PlanTask] = {}
        self._root_tasks: list[str] = []
        self._task_counter = 0
        self._max_depth = max_depth
        self._max_children = max_children
        self._max_tasks = max_tasks
        self._log = logger.bind(component="planner")

    def create_task(
        self,
        description: str,
        parent_id: str = "",
        task_type: str = "",
        priority: TaskPriority = TaskPriority.MEDIUM,
        agent_role: str = "",
        model_preference: str = "",
        dependencies: list[str] | None = None,
        can_parallelize: bool = False,
    ) -> PlanTask:
        """Create a new task."""
        self._task_counter += 1

        depth = 0
        if parent_id:
            parent = self._tasks.get(parent_id)
            if parent:
                depth = parent.depth + 1

        if depth >= self._max_depth:
            depth = self._max_depth - 1

        task = PlanTask(
            task_id=f"task-{self._task_counter}",
            parent_id=parent_id,
            depth=depth,
            description=description,
            task_type=task_type,
            priority=priority,
            agent_role=agent_role,
            model_preference=model_preference,
            dependencies=dependencies or [],
            can_parallelize=can_parallelize,
        )

        self._tasks[task.task_id] = task

        if parent_id and parent_id in self._tasks:
            self._tasks[parent_id].children.append(task.task_id)
        elif not parent_id:
            self._root_tasks.append(task.task_id)

        return task

    def decompose(
        self,
        task_id: str,
        subtasks: list[dict[str, Any]],
    ) -> list[PlanTask]:
        """Decompose a task into sub-tasks."""
        task = self._tasks.get(task_id)
        if not task:
            return []

        if task.depth >= self._max_depth - 1:
            return []

        if len(subtasks) > self._max_children:
            subtasks = subtasks[:self._max_children]

        created = []
        for st in subtasks:
            child = self.create_task(
                description=st.get("description", ""),
                parent_id=task_id,
                task_type=st.get("type", task.task_type),
                priority=TaskPriority(st.get("priority", "medium")),
                agent_role=st.get("agent_role", ""),
                model_preference=st.get("model", ""),
                dependencies=st.get("dependencies", []),
                can_parallelize=st.get("parallel", False),
            )
            created.append(child)

        task.status = TaskStatus.WAITING
        return created

    def start_task(self, task_id: str) -> None:
        """Mark a task as started."""
        task = self._tasks.get(task_id)
        if task:
            task.status = TaskStatus.IN_PROGRESS
            task.started_at = time.time()

    def complete_task(
        self,
        task_id: str,
        result: dict[str, Any] | None = None,
        findings_count: int = 0,
    ) -> None:
        """Mark a task as completed."""
        task = self._tasks.get(task_id)
        if not task:
            return

        task.status = TaskStatus.COMPLETED
        task.completed_at = time.time()
        task.result = result or {}
        task.findings_count = findings_count

        # Check if parent should be updated
        if task.parent_id:
            self._check_parent_completion(task.parent_id)

    def fail_task(self, task_id: str, error: str = "") -> None:
        """Mark a task as failed."""
        task = self._tasks.get(task_id)
        if task:
            task.status = TaskStatus.FAILED
            task.completed_at = time.time()
            task.result = {"error": error}

    def _check_parent_completion(self, parent_id: str) -> None:
        """Check if all children are done and update parent."""
        parent = self._tasks.get(parent_id)
        if not parent:
            return

        children = [self._tasks.get(cid) for cid in parent.children]
        children = [c for c in children if c is not None]

        if not children:
            return

        all_done = all(
            c.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.SKIPPED)
            for c in children
        )

        if all_done:
            # Aggregate results
            total_findings = sum(c.findings_count for c in children)
            parent.findings_count = total_findings
            parent.status = TaskStatus.COMPLETED
            parent.completed_at = time.time()

            # Recurse up
            if parent.parent_id:
                self._check_parent_completion(parent.parent_id)

    def get_ready_tasks(self) -> list[PlanTask]:
        """Get tasks that are ready to execute."""
        ready = []
        for task in self._tasks.values():
            if task.status != TaskStatus.PENDING:
                continue

            # Check dependencies
            deps_met = all(
                self._tasks.get(dep_id, PlanTask()).status == TaskStatus.COMPLETED
                for dep_id in task.dependencies
            )

            if deps_met:
                ready.append(task)

        # Sort by priority
        ready.sort(
            key=lambda t: PRIORITY_VALUES.get(t.priority, 2),
            reverse=True,
        )

        return ready

    def get_parallel_groups(self) -> list[list[PlanTask]]:
        """Get groups of tasks that can run in parallel."""
        ready = self.get_ready_tasks()
        parallel = [t for t in ready if t.can_parallelize]
        sequential = [t for t in ready if not t.can_parallelize]

        groups = []
        if parallel:
            groups.append(parallel)
        for t in sequential:
            groups.append([t])

        return groups

    def get_progress(self) -> dict[str, Any]:
        """Get overall progress."""
        total = len(self._tasks)
        if total == 0:
            return {"total": 0, "completed": 0, "progress": 0.0}

        completed = sum(1 for t in self._tasks.values() if t.status == TaskStatus.COMPLETED)
        failed = sum(1 for t in self._tasks.values() if t.status == TaskStatus.FAILED)
        in_progress = sum(1 for t in self._tasks.values() if t.status == TaskStatus.IN_PROGRESS)

        return {
            "total": total,
            "completed": completed,
            "failed": failed,
            "in_progress": in_progress,
            "pending": total - completed - failed - in_progress,
            "progress": completed / total,
        }

    def build_planner_prompt(self, max_tasks: int = 10) -> str:
        """Build planner context for LLM."""
        lines = ["## Task Plan\n"]
        progress = self.get_progress()
        lines.append(f"Tasks: {progress['total']} ({progress['completed']} done)")
        lines.append(f"Progress: {progress['progress']:.0%}")

        # Tree view of recent tasks
        count = 0
        for task_id in self._root_tasks[-5:]:
            task = self._tasks.get(task_id)
            if not task:
                continue
            indent = "  " * task.depth
            status_icon = {
                TaskStatus.COMPLETED: "+",
                TaskStatus.FAILED: "X",
                TaskStatus.IN_PROGRESS: "~",
                TaskStatus.PENDING: "-",
            }.get(task.status, "?")

            lines.append(f"{indent}[{status_icon}] {task.description[:30]}")
            count += 1

            # Show children
            for cid in task.children[:3]:
                child = self._tasks.get(cid)
                if child and count < max_tasks:
                    c_indent = "  " * child.depth
                    c_icon = {
                        TaskStatus.COMPLETED: "+",
                        TaskStatus.FAILED: "X",
                        TaskStatus.IN_PROGRESS: "~",
                        TaskStatus.PENDING: "-",
                    }.get(child.status, "?")
                    lines.append(f"{c_indent}[{c_icon}] {child.description[:25]}")
                    count += 1

        # Ready tasks
        ready = self.get_ready_tasks()[:3]
        if ready:
            lines.append(f"\nReady ({len(ready)}):")
            for t in ready:
                lines.append(f"  {t.description[:25]}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            **self.get_progress(),
            "max_depth": self._max_depth,
            "root_tasks": len(self._root_tasks),
        }
