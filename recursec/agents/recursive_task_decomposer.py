"""Recursive task decomposer — breaks complex tasks into subtasks.

Implements:
1. Task decomposition with dependency graph
2. Recursive splitting (subtasks can be decomposed further)
3. Complexity estimation and depth control
4. Parallel execution scheduling
5. Critical path analysis
6. Task merging (combine similar subtasks)
7. Decomposition prompt for LLM
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
    READY = "ready"           # All dependencies met
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"       # Waiting on dependency


class TaskComplexity(str, Enum):
    TRIVIAL = "trivial"       # Single tool call
    SIMPLE = "simple"         # 2-3 steps
    MODERATE = "moderate"     # 5-10 steps
    COMPLEX = "complex"       # 10+ steps, needs decomposition
    VERY_COMPLEX = "very_complex"  # Recursive decomposition


@dataclass
class SubTask:
    """A subtask in the decomposition tree."""
    task_id: str = ""
    parent_id: str = ""
    name: str = ""
    description: str = ""
    complexity: TaskComplexity = TaskComplexity.SIMPLE
    status: TaskStatus = TaskStatus.PENDING
    agent_role: str = ""
    tools_needed: list[str] = field(default_factory=list)
    knowledge_domains: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    children: list[str] = field(default_factory=list)
    depth: int = 0
    estimated_tokens: int = 1000
    actual_tokens: int = 0
    results: dict[str, Any] = field(default_factory=dict)
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def is_leaf(self) -> bool:
        return len(self.children) == 0

    @property
    def is_ready(self) -> bool:
        return self.status == TaskStatus.READY

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:10],
            "name": self.name[:20],
            "status": self.status.value[:6],
            "depth": self.depth,
            "children": len(self.children),
            "deps": len(self.depends_on),
        }


class RecursiveTaskDecomposer:
    """Decomposes complex tasks into subtask trees.

    Breaks tasks recursively, builds dependency graphs,
    identifies parallelizable branches, and schedules
    execution order.
    """

    def __init__(
        self,
        max_depth: int = 5,
        max_children: int = 8,
    ) -> None:
        self._tasks: dict[str, SubTask] = {}
        self._roots: list[str] = []
        self._max_depth = max_depth
        self._max_children = max_children
        self._counter = 0
        self._log = logger.bind(component="task_decomposer")

    def create_root(
        self,
        name: str,
        description: str,
        complexity: TaskComplexity = TaskComplexity.COMPLEX,
    ) -> SubTask:
        """Create a root task."""
        self._counter += 1
        task = SubTask(
            task_id=f"task-{self._counter}",
            name=name,
            description=description,
            complexity=complexity,
            depth=0,
        )
        self._tasks[task.task_id] = task
        self._roots.append(task.task_id)
        return task

    def decompose(
        self,
        parent_id: str,
        subtasks: list[dict[str, Any]],
    ) -> list[SubTask]:
        """Decompose a task into subtasks."""
        parent = self._tasks.get(parent_id)
        if not parent:
            return []

        if parent.depth >= self._max_depth:
            return []

        created: list[SubTask] = []
        for spec in subtasks[:self._max_children]:
            self._counter += 1
            task = SubTask(
                task_id=f"task-{self._counter}",
                parent_id=parent_id,
                name=spec.get("name", ""),
                description=spec.get("description", ""),
                complexity=TaskComplexity(spec.get("complexity", "simple")),
                agent_role=spec.get("role", ""),
                tools_needed=spec.get("tools", []),
                knowledge_domains=spec.get("knowledge", []),
                depends_on=spec.get("depends_on", []),
                depth=parent.depth + 1,
                estimated_tokens=spec.get("tokens", 1000),
            )
            self._tasks[task.task_id] = task
            parent.children.append(task.task_id)
            created.append(task)

        return created

    def get_ready_tasks(self) -> list[SubTask]:
        """Get all tasks ready for execution."""
        ready: list[SubTask] = []
        for task in self._tasks.values():
            if task.status != TaskStatus.PENDING:
                continue
            # Check if all dependencies are completed
            deps_met = all(
                self._tasks.get(dep_id, SubTask()).status == TaskStatus.COMPLETED
                for dep_id in task.depends_on
            )
            if deps_met and task.is_leaf:
                task.status = TaskStatus.READY
                ready.append(task)
        return ready

    def start_task(self, task_id: str) -> bool:
        """Mark a task as started."""
        task = self._tasks.get(task_id)
        if not task:
            return False
        task.status = TaskStatus.RUNNING
        task.started_at = time.time()
        return True

    def complete_task(
        self,
        task_id: str,
        results: dict[str, Any] | None = None,
        tokens_used: int = 0,
    ) -> bool:
        """Mark a task as completed."""
        task = self._tasks.get(task_id)
        if not task:
            return False
        task.status = TaskStatus.COMPLETED
        task.completed_at = time.time()
        task.results = results or {}
        task.actual_tokens = tokens_used

        # Check if parent is now complete
        if task.parent_id:
            self._check_parent_completion(task.parent_id)

        return True

    def fail_task(self, task_id: str, reason: str = "") -> bool:
        """Mark a task as failed."""
        task = self._tasks.get(task_id)
        if not task:
            return False
        task.status = TaskStatus.FAILED
        task.completed_at = time.time()
        task.results = {"error": reason}
        return True

    def _check_parent_completion(self, parent_id: str) -> None:
        """Check if all children are complete and mark parent."""
        parent = self._tasks.get(parent_id)
        if not parent:
            return

        children_status = [
            self._tasks[cid].status
            for cid in parent.children
            if cid in self._tasks
        ]

        if all(s == TaskStatus.COMPLETED for s in children_status):
            parent.status = TaskStatus.COMPLETED
            parent.completed_at = time.time()
            if parent.parent_id:
                self._check_parent_completion(parent.parent_id)

    def get_critical_path(self, root_id: str = "") -> list[SubTask]:
        """Get the critical path (longest dependency chain)."""
        if not root_id and self._roots:
            root_id = self._roots[0]

        def _longest_path(task_id: str) -> list[str]:
            task = self._tasks.get(task_id)
            if not task or not task.children:
                return [task_id]

            longest: list[str] = []
            for child_id in task.children:
                path = _longest_path(child_id)
                if len(path) > len(longest):
                    longest = path

            return [task_id] + longest

        path_ids = _longest_path(root_id)
        return [self._tasks[tid] for tid in path_ids if tid in self._tasks]

    def get_parallel_groups(self) -> list[list[SubTask]]:
        """Get groups of tasks that can run in parallel."""
        groups: list[list[SubTask]] = []
        remaining = {
            tid for tid, t in self._tasks.items()
            if t.status == TaskStatus.PENDING and t.is_leaf
        }
        completed = {
            tid for tid, t in self._tasks.items()
            if t.status == TaskStatus.COMPLETED
        }

        while remaining:
            group: list[SubTask] = []
            for tid in list(remaining):
                task = self._tasks[tid]
                deps_met = all(d in completed for d in task.depends_on)
                if deps_met:
                    group.append(task)
            if not group:
                break
            groups.append(group)
            for t in group:
                remaining.discard(t.task_id)
                completed.add(t.task_id)

        return groups

    def build_decomposition_prompt(self, root_id: str = "") -> str:
        """Build decomposition context for LLM."""
        lines = ["## Task Decomposition\n"]

        total = len(self._tasks)
        completed = sum(1 for t in self._tasks.values() if t.status == TaskStatus.COMPLETED)
        running = sum(1 for t in self._tasks.values() if t.status == TaskStatus.RUNNING)
        pending = sum(1 for t in self._tasks.values() if t.status in (TaskStatus.PENDING, TaskStatus.READY))

        lines.append(
            f"Tasks: {total} total — "
            f"{completed} done, {running} running, {pending} pending"
        )

        # Show tree for root
        target_root = root_id or (self._roots[0] if self._roots else "")
        if target_root and target_root in self._tasks:
            lines.append("\nTree:")
            self._tree_lines(target_root, lines, indent=0, max_depth=3)

        return "\n".join(lines)

    def _tree_lines(
        self,
        task_id: str,
        lines: list[str],
        indent: int,
        max_depth: int,
    ) -> None:
        """Build tree visualization lines."""
        task = self._tasks.get(task_id)
        if not task or indent > max_depth:
            return
        prefix = "  " * indent
        status_icon = {
            "completed": "[+]",
            "running": "[>]",
            "failed": "[!]",
            "pending": "[ ]",
            "ready": "[*]",
        }.get(task.status.value, "[?]")
        lines.append(f"{prefix}{status_icon} {task.name[:25]}")
        for child_id in task.children[:5]:
            self._tree_lines(child_id, lines, indent + 1, max_depth)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for t in self._tasks.values():
            s = t.status.value
            status_counts[s] = status_counts.get(s, 0) + 1

        depths = [t.depth for t in self._tasks.values()]
        return {
            "total_tasks": len(self._tasks),
            "roots": len(self._roots),
            "max_depth": max(depths) if depths else 0,
            "by_status": status_counts,
        }
