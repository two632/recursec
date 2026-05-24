"""Task dependency graph — DAG-based task scheduling.

Implements:
1. Directed acyclic graph for task dependencies
2. Topological ordering
3. Cycle detection
4. Critical path analysis
5. Parallel execution groups
6. Task graph prompt for LLM
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskState(str, Enum):
    BLOCKED = "blocked"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


PRIORITY_WEIGHTS: dict[TaskPriority, int] = {
    TaskPriority.CRITICAL: 4,
    TaskPriority.HIGH: 3,
    TaskPriority.MEDIUM: 2,
    TaskPriority.LOW: 1,
}


@dataclass
class TaskNode:
    """A node in the task dependency graph."""
    task_id: str = ""
    name: str = ""
    state: TaskState = TaskState.BLOCKED
    priority: TaskPriority = TaskPriority.MEDIUM
    dependencies: list[str] = field(default_factory=list)
    dependents: list[str] = field(default_factory=list)
    agent_role: str = ""
    estimated_duration_s: float = 60.0
    actual_duration_s: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0
    result: dict[str, Any] = field(default_factory=dict)

    @property
    def is_terminal(self) -> bool:
        return self.state in (TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:10],
            "name": self.name[:15],
            "state": self.state.value[:5],
            "deps": len(self.dependencies),
        }


class TaskDependencyGraph:
    """DAG-based task scheduling engine.

    Manages dependencies, topological ordering,
    parallel execution groups, and critical path.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, TaskNode] = {}
        self._task_counter = 0
        self._log = logger.bind(component="task_dag")

    def add_task(
        self,
        name: str,
        dependencies: list[str] | None = None,
        priority: TaskPriority = TaskPriority.MEDIUM,
        agent_role: str = "",
        estimated_duration_s: float = 60.0,
    ) -> TaskNode:
        """Add a task node."""
        self._task_counter += 1
        task_id = f"task-{self._task_counter}"

        deps = dependencies or []

        node = TaskNode(
            task_id=task_id,
            name=name,
            dependencies=deps,
            priority=priority,
            agent_role=agent_role,
            estimated_duration_s=estimated_duration_s,
        )

        # Determine initial state
        if not deps:
            node.state = TaskState.READY
        else:
            all_met = all(
                self._nodes.get(d) and self._nodes[d].state == TaskState.COMPLETED
                for d in deps
            )
            node.state = TaskState.READY if all_met else TaskState.BLOCKED

        self._nodes[task_id] = node

        # Register as dependent of dependencies
        for dep_id in deps:
            if dep_id in self._nodes:
                self._nodes[dep_id].dependents.append(task_id)

        return node

    def add_dependency(self, task_id: str, depends_on: str) -> bool:
        """Add a dependency edge."""
        if task_id not in self._nodes or depends_on not in self._nodes:
            return False

        # Check for cycle
        if self._would_create_cycle(task_id, depends_on):
            return False

        node = self._nodes[task_id]
        if depends_on not in node.dependencies:
            node.dependencies.append(depends_on)
            self._nodes[depends_on].dependents.append(task_id)

        # Update state
        self._update_state(task_id)
        return True

    def _would_create_cycle(self, task_id: str, new_dep: str) -> bool:
        """Check if adding dependency would create a cycle."""
        # If new_dep can reach task_id, adding the edge would create a cycle
        visited: set[str] = set()
        queue: deque[str] = deque([task_id])

        while queue:
            current = queue.popleft()
            if current == new_dep:
                return True
            if current in visited:
                continue
            visited.add(current)
            node = self._nodes.get(current)
            if node:
                queue.extend(node.dependents)

        return False

    def _update_state(self, task_id: str) -> None:
        """Update task state based on dependencies."""
        node = self._nodes.get(task_id)
        if not node or node.is_terminal or node.state == TaskState.RUNNING:
            return

        all_met = all(
            self._nodes.get(d) and self._nodes[d].state == TaskState.COMPLETED
            for d in node.dependencies
        )
        node.state = TaskState.READY if all_met else TaskState.BLOCKED

    def start_task(self, task_id: str) -> bool:
        """Mark a task as running."""
        node = self._nodes.get(task_id)
        if not node or node.state != TaskState.READY:
            return False

        node.state = TaskState.RUNNING
        node.started_at = time.time()
        return True

    def complete_task(
        self,
        task_id: str,
        result: dict[str, Any] | None = None,
        success: bool = True,
    ) -> list[TaskNode]:
        """Complete a task and return newly ready tasks."""
        node = self._nodes.get(task_id)
        if not node:
            return []

        node.state = TaskState.COMPLETED if success else TaskState.FAILED
        node.completed_at = time.time()
        node.actual_duration_s = node.completed_at - node.started_at
        if result:
            node.result = result

        # Update dependents
        newly_ready = []
        for dep_id in node.dependents:
            self._update_state(dep_id)
            dep_node = self._nodes.get(dep_id)
            if dep_node and dep_node.state == TaskState.READY:
                newly_ready.append(dep_node)

        return newly_ready

    def topological_sort(self) -> list[str]:
        """Get topological ordering of tasks."""
        in_degree: dict[str, int] = {}
        for node in self._nodes.values():
            in_degree.setdefault(node.task_id, 0)
            for dep_id in node.dependents:
                in_degree[dep_id] = in_degree.get(dep_id, 0) + 1

        queue: deque[str] = deque()
        for task_id, degree in in_degree.items():
            if degree == 0:
                queue.append(task_id)

        order = []
        while queue:
            current = queue.popleft()
            order.append(current)
            node = self._nodes.get(current)
            if node:
                for dep_id in node.dependents:
                    in_degree[dep_id] -= 1
                    if in_degree[dep_id] == 0:
                        queue.append(dep_id)

        return order

    def get_parallel_groups(self) -> list[list[str]]:
        """Get groups of tasks that can run in parallel."""
        groups: list[list[str]] = []
        completed: set[str] = set()
        remaining = set(self._nodes.keys())

        while remaining:
            group = []
            for task_id in list(remaining):
                node = self._nodes[task_id]
                deps_met = all(d in completed for d in node.dependencies)
                if deps_met:
                    group.append(task_id)

            if not group:
                break

            groups.append(group)
            for task_id in group:
                completed.add(task_id)
                remaining.discard(task_id)

        return groups

    def get_critical_path(self) -> list[str]:
        """Get the critical path (longest path)."""
        # Calculate earliest start/finish
        order = self.topological_sort()
        earliest_finish: dict[str, float] = {}

        for task_id in order:
            node = self._nodes[task_id]
            earliest_start = 0.0
            for dep_id in node.dependencies:
                if dep_id in earliest_finish:
                    earliest_start = max(earliest_start, earliest_finish[dep_id])
            earliest_finish[task_id] = earliest_start + node.estimated_duration_s

        if not earliest_finish:
            return []

        # Trace back from latest finish
        path = []
        current = max(earliest_finish, key=earliest_finish.get)  # type: ignore[arg-type]
        while current:
            path.append(current)
            node = self._nodes[current]
            # Find the dependency with the latest finish
            next_node = ""
            max_finish = -1.0
            for dep_id in node.dependencies:
                if dep_id in earliest_finish and earliest_finish[dep_id] > max_finish:
                    max_finish = earliest_finish[dep_id]
                    next_node = dep_id
            current = next_node

        path.reverse()
        return path

    def get_ready_tasks(self) -> list[TaskNode]:
        """Get all tasks ready to execute."""
        ready = [n for n in self._nodes.values() if n.state == TaskState.READY]
        ready.sort(
            key=lambda n: PRIORITY_WEIGHTS.get(n.priority, 2),
            reverse=True,
        )
        return ready

    def build_graph_prompt(self) -> str:
        """Build task graph context for LLM."""
        lines = ["## Task Graph\n"]
        lines.append(f"Tasks: {len(self._nodes)}")

        # State counts
        state_counts: dict[str, int] = {}
        for n in self._nodes.values():
            s = n.state.value
            state_counts[s] = state_counts.get(s, 0) + 1

        for state, count in state_counts.items():
            lines.append(f"  {state}: {count}")

        # Ready tasks
        ready = self.get_ready_tasks()
        if ready:
            lines.append(f"\nReady ({len(ready)}):")
            for t in ready[:5]:
                lines.append(f"  {t.name[:20]} [{t.priority.value}]")

        # Critical path
        cp = self.get_critical_path()
        if cp:
            total_est = sum(self._nodes[t].estimated_duration_s for t in cp)
            lines.append(f"\nCritical path ({len(cp)} tasks, ~{total_est:.0f}s):")
            for task_id in cp[:5]:
                n = self._nodes[task_id]
                lines.append(f"  {n.name[:20]}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        state_counts: dict[str, int] = {}
        for n in self._nodes.values():
            s = n.state.value
            state_counts[s] = state_counts.get(s, 0) + 1

        return {
            "tasks": len(self._nodes),
            "by_state": state_counts,
            "ready": len(self.get_ready_tasks()),
            "critical_path_len": len(self.get_critical_path()),
        }
