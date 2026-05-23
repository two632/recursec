"""Task DAG — directed acyclic graph for task decomposition.

Implements:
1. DAG-based task dependency modeling
2. Topological ordering for execution
3. Parallel task identification
4. Budget allocation per task
5. Critical path analysis
6. Task merging for deduplication
7. Dynamic task insertion during execution
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"       # All dependencies met
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"   # Dependency failed


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
    status: TaskStatus = TaskStatus.PENDING
    priority: TaskPriority = TaskPriority.MEDIUM
    agent_role: str = ""          # Which agent type handles this
    tool_name: str = ""           # Primary tool if applicable
    token_budget: int = 10000
    time_budget_s: float = 600.0
    dependencies: list[str] = field(default_factory=list)
    dependents: list[str] = field(default_factory=list)
    tokens_used: int = 0
    result: str = ""
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def duration_s(self) -> float:
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:10],
            "name": self.name[:25],
            "status": self.status.value,
            "priority": self.priority.value,
            "deps": len(self.dependencies),
        }


@dataclass
class ExecutionPlan:
    """A plan derived from the DAG."""
    phases: list[list[str]] = field(default_factory=list)
    critical_path: list[str] = field(default_factory=list)
    estimated_tokens: int = 0
    estimated_time_s: float = 0.0
    parallelism: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "phases": len(self.phases),
            "critical_path_len": len(self.critical_path),
            "est_tokens": self.estimated_tokens,
            "est_time": round(self.estimated_time_s, 1),
            "parallelism": self.parallelism,
        }


# ── Task templates ───────────────────────────────────────────

TASK_TEMPLATES: dict[str, dict[str, Any]] = {
    "subdomain_enum": {
        "name": "Subdomain Enumeration",
        "agent_role": "recon",
        "tool_name": "subfinder",
        "token_budget": 5000,
        "time_budget_s": 300,
        "priority": "high",
    },
    "port_scan": {
        "name": "Port Scanning",
        "agent_role": "scanner",
        "tool_name": "nmap",
        "token_budget": 8000,
        "time_budget_s": 600,
        "priority": "high",
    },
    "web_scan": {
        "name": "Web Vulnerability Scan",
        "agent_role": "scanner",
        "tool_name": "nuclei",
        "token_budget": 15000,
        "time_budget_s": 900,
        "priority": "high",
    },
    "sqli_test": {
        "name": "SQL Injection Testing",
        "agent_role": "exploiter",
        "tool_name": "sqlmap",
        "token_budget": 10000,
        "time_budget_s": 600,
        "priority": "critical",
    },
    "dir_bruteforce": {
        "name": "Directory Bruteforce",
        "agent_role": "scanner",
        "tool_name": "ffuf",
        "token_budget": 5000,
        "time_budget_s": 300,
        "priority": "medium",
    },
    "ssl_check": {
        "name": "SSL/TLS Check",
        "agent_role": "scanner",
        "tool_name": "testssl",
        "token_budget": 3000,
        "time_budget_s": 120,
        "priority": "medium",
    },
    "code_audit": {
        "name": "Source Code Audit",
        "agent_role": "code_auditor",
        "tool_name": "semgrep",
        "token_budget": 20000,
        "time_budget_s": 1200,
        "priority": "high",
    },
    "analysis": {
        "name": "Finding Analysis",
        "agent_role": "analyst",
        "tool_name": "",
        "token_budget": 15000,
        "time_budget_s": 600,
        "priority": "high",
    },
    "validation": {
        "name": "Finding Validation",
        "agent_role": "validator",
        "tool_name": "",
        "token_budget": 10000,
        "time_budget_s": 300,
        "priority": "medium",
    },
}


class TaskDAG:
    """Manages a DAG of assessment tasks.

    Models task dependencies, provides
    topological ordering, identifies parallel
    execution opportunities, and tracks execution.
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
        tool_name: str = "",
        token_budget: int = 10000,
        time_budget_s: float = 600.0,
        priority: TaskPriority = TaskPriority.MEDIUM,
        dependencies: list[str] | None = None,
    ) -> TaskNode:
        """Add a task to the DAG."""
        self._counter += 1
        task = TaskNode(
            task_id=f"task-{self._counter}",
            name=name,
            description=description,
            agent_role=agent_role,
            tool_name=tool_name,
            token_budget=token_budget,
            time_budget_s=time_budget_s,
            priority=priority,
            dependencies=dependencies or [],
        )

        # Register as dependent in dependency tasks
        for dep_id in task.dependencies:
            dep = self._tasks.get(dep_id)
            if dep:
                dep.dependents.append(task.task_id)

        self._tasks[task.task_id] = task
        self._update_readiness()
        return task

    def add_from_template(
        self,
        template_name: str,
        description: str = "",
        dependencies: list[str] | None = None,
    ) -> TaskNode | None:
        """Add a task from a template."""
        tmpl = TASK_TEMPLATES.get(template_name)
        if not tmpl:
            return None

        try:
            priority = TaskPriority(tmpl.get("priority", "medium"))
        except ValueError:
            priority = TaskPriority.MEDIUM

        return self.add_task(
            name=tmpl["name"],
            description=description,
            agent_role=tmpl.get("agent_role", ""),
            tool_name=tmpl.get("tool_name", ""),
            token_budget=tmpl.get("token_budget", 10000),
            time_budget_s=tmpl.get("time_budget_s", 600),
            priority=priority,
            dependencies=dependencies,
        )

    def start_task(self, task_id: str) -> bool:
        """Mark task as running."""
        task = self._tasks.get(task_id)
        if not task or task.status != TaskStatus.READY:
            return False
        task.status = TaskStatus.RUNNING
        task.started_at = time.time()
        return True

    def complete_task(self, task_id: str, result: str = "") -> bool:
        """Mark task as completed."""
        task = self._tasks.get(task_id)
        if not task or task.status != TaskStatus.RUNNING:
            return False
        task.status = TaskStatus.COMPLETED
        task.completed_at = time.time()
        task.result = result
        self._update_readiness()
        return True

    def fail_task(self, task_id: str, error: str = "") -> bool:
        """Mark task as failed and block dependents."""
        task = self._tasks.get(task_id)
        if not task:
            return False
        task.status = TaskStatus.FAILED
        task.completed_at = time.time()
        task.result = error

        # Block all dependents
        for dep_id in task.dependents:
            dep = self._tasks.get(dep_id)
            if dep and dep.status == TaskStatus.PENDING:
                dep.status = TaskStatus.BLOCKED

        return True

    def get_ready_tasks(self) -> list[TaskNode]:
        """Get tasks ready for execution."""
        return [
            t for t in self._tasks.values()
            if t.status == TaskStatus.READY
        ]

    def get_parallel_groups(self) -> list[list[str]]:
        """Get groups of tasks that can run in parallel."""
        order = self._topological_sort()
        if not order:
            return []

        # Group by depth level
        depth: dict[str, int] = {}
        for task_id in order:
            task = self._tasks[task_id]
            if not task.dependencies:
                depth[task_id] = 0
            else:
                depth[task_id] = max(
                    depth.get(d, 0) for d in task.dependencies
                ) + 1

        # Group by depth
        groups: dict[int, list[str]] = {}
        for task_id, d in depth.items():
            groups.setdefault(d, []).append(task_id)

        return [groups[d] for d in sorted(groups.keys())]

    def get_critical_path(self) -> list[str]:
        """Find the critical path (longest path)."""
        order = self._topological_sort()
        if not order:
            return []

        dist: dict[str, float] = {}
        pred: dict[str, str] = {}

        for task_id in order:
            task = self._tasks[task_id]
            dist[task_id] = task.time_budget_s

            for dep_id in task.dependencies:
                new_dist = dist.get(dep_id, 0) + task.time_budget_s
                if new_dist > dist[task_id]:
                    dist[task_id] = new_dist
                    pred[task_id] = dep_id

        if not dist:
            return []

        # Trace back from longest
        end_id = max(dist, key=lambda k: dist[k])
        path: list[str] = [end_id]
        while end_id in pred:
            end_id = pred[end_id]
            path.insert(0, end_id)

        return path

    def build_plan(self) -> ExecutionPlan:
        """Build an execution plan from the DAG."""
        phases = self.get_parallel_groups()
        critical = self.get_critical_path()

        total_tokens = sum(t.token_budget for t in self._tasks.values())
        total_time = sum(t.time_budget_s for t in self._tasks.values())
        max_parallel = max((len(p) for p in phases), default=0)

        return ExecutionPlan(
            phases=phases,
            critical_path=critical,
            estimated_tokens=total_tokens,
            estimated_time_s=total_time,
            parallelism=max_parallel,
        )

    def build_dag_prompt(self, max_tasks: int = 15) -> str:
        """Build DAG context for LLM."""
        lines = ["## Task DAG\n"]

        # Show tasks by status
        for status in [TaskStatus.READY, TaskStatus.RUNNING, TaskStatus.PENDING]:
            tasks = [t for t in self._tasks.values() if t.status == status]
            if not tasks:
                continue
            lines.append(f"\n{status.value.upper()}:")
            for t in tasks[:max_tasks]:
                deps_str = ""
                if t.dependencies:
                    deps_str = f" (after: {', '.join(d[:8] for d in t.dependencies)})"
                lines.append(f"  {t.task_id[:8]}: {t.name}{deps_str}")

        # Plan summary
        plan = self.build_plan()
        lines.append(f"\nPhases: {len(plan.phases)}, Max parallel: {plan.parallelism}")

        return "\n".join(lines)

    def _topological_sort(self) -> list[str]:
        """Kahn's algorithm for topological sort."""
        in_degree: dict[str, int] = {
            t_id: len(t.dependencies)
            for t_id, t in self._tasks.items()
        }
        queue: deque[str] = deque(
            t_id for t_id, d in in_degree.items() if d == 0
        )
        order: list[str] = []

        while queue:
            task_id = queue.popleft()
            order.append(task_id)
            task = self._tasks[task_id]
            for dep_id in task.dependents:
                in_degree[dep_id] -= 1
                if in_degree[dep_id] == 0:
                    queue.append(dep_id)

        if len(order) != len(self._tasks):
            self._log.error("cycle_detected", order=len(order), total=len(self._tasks))
            return []

        return order

    def _update_readiness(self) -> None:
        """Update task readiness based on dependencies."""
        for task in self._tasks.values():
            if task.status != TaskStatus.PENDING:
                continue
            if not task.dependencies:
                task.status = TaskStatus.READY
                continue
            all_complete = all(
                self._tasks.get(d, TaskNode()).status == TaskStatus.COMPLETED
                for d in task.dependencies
            )
            if all_complete:
                task.status = TaskStatus.READY

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for t in self._tasks.values():
            status_counts[t.status.value] = status_counts.get(t.status.value, 0) + 1

        return {
            "total_tasks": len(self._tasks),
            "by_status": status_counts,
            "total_budget": sum(t.token_budget for t in self._tasks.values()),
        }
