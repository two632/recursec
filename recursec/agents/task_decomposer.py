"""Task decomposer — recursive task breakdown.

Implements:
1. High-level task decomposition into subtasks
2. Dependency graph construction
3. Parallel/sequential ordering
4. Budget-aware decomposition
5. Depth-limited recursion
6. Task templates for common patterns
7. Dynamic re-decomposition on failure
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
    READY = "ready"          # Dependencies met
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ExecutionMode(str, Enum):
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    CONDITIONAL = "conditional"  # Execute based on parent result


@dataclass
class Task:
    """A decomposed task."""
    task_id: str = ""
    name: str = ""
    description: str = ""
    status: TaskStatus = TaskStatus.PENDING
    priority: TaskPriority = TaskPriority.MEDIUM
    execution_mode: ExecutionMode = ExecutionMode.SEQUENTIAL
    parent_task: str = ""
    subtasks: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    assigned_agent: str = ""
    assigned_model: str = ""
    tools: list[str] = field(default_factory=list)
    token_budget: int = 0
    time_budget_s: float = 0.0
    depth: int = 0
    max_depth: int = 3
    result: str = ""
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:10],
            "name": self.name[:25],
            "status": self.status.value,
            "priority": self.priority.value,
            "depth": self.depth,
            "subtasks": len(self.subtasks),
        }


@dataclass
class TaskGraph:
    """A graph of decomposed tasks."""
    graph_id: str = ""
    root_task: str = ""
    tasks: dict[str, Task] = field(default_factory=dict)
    total_tasks: int = 0
    completed_tasks: int = 0

    @property
    def progress(self) -> float:
        if self.total_tasks == 0:
            return 0.0
        return self.completed_tasks / self.total_tasks

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.graph_id[:10],
            "root": self.root_task[:10],
            "total": self.total_tasks,
            "completed": self.completed_tasks,
            "progress": round(self.progress * 100, 1),
        }


# ── Task decomposition templates ─────────────────────────────

TASK_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "full_assessment": [
        {"name": "Target profiling", "priority": "critical", "mode": "sequential",
         "tools": ["nmap", "whatweb", "httpx"], "time": 300},
        {"name": "Subdomain enumeration", "priority": "high", "mode": "parallel",
         "tools": ["subfinder", "amass"], "time": 300},
        {"name": "Port scanning", "priority": "critical", "mode": "parallel",
         "tools": ["nmap", "masscan"], "time": 600},
        {"name": "Vulnerability scanning", "priority": "critical", "mode": "parallel",
         "tools": ["nuclei", "nikto"], "time": 600},
        {"name": "Web application testing", "priority": "high", "mode": "sequential",
         "tools": ["sqlmap", "dalfox", "ffuf"], "time": 600},
        {"name": "Finding validation", "priority": "high", "mode": "sequential",
         "tools": ["nuclei", "curl"], "time": 300},
        {"name": "Report generation", "priority": "medium", "mode": "sequential",
         "tools": [], "time": 120},
    ],
    "web_assessment": [
        {"name": "Technology fingerprinting", "priority": "high", "mode": "sequential",
         "tools": ["whatweb", "httpx"], "time": 120},
        {"name": "Directory enumeration", "priority": "high", "mode": "parallel",
         "tools": ["ffuf", "gobuster"], "time": 300},
        {"name": "Injection testing", "priority": "critical", "mode": "sequential",
         "tools": ["sqlmap", "dalfox"], "time": 300},
        {"name": "Authentication testing", "priority": "high", "mode": "sequential",
         "tools": ["hydra", "ffuf"], "time": 300},
        {"name": "Business logic testing", "priority": "medium", "mode": "sequential",
         "tools": [], "time": 300},
    ],
    "network_assessment": [
        {"name": "Network discovery", "priority": "critical", "mode": "parallel",
         "tools": ["nmap", "masscan"], "time": 600},
        {"name": "Service enumeration", "priority": "high", "mode": "sequential",
         "tools": ["nmap", "enum4linux"], "time": 300},
        {"name": "Vulnerability scanning", "priority": "critical", "mode": "parallel",
         "tools": ["nuclei", "nmap"], "time": 600},
        {"name": "Credential testing", "priority": "high", "mode": "sequential",
         "tools": ["hydra", "crackmapexec"], "time": 300},
    ],
    "code_audit": [
        {"name": "SAST scanning", "priority": "critical", "mode": "parallel",
         "tools": ["semgrep", "bandit"], "time": 300},
        {"name": "Secret detection", "priority": "high", "mode": "parallel",
         "tools": ["trufflehog", "gitleaks"], "time": 120},
        {"name": "Dependency audit", "priority": "high", "mode": "parallel",
         "tools": ["trivy", "grype"], "time": 120},
        {"name": "Manual code review", "priority": "medium", "mode": "sequential",
         "tools": [], "time": 600},
    ],
}


class TaskDecomposer:
    """Decomposes high-level tasks into subtask graphs.

    Produces executable task graphs with dependency
    tracking, parallel execution support, and
    budget-aware decomposition.
    """

    def __init__(self, max_depth: int = 3) -> None:
        self._graphs: dict[str, TaskGraph] = {}
        self._counter = 0
        self._max_depth = max_depth
        self._log = logger.bind(component="task_decomposer")

    def decompose(
        self,
        task_name: str,
        template: str = "full_assessment",
        total_token_budget: int = 500_000,
        total_time_budget: float = 3600,
    ) -> TaskGraph:
        """Decompose a high-level task into a graph."""
        self._counter += 1

        # Create root task
        root = Task(
            task_id=f"task-{self._counter}",
            name=task_name,
            status=TaskStatus.PENDING,
            priority=TaskPriority.CRITICAL,
            token_budget=total_token_budget,
            time_budget_s=total_time_budget,
            depth=0,
            max_depth=self._max_depth,
        )

        graph = TaskGraph(
            graph_id=f"graph-{self._counter}",
            root_task=root.task_id,
        )
        graph.tasks[root.task_id] = root

        # Apply template
        subtask_templates = TASK_TEMPLATES.get(template, TASK_TEMPLATES["full_assessment"])
        num_subtasks = len(subtask_templates)
        token_per_subtask = total_token_budget // max(1, num_subtasks)
        time_per_subtask = total_time_budget / max(1, num_subtasks)

        prev_sequential: str = ""
        for tmpl in subtask_templates:
            self._counter += 1
            subtask = Task(
                task_id=f"task-{self._counter}",
                name=tmpl["name"],
                priority=TaskPriority(tmpl.get("priority", "medium")),
                execution_mode=ExecutionMode(tmpl.get("mode", "sequential")),
                parent_task=root.task_id,
                tools=tmpl.get("tools", []),
                token_budget=token_per_subtask,
                time_budget_s=tmpl.get("time", time_per_subtask),
                depth=1,
                max_depth=self._max_depth,
            )

            # Sequential tasks depend on previous
            if subtask.execution_mode == ExecutionMode.SEQUENTIAL and prev_sequential:
                subtask.dependencies.append(prev_sequential)

            if subtask.execution_mode == ExecutionMode.SEQUENTIAL:
                prev_sequential = subtask.task_id

            graph.tasks[subtask.task_id] = subtask
            root.subtasks.append(subtask.task_id)

        graph.total_tasks = len(graph.tasks)
        self._graphs[graph.graph_id] = graph

        return graph

    def get_ready_tasks(self, graph_id: str) -> list[Task]:
        """Get tasks that are ready to execute."""
        graph = self._graphs.get(graph_id)
        if not graph:
            return []

        ready = []
        for task in graph.tasks.values():
            if task.status != TaskStatus.PENDING:
                continue

            deps_met = all(
                graph.tasks.get(dep_id, Task()).status == TaskStatus.COMPLETED
                for dep_id in task.dependencies
            )
            if deps_met:
                task.status = TaskStatus.READY
                ready.append(task)

        return ready

    def complete_task(
        self,
        graph_id: str,
        task_id: str,
        result: str = "",
        success: bool = True,
    ) -> None:
        """Mark a task as completed."""
        graph = self._graphs.get(graph_id)
        if not graph:
            return

        task = graph.tasks.get(task_id)
        if not task:
            return

        task.status = TaskStatus.COMPLETED if success else TaskStatus.FAILED
        task.completed_at = time.time()
        task.result = result

        if success:
            graph.completed_tasks += 1

    def re_decompose(
        self,
        graph_id: str,
        task_id: str,
    ) -> list[Task]:
        """Re-decompose a failed task into smaller subtasks."""
        graph = self._graphs.get(graph_id)
        if not graph:
            return []

        task = graph.tasks.get(task_id)
        if not task:
            return []

        if task.depth >= task.max_depth:
            return []

        # Split budget
        sub_budget = task.token_budget // 2
        sub_time = task.time_budget_s / 2

        new_tasks = []
        for i in range(2):
            self._counter += 1
            subtask = Task(
                task_id=f"task-{self._counter}",
                name=f"{task.name} (retry {i + 1})",
                parent_task=task_id,
                tools=task.tools,
                token_budget=sub_budget,
                time_budget_s=sub_time,
                depth=task.depth + 1,
                max_depth=task.max_depth,
            )
            graph.tasks[subtask.task_id] = subtask
            task.subtasks.append(subtask.task_id)
            new_tasks.append(subtask)
            graph.total_tasks += 1

        return new_tasks

    def build_graph_prompt(self, graph_id: str) -> str:
        """Build a prompt describing the task graph."""
        graph = self._graphs.get(graph_id)
        if not graph:
            return ""

        lines = [f"## Task Graph ({graph.progress * 100:.0f}% complete)\n"]

        for task in sorted(graph.tasks.values(), key=lambda t: t.depth):
            indent = "  " * task.depth
            status_icon = {"completed": "+", "failed": "!", "running": ">", "pending": "-", "ready": "*"}.get(task.status.value, "?")
            lines.append(f"{indent}[{status_icon}] {task.name} ({task.priority.value})")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_tasks = sum(g.total_tasks for g in self._graphs.values())
        completed = sum(g.completed_tasks for g in self._graphs.values())

        return {
            "graphs": len(self._graphs),
            "total_tasks": total_tasks,
            "completed": completed,
            "progress": round(completed / max(1, total_tasks) * 100, 1),
        }
