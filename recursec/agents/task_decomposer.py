"""Task decomposer — recursive task breakdown into subtasks.

Implements:
1. Hierarchical task decomposition
2. Dependency graph between subtasks
3. Parallelizable task identification
4. Task priority and ordering
5. Bounded recursion depth
6. Decomposition prompt for LLM
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
    READY = "ready"        # All deps satisfied
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class TaskPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SubTask:
    """A decomposed subtask."""
    task_id: str = ""
    parent_id: str = ""
    name: str = ""
    description: str = ""
    status: TaskStatus = TaskStatus.PENDING
    priority: TaskPriority = TaskPriority.MEDIUM
    agent_role: str = ""
    tools_needed: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    children: list[str] = field(default_factory=list)
    depth: int = 0
    estimated_tokens: int = 1000
    result: str = ""
    findings_count: int = 0
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def is_leaf(self) -> bool:
        return len(self.children) == 0

    @property
    def duration_s(self) -> float:
        if self.completed_at and self.started_at:
            return self.completed_at - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:10],
            "name": self.name[:20],
            "status": self.status.value[:6],
            "depth": self.depth,
            "children": len(self.children),
            "deps": len(self.dependencies),
        }


@dataclass
class TaskTree:
    """A complete task decomposition tree."""
    root_id: str = ""
    root_task: str = ""
    tasks: dict[str, SubTask] = field(default_factory=dict)
    max_depth: int = 5
    total_tokens_estimated: int = 0
    created_at: float = field(default_factory=time.time)

    @property
    def depth(self) -> int:
        if not self.tasks:
            return 0
        return max(t.depth for t in self.tasks.values())

    @property
    def leaf_count(self) -> int:
        return sum(1 for t in self.tasks.values() if t.is_leaf)

    @property
    def completion_ratio(self) -> float:
        if not self.tasks:
            return 0.0
        completed = sum(
            1 for t in self.tasks.values()
            if t.status == TaskStatus.COMPLETED
        )
        return completed / len(self.tasks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root_task[:20],
            "tasks": len(self.tasks),
            "depth": self.depth,
            "leaves": self.leaf_count,
            "completion": f"{self.completion_ratio:.0%}",
        }


# ── Task decomposition templates ─────────────────────────────

DECOMPOSITION_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "full_assessment": [
        {"name": "Recon", "role": "recon", "priority": "high", "tools": ["subfinder", "nmap", "httpx"]},
        {"name": "Vulnerability Scan", "role": "vuln_scan", "priority": "high", "tools": ["nuclei", "nikto"], "deps": ["Recon"]},
        {"name": "Web Audit", "role": "web_audit", "priority": "high", "tools": ["sqlmap", "ffuf"], "deps": ["Recon"]},
        {"name": "Network Audit", "role": "network", "priority": "medium", "tools": ["nmap", "masscan"], "deps": ["Recon"]},
        {"name": "Exploitation", "role": "exploit", "priority": "medium", "tools": ["metasploit"], "deps": ["Vulnerability Scan", "Web Audit"]},
        {"name": "Validation", "role": "validator", "priority": "high", "deps": ["Exploitation"]},
        {"name": "Report", "role": "reporter", "priority": "low", "deps": ["Validation"]},
    ],
    "web_assessment": [
        {"name": "Web Recon", "role": "recon", "priority": "high", "tools": ["httpx", "ffuf", "gobuster"]},
        {"name": "Spider/Crawl", "role": "web_audit", "priority": "high", "tools": ["gospider"], "deps": ["Web Recon"]},
        {"name": "Injection Testing", "role": "web_audit", "priority": "high", "tools": ["sqlmap"], "deps": ["Spider/Crawl"]},
        {"name": "Auth Testing", "role": "web_audit", "priority": "high", "deps": ["Web Recon"]},
        {"name": "API Testing", "role": "web_audit", "priority": "medium", "deps": ["Web Recon"]},
        {"name": "Validation", "role": "validator", "priority": "high", "deps": ["Injection Testing", "Auth Testing"]},
    ],
    "network_assessment": [
        {"name": "Port Scan", "role": "recon", "priority": "high", "tools": ["nmap", "masscan"]},
        {"name": "Service Enum", "role": "recon", "priority": "high", "tools": ["nmap"], "deps": ["Port Scan"]},
        {"name": "Vuln Scan", "role": "vuln_scan", "priority": "high", "tools": ["nuclei", "nmap"], "deps": ["Service Enum"]},
        {"name": "Protocol Tests", "role": "network", "priority": "medium", "deps": ["Service Enum"]},
        {"name": "Exploitation", "role": "exploit", "priority": "medium", "deps": ["Vuln Scan"]},
    ],
    "cloud_assessment": [
        {"name": "Cloud Recon", "role": "cloud", "priority": "high", "tools": ["prowler"]},
        {"name": "IAM Review", "role": "cloud", "priority": "high", "deps": ["Cloud Recon"]},
        {"name": "Storage Audit", "role": "cloud", "priority": "high", "deps": ["Cloud Recon"]},
        {"name": "Network Review", "role": "cloud", "priority": "medium", "deps": ["Cloud Recon"]},
        {"name": "Serverless Audit", "role": "cloud", "priority": "medium", "deps": ["Cloud Recon"]},
    ],
}


class TaskDecomposer:
    """Recursive task breakdown into subtasks.

    Decomposes high-level security tasks into
    hierarchical subtasks with dependencies,
    enabling parallel and ordered execution.
    """

    def __init__(self, max_depth: int = 5) -> None:
        self._trees: dict[str, TaskTree] = {}
        self._task_counter = 0
        self._max_depth = max_depth
        self._log = logger.bind(component="task_decomposer")

    def decompose(
        self,
        task: str,
        template: str = "full_assessment",
    ) -> TaskTree:
        """Decompose a task using a template."""
        self._task_counter += 1
        root_id = f"task-{self._task_counter}"

        tree = TaskTree(
            root_id=root_id,
            root_task=task,
            max_depth=self._max_depth,
        )

        # Create root task
        root = SubTask(
            task_id=root_id,
            name=task[:50],
            description=task,
            status=TaskStatus.RUNNING,
            priority=TaskPriority.CRITICAL,
            agent_role="coordinator",
            depth=0,
        )
        tree.tasks[root_id] = root

        # Apply template
        template_tasks = DECOMPOSITION_TEMPLATES.get(template, [])
        name_to_id: dict[str, str] = {}

        for spec in template_tasks:
            self._task_counter += 1
            tid = f"task-{self._task_counter}"
            name_to_id[spec["name"]] = tid

            # Resolve dependency IDs
            dep_ids = []
            for dep_name in spec.get("deps", []):
                if dep_name in name_to_id:
                    dep_ids.append(name_to_id[dep_name])

            sub = SubTask(
                task_id=tid,
                parent_id=root_id,
                name=spec["name"],
                description=spec["name"],
                priority=TaskPriority(spec.get("priority", "medium")),
                agent_role=spec.get("role", ""),
                tools_needed=spec.get("tools", []),
                dependencies=dep_ids,
                depth=1,
            )

            # Set status
            if not dep_ids:
                sub.status = TaskStatus.READY

            tree.tasks[tid] = sub
            root.children.append(tid)

        # Estimate tokens
        tree.total_tokens_estimated = len(tree.tasks) * 2000

        self._trees[root_id] = tree
        return tree

    def add_subtask(
        self,
        tree_id: str,
        parent_id: str,
        name: str,
        agent_role: str = "",
        tools: list[str] | None = None,
        dependencies: list[str] | None = None,
    ) -> SubTask | None:
        """Add a subtask to an existing tree."""
        tree = self._trees.get(tree_id)
        if not tree:
            return None

        parent = tree.tasks.get(parent_id)
        if not parent:
            return None

        new_depth = parent.depth + 1
        if new_depth > tree.max_depth:
            return None

        self._task_counter += 1
        tid = f"task-{self._task_counter}"

        sub = SubTask(
            task_id=tid,
            parent_id=parent_id,
            name=name,
            description=name,
            agent_role=agent_role,
            tools_needed=tools or [],
            dependencies=dependencies or [],
            depth=new_depth,
        )

        if not sub.dependencies:
            sub.status = TaskStatus.READY

        tree.tasks[tid] = sub
        parent.children.append(tid)

        return sub

    def complete_task(
        self,
        tree_id: str,
        task_id: str,
        result: str = "",
        findings_count: int = 0,
    ) -> list[str]:
        """Mark a task as completed. Returns newly ready task IDs."""
        tree = self._trees.get(tree_id)
        if not tree:
            return []

        task = tree.tasks.get(task_id)
        if not task:
            return []

        task.status = TaskStatus.COMPLETED
        task.result = result
        task.findings_count = findings_count
        task.completed_at = time.time()

        # Check if any tasks are now ready
        newly_ready: list[str] = []
        for t in tree.tasks.values():
            if t.status != TaskStatus.PENDING:
                continue
            if all(
                tree.tasks.get(dep, SubTask()).status == TaskStatus.COMPLETED
                for dep in t.dependencies
            ):
                t.status = TaskStatus.READY
                newly_ready.append(t.task_id)

        return newly_ready

    def get_ready_tasks(self, tree_id: str) -> list[SubTask]:
        """Get all tasks ready for execution."""
        tree = self._trees.get(tree_id)
        if not tree:
            return []
        return [t for t in tree.tasks.values() if t.status == TaskStatus.READY]

    def get_parallel_groups(self, tree_id: str) -> list[list[str]]:
        """Get groups of tasks that can run in parallel."""
        ready = self.get_ready_tasks(tree_id)
        if not ready:
            return []

        # Group by no mutual dependencies
        groups: list[list[str]] = []
        assigned: set[str] = set()

        for task in ready:
            if task.task_id in assigned:
                continue

            group = [task.task_id]
            assigned.add(task.task_id)

            for other in ready:
                if other.task_id in assigned:
                    continue
                # Can run in parallel if no dependency between them
                if (task.task_id not in other.dependencies
                        and other.task_id not in task.dependencies):
                    group.append(other.task_id)
                    assigned.add(other.task_id)

            groups.append(group)

        return groups

    def build_decomposition_prompt(self, tree_id: str = "") -> str:
        """Build task decomposition context for LLM."""
        lines = ["## Task Decomposition\n"]

        if tree_id and tree_id in self._trees:
            tree = self._trees[tree_id]
            lines.append(f"Task: {tree.root_task[:30]}")
            lines.append(
                f"Subtasks: {len(tree.tasks)} | "
                f"Depth: {tree.depth} | "
                f"Completion: {tree.completion_ratio:.0%}"
            )

            # Ready tasks
            ready = self.get_ready_tasks(tree_id)
            if ready:
                lines.append(f"\nReady ({len(ready)}):")
                for t in ready[:5]:
                    lines.append(f"  → {t.name} [{t.agent_role}]")

            # Running tasks
            running = [t for t in tree.tasks.values() if t.status == TaskStatus.RUNNING]
            if running:
                lines.append(f"Running ({len(running)}):")
                for t in running[:3]:
                    lines.append(f"  ⋯ {t.name}")

        else:
            lines.append(f"Active trees: {len(self._trees)}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_tasks = sum(len(t.tasks) for t in self._trees.values())
        completed = sum(
            sum(1 for st in t.tasks.values() if st.status == TaskStatus.COMPLETED)
            for t in self._trees.values()
        )

        return {
            "trees": len(self._trees),
            "total_tasks": total_tasks,
            "completed": completed,
            "max_depth": max((t.depth for t in self._trees.values()), default=0),
        }
