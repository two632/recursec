"""Task decomposer — intelligent task breakdown for recursive agents.

Implements:
1. Goal decomposition into sub-tasks
2. Dependency graph between tasks
3. Task priority and ordering (topological sort)
4. Parallel task identification
5. Task estimation (tokens, time)
6. Dynamic re-planning when tasks fail
7. Task context generation for agent spawning
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
    READY = "ready"           # All deps met, can start
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class TaskPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SubTask:
    """A decomposed sub-task."""
    task_id: str = ""
    parent_id: str = ""
    title: str = ""
    description: str = ""
    status: TaskStatus = TaskStatus.PENDING
    priority: TaskPriority = TaskPriority.MEDIUM
    agent_role: str = ""      # Role of agent to handle this
    tool_hints: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)  # Task IDs that must complete first
    children: list[str] = field(default_factory=list)

    # Estimation
    estimated_tokens: int = 5000
    estimated_duration_s: float = 60.0
    actual_tokens: int = 0
    actual_duration_s: float = 0.0

    # Execution
    assigned_agent: str = ""
    result: str = ""
    error: str = ""
    findings_count: int = 0

    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def is_leaf(self) -> bool:
        return len(self.children) == 0

    @property
    def is_blocked(self) -> bool:
        return self.status == TaskStatus.BLOCKED

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:10],
            "title": self.title[:25],
            "status": self.status.value,
            "priority": self.priority.value,
            "role": self.agent_role[:10],
            "deps": len(self.dependencies),
            "children": len(self.children),
        }


# ── Task templates for common security operations ────────────

TASK_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "full_assessment": [
        {"title": "Passive Reconnaissance", "role": "recon", "priority": "high",
         "tools": ["subfinder", "amass", "theHarvester", "whois"], "deps": []},
        {"title": "Active Reconnaissance", "role": "recon", "priority": "high",
         "tools": ["nmap", "masscan", "httpx"], "deps": ["Passive Reconnaissance"]},
        {"title": "Technology Fingerprinting", "role": "scanner", "priority": "medium",
         "tools": ["whatweb", "wappalyzer"], "deps": ["Active Reconnaissance"]},
        {"title": "Vulnerability Scanning", "role": "scanner", "priority": "high",
         "tools": ["nuclei", "nikto"], "deps": ["Technology Fingerprinting"]},
        {"title": "Web Application Testing", "role": "exploiter", "priority": "high",
         "tools": ["sqlmap", "ffuf", "burpsuite"], "deps": ["Vulnerability Scanning"]},
        {"title": "Authentication Testing", "role": "exploiter", "priority": "medium",
         "tools": ["hydra", "jwt_tool"], "deps": ["Technology Fingerprinting"]},
        {"title": "Exploitation", "role": "exploiter", "priority": "critical",
         "tools": ["metasploit"], "deps": ["Web Application Testing"]},
        {"title": "Finding Validation", "role": "validator", "priority": "high",
         "tools": [], "deps": ["Exploitation", "Vulnerability Scanning"]},
        {"title": "Report Generation", "role": "analyst", "priority": "medium",
         "tools": [], "deps": ["Finding Validation"]},
    ],
    "web_assessment": [
        {"title": "Subdomain Enumeration", "role": "recon", "priority": "high",
         "tools": ["subfinder", "amass"], "deps": []},
        {"title": "HTTP Probing", "role": "recon", "priority": "high",
         "tools": ["httpx"], "deps": ["Subdomain Enumeration"]},
        {"title": "Directory Fuzzing", "role": "scanner", "priority": "medium",
         "tools": ["ffuf", "gobuster"], "deps": ["HTTP Probing"]},
        {"title": "Vulnerability Scanning", "role": "scanner", "priority": "high",
         "tools": ["nuclei"], "deps": ["HTTP Probing"]},
        {"title": "SQL Injection Testing", "role": "exploiter", "priority": "high",
         "tools": ["sqlmap"], "deps": ["Directory Fuzzing"]},
        {"title": "XSS Testing", "role": "exploiter", "priority": "medium",
         "tools": ["dalfox"], "deps": ["Directory Fuzzing"]},
    ],
    "network_assessment": [
        {"title": "Network Discovery", "role": "recon", "priority": "high",
         "tools": ["nmap", "masscan"], "deps": []},
        {"title": "Service Enumeration", "role": "scanner", "priority": "high",
         "tools": ["nmap"], "deps": ["Network Discovery"]},
        {"title": "Vulnerability Scanning", "role": "scanner", "priority": "high",
         "tools": ["nmap", "nuclei"], "deps": ["Service Enumeration"]},
        {"title": "Exploitation", "role": "exploiter", "priority": "critical",
         "tools": ["metasploit"], "deps": ["Vulnerability Scanning"]},
    ],
}


class TaskDecomposer:
    """Decomposes goals into sub-tasks with dependencies.

    Creates a directed acyclic graph of tasks,
    identifies parallelism opportunities, and
    supports dynamic re-planning.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, SubTask] = {}
        self._counter = 0
        self._log = logger.bind(component="task_decomposer")

    def decompose_from_template(
        self,
        template_name: str,
        parent_id: str = "",
    ) -> list[SubTask]:
        """Decompose a goal using a predefined template."""
        template = TASK_TEMPLATES.get(template_name, [])
        if not template:
            return []

        # Create tasks
        tasks: list[SubTask] = []
        title_to_id: dict[str, str] = {}

        for tmpl in template:
            self._counter += 1
            task = SubTask(
                task_id=f"task-{self._counter}",
                parent_id=parent_id,
                title=tmpl["title"],
                priority=TaskPriority(tmpl.get("priority", "medium")),
                agent_role=tmpl.get("role", ""),
                tool_hints=tmpl.get("tools", []),
            )
            self._tasks[task.task_id] = task
            tasks.append(task)
            title_to_id[task.title] = task.task_id

        # Resolve dependencies
        for i, tmpl in enumerate(template):
            task = tasks[i]
            for dep_title in tmpl.get("deps", []):
                dep_id = title_to_id.get(dep_title)
                if dep_id:
                    task.dependencies.append(dep_id)

        # Update readiness
        self._update_readiness()
        return tasks

    def add_task(
        self,
        title: str,
        description: str = "",
        parent_id: str = "",
        priority: TaskPriority = TaskPriority.MEDIUM,
        agent_role: str = "",
        tool_hints: list[str] | None = None,
        dependencies: list[str] | None = None,
        estimated_tokens: int = 5000,
        estimated_duration_s: float = 60.0,
    ) -> SubTask:
        """Add a custom task."""
        self._counter += 1
        task = SubTask(
            task_id=f"task-{self._counter}",
            parent_id=parent_id,
            title=title,
            description=description,
            priority=priority,
            agent_role=agent_role,
            tool_hints=tool_hints or [],
            dependencies=dependencies or [],
            estimated_tokens=estimated_tokens,
            estimated_duration_s=estimated_duration_s,
        )
        self._tasks[task.task_id] = task
        self._update_readiness()
        return task

    def start_task(self, task_id: str, agent_id: str = "") -> bool:
        """Mark a task as started."""
        task = self._tasks.get(task_id)
        if not task or task.status != TaskStatus.READY:
            return False

        task.status = TaskStatus.IN_PROGRESS
        task.assigned_agent = agent_id
        task.started_at = time.time()
        return True

    def complete_task(
        self,
        task_id: str,
        result: str = "",
        findings_count: int = 0,
        tokens_used: int = 0,
    ) -> bool:
        """Mark a task as completed."""
        task = self._tasks.get(task_id)
        if not task:
            return False

        task.status = TaskStatus.COMPLETED
        task.result = result
        task.findings_count = findings_count
        task.actual_tokens = tokens_used
        task.completed_at = time.time()
        task.actual_duration_s = task.completed_at - task.started_at

        self._update_readiness()
        return True

    def fail_task(self, task_id: str, error: str = "") -> bool:
        """Mark a task as failed."""
        task = self._tasks.get(task_id)
        if not task:
            return False

        task.status = TaskStatus.FAILED
        task.error = error
        task.completed_at = time.time()

        self._update_readiness()
        return True

    def get_ready_tasks(self) -> list[SubTask]:
        """Get tasks ready for execution."""
        return [t for t in self._tasks.values() if t.status == TaskStatus.READY]

    def get_parallel_groups(self) -> list[list[SubTask]]:
        """Identify groups of tasks that can run in parallel."""
        ready = self.get_ready_tasks()
        if not ready:
            return []
        return [ready]  # All ready tasks can run in parallel

    def replan_after_failure(self, failed_task_id: str) -> list[SubTask]:
        """Re-plan after a task failure."""
        failed = self._tasks.get(failed_task_id)
        if not failed:
            return []

        # Skip dependent tasks
        affected: list[SubTask] = []
        for task in self._tasks.values():
            if failed_task_id in task.dependencies:
                if task.status in (TaskStatus.PENDING, TaskStatus.READY):
                    task.status = TaskStatus.SKIPPED
                    affected.append(task)

        return affected

    def build_task_prompt(self, max_tasks: int = 10) -> str:
        """Build task context for LLM."""
        lines = ["## Task Decomposition\n"]

        status_counts: dict[str, int] = {}
        for t in self._tasks.values():
            status_counts[t.status.value] = status_counts.get(t.status.value, 0) + 1

        lines.append(f"Tasks: {len(self._tasks)} | " + " ".join(
            f"{k}={v}" for k, v in status_counts.items()
        ))

        ready = self.get_ready_tasks()
        if ready:
            lines.append(f"\nReady to execute ({len(ready)}):")
            for t in ready[:max_tasks]:
                tools = ",".join(t.tool_hints[:3]) if t.tool_hints else "none"
                lines.append(
                    f"  [{t.priority.value[0].upper()}] {t.title[:25]} "
                    f"(role={t.agent_role}, tools={tools})"
                )

        in_progress = [t for t in self._tasks.values() if t.status == TaskStatus.IN_PROGRESS]
        if in_progress:
            lines.append(f"\nIn progress ({len(in_progress)}):")
            for t in in_progress[:5]:
                elapsed = time.time() - t.started_at if t.started_at else 0
                lines.append(f"  {t.title[:25]} ({elapsed:.0f}s)")

        return "\n".join(lines)

    def _update_readiness(self) -> None:
        """Update task readiness based on dependency status."""
        for task in self._tasks.values():
            if task.status != TaskStatus.PENDING:
                continue

            if not task.dependencies:
                task.status = TaskStatus.READY
                continue

            all_deps_met = True
            any_dep_failed = False
            for dep_id in task.dependencies:
                dep = self._tasks.get(dep_id)
                if not dep or dep.status != TaskStatus.COMPLETED:
                    all_deps_met = False
                if dep and dep.status in (TaskStatus.FAILED, TaskStatus.SKIPPED):
                    any_dep_failed = True

            if any_dep_failed:
                task.status = TaskStatus.BLOCKED
            elif all_deps_met:
                task.status = TaskStatus.READY

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for t in self._tasks.values():
            status_counts[t.status.value] = status_counts.get(t.status.value, 0) + 1

        return {
            "total_tasks": len(self._tasks),
            "by_status": status_counts,
            "ready": len(self.get_ready_tasks()),
            "total_findings": sum(t.findings_count for t in self._tasks.values()),
        }
