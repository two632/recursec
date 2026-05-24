"""Task priority engine — dynamic task reordering.

Implements:
1. Multi-factor priority scoring
2. Finding-driven reprioritization
3. Dependency-aware ordering
4. Deadline tracking
5. Resource-constrained scheduling
6. Priority prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskUrgency(str, Enum):
    CRITICAL = "critical"     # Must do immediately
    HIGH = "high"             # Do soon
    MEDIUM = "medium"         # Normal priority
    LOW = "low"               # Can defer
    BACKGROUND = "background" # Do when idle


class TaskCategory(str, Enum):
    EXPLOIT = "exploit"           # Exploitation tasks
    SCAN = "scan"                 # Scanning tasks
    ANALYZE = "analyze"           # Analysis tasks
    VALIDATE = "validate"         # Validation tasks
    RECON = "recon"               # Reconnaissance
    REPORT = "report"             # Reporting
    FOLLOWUP = "followup"         # Follow-up tasks


URGENCY_SCORES: dict[TaskUrgency, float] = {
    TaskUrgency.CRITICAL: 10.0,
    TaskUrgency.HIGH: 7.0,
    TaskUrgency.MEDIUM: 4.0,
    TaskUrgency.LOW: 2.0,
    TaskUrgency.BACKGROUND: 0.5,
}

SEVERITY_BOOST: dict[str, float] = {
    "critical": 5.0,
    "high": 3.0,
    "medium": 1.5,
    "low": 0.5,
    "info": 0.0,
}


@dataclass
class PriorityTask:
    """A prioritized task."""
    task_id: str = ""
    description: str = ""
    category: TaskCategory = TaskCategory.SCAN
    urgency: TaskUrgency = TaskUrgency.MEDIUM
    base_score: float = 0.0
    dynamic_score: float = 0.0
    finding_severity: str = ""
    dependencies: list[str] = field(default_factory=list)
    blocked_by: list[str] = field(default_factory=list)
    estimated_tokens: int = 500
    deadline: float = 0.0
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed: bool = False

    @property
    def effective_score(self) -> float:
        age_hours = (time.time() - self.created_at) / 3600
        age_bonus = min(2.0, age_hours * 0.5)

        deadline_bonus = 0.0
        if self.deadline > 0:
            remaining = self.deadline - time.time()
            if remaining < 300:
                deadline_bonus = 5.0
            elif remaining < 900:
                deadline_bonus = 2.0

        return self.dynamic_score + age_bonus + deadline_bonus

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:8],
            "desc": self.description[:20],
            "score": f"{self.effective_score:.1f}",
            "urgency": self.urgency.value[:6],
        }


class TaskPriorityEngine:
    """Dynamic task prioritization and reordering.

    Reorders tasks based on findings, time
    pressure, dependencies, and resources.
    """

    def __init__(self, max_tasks: int = 100) -> None:
        self._tasks: dict[str, PriorityTask] = {}
        self._task_counter = 0
        self._max_tasks = max_tasks
        self._completed: list[str] = []
        self._log = logger.bind(component="priority")

    def add_task(
        self,
        description: str,
        category: TaskCategory = TaskCategory.SCAN,
        urgency: TaskUrgency = TaskUrgency.MEDIUM,
        finding_severity: str = "",
        dependencies: list[str] | None = None,
        estimated_tokens: int = 500,
    ) -> PriorityTask:
        """Add a new task."""
        self._task_counter += 1

        base = URGENCY_SCORES.get(urgency, 4.0)
        severity_boost = SEVERITY_BOOST.get(finding_severity.lower(), 0.0)

        # Category bonuses
        cat_bonus = {
            TaskCategory.EXPLOIT: 2.0,
            TaskCategory.VALIDATE: 1.5,
            TaskCategory.ANALYZE: 1.0,
            TaskCategory.SCAN: 0.5,
            TaskCategory.RECON: 0.0,
            TaskCategory.REPORT: -1.0,
            TaskCategory.FOLLOWUP: 0.0,
        }.get(category, 0.0)

        dynamic = base + severity_boost + cat_bonus

        task = PriorityTask(
            task_id=f"task-{self._task_counter}",
            description=description,
            category=category,
            urgency=urgency,
            base_score=base,
            dynamic_score=dynamic,
            finding_severity=finding_severity,
            dependencies=dependencies or [],
            estimated_tokens=estimated_tokens,
        )
        self._tasks[task.task_id] = task
        return task

    def reprioritize_from_finding(
        self,
        finding_type: str,
        severity: str,
    ) -> list[PriorityTask]:
        """Generate new tasks from a finding."""
        new_tasks: list[PriorityTask] = []

        if severity.lower() in ("critical", "high"):
            # Exploitation task
            task = self.add_task(
                f"Exploit {finding_type}",
                category=TaskCategory.EXPLOIT,
                urgency=TaskUrgency.HIGH,
                finding_severity=severity,
            )
            new_tasks.append(task)

            # Validation task
            val = self.add_task(
                f"Validate {finding_type}",
                category=TaskCategory.VALIDATE,
                urgency=TaskUrgency.HIGH,
                finding_severity=severity,
                dependencies=[task.task_id],
            )
            new_tasks.append(val)

        elif severity.lower() == "medium":
            task = self.add_task(
                f"Investigate {finding_type}",
                category=TaskCategory.ANALYZE,
                urgency=TaskUrgency.MEDIUM,
                finding_severity=severity,
            )
            new_tasks.append(task)

        return new_tasks

    def get_next_tasks(
        self,
        count: int = 5,
        token_budget: int = 0,
    ) -> list[PriorityTask]:
        """Get the next tasks to execute."""
        ready = [
            t for t in self._tasks.values()
            if not t.completed
            and not t.started_at
            and self._deps_met(t)
        ]

        # Sort by effective score
        ready.sort(key=lambda t: t.effective_score, reverse=True)

        if token_budget > 0:
            selected: list[PriorityTask] = []
            remaining = token_budget
            for task in ready:
                if task.estimated_tokens <= remaining:
                    selected.append(task)
                    remaining -= task.estimated_tokens
                    if len(selected) >= count:
                        break
            return selected

        return ready[:count]

    def _deps_met(self, task: PriorityTask) -> bool:
        """Check if all dependencies are completed."""
        for dep_id in task.dependencies:
            if dep_id not in self._completed:
                dep_task = self._tasks.get(dep_id)
                if dep_task and not dep_task.completed:
                    return False
        return True

    def start_task(self, task_id: str) -> None:
        """Mark a task as started."""
        task = self._tasks.get(task_id)
        if task:
            task.started_at = time.time()

    def complete_task(self, task_id: str) -> None:
        """Mark a task as completed."""
        task = self._tasks.get(task_id)
        if task:
            task.completed = True
            self._completed.append(task_id)

    def boost_urgency(
        self,
        task_id: str,
        new_urgency: TaskUrgency,
    ) -> None:
        """Boost a task's urgency."""
        task = self._tasks.get(task_id)
        if task:
            task.urgency = new_urgency
            task.dynamic_score += URGENCY_SCORES.get(new_urgency, 0.0)

    def build_priority_prompt(self, top_n: int = 5) -> str:
        """Build priority context for LLM."""
        lines = ["## Task Queue\n"]

        pending = sum(
            1 for t in self._tasks.values()
            if not t.completed
        )
        lines.append(f"Pending: {pending}, Done: {len(self._completed)}")

        next_tasks = self.get_next_tasks(top_n)
        if next_tasks:
            lines.append("\nNext:")
            for t in next_tasks:
                lines.append(
                    f"  [{t.urgency.value[:6]}] ({t.effective_score:.1f}) "
                    f"{t.description[:30]}"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        urgency_counts: dict[str, int] = {}
        for t in self._tasks.values():
            if not t.completed:
                urgency_counts[t.urgency.value] = (
                    urgency_counts.get(t.urgency.value, 0) + 1
                )

        return {
            "total": len(self._tasks),
            "pending": len(self._tasks) - len(self._completed),
            "completed": len(self._completed),
            "by_urgency": urgency_counts,
        }
