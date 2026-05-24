"""Autonomous execution loop — runs the agent 24/7.

This is the daemon that:
1. Accepts tasks from queue
2. Runs the full pipeline for each task
3. Learns from results
4. Schedules recurring scans
5. Monitors for changes
6. Self-heals on errors
7. Reports findings in real-time
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class LoopState(str, Enum):
    STARTING = "starting"
    RUNNING = "running"
    PROCESSING = "processing"
    WAITING = "waiting"
    PAUSED = "paused"
    ERROR = "error"
    STOPPED = "stopped"


class TaskSource(str, Enum):
    USER = "user"
    SCHEDULE = "schedule"
    CHANGE_DETECTION = "change_detection"
    FOLLOW_UP = "follow_up"
    SELF_IMPROVEMENT = "self_improvement"


@dataclass
class QueuedTask:
    """A task in the execution queue."""
    task_id: str = ""
    description: str = ""
    target: str = ""
    source: TaskSource = TaskSource.USER
    priority: int = 5
    scheduled_at: float = 0.0
    max_retries: int = 3
    retries: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:8],
            "desc": self.description[:20],
            "source": self.source.value[:8],
            "priority": self.priority,
        }


@dataclass
class ScheduledScan:
    """A recurring scheduled scan."""
    scan_id: str = ""
    description: str = ""
    target: str = ""
    interval_s: float = 86400.0
    last_run: float = 0.0
    next_run: float = 0.0
    enabled: bool = True
    task_type: str = "web_vuln_scan"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.scan_id[:8],
            "target": self.target[:15],
            "interval": f"{self.interval_s / 3600:.0f}h",
            "enabled": self.enabled,
        }


@dataclass
class LoopStats:
    """Statistics for the autonomous loop."""
    tasks_completed: int = 0
    tasks_failed: int = 0
    total_findings: int = 0
    total_runtime_s: float = 0.0
    errors: list[str] = field(default_factory=list)
    uptime_start: float = field(default_factory=time.time)

    @property
    def uptime_s(self) -> float:
        return time.time() - self.uptime_start

    def to_dict(self) -> dict[str, Any]:
        return {
            "completed": self.tasks_completed,
            "failed": self.tasks_failed,
            "findings": self.total_findings,
            "uptime": f"{self.uptime_s / 3600:.1f}h",
            "errors": len(self.errors),
        }


class AutonomousLoop:
    """The 24/7 autonomous execution loop."""

    def __init__(self) -> None:
        self._state = LoopState.STOPPED
        self._task_queue: list[QueuedTask] = []
        self._schedules: list[ScheduledScan] = []
        self._stats = LoopStats()
        self._task_counter = 0
        self._schedule_counter = 0
        self._log = logger.bind(component="autonomous_loop")

    @property
    def state(self) -> LoopState:
        return self._state

    def enqueue_task(
        self,
        description: str,
        target: str = "",
        source: TaskSource = TaskSource.USER,
        priority: int = 5,
        metadata: dict[str, Any] | None = None,
    ) -> QueuedTask:
        """Add a task to the execution queue."""
        self._task_counter += 1
        task = QueuedTask(
            task_id=f"qtask-{self._task_counter}",
            description=description,
            target=target,
            source=source,
            priority=priority,
            metadata=metadata or {},
        )
        self._task_queue.append(task)
        # Sort by priority (highest first)
        self._task_queue.sort(key=lambda t: t.priority, reverse=True)
        return task

    def dequeue_task(self) -> QueuedTask | None:
        """Get the next task from the queue."""
        if not self._task_queue:
            return None
        return self._task_queue.pop(0)

    def add_schedule(
        self,
        description: str,
        target: str,
        interval_hours: float = 24.0,
        task_type: str = "web_vuln_scan",
    ) -> ScheduledScan:
        """Add a recurring scheduled scan."""
        self._schedule_counter += 1
        scan = ScheduledScan(
            scan_id=f"sched-{self._schedule_counter}",
            description=description,
            target=target,
            interval_s=interval_hours * 3600,
            next_run=time.time() + interval_hours * 3600,
            task_type=task_type,
        )
        self._schedules.append(scan)
        return scan

    def check_schedules(self) -> list[QueuedTask]:
        """Check for due scheduled scans and enqueue them."""
        now = time.time()
        tasks = []
        for scan in self._schedules:
            if scan.enabled and now >= scan.next_run:
                task = self.enqueue_task(
                    description=scan.description,
                    target=scan.target,
                    source=TaskSource.SCHEDULE,
                    priority=3,
                )
                scan.last_run = now
                scan.next_run = now + scan.interval_s
                tasks.append(task)
        return tasks

    def record_completion(self, findings_count: int = 0) -> None:
        """Record a task completion."""
        self._stats.tasks_completed += 1
        self._stats.total_findings += findings_count

    def record_failure(self, error: str) -> None:
        """Record a task failure."""
        self._stats.tasks_failed += 1
        self._stats.errors.append(error)
        if len(self._stats.errors) > 100:
            self._stats.errors = self._stats.errors[-50:]

    def get_queue_size(self) -> int:
        """Get current queue size."""
        return len(self._task_queue)

    def get_stats(self) -> dict[str, Any]:
        return {
            "state": self._state.value,
            "queue_size": len(self._task_queue),
            "schedules": len(self._schedules),
            "active_schedules": sum(1 for s in self._schedules if s.enabled),
            **self._stats.to_dict(),
        }

    def build_loop_prompt(self) -> str:
        """Build LLM prompt with loop state."""
        stats = self.get_stats()
        lines = ["## Autonomous Loop Status"]
        lines.append(f"State: {stats['state']}")
        lines.append(f"Queue: {stats['queue_size']} tasks")
        lines.append(f"Completed: {stats['completed']}")
        lines.append(f"Findings: {stats['findings']}")
        lines.append(f"Uptime: {stats.get('uptime', '0h')}")
        return "\n".join(lines)
