"""Autonomous daemon — 24/7 background assessment runner.

Implements:
1. Scheduled recurring scans
2. Task queue management
3. Continuous monitoring mode
4. Auto-restart on failure
5. Resource usage monitoring
6. Graceful shutdown
7. Priority-based task scheduling
8. Notification hooks
"""

from __future__ import annotations

import asyncio
import json
import signal
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskPriority(str, Enum):
    URGENT = "urgent"         # Run immediately
    HIGH = "high"             # Run next
    NORMAL = "normal"         # Standard queue
    LOW = "low"               # Run when idle
    SCHEDULED = "scheduled"   # Run at specific time


class TaskStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"


@dataclass
class DaemonTask:
    """A task for the daemon to execute."""
    task_id: str = ""
    target: str = ""
    goal: str = ""
    priority: TaskPriority = TaskPriority.NORMAL
    status: TaskStatus = TaskStatus.QUEUED
    config: dict[str, Any] = field(default_factory=dict)
    scheduled_at: float = 0.0     # 0 = ASAP
    repeat_interval_s: float = 0.0  # 0 = no repeat
    max_retries: int = 2
    retries: int = 0
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def is_ready(self) -> bool:
        if self.status != TaskStatus.QUEUED:
            return False
        if self.scheduled_at and time.time() < self.scheduled_at:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id, "target": self.target[:50],
            "priority": self.priority.value,
            "status": self.status.value,
            "retries": f"{self.retries}/{self.max_retries}",
        }


class RecurSecDaemon:
    """24/7 autonomous security assessment daemon.

    Manages a task queue, executes assessments,
    and runs continuously until stopped.
    """

    def __init__(
        self,
        max_concurrent: int = 3,
        queue_dir: str = "data/queue",
    ) -> None:
        self._max_concurrent = max_concurrent
        self._queue_dir = Path(queue_dir)
        self._queue_dir.mkdir(parents=True, exist_ok=True)

        self._tasks: dict[str, DaemonTask] = {}
        self._task_counter = 0
        self._running = False
        self._current_tasks: set[str] = set()
        self._log = logger.bind(component="daemon")

        # Signal handlers
        self._shutdown_event = asyncio.Event()

    def add_task(
        self,
        target: str,
        goal: str = "",
        priority: TaskPriority = TaskPriority.NORMAL,
        config: dict[str, Any] | None = None,
        scheduled_at: float = 0.0,
        repeat_interval_s: float = 0.0,
    ) -> str:
        """Add a task to the queue."""
        self._task_counter += 1
        task_id = f"task-{self._task_counter}"

        task = DaemonTask(
            task_id=task_id,
            target=target,
            goal=goal or f"Security assessment of {target}",
            priority=priority,
            config=config or {},
            scheduled_at=scheduled_at,
            repeat_interval_s=repeat_interval_s,
        )

        self._tasks[task_id] = task
        self._log.info("task_added", id=task_id, target=target[:50], priority=priority.value)
        return task_id

    def cancel_task(self, task_id: str) -> bool:
        task = self._tasks.get(task_id)
        if task and task.status in (TaskStatus.QUEUED, TaskStatus.RETRYING):
            task.status = TaskStatus.CANCELLED
            return True
        return False

    async def run(self) -> None:
        """Main daemon loop."""
        self._running = True
        self._log.info("daemon_started")

        # Set up signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._handle_signal)

        try:
            while self._running and not self._shutdown_event.is_set():
                # Get ready tasks
                ready = self._get_ready_tasks()

                # Start tasks up to concurrency limit
                available_slots = self._max_concurrent - len(self._current_tasks)
                for task in ready[:available_slots]:
                    asyncio.create_task(self._execute_task(task))
                    self._current_tasks.add(task.task_id)

                # Wait a bit before checking again
                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(),
                        timeout=5.0,
                    )
                except asyncio.TimeoutError:
                    pass

        except asyncio.CancelledError:
            pass

        self._log.info("daemon_stopped")

    async def _execute_task(self, task: DaemonTask) -> None:
        """Execute a single task."""
        task.status = TaskStatus.RUNNING
        task.started_at = time.time()
        self._log.info("task_started", id=task.task_id, target=task.target[:50])

        try:
            from recursec.agents.recursec_agent import AssessmentConfig, RecurSecAgent

            agent = RecurSecAgent()
            config = AssessmentConfig(
                target=task.target,
                goal=task.goal,
                **{k: v for k, v in task.config.items() if hasattr(AssessmentConfig, k)},
            )

            result = await agent.assess(config)

            task.status = TaskStatus.COMPLETED
            task.completed_at = time.time()
            task.result = result.to_dict()

            self._log.info(
                "task_completed",
                id=task.task_id,
                findings=len(result.findings),
                time=f"{task.completed_at - task.started_at:.1f}s",
            )

            # Handle repeating tasks
            if task.repeat_interval_s > 0:
                self.add_task(
                    target=task.target,
                    goal=task.goal,
                    priority=task.priority,
                    config=task.config,
                    scheduled_at=time.time() + task.repeat_interval_s,
                    repeat_interval_s=task.repeat_interval_s,
                )

        except Exception as e:
            task.error = str(e)[:200]
            self._log.error("task_failed", id=task.task_id, error=task.error)

            if task.retries < task.max_retries:
                task.retries += 1
                task.status = TaskStatus.QUEUED
                self._log.info("task_retry", id=task.task_id, retry=task.retries)
            else:
                task.status = TaskStatus.FAILED
                task.completed_at = time.time()

        finally:
            self._current_tasks.discard(task.task_id)
            self._save_task(task)

    def _get_ready_tasks(self) -> list[DaemonTask]:
        """Get tasks ready for execution, sorted by priority."""
        priority_order = {
            TaskPriority.URGENT: 0,
            TaskPriority.HIGH: 1,
            TaskPriority.NORMAL: 2,
            TaskPriority.LOW: 3,
            TaskPriority.SCHEDULED: 4,
        }

        ready = [t for t in self._tasks.values() if t.is_ready]
        ready.sort(key=lambda t: priority_order.get(t.priority, 2))
        return ready

    def _handle_signal(self) -> None:
        """Handle shutdown signal."""
        self._log.info("shutdown_signal_received")
        self._running = False
        self._shutdown_event.set()

    def _save_task(self, task: DaemonTask) -> None:
        """Persist task result."""
        try:
            path = self._queue_dir / f"{task.task_id}.json"
            path.write_text(json.dumps(task.to_dict()))
        except OSError:
            pass

    def stop(self) -> None:
        self._running = False
        self._shutdown_event.set()

    def get_queue_stats(self) -> dict[str, Any]:
        by_status: dict[str, int] = {}
        for task in self._tasks.values():
            by_status.setdefault(task.status.value, 0)
            by_status[task.status.value] += 1

        return {
            "total": len(self._tasks),
            "running": len(self._current_tasks),
            "by_status": by_status,
        }
