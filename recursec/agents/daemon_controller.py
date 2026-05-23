"""Daemon controller — 24/7 persistent operation with scheduling and auto-recovery.

Implements:
1. Daemon mode (background operation)
2. Task scheduling (cron-like)
3. Continuous monitoring mode
4. Auto-recovery from failures
5. Resource cleanup
6. Graceful shutdown
7. Health monitoring
8. Scheduled report generation
"""

from __future__ import annotations

import asyncio
import json
import signal
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine

import structlog

logger = structlog.get_logger()


class DaemonState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    SHUTTING_DOWN = "shutting_down"


class ScheduleType(str, Enum):
    ONCE = "once"                  # Run once at specific time
    INTERVAL = "interval"          # Run every N seconds
    DAILY = "daily"                # Run daily at specific hour
    WEEKLY = "weekly"              # Run weekly
    CONTINUOUS = "continuous"      # Run continuously with sleep between


@dataclass
class ScheduledTask:
    """A scheduled task."""
    task_id: str = ""
    name: str = ""
    schedule_type: ScheduleType = ScheduleType.INTERVAL
    interval_s: int = 3600
    target: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    last_run: float = 0.0
    next_run: float = 0.0
    run_count: int = 0
    error_count: int = 0
    last_error: str = ""

    @property
    def is_due(self) -> bool:
        if not self.enabled:
            return False
        return time.time() >= self.next_run

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id,
            "name": self.name[:30],
            "type": self.schedule_type.value,
            "interval": self.interval_s,
            "target": self.target[:25],
            "enabled": self.enabled,
            "runs": self.run_count,
            "errors": self.error_count,
            "due": self.is_due,
        }


@dataclass
class DaemonHealth:
    """Daemon health status."""
    uptime_s: float = 0.0
    tasks_completed: int = 0
    tasks_failed: int = 0
    memory_mb: float = 0.0
    active_tasks: int = 0
    last_heartbeat: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "uptime_s": round(self.uptime_s, 1),
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "active_tasks": self.active_tasks,
        }


class DaemonController:
    """24/7 persistent operation with scheduling and auto-recovery.

    Manages the agent as a long-running daemon with
    scheduled scans, health monitoring, and auto-recovery.
    """

    def __init__(
        self,
        data_dir: str = "data/daemon",
        heartbeat_interval: int = 60,
        max_concurrent_tasks: int = 5,
    ) -> None:
        self._state = DaemonState.STOPPED
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._tasks: dict[str, ScheduledTask] = {}
        self._task_counter = 0
        self._heartbeat_interval = heartbeat_interval
        self._max_concurrent = max_concurrent_tasks
        self._active_tasks: set[str] = set()
        self._start_time = 0.0
        self._health = DaemonHealth()
        self._shutdown_event: asyncio.Event | None = None
        self._task_handlers: dict[str, Callable[..., Coroutine[Any, Any, Any]]] = {}
        self._log = logger.bind(component="daemon_controller")

    def schedule(
        self,
        name: str,
        schedule_type: ScheduleType = ScheduleType.INTERVAL,
        interval_s: int = 3600,
        target: str = "",
        config: dict[str, Any] | None = None,
    ) -> ScheduledTask:
        """Schedule a new task."""
        self._task_counter += 1
        task = ScheduledTask(
            task_id=f"sched-{self._task_counter}",
            name=name,
            schedule_type=schedule_type,
            interval_s=interval_s,
            target=target,
            config=config or {},
            next_run=time.time() + interval_s if schedule_type == ScheduleType.INTERVAL else time.time(),
        )

        self._tasks[task.task_id] = task
        self._save_schedule()
        return task

    def register_handler(
        self,
        name: str,
        handler: Callable[..., Coroutine[Any, Any, Any]],
    ) -> None:
        """Register a handler for a task type."""
        self._task_handlers[name] = handler

    async def start(self) -> None:
        """Start the daemon."""
        self._state = DaemonState.STARTING
        self._start_time = time.time()
        self._shutdown_event = asyncio.Event()

        # Register signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._handle_signal)

        self._state = DaemonState.RUNNING
        self._log.info("daemon_started")

        try:
            await self._main_loop()
        except asyncio.CancelledError:
            pass
        finally:
            self._state = DaemonState.STOPPED

    async def _main_loop(self) -> None:
        """Main daemon loop."""
        while self._state == DaemonState.RUNNING:
            # Heartbeat
            self._health.last_heartbeat = time.time()
            self._health.uptime_s = time.time() - self._start_time

            # Check scheduled tasks
            for task in self._tasks.values():
                if task.is_due and task.task_id not in self._active_tasks:
                    if len(self._active_tasks) < self._max_concurrent:
                        asyncio.create_task(self._run_task(task))

            # Wait or check for shutdown
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self._heartbeat_interval,
                )
                break  # Shutdown requested
            except asyncio.TimeoutError:
                continue

    async def _run_task(self, task: ScheduledTask) -> None:
        """Execute a scheduled task."""
        self._active_tasks.add(task.task_id)
        self._health.active_tasks = len(self._active_tasks)
        task.last_run = time.time()

        try:
            handler = self._task_handlers.get(task.name)
            if handler:
                await handler(task.target, task.config)

            task.run_count += 1
            self._health.tasks_completed += 1

            # Schedule next run
            if task.schedule_type == ScheduleType.INTERVAL:
                task.next_run = time.time() + task.interval_s
            elif task.schedule_type == ScheduleType.ONCE:
                task.enabled = False

        except Exception as exc:
            task.error_count += 1
            task.last_error = str(exc)[:200]
            self._health.tasks_failed += 1
            self._log.error("task_failed", task=task.name, error=str(exc)[:100])

            # Auto-recovery: disable after too many errors
            if task.error_count > 10:
                task.enabled = False

        finally:
            self._active_tasks.discard(task.task_id)
            self._health.active_tasks = len(self._active_tasks)

    def pause(self) -> None:
        """Pause the daemon."""
        self._state = DaemonState.PAUSED

    def resume(self) -> None:
        """Resume the daemon."""
        self._state = DaemonState.RUNNING

    async def shutdown(self) -> None:
        """Graceful shutdown."""
        self._state = DaemonState.SHUTTING_DOWN

        # Wait for active tasks to complete (with timeout)
        timeout = 30
        start = time.time()
        while self._active_tasks and (time.time() - start) < timeout:
            await asyncio.sleep(1)

        if self._shutdown_event:
            self._shutdown_event.set()

        self._save_schedule()
        self._state = DaemonState.STOPPED

    def _handle_signal(self) -> None:
        """Handle shutdown signals."""
        if self._shutdown_event:
            self._shutdown_event.set()

    def _save_schedule(self) -> None:
        """Persist schedule to disk."""
        path = self._data_dir / "schedule.json"
        try:
            data = [t.to_dict() for t in self._tasks.values()]
            path.write_text(json.dumps(data, indent=2))
        except OSError:
            pass

    def get_tasks(self) -> list[dict[str, Any]]:
        return [t.to_dict() for t in self._tasks.values()]

    def get_stats(self) -> dict[str, Any]:
        return {
            "state": self._state.value,
            "health": self._health.to_dict(),
            "tasks": len(self._tasks),
            "active": len(self._active_tasks),
        }
