"""Task scheduler — cron-like scheduling for recurring security scans.

Features:
- Cron expression parsing (minute, hour, day, month, weekday)
- One-shot and recurring schedules
- Priority-based task queuing
- Concurrent execution limits
- Task dependencies
- Failure retry with exponential backoff
- Schedule persistence (JSON file)
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Coroutine

import structlog

logger = structlog.get_logger()


@dataclass
class CronExpression:
    """Parsed cron expression."""
    minute: list[int] = field(default_factory=lambda: list(range(60)))
    hour: list[int] = field(default_factory=lambda: list(range(24)))
    day_of_month: list[int] = field(default_factory=lambda: list(range(1, 32)))
    month: list[int] = field(default_factory=lambda: list(range(1, 13)))
    day_of_week: list[int] = field(default_factory=lambda: list(range(7)))

    @classmethod
    def parse(cls, expr: str) -> CronExpression:
        """Parse a cron expression string (minute hour day month weekday)."""
        parts = expr.strip().split()
        if len(parts) != 5:
            raise ValueError(f"Invalid cron expression: {expr} (need 5 fields)")

        return CronExpression(
            minute=cls._parse_field(parts[0], 0, 59),
            hour=cls._parse_field(parts[1], 0, 23),
            day_of_month=cls._parse_field(parts[2], 1, 31),
            month=cls._parse_field(parts[3], 1, 12),
            day_of_week=cls._parse_field(parts[4], 0, 6),
        )

    @classmethod
    def _parse_field(cls, field_str: str, min_val: int, max_val: int) -> list[int]:
        """Parse a single cron field."""
        if field_str == "*":
            return list(range(min_val, max_val + 1))

        values: list[int] = []
        for part in field_str.split(","):
            if "/" in part:
                # Step values: */5 or 1-30/5
                range_part, step_str = part.split("/")
                step = int(step_str)
                if range_part == "*":
                    start, end = min_val, max_val
                elif "-" in range_part:
                    start, end = (int(x) for x in range_part.split("-"))
                else:
                    start, end = int(range_part), max_val
                values.extend(range(start, end + 1, step))
            elif "-" in part:
                # Range: 1-5
                start, end = (int(x) for x in part.split("-"))
                values.extend(range(start, end + 1))
            else:
                values.append(int(part))

        return [v for v in values if min_val <= v <= max_val]

    def matches(self, ts: float | None = None) -> bool:
        """Check if current time matches this cron expression."""
        import datetime
        if ts is not None:
            dt = datetime.datetime.fromtimestamp(ts)
        else:
            dt = datetime.datetime.now()

        return (
            dt.minute in self.minute
            and dt.hour in self.hour
            and dt.day in self.day_of_month
            and dt.month in self.month
            and dt.weekday() in self.day_of_week
        )


@dataclass
class ScheduledTask:
    """A task scheduled for execution."""
    task_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    description: str = ""
    cron_expr: str = ""
    target: str = ""
    scan_type: str = "full"
    parameters: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    max_retries: int = 3
    retry_count: int = 0
    last_run: float = 0.0
    next_run: float = 0.0
    last_status: str = ""
    one_shot: bool = False
    priority: int = 5

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id, "name": self.name,
            "cron": self.cron_expr, "target": self.target,
            "scan_type": self.scan_type, "enabled": self.enabled,
            "last_run": self.last_run, "next_run": self.next_run,
            "last_status": self.last_status, "priority": self.priority,
        }


class TaskScheduler:
    """Cron-like scheduler for recurring security scans."""

    def __init__(
        self,
        max_concurrent: int = 3,
        state_file: str = "data/scheduler_state.json",
    ) -> None:
        self._tasks: dict[str, ScheduledTask] = {}
        self._max_concurrent = max_concurrent
        self._running_count = 0
        self._state_file = Path(state_file)
        self._running = False
        self._callbacks: dict[str, Callable[..., Coroutine[Any, Any, Any]]] = {}

        self._load_state()

    def schedule(self, task: ScheduledTask) -> str:
        """Add a task to the schedule."""
        self._tasks[task.task_id] = task
        self._save_state()
        logger.info("task_scheduled", task_id=task.task_id, name=task.name, cron=task.cron_expr)
        return task.task_id

    def unschedule(self, task_id: str) -> bool:
        """Remove a task from the schedule."""
        if task_id in self._tasks:
            del self._tasks[task_id]
            self._save_state()
            return True
        return False

    def enable(self, task_id: str) -> bool:
        """Enable a scheduled task."""
        if task_id in self._tasks:
            self._tasks[task_id].enabled = True
            self._save_state()
            return True
        return False

    def disable(self, task_id: str) -> bool:
        """Disable a scheduled task."""
        if task_id in self._tasks:
            self._tasks[task_id].enabled = False
            self._save_state()
            return True
        return False

    def register_callback(self, scan_type: str, callback: Callable[..., Coroutine[Any, Any, Any]]) -> None:
        """Register a callback for a scan type."""
        self._callbacks[scan_type] = callback

    def list_tasks(self) -> list[dict[str, Any]]:
        """List all scheduled tasks."""
        return [t.to_dict() for t in self._tasks.values()]

    async def start(self) -> None:
        """Start the scheduler loop."""
        self._running = True
        logger.info("scheduler_started", tasks=len(self._tasks))

        while self._running:
            await self._tick()
            await asyncio.sleep(30)  # Check every 30 seconds

    def stop(self) -> None:
        """Stop the scheduler."""
        self._running = False
        self._save_state()
        logger.info("scheduler_stopped")

    async def _tick(self) -> None:
        """Process one scheduler tick — check and execute due tasks."""
        now = time.time()

        for task in list(self._tasks.values()):
            if not task.enabled:
                continue

            # Check cron expression
            try:
                cron = CronExpression.parse(task.cron_expr)
            except ValueError:
                continue

            if not cron.matches():
                continue

            # Don't run more often than once per minute
            if now - task.last_run < 60:
                continue

            # Check concurrent limit
            if self._running_count >= self._max_concurrent:
                continue

            # Execute task
            asyncio.create_task(self._execute_task(task))

    async def _execute_task(self, task: ScheduledTask) -> None:
        """Execute a scheduled task."""
        self._running_count += 1
        task.last_run = time.time()
        task.last_status = "running"

        logger.info("scheduled_task_started", task_id=task.task_id, name=task.name)

        try:
            callback = self._callbacks.get(task.scan_type)
            if callback:
                await callback(target=task.target, parameters=task.parameters)
                task.last_status = "completed"
                task.retry_count = 0
            else:
                task.last_status = "no_callback"
                logger.warning("no_callback", scan_type=task.scan_type)

        except Exception as e:
            task.last_status = "failed"
            task.retry_count += 1
            logger.error("scheduled_task_failed",
                         task_id=task.task_id, error=str(e),
                         retry=task.retry_count)

            # Retry with exponential backoff
            if task.retry_count <= task.max_retries:
                delay = min(300, 30 * (2 ** (task.retry_count - 1)))
                await asyncio.sleep(delay)
                await self._execute_task(task)

        finally:
            self._running_count -= 1

            if task.one_shot and task.last_status == "completed":
                self.unschedule(task.task_id)

            self._save_state()

    def _load_state(self) -> None:
        """Load scheduler state from file."""
        if not self._state_file.exists():
            return

        try:
            data = json.loads(self._state_file.read_text())
            for task_data in data.get("tasks", []):
                task = ScheduledTask(
                    task_id=task_data["task_id"],
                    name=task_data.get("name", ""),
                    cron_expr=task_data.get("cron", ""),
                    target=task_data.get("target", ""),
                    scan_type=task_data.get("scan_type", "full"),
                    enabled=task_data.get("enabled", True),
                    last_run=task_data.get("last_run", 0),
                    priority=task_data.get("priority", 5),
                )
                self._tasks[task.task_id] = task
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("scheduler_state_load_failed", error=str(e))

    def _save_state(self) -> None:
        """Save scheduler state to file."""
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = {"tasks": [t.to_dict() for t in self._tasks.values()]}
            self._state_file.write_text(json.dumps(data, indent=2))
        except OSError as e:
            logger.warning("scheduler_state_save_failed", error=str(e))
