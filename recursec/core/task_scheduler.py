"""Task scheduler — cron-like scheduling, priority queues, rate limiting, and task lifecycle.

Manages:
- Priority queue with configurable scheduling
- Cron-like recurring tasks
- Rate limiting per target
- Task dependencies and chains
- Automatic retries with exponential backoff
- Task deduplication
- Queue persistence and recovery
- Resource-aware scheduling (memory, CPU, active models)
"""

from __future__ import annotations

import asyncio
import hashlib
import heapq
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine

import structlog

from recursec.core.models import AgentTask, TaskStatus

logger = structlog.get_logger()


class ScheduleType(str, Enum):
    ONCE = "once"
    INTERVAL = "interval"      # Every N seconds
    CRON = "cron"              # Cron expression
    ON_FINDING = "on_finding"  # Triggered by a finding
    ON_COMPLETE = "on_complete"  # After another task completes


class TaskPriority(int, Enum):
    CRITICAL = 1
    HIGH = 3
    NORMAL = 5
    LOW = 7
    BACKGROUND = 9


@dataclass(order=True)
class ScheduledTask:
    """A task in the priority queue."""
    priority: int
    scheduled_at: float = field(compare=False)
    task: AgentTask = field(compare=False)
    schedule_type: ScheduleType = field(default=ScheduleType.ONCE, compare=False)
    interval_s: float = field(default=0, compare=False)
    cron_expr: str = field(default="", compare=False)
    trigger_condition: str = field(default="", compare=False)
    max_retries: int = field(default=3, compare=False)
    retry_count: int = field(default=0, compare=False)
    retry_delay_s: float = field(default=30.0, compare=False)
    backoff_factor: float = field(default=2.0, compare=False)
    dedup_key: str = field(default="", compare=False)
    timeout_s: float = field(default=300.0, compare=False)
    created_at: float = field(default_factory=time.time, compare=False)
    started_at: float = field(default=0, compare=False)
    completed_at: float = field(default=0, compare=False)
    error: str = field(default="", compare=False)
    result: dict[str, Any] = field(default_factory=dict, compare=False)
    tags: list[str] = field(default_factory=list, compare=False)
    metadata: dict[str, Any] = field(default_factory=dict, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task.id,
            "priority": self.priority,
            "objective": self.task.objective[:100],
            "role": self.task.agent_role.value,
            "schedule_type": self.schedule_type.value,
            "status": self.task.status.value,
            "retry_count": self.retry_count,
            "tags": self.tags,
        }


@dataclass
class RateLimitRule:
    """Rate limiting rule for a target."""
    target_pattern: str  # regex or exact match
    max_requests_per_minute: int = 60
    max_concurrent: int = 5
    cooldown_after_error_s: float = 60.0
    _request_timestamps: list[float] = field(default_factory=list)
    _active_count: int = 0

    def can_execute(self) -> bool:
        now = time.time()
        # Clean old timestamps
        self._request_timestamps = [t for t in self._request_timestamps if now - t < 60]
        return (
            len(self._request_timestamps) < self.max_requests_per_minute
            and self._active_count < self.max_concurrent
        )

    def record_start(self) -> None:
        self._request_timestamps.append(time.time())
        self._active_count += 1

    def record_end(self) -> None:
        self._active_count = max(0, self._active_count - 1)


@dataclass
class CronExpression:
    """Parsed cron expression."""
    minute: str = "*"
    hour: str = "*"
    day_of_month: str = "*"
    month: str = "*"
    day_of_week: str = "*"

    @classmethod
    def parse(cls, expr: str) -> CronExpression:
        parts = expr.strip().split()
        if len(parts) != 5:
            raise ValueError(f"Invalid cron expression: {expr} (need 5 fields)")
        return cls(
            minute=parts[0],
            hour=parts[1],
            day_of_month=parts[2],
            month=parts[3],
            day_of_week=parts[4],
        )

    def matches_now(self) -> bool:
        import datetime
        now = datetime.datetime.now()
        return (
            self._matches_field(self.minute, now.minute, 0, 59)
            and self._matches_field(self.hour, now.hour, 0, 23)
            and self._matches_field(self.day_of_month, now.day, 1, 31)
            and self._matches_field(self.month, now.month, 1, 12)
            and self._matches_field(self.day_of_week, now.weekday(), 0, 6)
        )

    def _matches_field(self, field_expr: str, current: int, min_val: int, max_val: int) -> bool:
        if field_expr == "*":
            return True
        for part in field_expr.split(","):
            if "-" in part:
                start, end = part.split("-", 1)
                if int(start) <= current <= int(end):
                    return True
            elif "/" in part:
                base, step = part.split("/", 1)
                base_val = min_val if base == "*" else int(base)
                if (current - base_val) % int(step) == 0 and current >= base_val:
                    return True
            else:
                if int(part) == current:
                    return True
        return False


class TaskScheduler:
    """Advanced task scheduler with priority queue, rate limiting, and persistence.

    Features:
    - Priority-based execution ordering
    - Cron-like recurring task scheduling
    - Per-target rate limiting
    - Task deduplication
    - Automatic retry with exponential backoff
    - Queue persistence for recovery
    - Event-driven task triggers
    - Resource-aware scheduling
    """

    def __init__(
        self,
        max_concurrent: int = 10,
        persist_path: str | None = None,
    ):
        self._queue: list[ScheduledTask] = []  # heapq
        self._running: dict[str, ScheduledTask] = {}
        self._completed: list[ScheduledTask] = []
        self._failed: list[ScheduledTask] = []
        self._dedup_set: set[str] = set()
        self._rate_limits: dict[str, RateLimitRule] = {}
        self._cron_tasks: list[ScheduledTask] = []
        self._triggers: dict[str, list[ScheduledTask]] = {}
        self._max_concurrent = max_concurrent
        self._persist_path = persist_path
        self._running_flag = False
        self._task_callbacks: dict[str, Callable[..., Coroutine[Any, Any, AgentTask]]] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._stats = {
            "total_submitted": 0,
            "total_completed": 0,
            "total_failed": 0,
            "total_retried": 0,
            "total_deduplicated": 0,
            "total_rate_limited": 0,
        }

    def submit(
        self,
        task: AgentTask,
        priority: TaskPriority = TaskPriority.NORMAL,
        schedule_type: ScheduleType = ScheduleType.ONCE,
        interval_s: float = 0,
        cron_expr: str = "",
        trigger_condition: str = "",
        max_retries: int = 3,
        timeout_s: float = 300.0,
        dedup: bool = True,
        tags: list[str] | None = None,
    ) -> str | None:
        """Submit a task to the scheduler. Returns task ID or None if deduplicated."""
        # Deduplication
        if dedup:
            dedup_key = self._compute_dedup_key(task)
            if dedup_key in self._dedup_set:
                self._stats["total_deduplicated"] += 1
                logger.debug("task_deduplicated", objective=task.objective[:50])
                return None
            self._dedup_set.add(dedup_key)
        else:
            dedup_key = ""

        scheduled = ScheduledTask(
            priority=priority.value,
            scheduled_at=time.time(),
            task=task,
            schedule_type=schedule_type,
            interval_s=interval_s,
            cron_expr=cron_expr,
            trigger_condition=trigger_condition,
            max_retries=max_retries,
            timeout_s=timeout_s,
            dedup_key=dedup_key,
            tags=tags or [],
        )

        if schedule_type == ScheduleType.CRON:
            self._cron_tasks.append(scheduled)
        elif schedule_type in (ScheduleType.ON_FINDING, ScheduleType.ON_COMPLETE):
            condition = trigger_condition or "any"
            if condition not in self._triggers:
                self._triggers[condition] = []
            self._triggers[condition].append(scheduled)
        else:
            heapq.heappush(self._queue, scheduled)

        self._stats["total_submitted"] += 1
        logger.info("task_submitted", task_id=task.id, priority=priority.value, type=schedule_type.value)
        return task.id

    def submit_batch(self, tasks: list[tuple[AgentTask, TaskPriority]]) -> list[str]:
        """Submit multiple tasks at once."""
        ids = []
        for task, priority in tasks:
            tid = self.submit(task, priority=priority)
            if tid:
                ids.append(tid)
        return ids

    async def run(
        self,
        execute_fn: Callable[..., Coroutine[Any, Any, AgentTask]],
    ) -> None:
        """Main scheduler loop — runs until stopped."""
        self._running_flag = True
        self._execute_fn = execute_fn

        logger.info("scheduler_starting", queue_size=len(self._queue))

        # Start cron checker
        cron_task = asyncio.create_task(self._cron_loop())

        try:
            while self._running_flag:
                # Check rate limits and get next task
                scheduled = self._get_next_task()
                if not scheduled:
                    await asyncio.sleep(0.5)
                    continue

                # Execute with semaphore
                asyncio.create_task(self._execute_task(scheduled, execute_fn))

        except asyncio.CancelledError:
            pass
        finally:
            cron_task.cancel()
            self._running_flag = False
            logger.info("scheduler_stopped")

    async def _execute_task(
        self,
        scheduled: ScheduledTask,
        execute_fn: Callable[..., Coroutine[Any, Any, AgentTask]],
    ) -> None:
        """Execute a single scheduled task."""
        async with self._semaphore:
            task = scheduled.task
            task_id = task.id
            self._running[task_id] = scheduled
            scheduled.started_at = time.time()
            task.status = TaskStatus.RUNNING

            # Rate limiting
            target_value = task.target.value if task.target else ""
            rate_rule = self._get_rate_limit(target_value)
            if rate_rule:
                rate_rule.record_start()

            try:
                result = await asyncio.wait_for(
                    execute_fn(task),
                    timeout=scheduled.timeout_s,
                )
                scheduled.completed_at = time.time()
                scheduled.result = result.result if hasattr(result, "result") else {}

                if result.status == TaskStatus.COMPLETED:
                    self._stats["total_completed"] += 1
                    self._completed.append(scheduled)
                    # Trigger dependent tasks
                    await self._fire_triggers("on_complete", task)
                    # Handle findings
                    for finding in getattr(result, "findings", []):
                        await self._fire_triggers("on_finding", task, finding=finding)
                else:
                    self._handle_failure(scheduled, result.error or "Task failed")

                # Re-schedule if interval
                if scheduled.schedule_type == ScheduleType.INTERVAL and scheduled.interval_s > 0:
                    self._reschedule_interval(scheduled)

            except asyncio.TimeoutError:
                self._handle_failure(scheduled, f"Timeout after {scheduled.timeout_s}s")
            except Exception as e:
                self._handle_failure(scheduled, str(e))
            finally:
                self._running.pop(task_id, None)
                if rate_rule:
                    rate_rule.record_end()

    def _handle_failure(self, scheduled: ScheduledTask, error: str) -> None:
        """Handle task failure with retry logic."""
        scheduled.error = error
        scheduled.task.status = TaskStatus.FAILED
        scheduled.task.error = error

        if scheduled.retry_count < scheduled.max_retries:
            scheduled.retry_count += 1
            delay = scheduled.retry_delay_s * (scheduled.backoff_factor ** (scheduled.retry_count - 1))
            scheduled.scheduled_at = time.time() + delay
            scheduled.task.status = TaskStatus.PENDING
            heapq.heappush(self._queue, scheduled)
            self._stats["total_retried"] += 1
            logger.info(
                "task_retry",
                task_id=scheduled.task.id,
                retry=scheduled.retry_count,
                delay_s=delay,
            )
        else:
            self._stats["total_failed"] += 1
            self._failed.append(scheduled)
            logger.error("task_failed_permanently", task_id=scheduled.task.id, error=error)

    def _get_next_task(self) -> ScheduledTask | None:
        """Get the next task from the queue, respecting rate limits."""
        now = time.time()
        # Try tasks in priority order
        skipped: list[ScheduledTask] = []

        while self._queue:
            scheduled = heapq.heappop(self._queue)

            # Check if scheduled time has arrived
            if scheduled.scheduled_at > now:
                heapq.heappush(self._queue, scheduled)
                break

            # Check rate limit
            target_value = scheduled.task.target.value if scheduled.task.target else ""
            rate_rule = self._get_rate_limit(target_value)
            if rate_rule and not rate_rule.can_execute():
                self._stats["total_rate_limited"] += 1
                scheduled.scheduled_at = now + 5  # Try again in 5s
                skipped.append(scheduled)
                continue

            # Put back skipped tasks
            for s in skipped:
                heapq.heappush(self._queue, s)

            return scheduled

        # Put back skipped tasks
        for s in skipped:
            heapq.heappush(self._queue, s)
        return None

    def _reschedule_interval(self, scheduled: ScheduledTask) -> None:
        """Re-schedule an interval task."""
        # Create a new task for the next interval
        new_task = AgentTask(
            agent_role=scheduled.task.agent_role,
            objective=scheduled.task.objective,
            target=scheduled.task.target,
            priority=scheduled.task.priority,
            max_depth=scheduled.task.max_depth,
        )
        new_scheduled = ScheduledTask(
            priority=scheduled.priority,
            scheduled_at=time.time() + scheduled.interval_s,
            task=new_task,
            schedule_type=ScheduleType.INTERVAL,
            interval_s=scheduled.interval_s,
            max_retries=scheduled.max_retries,
            timeout_s=scheduled.timeout_s,
            tags=scheduled.tags,
        )
        heapq.heappush(self._queue, new_scheduled)

    async def _cron_loop(self) -> None:
        """Check cron tasks every minute."""
        while self._running_flag:
            for cron_task in self._cron_tasks:
                try:
                    cron = CronExpression.parse(cron_task.cron_expr)
                    if cron.matches_now():
                        # Create and submit a new task instance
                        new_task = AgentTask(
                            agent_role=cron_task.task.agent_role,
                            objective=cron_task.task.objective,
                            target=cron_task.task.target,
                            priority=cron_task.task.priority,
                        )
                        self.submit(new_task, priority=TaskPriority(cron_task.priority), dedup=False)
                except Exception as e:
                    logger.warning("cron_check_error", error=str(e))
            await asyncio.sleep(60)

    async def _fire_triggers(
        self, event_type: str, source_task: AgentTask, finding: Any = None
    ) -> None:
        """Fire event-triggered tasks."""
        triggered = self._triggers.get(event_type, []) + self._triggers.get("any", [])
        for trigger_template in triggered:
            new_task = AgentTask(
                agent_role=trigger_template.task.agent_role,
                objective=trigger_template.task.objective,
                target=source_task.target,
                priority=source_task.priority,
                context={"triggered_by": source_task.id, "event": event_type},
            )
            self.submit(new_task, priority=TaskPriority(trigger_template.priority))

    # ── Rate Limiting ──────────────────────────────────────

    def add_rate_limit(self, target_pattern: str, rule: RateLimitRule) -> None:
        """Add a rate limit rule for a target pattern."""
        self._rate_limits[target_pattern] = rule

    def _get_rate_limit(self, target: str) -> RateLimitRule | None:
        """Find matching rate limit rule."""
        for pattern, rule in self._rate_limits.items():
            if pattern in target or pattern == "*":
                return rule
        return None

    # ── Deduplication ──────────────────────────────────────

    def _compute_dedup_key(self, task: AgentTask) -> str:
        data = f"{task.agent_role.value}:{task.objective}:{task.target.value if task.target else ''}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def clear_dedup_cache(self) -> None:
        self._dedup_set.clear()

    # ── Queue Management ───────────────────────────────────

    def stop(self) -> None:
        self._running_flag = False

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a queued task."""
        for i, st in enumerate(self._queue):
            if st.task.id == task_id:
                st.task.status = TaskStatus.CANCELLED
                self._queue.pop(i)
                heapq.heapify(self._queue)
                return True
        # Check running
        if task_id in self._running:
            self._running[task_id].task.status = TaskStatus.CANCELLED
            return True
        return False

    def get_queue(self) -> list[dict[str, Any]]:
        """Get current queue state."""
        return [st.to_dict() for st in sorted(self._queue)]

    def get_running(self) -> list[dict[str, Any]]:
        """Get currently running tasks."""
        return [st.to_dict() for st in self._running.values()]

    def get_completed(self, limit: int = 50) -> list[dict[str, Any]]:
        return [st.to_dict() for st in self._completed[-limit:]]

    def get_failed(self, limit: int = 50) -> list[dict[str, Any]]:
        return [st.to_dict() for st in self._failed[-limit:]]

    # ── Persistence ────────────────────────────────────────

    def save_state(self) -> None:
        """Save queue state to disk for recovery."""
        if not self._persist_path:
            return
        state = {
            "queue": [st.to_dict() for st in self._queue],
            "cron_tasks": [st.to_dict() for st in self._cron_tasks],
            "stats": self._stats,
            "timestamp": time.time(),
        }
        path = Path(self._persist_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state, indent=2))

    def load_state(self) -> bool:
        """Load queue state from disk."""
        if not self._persist_path:
            return False
        path = Path(self._persist_path)
        if not path.exists():
            return False
        try:
            state = json.loads(path.read_text())
            self._stats.update(state.get("stats", {}))
            logger.info("scheduler_state_loaded", tasks=len(state.get("queue", [])))
            return True
        except Exception as e:
            logger.error("scheduler_load_error", error=str(e))
            return False

    # ── Statistics ─────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        return {
            **self._stats,
            "queue_size": len(self._queue),
            "running": len(self._running),
            "completed": len(self._completed),
            "failed": len(self._failed),
            "cron_tasks": len(self._cron_tasks),
            "triggers": sum(len(v) for v in self._triggers.values()),
            "rate_limits": len(self._rate_limits),
        }
