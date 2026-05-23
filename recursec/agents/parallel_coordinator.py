"""Parallel coordinator — manages concurrent agent and tool execution.

Implements:
1. Work queue with priority
2. Worker pool management
3. Fan-out / fan-in patterns
4. Result aggregation from parallel tasks
5. Dependency-aware scheduling
6. Resource-aware throttling
7. Deadlock detection
8. Progress tracking across parallel tasks
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine

import structlog

logger = structlog.get_logger()


class TaskPriority(str, Enum):
    CRITICAL = "critical"      # Execute immediately
    HIGH = "high"              # Execute next
    NORMAL = "normal"          # Standard queue
    LOW = "low"                # Background
    DEFERRED = "deferred"      # Execute when idle


class ParallelTaskStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


PRIORITY_VALUES = {
    TaskPriority.CRITICAL: 0,
    TaskPriority.HIGH: 1,
    TaskPriority.NORMAL: 2,
    TaskPriority.LOW: 3,
    TaskPriority.DEFERRED: 4,
}


@dataclass
class ParallelTask:
    """A task to be executed in parallel."""
    task_id: str = ""
    name: str = ""
    priority: TaskPriority = TaskPriority.NORMAL
    depends_on: list[str] = field(default_factory=list)
    timeout_s: float = 300.0
    status: ParallelTaskStatus = ParallelTaskStatus.QUEUED
    result: Any = None
    error: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0
    worker_fn: Any = None          # Async callable

    @property
    def duration_s(self) -> float:
        if self.completed_at and self.started_at:
            return self.completed_at - self.started_at
        if self.started_at:
            return time.time() - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id, "name": self.name[:60],
            "priority": self.priority.value,
            "status": self.status.value,
            "duration_s": round(self.duration_s, 1),
        }


@dataclass
class FanOutResult:
    """Result of a fan-out operation."""
    total_tasks: int = 0
    completed: int = 0
    failed: int = 0
    results: dict[str, Any] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total_tasks, "completed": self.completed,
            "failed": self.failed, "duration_s": round(self.duration_s, 1),
        }


class ParallelCoordinator:
    """Manages concurrent execution of agents and tools.

    Supports priority queuing, fan-out/fan-in patterns,
    and dependency-aware scheduling.
    """

    def __init__(self, max_workers: int = 10) -> None:
        self._tasks: dict[str, ParallelTask] = {}
        self._task_counter = 0
        self._max_workers = max_workers
        self._active_workers = 0
        self._completed_tasks: dict[str, Any] = {}
        self._progress: dict[str, float] = {}
        self._log = logger.bind(component="parallel_coordinator")

    def submit(
        self,
        name: str,
        worker_fn: Callable[..., Coroutine[Any, Any, Any]],
        priority: TaskPriority = TaskPriority.NORMAL,
        depends_on: list[str] | None = None,
        timeout_s: float = 300.0,
    ) -> str:
        """Submit a task for execution."""
        self._task_counter += 1
        task_id = f"ptask-{self._task_counter}"

        task = ParallelTask(
            task_id=task_id,
            name=name,
            priority=priority,
            depends_on=depends_on or [],
            timeout_s=timeout_s,
            worker_fn=worker_fn,
        )

        self._tasks[task_id] = task
        return task_id

    async def execute_all(self) -> dict[str, Any]:
        """Execute all queued tasks respecting dependencies."""
        results: dict[str, Any] = {}
        start = time.time()

        while True:
            # Get ready tasks
            ready = self._get_ready_tasks()

            if not ready:
                # Check if all done
                all_done = all(
                    t.status in (ParallelTaskStatus.COMPLETED,
                                 ParallelTaskStatus.FAILED,
                                 ParallelTaskStatus.CANCELLED,
                                 ParallelTaskStatus.TIMEOUT)
                    for t in self._tasks.values()
                )
                if all_done:
                    break

                running = [t for t in self._tasks.values()
                           if t.status == ParallelTaskStatus.RUNNING]
                if not running:
                    # Deadlock or no more work
                    break
                await asyncio.sleep(0.5)
                continue

            # Execute batch
            batch_tasks = []
            for task in ready[:self._max_workers - self._active_workers]:
                task.status = ParallelTaskStatus.RUNNING
                task.started_at = time.time()
                self._active_workers += 1
                batch_tasks.append(self._execute_task(task))

            if batch_tasks:
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)

                for task_data, result in zip(
                    ready[:len(batch_results)], batch_results,
                ):
                    self._active_workers = max(0, self._active_workers - 1)

                    if isinstance(result, Exception):
                        task_data.status = ParallelTaskStatus.FAILED
                        task_data.error = str(result)[:200]
                    else:
                        task_data.status = ParallelTaskStatus.COMPLETED
                        task_data.result = result
                        results[task_data.task_id] = result

                    task_data.completed_at = time.time()
                    self._completed_tasks[task_data.task_id] = task_data.result

        return {
            "results": results,
            "total": len(self._tasks),
            "completed": sum(
                1 for t in self._tasks.values()
                if t.status == ParallelTaskStatus.COMPLETED
            ),
            "failed": sum(
                1 for t in self._tasks.values()
                if t.status == ParallelTaskStatus.FAILED
            ),
            "duration_s": time.time() - start,
        }

    async def fan_out(
        self,
        tasks: list[dict[str, Any]],
    ) -> FanOutResult:
        """Fan-out: execute multiple independent tasks in parallel."""
        start = time.time()
        result = FanOutResult(total_tasks=len(tasks))

        async def run_one(spec: dict[str, Any]) -> tuple[str, Any]:
            fn = spec.get("fn")
            name = spec.get("name", "unknown")
            if fn:
                return name, await fn()
            return name, None

        gather_tasks = [run_one(spec) for spec in tasks]
        outcomes = await asyncio.gather(*gather_tasks, return_exceptions=True)

        for i, outcome in enumerate(outcomes):
            name = tasks[i].get("name", f"task-{i}")
            if isinstance(outcome, Exception):
                result.failed += 1
                result.errors[name] = str(outcome)[:200]
            else:
                result.completed += 1
                task_name, task_result = outcome
                result.results[task_name] = task_result

        result.duration_s = time.time() - start
        return result

    async def fan_in(
        self,
        results: dict[str, Any],
        aggregator: Callable[[dict[str, Any]], Any] | None = None,
    ) -> Any:
        """Fan-in: aggregate results from parallel tasks."""
        if aggregator:
            return aggregator(results)

        # Default: merge all results
        merged: dict[str, Any] = {}
        for key, value in results.items():
            if isinstance(value, dict):
                merged.update(value)
            elif isinstance(value, list):
                merged.setdefault("items", []).extend(value)
            else:
                merged[key] = value
        return merged

    async def _execute_task(self, task: ParallelTask) -> Any:
        """Execute a single task with timeout."""
        if not task.worker_fn:
            return None

        try:
            return await asyncio.wait_for(
                task.worker_fn(),
                timeout=task.timeout_s,
            )
        except asyncio.TimeoutError:
            task.status = ParallelTaskStatus.TIMEOUT
            raise

    def _get_ready_tasks(self) -> list[ParallelTask]:
        """Get tasks ready for execution (dependencies met, sorted by priority)."""
        ready = []
        for task in self._tasks.values():
            if task.status != ParallelTaskStatus.QUEUED:
                continue

            deps_met = all(
                dep_id in self._completed_tasks or
                (dep_id in self._tasks and
                 self._tasks[dep_id].status in (
                     ParallelTaskStatus.FAILED,
                     ParallelTaskStatus.CANCELLED,
                 ))
                for dep_id in task.depends_on
            )

            if deps_met:
                ready.append(task)

        ready.sort(key=lambda t: PRIORITY_VALUES.get(t.priority, 2))
        return ready

    def cancel_task(self, task_id: str) -> bool:
        task = self._tasks.get(task_id)
        if task and task.status == ParallelTaskStatus.QUEUED:
            task.status = ParallelTaskStatus.CANCELLED
            return True
        return False

    def update_progress(self, task_id: str, progress: float) -> None:
        self._progress[task_id] = max(0.0, min(1.0, progress))

    def get_progress(self) -> dict[str, float]:
        return dict(self._progress)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for t in self._tasks.values():
            status_counts[t.status.value] += 1

        return {
            "total_tasks": len(self._tasks),
            "active_workers": self._active_workers,
            "max_workers": self._max_workers,
            "status": dict(status_counts),
        }
