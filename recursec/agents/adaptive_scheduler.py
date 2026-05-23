"""Adaptive scheduler — intelligent task scheduling and resource allocation.

Dynamically adjusts the assessment strategy based on:
1. Discovered attack surface (what we know)
2. Current findings (what we've found)
3. Resource budgets (what we can still do)
4. Time constraints (how long do we have)
5. Model availability (which LLMs are up)
6. Historical effectiveness (what worked before)

Scheduling strategies:
- Breadth-first: Cover all attack surfaces shallowly
- Depth-first: Deep-dive into promising areas
- Risk-based: Focus on highest-risk areas first
- Coverage-based: Ensure all categories are tested
- Adaptive: Switch between strategies based on progress

The scheduler maintains a priority queue of tasks and
reorders dynamically as new information arrives.
"""

from __future__ import annotations

import heapq
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class SchedulingStrategy(str, Enum):
    BREADTH_FIRST = "breadth_first"
    DEPTH_FIRST = "depth_first"
    RISK_BASED = "risk_based"
    COVERAGE_BASED = "coverage_based"
    ADAPTIVE = "adaptive"


class TaskStatus(str, Enum):
    QUEUED = "queued"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    DEFERRED = "deferred"


class TaskPriority(int, Enum):
    CRITICAL = 1
    HIGH = 3
    MEDIUM = 5
    LOW = 7
    BACKGROUND = 9


@dataclass
class ScheduledTask:
    """A task in the scheduler's queue."""
    task_id: str = field(default_factory=lambda: str(uuid.uuid4())[:10])
    name: str = ""
    description: str = ""
    agent_role: str = ""  # Which agent type should run this
    priority: TaskPriority = TaskPriority.MEDIUM
    status: TaskStatus = TaskStatus.QUEUED
    estimated_duration_s: float = 60.0
    estimated_tokens: int = 5000
    dependencies: list[str] = field(default_factory=list)  # task_ids
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    category: str = ""  # recon, vuln_scan, exploit, etc.
    target: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 2
    generated_tasks: list[str] = field(default_factory=list)

    def __lt__(self, other: ScheduledTask) -> bool:
        """For heap comparison — lower priority value = higher priority."""
        if self.priority.value != other.priority.value:
            return self.priority.value < other.priority.value
        return self.created_at < other.created_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id, "name": self.name[:100],
            "agent_role": self.agent_role,
            "priority": self.priority.value,
            "status": self.status.value,
            "category": self.category,
            "target": self.target[:50],
            "estimated_s": self.estimated_duration_s,
            "retry": self.retry_count,
        }


class AdaptiveScheduler:
    """Intelligent task scheduler for agent coordination.

    Maintains a priority queue and dynamically reorders tasks
    based on assessment progress and resource availability.
    """

    def __init__(
        self,
        strategy: SchedulingStrategy = SchedulingStrategy.ADAPTIVE,
        max_queue_size: int = 500,
    ) -> None:
        self._strategy = strategy
        self._max_queue_size = max_queue_size
        self._queue: list[ScheduledTask] = []  # heapq
        self._tasks: dict[str, ScheduledTask] = {}
        self._completed: list[str] = []
        self._category_coverage: dict[str, int] = defaultdict(int)
        self._category_findings: dict[str, int] = defaultdict(int)
        self._log = logger.bind(component="scheduler")

    def add_task(self, task: ScheduledTask) -> str:
        """Add a task to the queue."""
        if len(self._tasks) >= self._max_queue_size:
            self._evict_lowest_priority()

        self._tasks[task.task_id] = task

        # Adjust priority based on strategy
        if self._strategy == SchedulingStrategy.RISK_BASED:
            self._adjust_for_risk(task)
        elif self._strategy == SchedulingStrategy.COVERAGE_BASED:
            self._adjust_for_coverage(task)
        elif self._strategy == SchedulingStrategy.ADAPTIVE:
            self._adjust_adaptive(task)

        heapq.heappush(self._queue, task)
        self._category_coverage[task.category] += 1

        return task.task_id

    def add_tasks(self, tasks: list[ScheduledTask]) -> list[str]:
        """Add multiple tasks."""
        return [self.add_task(t) for t in tasks]

    def get_next(self) -> ScheduledTask | None:
        """Get the next task to execute."""
        while self._queue:
            task = heapq.heappop(self._queue)

            # Skip if already completed/running/skipped
            if task.status not in (TaskStatus.QUEUED, TaskStatus.SCHEDULED):
                continue

            # Check dependencies
            if not self._dependencies_met(task):
                task.status = TaskStatus.DEFERRED
                heapq.heappush(self._queue, task)
                continue

            task.status = TaskStatus.SCHEDULED
            return task

        return None

    def get_next_batch(self, max_batch: int = 5) -> list[ScheduledTask]:
        """Get a batch of non-dependent tasks for parallel execution."""
        batch = []
        deferred = []

        while self._queue and len(batch) < max_batch:
            task = heapq.heappop(self._queue)

            if task.status not in (TaskStatus.QUEUED, TaskStatus.SCHEDULED):
                continue

            if not self._dependencies_met(task):
                deferred.append(task)
                continue

            # Check for conflicts with tasks already in batch
            if not any(self._conflicts_with(task, b) for b in batch):
                task.status = TaskStatus.SCHEDULED
                batch.append(task)
            else:
                deferred.append(task)

        # Re-add deferred tasks
        for task in deferred:
            task.status = TaskStatus.QUEUED
            heapq.heappush(self._queue, task)

        return batch

    def complete_task(
        self,
        task_id: str,
        result: dict[str, Any] | None = None,
        findings_count: int = 0,
    ) -> None:
        """Mark a task as completed and process results."""
        task = self._tasks.get(task_id)
        if not task:
            return

        task.status = TaskStatus.COMPLETED
        task.completed_at = time.time()
        task.result = result or {}
        self._completed.append(task_id)

        # Track findings per category
        if findings_count > 0:
            self._category_findings[task.category] += findings_count

        # Adaptive: reprioritize queue based on results
        if self._strategy == SchedulingStrategy.ADAPTIVE:
            self._reprioritize_after_result(task, findings_count)

        self._log.info(
            "task_completed",
            task=task_id, name=task.name[:50],
            findings=findings_count,
        )

    def fail_task(self, task_id: str, error: str = "") -> None:
        """Mark a task as failed, possibly retrying."""
        task = self._tasks.get(task_id)
        if not task:
            return

        if task.retry_count < task.max_retries:
            task.retry_count += 1
            task.status = TaskStatus.QUEUED
            # Lower priority slightly on retry
            if task.priority.value < TaskPriority.BACKGROUND.value:
                task.priority = TaskPriority(task.priority.value + 1)
            heapq.heappush(self._queue, task)
            self._log.info("task_retrying", task=task_id, retry=task.retry_count)
        else:
            task.status = TaskStatus.FAILED
            task.result = {"error": error}
            self._log.warning("task_failed", task=task_id, error=error[:100])

    def skip_task(self, task_id: str, reason: str = "") -> None:
        """Skip a task."""
        task = self._tasks.get(task_id)
        if task:
            task.status = TaskStatus.SKIPPED
            task.result = {"skip_reason": reason}

    def inject_task(self, task: ScheduledTask) -> None:
        """Inject a high-priority task (e.g., from a finding that needs immediate followup)."""
        task.priority = TaskPriority.CRITICAL
        self.add_task(task)
        self._log.info("task_injected", task=task.task_id, name=task.name[:50])

    # ── Strategy Adjustments ─────────────────────────────

    def _adjust_for_risk(self, task: ScheduledTask) -> None:
        """Risk-based: prioritize tasks for high-risk categories."""
        high_risk_categories = {"exploit", "vuln_scan", "web_scan", "code_audit"}
        if task.category in high_risk_categories:
            task.priority = TaskPriority(max(1, task.priority.value - 2))

    def _adjust_for_coverage(self, task: ScheduledTask) -> None:
        """Coverage-based: prioritize under-tested categories."""
        coverage_count = self._category_coverage.get(task.category, 0)
        if coverage_count < 2:
            task.priority = TaskPriority(max(1, task.priority.value - 2))
        elif coverage_count > 5:
            task.priority = TaskPriority(min(9, task.priority.value + 1))

    def _adjust_adaptive(self, task: ScheduledTask) -> None:
        """Adaptive: adjust based on what's working."""
        findings = self._category_findings.get(task.category, 0)
        coverage = self._category_coverage.get(task.category, 0)

        if coverage > 0 and findings / coverage > 0.5:
            # This category is productive — prioritize more
            task.priority = TaskPriority(max(1, task.priority.value - 2))
        elif coverage > 3 and findings == 0:
            # This category is not productive — deprioritize
            task.priority = TaskPriority(min(9, task.priority.value + 2))

    def _reprioritize_after_result(self, completed: ScheduledTask, findings: int) -> None:
        """Reprioritize remaining tasks based on what we just learned."""
        if findings > 0:
            # Boost priority for related tasks
            for task in self._queue:
                if task.category == completed.category and task.status == TaskStatus.QUEUED:
                    task.priority = TaskPriority(max(1, task.priority.value - 1))

            # Re-heapify
            heapq.heapify(self._queue)

    # ── Dependency Management ────────────────────────────

    def _dependencies_met(self, task: ScheduledTask) -> bool:
        """Check if all dependencies of a task are completed."""
        for dep_id in task.dependencies:
            dep = self._tasks.get(dep_id)
            if not dep or dep.status != TaskStatus.COMPLETED:
                return False
        return True

    def _conflicts_with(self, task: ScheduledTask, other: ScheduledTask) -> bool:
        """Check if two tasks conflict (can't run in parallel)."""
        # Same target + same category = potential conflict
        return task.target == other.target and task.category == other.category

    def _evict_lowest_priority(self) -> None:
        """Remove the lowest priority task from the queue."""
        if self._queue:
            # Find and remove lowest priority (highest value)
            worst_idx = 0
            for idx, task in enumerate(self._queue):
                if task.priority.value > self._queue[worst_idx].priority.value:
                    worst_idx = idx
            removed = self._queue.pop(worst_idx)
            removed.status = TaskStatus.SKIPPED
            heapq.heapify(self._queue)

    # ── Reporting ────────────────────────────────────────

    def get_queue_status(self) -> dict[str, Any]:
        by_status: dict[str, int] = defaultdict(int)
        by_category: dict[str, int] = defaultdict(int)
        by_priority: dict[int, int] = defaultdict(int)
        for task in self._tasks.values():
            by_status[task.status.value] += 1
            by_category[task.category] += 1
            by_priority[task.priority.value] += 1
        return {
            "total_tasks": len(self._tasks),
            "queue_length": len(self._queue),
            "completed": len(self._completed),
            "by_status": dict(by_status),
            "by_category": dict(by_category),
            "by_priority": dict(by_priority),
            "strategy": self._strategy.value,
            "category_findings": dict(self._category_findings),
        }

    def get_pending_tasks(self, limit: int = 20) -> list[dict[str, Any]]:
        return [
            t.to_dict() for t in sorted(self._queue)[:limit]
            if t.status in (TaskStatus.QUEUED, TaskStatus.SCHEDULED)
        ]
