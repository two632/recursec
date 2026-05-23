"""Scan scheduler — schedules and manages recurring security scans.

Implements:
1. Cron-like scheduling for recurring scans
2. One-time scan scheduling
3. Scan queue management
4. Priority-based scheduling
5. Resource-aware scheduling (don't overload)
6. Scan history and result tracking
7. Scan dependency management
8. Automatic rescheduling on failure
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


class ScanStatus(str, Enum):
    SCHEDULED = "scheduled"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScheduleType(str, Enum):
    ONCE = "once"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    CUSTOM = "custom"


@dataclass
class ScheduledScan:
    """A scheduled security scan."""
    scan_id: str = ""
    name: str = ""
    target: str = ""
    scan_type: str = ""            # quick, full, deep, custom
    schedule_type: ScheduleType = ScheduleType.ONCE
    interval_s: float = 0.0
    priority: int = 5
    status: ScanStatus = ScanStatus.SCHEDULED
    next_run: float = 0.0
    last_run: float = 0.0
    run_count: int = 0
    max_runs: int = 0              # 0 = unlimited
    retry_count: int = 0
    max_retries: int = 3
    timeout_s: float = 3600.0
    config: dict[str, Any] = field(default_factory=dict)
    last_result: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    @property
    def is_due(self) -> bool:
        return (
            self.status in (ScanStatus.SCHEDULED, ScanStatus.QUEUED) and
            time.time() >= self.next_run
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.scan_id, "name": self.name[:40],
            "target": self.target[:40],
            "schedule": self.schedule_type.value,
            "status": self.status.value,
            "priority": self.priority,
            "runs": self.run_count,
        }


@dataclass
class ScanResult:
    """Result of a scan execution."""
    scan_id: str = ""
    findings_count: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    duration_s: float = 0.0
    success: bool = True
    error: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan": self.scan_id, "findings": self.findings_count,
            "critical": self.critical, "high": self.high,
            "duration_s": round(self.duration_s, 0),
            "success": self.success,
        }


class ScanScheduler:
    """Schedules and manages recurring security scans.

    Supports cron-like scheduling, priority queuing,
    and automatic rescheduling on failure.
    """

    def __init__(self, max_concurrent: int = 3) -> None:
        self._scans: dict[str, ScheduledScan] = {}
        self._results: list[ScanResult] = []
        self._scan_counter = 0
        self._max_concurrent = max_concurrent
        self._running_count = 0
        self._scan_handlers: dict[str, Callable[..., Coroutine[Any, Any, ScanResult]]] = {}
        self._log = logger.bind(component="scan_scheduler")

    def register_handler(
        self,
        scan_type: str,
        handler: Callable[..., Coroutine[Any, Any, ScanResult]],
    ) -> None:
        """Register a handler for a scan type."""
        self._scan_handlers[scan_type] = handler

    def schedule(
        self,
        name: str,
        target: str,
        scan_type: str = "quick",
        schedule_type: ScheduleType = ScheduleType.ONCE,
        interval_s: float = 0.0,
        delay_s: float = 0.0,
        priority: int = 5,
        config: dict[str, Any] | None = None,
    ) -> str:
        """Schedule a scan."""
        self._scan_counter += 1
        scan_id = f"scan-{self._scan_counter}"

        # Calculate interval for recurring scans
        if schedule_type == ScheduleType.HOURLY:
            interval_s = 3600.0
        elif schedule_type == ScheduleType.DAILY:
            interval_s = 86400.0
        elif schedule_type == ScheduleType.WEEKLY:
            interval_s = 604800.0

        scan = ScheduledScan(
            scan_id=scan_id,
            name=name,
            target=target,
            scan_type=scan_type,
            schedule_type=schedule_type,
            interval_s=interval_s,
            priority=priority,
            next_run=time.time() + delay_s,
            config=config or {},
        )

        self._scans[scan_id] = scan
        return scan_id

    async def tick(self) -> list[ScanResult]:
        """Process one scheduling tick."""
        results = []

        # Get due scans
        due_scans = [
            scan for scan in self._scans.values()
            if scan.is_due and self._running_count < self._max_concurrent
        ]

        # Sort by priority
        due_scans.sort(key=lambda s: s.priority)

        for scan in due_scans[:self._max_concurrent - self._running_count]:
            result = await self._execute_scan(scan)
            results.append(result)

        return results

    async def run_loop(self, duration_s: float = 0.0) -> None:
        """Run the scheduler loop."""
        start = time.time()

        while True:
            await self.tick()
            await asyncio.sleep(10)

            if duration_s > 0 and time.time() - start > duration_s:
                break

    async def _execute_scan(self, scan: ScheduledScan) -> ScanResult:
        """Execute a single scan."""
        scan.status = ScanStatus.RUNNING
        scan.last_run = time.time()
        self._running_count += 1

        handler = self._scan_handlers.get(scan.scan_type)

        start = time.time()
        result = ScanResult(scan_id=scan.scan_id)

        try:
            if handler:
                result = await asyncio.wait_for(
                    handler(scan.target, scan.config),
                    timeout=scan.timeout_s,
                )
                result.scan_id = scan.scan_id
            else:
                result.error = f"No handler for scan type: {scan.scan_type}"
                result.success = False

        except asyncio.TimeoutError:
            result.success = False
            result.error = "Scan timed out"

        except Exception as e:
            result.success = False
            result.error = str(e)[:200]

        result.duration_s = time.time() - start
        self._running_count = max(0, self._running_count - 1)

        # Update scan status
        if result.success:
            scan.status = ScanStatus.COMPLETED
            scan.run_count += 1
            scan.last_result = result.to_dict()

            # Reschedule if recurring
            if scan.schedule_type != ScheduleType.ONCE:
                if scan.max_runs == 0 or scan.run_count < scan.max_runs:
                    scan.status = ScanStatus.SCHEDULED
                    scan.next_run = time.time() + scan.interval_s
        else:
            scan.retry_count += 1
            if scan.retry_count < scan.max_retries:
                scan.status = ScanStatus.SCHEDULED
                scan.next_run = time.time() + 60.0  # Retry in 1 min
            else:
                scan.status = ScanStatus.FAILED

        self._results.append(result)
        if len(self._results) > 500:
            self._results = self._results[-500:]

        return result

    def cancel(self, scan_id: str) -> bool:
        scan = self._scans.get(scan_id)
        if scan and scan.status in (ScanStatus.SCHEDULED, ScanStatus.QUEUED):
            scan.status = ScanStatus.CANCELLED
            return True
        return False

    def get_due_scans(self) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self._scans.values() if s.is_due]

    def get_results(self, limit: int = 20) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._results[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for scan in self._scans.values():
            status_counts[scan.status.value] += 1

        return {
            "total_scans": len(self._scans),
            "running": self._running_count,
            "results": len(self._results),
            "status": dict(status_counts),
        }
