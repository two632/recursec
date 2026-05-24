"""Convergence monitor — detects when agent should stop.

Implements:
1. Diminishing returns detection
2. Finding rate tracking (findings per time unit)
3. Novelty scoring (are we finding new things?)
4. Exploration vs exploitation balance
5. Convergence criteria (configurable thresholds)
6. Stop recommendations
7. Convergence prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ConvergenceState(str, Enum):
    EXPLORING = "exploring"         # Still finding new things
    CONVERGING = "converging"       # Rate is declining
    DIMINISHING = "diminishing"     # Very few new findings
    CONVERGED = "converged"         # Should stop
    STUCK = "stuck"                 # No progress at all


@dataclass
class FindingWindow:
    """A time window of findings."""
    start_time: float = 0.0
    end_time: float = 0.0
    total_findings: int = 0
    unique_findings: int = 0
    duplicate_findings: int = 0
    novel_findings: int = 0      # Never-seen-before type
    severity_sum: float = 0.0

    @property
    def duration_s(self) -> float:
        return max(0.001, self.end_time - self.start_time)

    @property
    def finding_rate(self) -> float:
        return self.total_findings / self.duration_s

    @property
    def novelty_ratio(self) -> float:
        if self.total_findings == 0:
            return 0.0
        return self.novel_findings / self.total_findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total_findings,
            "unique": self.unique_findings,
            "rate": round(self.finding_rate, 3),
            "novelty": round(self.novelty_ratio, 2),
        }


@dataclass
class ConvergenceConfig:
    """Configuration for convergence detection."""
    window_size_s: float = 300.0     # 5 minute windows
    min_windows: int = 3             # Minimum windows before deciding
    rate_decline_threshold: float = 0.3   # Rate dropped by 70%
    novelty_threshold: float = 0.1        # Less than 10% novel
    stuck_threshold_s: float = 600.0      # No findings for 10 minutes
    max_duration_s: float = 7200.0        # Hard stop at 2 hours
    max_findings: int = 500               # Hard stop at 500 findings


class ConvergenceMonitor:
    """Monitors assessment progress for convergence.

    Tracks finding rates, novelty, and progress
    to determine when the agent should stop or
    change strategy.
    """

    def __init__(self, config: ConvergenceConfig | None = None) -> None:
        self._config = config or ConvergenceConfig()
        self._windows: list[FindingWindow] = []
        self._current_window: FindingWindow | None = None
        self._seen_types: set[str] = set()
        self._seen_hashes: set[str] = set()
        self._total_findings = 0
        self._start_time = time.time()
        self._last_finding_time = time.time()
        self._state = ConvergenceState.EXPLORING
        self._log = logger.bind(component="convergence")

    def record_finding(
        self,
        finding_type: str,
        severity: float = 0.5,
        finding_hash: str = "",
    ) -> None:
        """Record a new finding."""
        now = time.time()

        # Create window if needed
        if self._current_window is None:
            self._current_window = FindingWindow(start_time=now)

        window = self._current_window
        window.end_time = now
        window.total_findings += 1

        # Check uniqueness
        is_duplicate = False
        if finding_hash:
            if finding_hash in self._seen_hashes:
                is_duplicate = True
            self._seen_hashes.add(finding_hash)

        if is_duplicate:
            window.duplicate_findings += 1
        else:
            window.unique_findings += 1

        # Check novelty
        if finding_type not in self._seen_types:
            window.novel_findings += 1
            self._seen_types.add(finding_type)

        window.severity_sum += severity
        self._total_findings += 1
        self._last_finding_time = now

        # Rotate window if needed
        if now - window.start_time >= self._config.window_size_s:
            self._windows.append(window)
            self._current_window = FindingWindow(start_time=now)
            self._update_state()

    def _update_state(self) -> None:
        """Update convergence state based on windows."""
        if len(self._windows) < self._config.min_windows:
            self._state = ConvergenceState.EXPLORING
            return

        # Check rate decline
        recent = self._windows[-1]
        oldest = self._windows[0]

        if oldest.finding_rate > 0:
            rate_ratio = recent.finding_rate / oldest.finding_rate
            if rate_ratio < self._config.rate_decline_threshold:
                if recent.novelty_ratio < self._config.novelty_threshold:
                    self._state = ConvergenceState.CONVERGED
                    return
                self._state = ConvergenceState.DIMINISHING
                return

        # Check novelty across recent windows
        recent_novelty = sum(
            w.novelty_ratio for w in self._windows[-3:]
        ) / min(3, len(self._windows))

        if recent_novelty < self._config.novelty_threshold:
            self._state = ConvergenceState.CONVERGING
            return

        self._state = ConvergenceState.EXPLORING

    def should_stop(self) -> tuple[bool, str]:
        """Check if the assessment should stop."""
        now = time.time()
        elapsed = now - self._start_time

        # Hard time limit
        if elapsed > self._config.max_duration_s:
            return True, "max_duration_exceeded"

        # Hard finding limit
        if self._total_findings >= self._config.max_findings:
            return True, "max_findings_reached"

        # Stuck (no findings for a long time)
        since_last = now - self._last_finding_time
        if since_last > self._config.stuck_threshold_s:
            self._state = ConvergenceState.STUCK
            return True, "stuck_no_progress"

        # Converged
        if self._state == ConvergenceState.CONVERGED:
            return True, "converged"

        return False, ""

    def should_change_strategy(self) -> bool:
        """Check if agent should change approach."""
        return self._state in (
            ConvergenceState.DIMINISHING,
            ConvergenceState.CONVERGING,
        )

    def build_convergence_prompt(self) -> str:
        """Build convergence context for LLM."""
        now = time.time()
        elapsed = now - self._start_time
        lines = ["## Convergence\n"]

        lines.append(
            f"State: {self._state.value} | "
            f"Findings: {self._total_findings} | "
            f"Elapsed: {elapsed:.0f}s"
        )

        lines.append(f"Unique types: {len(self._seen_types)}")

        since_last = now - self._last_finding_time
        lines.append(f"Since last finding: {since_last:.0f}s")

        # Window trend
        if self._windows:
            rates = [w.finding_rate for w in self._windows[-5:]]
            lines.append(f"Recent rates: {', '.join(f'{r:.3f}' for r in rates)}/s")

            novelties = [w.novelty_ratio for w in self._windows[-5:]]
            lines.append(f"Novelty trend: {', '.join(f'{n:.0%}' for n in novelties)}")

        should_stop, reason = self.should_stop()
        if should_stop:
            lines.append(f"\nRECOMMENDATION: STOP ({reason})")
        elif self.should_change_strategy():
            lines.append("\nRECOMMENDATION: Change strategy (diminishing returns)")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        now = time.time()
        return {
            "state": self._state.value,
            "total_findings": self._total_findings,
            "unique_types": len(self._seen_types),
            "windows": len(self._windows),
            "elapsed_s": round(now - self._start_time, 1),
            "since_last_finding_s": round(now - self._last_finding_time, 1),
        }
