"""Convergence monitor — detects when assessment has explored enough.

Implements:
1. Diminishing returns detection (new findings rate)
2. Coverage tracking (attack surface explored %)
3. Token efficiency monitoring (findings per token)
4. Time-based convergence thresholds
5. Agent productivity tracking
6. Early stopping recommendations
7. Convergence prompt for LLM decisions
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ConvergenceState(str, Enum):
    EXPLORING = "exploring"           # Still finding new things
    DIMINISHING = "diminishing"       # Rate of findings dropping
    CONVERGING = "converging"         # Near-convergence
    CONVERGED = "converged"           # Stop — diminishing returns
    FORCED_STOP = "forced_stop"       # Budget/time exhausted


@dataclass
class ConvergenceWindow:
    """A time window for measuring convergence."""
    window_start: float = 0.0
    window_end: float = 0.0
    findings_count: int = 0
    tokens_used: int = 0
    agents_active: int = 0
    tools_run: int = 0

    @property
    def duration_s(self) -> float:
        return self.window_end - self.window_start

    @property
    def finding_rate(self) -> float:
        """Findings per minute."""
        d = self.duration_s
        if d <= 0:
            return 0.0
        return (self.findings_count / d) * 60.0

    @property
    def token_efficiency(self) -> float:
        """Findings per 1000 tokens."""
        if self.tokens_used == 0:
            return 0.0
        return (self.findings_count / self.tokens_used) * 1000.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": self.findings_count,
            "rate": round(self.finding_rate, 2),
            "tokens": self.tokens_used,
            "efficiency": round(self.token_efficiency, 2),
        }


@dataclass
class ConvergenceMetrics:
    """Overall convergence metrics."""
    state: ConvergenceState = ConvergenceState.EXPLORING
    total_findings: int = 0
    total_tokens: int = 0
    total_duration_s: float = 0.0
    unique_targets_tested: int = 0
    total_targets: int = 0
    coverage_pct: float = 0.0
    current_finding_rate: float = 0.0
    peak_finding_rate: float = 0.0
    rate_of_change: float = 0.0       # Negative = declining
    windows: list[ConvergenceWindow] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "findings": self.total_findings,
            "coverage": f"{self.coverage_pct:.0f}%",
            "rate": round(self.current_finding_rate, 2),
            "peak_rate": round(self.peak_finding_rate, 2),
            "recommendation": self.recommendation[:30],
        }


class ConvergenceMonitor:
    """Monitors assessment convergence.

    Tracks finding rates, coverage, and token
    efficiency to recommend when an assessment
    has explored enough of the attack surface.
    """

    def __init__(
        self,
        window_size_s: float = 300.0,    # 5-minute windows
        min_rate_threshold: float = 0.1,  # Minimum findings/min
        convergence_windows: int = 3,     # Consecutive low-rate windows
        max_tokens: int = 1000000,
        max_duration_s: float = 14400.0,  # 4 hours
    ) -> None:
        self._window_size = window_size_s
        self._min_rate = min_rate_threshold
        self._convergence_count = convergence_windows
        self._max_tokens = max_tokens
        self._max_duration = max_duration_s

        self._metrics = ConvergenceMetrics()
        self._windows: list[ConvergenceWindow] = []
        self._current_window: ConvergenceWindow | None = None
        self._started_at: float = 0.0
        self._targets_tested: set[str] = set()
        self._low_rate_streak: int = 0
        self._log = logger.bind(component="convergence_monitor")

    def start(self, total_targets: int = 0) -> None:
        """Start convergence monitoring."""
        self._started_at = time.time()
        self._metrics.total_targets = total_targets
        self._start_new_window()

    def record_finding(self, target: str = "") -> None:
        """Record a new finding."""
        self._metrics.total_findings += 1
        if target:
            self._targets_tested.add(target)

        if self._current_window:
            self._current_window.findings_count += 1

        self._check_window()

    def record_tokens(self, tokens: int) -> None:
        """Record token usage."""
        self._metrics.total_tokens += tokens
        if self._current_window:
            self._current_window.tokens_used += tokens
        self._check_window()

    def record_tool_run(self) -> None:
        """Record a tool execution."""
        if self._current_window:
            self._current_window.tools_run += 1

    def check_convergence(self) -> ConvergenceMetrics:
        """Check current convergence state."""
        self._check_window()
        self._update_metrics()
        return self._metrics

    def should_stop(self) -> bool:
        """Whether the assessment should stop."""
        self._check_window()
        self._update_metrics()
        return self._metrics.state in (
            ConvergenceState.CONVERGED,
            ConvergenceState.FORCED_STOP,
        )

    def build_convergence_prompt(self) -> str:
        """Build convergence context for LLM."""
        m = self.check_convergence()
        lines = ["## Convergence Status\n"]

        lines.append(
            f"State: {m.state.value} | "
            f"Findings: {m.total_findings} | "
            f"Coverage: {m.coverage_pct:.0f}%"
        )
        lines.append(
            f"Finding rate: {m.current_finding_rate:.1f}/min "
            f"(peak: {m.peak_finding_rate:.1f}/min)"
        )
        lines.append(
            f"Tokens: {m.total_tokens:,} / {self._max_tokens:,} "
            f"({m.total_tokens / self._max_tokens:.0%})"
        )

        elapsed = time.time() - self._started_at if self._started_at else 0
        lines.append(
            f"Time: {elapsed:.0f}s / {self._max_duration:.0f}s "
            f"({elapsed / self._max_duration:.0%})"
        )

        if m.recommendation:
            lines.append(f"\nRecommendation: {m.recommendation}")

        # Recent window trend
        if len(self._windows) >= 2:
            lines.append("\nRecent windows:")
            for w in self._windows[-3:]:
                lines.append(
                    f"  rate={w.finding_rate:.1f}/min "
                    f"eff={w.token_efficiency:.2f}f/1Kt "
                    f"tools={w.tools_run}"
                )

        return "\n".join(lines)

    def _start_new_window(self) -> None:
        """Start a new measurement window."""
        if self._current_window:
            self._current_window.window_end = time.time()
            self._windows.append(self._current_window)

        self._current_window = ConvergenceWindow(
            window_start=time.time(),
        )

    def _check_window(self) -> None:
        """Check if current window should be closed."""
        if not self._current_window:
            return

        elapsed = time.time() - self._current_window.window_start
        if elapsed >= self._window_size:
            self._start_new_window()

    def _update_metrics(self) -> None:
        """Update convergence metrics."""
        m = self._metrics

        # Coverage
        m.unique_targets_tested = len(self._targets_tested)
        if m.total_targets > 0:
            m.coverage_pct = (m.unique_targets_tested / m.total_targets) * 100.0

        # Duration
        if self._started_at:
            m.total_duration_s = time.time() - self._started_at

        # Current and peak finding rate
        if self._windows:
            latest = self._windows[-1]
            m.current_finding_rate = latest.finding_rate
            m.peak_finding_rate = max(w.finding_rate for w in self._windows)

            # Rate of change
            if len(self._windows) >= 2:
                prev = self._windows[-2]
                m.rate_of_change = latest.finding_rate - prev.finding_rate

        # Convergence detection
        self._detect_convergence()

    def _detect_convergence(self) -> None:
        """Detect convergence state."""
        m = self._metrics

        # Hard limits
        if m.total_tokens >= self._max_tokens:
            m.state = ConvergenceState.FORCED_STOP
            m.recommendation = "Token budget exhausted. Stop assessment."
            return

        if m.total_duration_s >= self._max_duration:
            m.state = ConvergenceState.FORCED_STOP
            m.recommendation = "Time limit reached. Stop assessment."
            return

        # Rate-based convergence
        if self._windows:
            recent_low = sum(
                1 for w in self._windows[-self._convergence_count:]
                if w.finding_rate < self._min_rate
            )

            if recent_low >= self._convergence_count:
                m.state = ConvergenceState.CONVERGED
                m.recommendation = (
                    f"Finding rate below {self._min_rate}/min for "
                    f"{self._convergence_count} consecutive windows. "
                    "Consider stopping or pivoting strategy."
                )
            elif recent_low >= 1:
                m.state = ConvergenceState.DIMINISHING
                m.recommendation = "Finding rate declining. Consider new strategies."
            elif m.rate_of_change < -0.5:
                m.state = ConvergenceState.CONVERGING
                m.recommendation = "Finding rate decreasing rapidly."
            else:
                m.state = ConvergenceState.EXPLORING
                m.recommendation = "Still discovering. Continue current approach."

    def get_stats(self) -> dict[str, Any]:
        m = self.check_convergence()
        return m.to_dict()
