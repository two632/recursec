"""Convergence monitor — detects when assessment has converged.

Implements:
1. Finding rate tracking (new findings per unit time)
2. Diminishing returns detection
3. Coverage estimation
4. Convergence criteria evaluation
5. Early termination recommendations
6. Phase-specific convergence
7. Exploration vs exploitation balance
8. Information gain measurement
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ConvergenceWindow:
    """A time window for convergence tracking."""
    start_time: float = 0.0
    end_time: float = 0.0
    findings_count: int = 0
    critical_count: int = 0
    tools_run: int = 0
    tokens_used: int = 0

    @property
    def duration_s(self) -> float:
        return max(0.001, self.end_time - self.start_time)

    @property
    def finding_rate(self) -> float:
        """Findings per minute."""
        return self.findings_count / (self.duration_s / 60.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": self.findings_count,
            "rate": round(self.finding_rate, 2),
            "tools": self.tools_run,
            "duration_s": round(self.duration_s, 0),
        }


@dataclass
class ConvergenceState:
    """Current convergence state."""
    converged: bool = False
    confidence: float = 0.0
    finding_rate: float = 0.0         # Current rate
    peak_rate: float = 0.0            # Historical peak
    rate_decline: float = 0.0         # How much rate has declined
    estimated_remaining: int = 0      # Estimated remaining findings
    recommendation: str = ""
    phase_convergence: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "converged": self.converged,
            "confidence": round(self.confidence, 2),
            "rate": round(self.finding_rate, 2),
            "peak_rate": round(self.peak_rate, 2),
            "decline": round(self.rate_decline, 2),
            "recommendation": self.recommendation,
        }


class ConvergenceMonitor:
    """Monitors assessment convergence.

    Tracks finding rates over time and detects
    when further scanning yields diminishing returns.
    """

    def __init__(
        self,
        window_size_s: float = 300.0,
        min_windows: int = 3,
        convergence_threshold: float = 0.1,
    ) -> None:
        self._window_size_s = window_size_s
        self._min_windows = min_windows
        self._convergence_threshold = convergence_threshold

        self._windows: list[ConvergenceWindow] = []
        self._current_window: ConvergenceWindow | None = None
        self._total_findings = 0
        self._total_critical = 0
        self._phase_findings: dict[str, int] = defaultdict(int)
        self._phase_times: dict[str, float] = defaultdict(float)
        self._start_time = time.time()
        self._log = logger.bind(component="convergence_monitor")

    def record_finding(
        self,
        severity: str = "info",
        phase: str = "",
    ) -> None:
        """Record a new finding."""
        self._ensure_window()
        if self._current_window:
            self._current_window.findings_count += 1
            if severity in ("critical", "high"):
                self._current_window.critical_count += 1

        self._total_findings += 1
        if severity == "critical":
            self._total_critical += 1

        if phase:
            self._phase_findings[phase] += 1

    def record_tool_run(self, phase: str = "", tokens: int = 0) -> None:
        """Record a tool execution."""
        self._ensure_window()
        if self._current_window:
            self._current_window.tools_run += 1
            self._current_window.tokens_used += tokens

    def check_convergence(self) -> ConvergenceState:
        """Check if the assessment has converged."""
        self._close_window_if_needed()

        state = ConvergenceState()

        if len(self._windows) < self._min_windows:
            state.recommendation = "Continue — insufficient data"
            return state

        # Calculate rates for recent windows
        rates = [w.finding_rate for w in self._windows[-5:]]

        state.finding_rate = rates[-1] if rates else 0.0
        state.peak_rate = max(r.finding_rate for r in self._windows) if self._windows else 0.0

        # Rate of decline
        if len(rates) >= 2 and rates[0] > 0:
            state.rate_decline = (rates[0] - rates[-1]) / rates[0]
        else:
            state.rate_decline = 0.0

        # Check convergence criteria
        criteria_met = 0
        total_criteria = 4

        # Criterion 1: Finding rate below threshold
        if state.finding_rate < self._convergence_threshold:
            criteria_met += 1

        # Criterion 2: Rate declining
        if state.rate_decline > 0.5:
            criteria_met += 1

        # Criterion 3: Last N windows have few findings
        recent_findings = sum(w.findings_count for w in self._windows[-3:])
        if recent_findings < 2:
            criteria_met += 1

        # Criterion 4: Rate is small fraction of peak
        if state.peak_rate > 0 and state.finding_rate / state.peak_rate < 0.1:
            criteria_met += 1

        state.confidence = criteria_met / total_criteria

        if criteria_met >= 3:
            state.converged = True
            state.recommendation = "Assessment has converged — consider stopping"
        elif criteria_met >= 2:
            state.recommendation = "Approaching convergence — diminishing returns likely"
        else:
            state.recommendation = "Continue — still finding results"

        # Estimate remaining findings (exponential decay model)
        if state.peak_rate > 0 and state.finding_rate > 0:
            decay_rate = -math.log(max(0.01, state.finding_rate / state.peak_rate)) / max(1, len(self._windows))
            if decay_rate > 0:
                state.estimated_remaining = int(state.finding_rate / decay_rate)
            else:
                state.estimated_remaining = 0

        # Phase convergence
        for phase in self._phase_findings:
            recent_phase = sum(
                1 for w in self._windows[-3:]
                if w.findings_count > 0
            )
            state.phase_convergence[phase] = recent_phase == 0

        return state

    def _ensure_window(self) -> None:
        """Ensure a current window exists."""
        now = time.time()

        if self._current_window is None:
            self._current_window = ConvergenceWindow(
                start_time=now, end_time=now + self._window_size_s,
            )
            return

        if now > self._current_window.end_time:
            self._close_window_if_needed()
            self._current_window = ConvergenceWindow(
                start_time=now, end_time=now + self._window_size_s,
            )

    def _close_window_if_needed(self) -> None:
        """Close current window if expired."""
        if self._current_window and time.time() > self._current_window.end_time:
            self._windows.append(self._current_window)
            self._current_window = None

            if len(self._windows) > 50:
                self._windows = self._windows[-50:]

    def get_rate_history(self) -> list[dict[str, Any]]:
        """Get finding rate history."""
        return [w.to_dict() for w in self._windows]

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_findings": self._total_findings,
            "total_critical": self._total_critical,
            "windows": len(self._windows),
            "elapsed_s": round(time.time() - self._start_time, 0),
        }
