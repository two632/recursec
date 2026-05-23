"""Convergence monitor — detects when the agent is making diminishing returns.

Implements:
1. Finding rate tracking over time windows
2. Exponential decay modeling for diminishing returns
3. Phase transition detection (recon → scanning → exploit)
4. Budget efficiency scoring
5. Stagnation detection
6. Convergence prediction
7. Adaptive stopping criteria
8. Performance trend analysis
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class PerformanceWindow:
    """A time window of performance data."""
    window_start: float = 0.0
    window_end: float = 0.0
    findings_count: int = 0
    tokens_used: int = 0
    tools_run: int = 0
    critical_findings: int = 0
    high_findings: int = 0

    @property
    def duration_s(self) -> float:
        return max(0.01, self.window_end - self.window_start)

    @property
    def finding_rate(self) -> float:
        """Findings per minute."""
        return self.findings_count / max(0.01, self.duration_s / 60.0)

    @property
    def token_efficiency(self) -> float:
        """Findings per 1000 tokens."""
        if self.tokens_used == 0:
            return 0.0
        return self.findings_count / (self.tokens_used / 1000.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "duration_s": round(self.duration_s, 1),
            "findings": self.findings_count,
            "rate": round(self.finding_rate, 2),
            "tokens": self.tokens_used,
            "efficiency": round(self.token_efficiency, 4),
        }


@dataclass
class ConvergenceStatus:
    """Current convergence status."""
    is_converged: bool = False
    is_stagnant: bool = False
    finding_rate_trend: str = ""    # increasing, stable, decreasing
    predicted_remaining_findings: int = 0
    efficiency_trend: str = ""
    recommendation: str = ""
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "converged": self.is_converged,
            "stagnant": self.is_stagnant,
            "rate_trend": self.finding_rate_trend,
            "predicted_remaining": self.predicted_remaining_findings,
            "efficiency_trend": self.efficiency_trend,
            "recommendation": self.recommendation[:60],
            "confidence": round(self.confidence, 2),
        }


class ConvergenceMonitor:
    """Detects when the agent is making diminishing returns.

    Uses finding rate tracking, exponential decay modeling,
    and efficiency scoring to decide when to stop or switch.
    """

    def __init__(
        self,
        window_size_s: float = 300.0,       # 5-minute windows
        stagnation_threshold: int = 3,        # Windows without findings
        min_efficiency: float = 0.001,        # Min findings/1K tokens
        convergence_threshold: float = 0.1,   # Rate drop threshold
    ) -> None:
        self._windows: list[PerformanceWindow] = []
        self._current_window: PerformanceWindow | None = None
        self._window_size = window_size_s
        self._stagnation_threshold = stagnation_threshold
        self._min_efficiency = min_efficiency
        self._convergence_threshold = convergence_threshold
        self._total_findings = 0
        self._total_tokens = 0
        self._start_time = time.time()
        self._log = logger.bind(component="convergence_monitor")

    def record_finding(
        self,
        severity: str = "medium",
        tokens_used: int = 0,
    ) -> None:
        """Record a new finding."""
        window = self._get_current_window()
        window.findings_count += 1
        window.tokens_used += tokens_used
        self._total_findings += 1
        self._total_tokens += tokens_used

        if severity == "critical":
            window.critical_findings += 1
        elif severity == "high":
            window.high_findings += 1

    def record_tool_run(self, tokens_used: int = 0) -> None:
        """Record a tool execution."""
        window = self._get_current_window()
        window.tools_run += 1
        window.tokens_used += tokens_used
        self._total_tokens += tokens_used

    def check_convergence(self) -> ConvergenceStatus:
        """Check if the assessment has converged."""
        self._close_current_window()
        status = ConvergenceStatus()

        if len(self._windows) < 2:
            status.recommendation = "Continue — insufficient data"
            return status

        # Calculate finding rate trend
        recent_rates = [w.finding_rate for w in self._windows[-5:]]
        status.finding_rate_trend = self._trend(recent_rates)

        # Stagnation detection
        zero_windows = sum(
            1 for w in self._windows[-self._stagnation_threshold:]
            if w.findings_count == 0
        )
        status.is_stagnant = zero_windows >= self._stagnation_threshold

        # Convergence detection via exponential decay
        if len(self._windows) >= 3:
            status.is_converged = self._check_exponential_decay()

        # Efficiency trend
        recent_eff = [w.token_efficiency for w in self._windows[-5:]]
        status.efficiency_trend = self._trend(recent_eff)

        # Predict remaining findings
        status.predicted_remaining_findings = self._predict_remaining()

        # Confidence
        status.confidence = min(1.0, len(self._windows) * 0.1)

        # Recommendation
        status.recommendation = self._recommend(status)

        return status

    def _check_exponential_decay(self) -> bool:
        """Check if finding rate follows exponential decay."""
        rates = [w.finding_rate for w in self._windows[-6:]]
        if not rates or max(rates) == 0:
            return False

        # Simple decay check: is each window worse than the last?
        decreasing_count = 0
        for i in range(1, len(rates)):
            if rates[i] < rates[i - 1]:
                decreasing_count += 1

        # If 80% of transitions are decreasing, likely converged
        if len(rates) > 2:
            ratio = decreasing_count / (len(rates) - 1)
            if ratio >= 0.8 and rates[-1] < self._convergence_threshold:
                return True

        return False

    def _predict_remaining(self) -> int:
        """Predict remaining findings using exponential decay model."""
        if len(self._windows) < 2:
            return 10  # Default estimate

        rates = [w.finding_rate for w in self._windows]
        if not rates or rates[0] == 0:
            return 0

        # Fit simple exponential decay: rate(t) = rate(0) * exp(-lambda * t)
        if rates[-1] > 0 and rates[0] > 0:
            ratio = rates[-1] / rates[0]
            if ratio > 0 and ratio < 1:
                decay_lambda = -math.log(ratio) / len(rates)
                # Predict findings in next 10 windows
                predicted = 0
                for future_t in range(len(rates), len(rates) + 10):
                    predicted_rate = rates[0] * math.exp(-decay_lambda * future_t)
                    predicted += predicted_rate * (self._window_size / 60.0)
                return max(0, int(predicted))

        return 0

    def _recommend(self, status: ConvergenceStatus) -> str:
        """Generate recommendation."""
        if status.is_stagnant and status.is_converged:
            return "STOP — assessment has converged with no new findings"

        if status.is_stagnant:
            return "SWITCH — try different approach or tools"

        if status.is_converged:
            return "REVIEW — diminishing returns, consider stopping"

        if status.efficiency_trend == "decreasing":
            return "OPTIMIZE — efficiency declining, adjust strategy"

        if status.finding_rate_trend == "increasing":
            return "CONTINUE — still finding new vulnerabilities"

        return "CONTINUE — assessment in progress"

    def _get_current_window(self) -> PerformanceWindow:
        """Get or create the current time window."""
        now = time.time()

        if self._current_window is None:
            self._current_window = PerformanceWindow(
                window_start=now,
                window_end=now + self._window_size,
            )
            return self._current_window

        if now > self._current_window.window_end:
            self._close_current_window()
            self._current_window = PerformanceWindow(
                window_start=now,
                window_end=now + self._window_size,
            )

        return self._current_window

    def _close_current_window(self) -> None:
        """Close the current window and archive it."""
        if self._current_window:
            self._current_window.window_end = time.time()
            self._windows.append(self._current_window)
            self._current_window = None

            if len(self._windows) > 100:
                self._windows = self._windows[-100:]

    @staticmethod
    def _trend(values: list[float]) -> str:
        """Determine trend from a list of values."""
        if len(values) < 2:
            return "insufficient_data"

        increases = 0
        decreases = 0
        for i in range(1, len(values)):
            if values[i] > values[i - 1] * 1.1:
                increases += 1
            elif values[i] < values[i - 1] * 0.9:
                decreases += 1

        if increases > decreases:
            return "increasing"
        if decreases > increases:
            return "decreasing"
        return "stable"

    def get_windows(self, limit: int = 10) -> list[dict[str, Any]]:
        return [w.to_dict() for w in self._windows[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        elapsed = time.time() - self._start_time
        return {
            "total_findings": self._total_findings,
            "total_tokens": self._total_tokens,
            "windows": len(self._windows),
            "elapsed_s": round(elapsed, 1),
            "avg_rate": round(
                self._total_findings / max(0.01, elapsed / 60.0), 2,
            ),
        }
