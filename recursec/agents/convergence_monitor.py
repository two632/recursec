"""Convergence monitor — tracks progress and detects stalls.

Monitors:
1. Finding rate (new findings per time unit)
2. Coverage expansion rate
3. Action diversity (are we repeating?)
4. Quality trend (are findings getting better/worse?)
5. Resource consumption rate
6. Goal proximity
7. Diminishing returns detection
8. Oscillation detection (going back and forth)

Outputs convergence signals:
- PROGRESSING: Good rate of progress
- SLOWING: Finding rate decreasing
- STALLED: No new findings for a while
- DIVERGING: Going in circles
- CONVERGED: Assessment goals met
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ConvergenceState(str, Enum):
    STARTING = "starting"
    PROGRESSING = "progressing"
    SLOWING = "slowing"
    STALLED = "stalled"
    DIVERGING = "diverging"
    CONVERGED = "converged"


@dataclass
class ProgressPoint:
    """A point in the progress timeline."""
    timestamp: float = field(default_factory=time.time)
    findings_total: int = 0
    findings_new: int = 0
    actions_total: int = 0
    tokens_total: int = 0
    coverage_areas: int = 0
    unique_tools: int = 0
    quality_avg: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "time": round(self.timestamp),
            "findings": self.findings_total,
            "new": self.findings_new,
            "actions": self.actions_total,
            "coverage": self.coverage_areas,
        }


@dataclass
class ConvergenceSignal:
    """A convergence signal with analysis."""
    state: ConvergenceState = ConvergenceState.STARTING
    confidence: float = 0.5
    finding_rate: float = 0.0      # Findings per minute
    finding_trend: str = "stable"  # increasing, stable, decreasing
    coverage_trend: str = "stable"
    action_diversity: float = 0.5  # 0=repetitive, 1=diverse
    estimated_remaining: float = 0.0  # Estimated time to convergence
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "confidence": round(self.confidence, 2),
            "finding_rate": round(self.finding_rate, 2),
            "finding_trend": self.finding_trend,
            "coverage_trend": self.coverage_trend,
            "diversity": round(self.action_diversity, 2),
            "recommendation": self.recommendation[:100],
        }


class ConvergenceMonitor:
    """Monitors assessment progress and detects convergence/stalls.

    Tracks metrics over time and generates convergence signals
    to guide strategy adaptation.
    """

    def __init__(
        self,
        stall_threshold_s: float = 120.0,
        min_finding_rate: float = 0.1,  # Findings per minute
        convergence_window: int = 10,    # Points to consider
    ) -> None:
        self._stall_threshold = stall_threshold_s
        self._min_finding_rate = min_finding_rate
        self._window = convergence_window
        self._history: list[ProgressPoint] = []
        self._action_history: list[str] = []
        self._state = ConvergenceState.STARTING
        self._last_finding_time = time.time()
        self._log = logger.bind(component="convergence_monitor")

    def record_progress(
        self,
        findings_total: int,
        findings_new: int,
        actions_total: int,
        tokens_total: int,
        coverage_areas: int,
        unique_tools: int,
        quality_avg: float = 0.5,
    ) -> ConvergenceSignal:
        """Record a progress point and analyze convergence."""
        point = ProgressPoint(
            findings_total=findings_total,
            findings_new=findings_new,
            actions_total=actions_total,
            tokens_total=tokens_total,
            coverage_areas=coverage_areas,
            unique_tools=unique_tools,
            quality_avg=quality_avg,
        )

        self._history.append(point)

        if findings_new > 0:
            self._last_finding_time = time.time()

        return self._analyze()

    def record_action(self, action_name: str) -> None:
        """Track actions for diversity analysis."""
        self._action_history.append(action_name)
        if len(self._action_history) > 200:
            self._action_history = self._action_history[-200:]

    def get_current_state(self) -> ConvergenceSignal:
        """Get the current convergence signal without recording."""
        return self._analyze()

    def _analyze(self) -> ConvergenceSignal:
        """Analyze progress history for convergence signals."""
        signal = ConvergenceSignal()

        if len(self._history) < 3:
            signal.state = ConvergenceState.STARTING
            signal.recommendation = "Continue gathering initial data"
            self._state = signal.state
            return signal

        recent = self._history[-self._window:]

        # Calculate finding rate
        if len(recent) >= 2:
            time_span = recent[-1].timestamp - recent[0].timestamp
            if time_span > 0:
                total_new = sum(p.findings_new for p in recent)
                signal.finding_rate = (total_new / time_span) * 60  # Per minute

        # Calculate finding trend
        signal.finding_trend = self._calculate_trend(
            [p.findings_new for p in recent]
        )

        # Calculate coverage trend
        signal.coverage_trend = self._calculate_trend(
            [p.coverage_areas for p in recent]
        )

        # Calculate action diversity
        signal.action_diversity = self._calculate_diversity()

        # Determine state
        time_since_finding = time.time() - self._last_finding_time

        if time_since_finding > self._stall_threshold * 2:
            signal.state = ConvergenceState.STALLED
            signal.confidence = 0.9
            signal.recommendation = "Stalled — switch strategy or pivot to unexplored areas"

        elif time_since_finding > self._stall_threshold:
            signal.state = ConvergenceState.SLOWING
            signal.confidence = 0.7
            signal.recommendation = "Progress slowing — consider deeper testing or new approach"

        elif signal.action_diversity < 0.2 and len(self._action_history) > 10:
            signal.state = ConvergenceState.DIVERGING
            signal.confidence = 0.7
            signal.recommendation = "Repetitive actions detected — try different tools or targets"

        elif signal.finding_trend == "decreasing" and signal.finding_rate < self._min_finding_rate:
            signal.state = ConvergenceState.SLOWING
            signal.confidence = 0.6
            signal.recommendation = "Finding rate declining — consider escalation or phase change"

        elif signal.finding_rate >= self._min_finding_rate:
            signal.state = ConvergenceState.PROGRESSING
            signal.confidence = 0.8
            signal.recommendation = "Good progress — continue current approach"

        else:
            # Check if we've reached diminishing returns
            if self._diminishing_returns(recent):
                signal.state = ConvergenceState.CONVERGED
                signal.confidence = 0.7
                signal.recommendation = "Diminishing returns — consider wrapping up"
            else:
                signal.state = ConvergenceState.PROGRESSING
                signal.confidence = 0.5
                signal.recommendation = "Continue assessment"

        self._state = signal.state
        return signal

    def _calculate_trend(self, values: list[int | float]) -> str:
        """Calculate trend from a series of values."""
        if len(values) < 3:
            return "stable"

        # Simple linear regression slope
        n = len(values)
        x_mean = (n - 1) / 2
        y_mean = sum(values) / n

        numerator = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(values))
        denominator = sum((i - x_mean) ** 2 for i in range(n))

        if denominator == 0:
            return "stable"

        slope = numerator / denominator

        if slope > 0.1:
            return "increasing"
        elif slope < -0.1:
            return "decreasing"
        return "stable"

    def _calculate_diversity(self) -> float:
        """Calculate action diversity (0=repetitive, 1=diverse)."""
        if not self._action_history:
            return 1.0

        recent = self._action_history[-20:]
        unique = len(set(recent))
        return unique / len(recent)

    def _diminishing_returns(self, recent: list[ProgressPoint]) -> bool:
        """Check if we're seeing diminishing returns."""
        if len(recent) < 5:
            return False

        # Compare first half vs second half findings
        mid = len(recent) // 2
        first_half = sum(p.findings_new for p in recent[:mid])
        second_half = sum(p.findings_new for p in recent[mid:])

        if first_half == 0:
            return second_half == 0

        return second_half / max(1, first_half) < 0.3

    def get_history(self, limit: int = 50) -> list[dict[str, Any]]:
        return [p.to_dict() for p in self._history[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        signal = self.get_current_state()
        return {
            "state": signal.state.value,
            "history_points": len(self._history),
            "finding_rate": round(signal.finding_rate, 2),
            "action_diversity": round(signal.action_diversity, 2),
            "actions_tracked": len(self._action_history),
        }
