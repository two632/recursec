"""Convergence monitor — tracks whether agents are making progress or stuck.

Implements:
1. Progress rate tracking
2. Diminishing returns detection
3. Plateau detection (stuck at same level)
4. Oscillation detection (going back and forth)
5. Budget exhaustion prediction
6. Convergence criteria evaluation
7. Early stopping recommendations
8. Stagnation alerts
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ConvergenceState(str, Enum):
    EXPLORING = "exploring"       # Early phase, high variance
    CONVERGING = "converging"     # Making steady progress
    PLATEAU = "plateau"           # Progress stalled
    OSCILLATING = "oscillating"   # Going back and forth
    DIMINISHING = "diminishing"   # Returns getting smaller
    CONVERGED = "converged"       # Reached stable state
    DIVERGING = "diverging"       # Getting worse


@dataclass
class ProgressPoint:
    """A point on the progress curve."""
    timestamp: float = 0.0
    metric_value: float = 0.0
    tokens_spent: int = 0
    findings_count: int = 0
    coverage: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": round(self.metric_value, 3),
            "tokens": self.tokens_spent,
            "findings": self.findings_count,
            "coverage": round(self.coverage, 2),
        }


@dataclass
class ConvergenceReport:
    """Report on convergence status."""
    state: ConvergenceState = ConvergenceState.EXPLORING
    progress_rate: float = 0.0     # Change per unit time
    efficiency: float = 0.0        # Findings per token
    estimated_remaining_tokens: int = 0
    should_stop: bool = False
    reason: str = ""
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "rate": round(self.progress_rate, 4),
            "efficiency": round(self.efficiency, 6),
            "est_remaining": self.estimated_remaining_tokens,
            "stop": self.should_stop,
            "reason": self.reason[:40],
        }


class ConvergenceMonitor:
    """Tracks whether agents are making progress or stuck.

    Detects plateaus, oscillations, diminishing returns,
    and recommends when to stop or change strategy.
    """

    def __init__(
        self,
        window_size: int = 20,
        plateau_threshold: float = 0.02,
        oscillation_threshold: float = 0.1,
    ) -> None:
        self._tracks: dict[str, list[ProgressPoint]] = defaultdict(list)
        self._states: dict[str, ConvergenceState] = {}
        self._window_size = window_size
        self._plateau_threshold = plateau_threshold
        self._oscillation_threshold = oscillation_threshold
        self._alerts: list[dict[str, Any]] = []
        self._log = logger.bind(component="convergence_monitor")

    def record(
        self,
        track_id: str,
        metric_value: float,
        tokens_spent: int = 0,
        findings_count: int = 0,
        coverage: float = 0.0,
    ) -> ConvergenceReport:
        """Record a progress point and evaluate convergence."""
        point = ProgressPoint(
            timestamp=time.time(),
            metric_value=metric_value,
            tokens_spent=tokens_spent,
            findings_count=findings_count,
            coverage=coverage,
        )

        self._tracks[track_id].append(point)
        if len(self._tracks[track_id]) > 200:
            self._tracks[track_id] = self._tracks[track_id][-200:]

        return self.evaluate(track_id)

    def evaluate(self, track_id: str) -> ConvergenceReport:
        """Evaluate convergence state for a track."""
        points = self._tracks.get(track_id, [])

        if len(points) < 3:
            return ConvergenceReport(state=ConvergenceState.EXPLORING)

        # Get recent window
        window = points[-self._window_size:]
        values = [p.metric_value for p in window]

        # Compute statistics
        progress_rate = self._compute_progress_rate(values)
        variance = self._compute_variance(values)
        trend = self._compute_trend(values)
        efficiency = self._compute_efficiency(points)

        # Determine state
        state = self._determine_state(progress_rate, variance, trend, values)
        self._states[track_id] = state

        # Generate recommendations
        recommendations = self._generate_recommendations(state, efficiency, points)

        should_stop = state in (ConvergenceState.CONVERGED, ConvergenceState.PLATEAU) and len(points) > 20

        report = ConvergenceReport(
            state=state,
            progress_rate=progress_rate,
            efficiency=efficiency,
            should_stop=should_stop,
            reason=self._state_reason(state, progress_rate, variance),
            recommendations=recommendations,
        )

        # Generate alert for concerning states
        if state in (ConvergenceState.PLATEAU, ConvergenceState.DIVERGING):
            self._alerts.append({
                "track": track_id,
                "state": state.value,
                "time": time.time(),
            })
            if len(self._alerts) > 100:
                self._alerts = self._alerts[-100:]

        return report

    @staticmethod
    def _compute_progress_rate(values: list[float]) -> float:
        """Compute progress rate (slope of recent values)."""
        if len(values) < 2:
            return 0.0

        n = len(values)
        x_mean = (n - 1) / 2
        y_mean = sum(values) / n

        numerator = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(values))
        denominator = sum((i - x_mean) ** 2 for i in range(n))

        if denominator == 0:
            return 0.0
        return numerator / denominator

    @staticmethod
    def _compute_variance(values: list[float]) -> float:
        """Compute variance of values."""
        if len(values) < 2:
            return 0.0

        mean = sum(values) / len(values)
        return sum((v - mean) ** 2 for v in values) / (len(values) - 1)

    @staticmethod
    def _compute_trend(values: list[float]) -> str:
        """Compute trend direction."""
        if len(values) < 4:
            return "unknown"

        first_half = sum(values[:len(values) // 2]) / (len(values) // 2)
        second_half = sum(values[len(values) // 2:]) / (len(values) - len(values) // 2)

        diff = second_half - first_half
        if abs(diff) < 0.01:
            return "stable"
        return "up" if diff > 0 else "down"

    @staticmethod
    def _compute_efficiency(points: list[ProgressPoint]) -> float:
        """Compute findings per 1000 tokens."""
        total_tokens = sum(p.tokens_spent for p in points)
        total_findings = sum(p.findings_count for p in points)
        if total_tokens == 0:
            return 0.0
        return total_findings / (total_tokens / 1000)

    def _determine_state(
        self,
        progress_rate: float,
        variance: float,
        trend: str,
        values: list[float],
    ) -> ConvergenceState:
        """Determine convergence state from statistics."""
        abs_rate = abs(progress_rate)

        # Check for oscillation (high variance, low net progress)
        if variance > self._oscillation_threshold and abs_rate < self._plateau_threshold:
            return ConvergenceState.OSCILLATING

        # Check for plateau
        if abs_rate < self._plateau_threshold and len(values) > 5:
            return ConvergenceState.PLATEAU

        # Check for diverging (getting worse)
        if progress_rate < -self._plateau_threshold:
            return ConvergenceState.DIVERGING

        # Check for diminishing returns
        if len(values) > 10:
            early_rate = abs(values[5] - values[0]) / 5
            late_rate = abs(values[-1] - values[-6]) / 5
            if early_rate > 0 and late_rate / early_rate < 0.3:
                return ConvergenceState.DIMINISHING

        # Check for convergence
        if abs_rate < self._plateau_threshold * 2 and variance < 0.01:
            return ConvergenceState.CONVERGED

        # Active progress
        if progress_rate > self._plateau_threshold:
            return ConvergenceState.CONVERGING

        return ConvergenceState.EXPLORING

    @staticmethod
    def _generate_recommendations(
        state: ConvergenceState,
        efficiency: float,
        points: list[ProgressPoint],
    ) -> list[str]:
        """Generate recommendations based on convergence state."""
        recs = []

        if state == ConvergenceState.PLATEAU:
            recs.append("Consider changing strategy or target area")
            recs.append("Try different tools or models")

        elif state == ConvergenceState.OSCILLATING:
            recs.append("Agent may be conflicting — check for contradictory rules")
            recs.append("Consider reducing exploration rate")

        elif state == ConvergenceState.DIVERGING:
            recs.append("Quality is degrading — review recent changes")
            recs.append("Consider rolling back to previous strategy")

        elif state == ConvergenceState.DIMINISHING:
            recs.append("Most low-hanging fruit found — consider deeper analysis")
            recs.append("May be time to focus on validation instead of discovery")

        if efficiency < 0.001 and len(points) > 10:
            recs.append("Very low efficiency — review token allocation")

        return recs

    @staticmethod
    def _state_reason(
        state: ConvergenceState,
        progress_rate: float,
        variance: float,
    ) -> str:
        """Generate a reason string for the state."""
        if state == ConvergenceState.PLATEAU:
            return f"Progress rate {progress_rate:.4f} below threshold"
        if state == ConvergenceState.OSCILLATING:
            return f"High variance {variance:.3f} with low progress"
        if state == ConvergenceState.CONVERGED:
            return "Stable with minimal change"
        if state == ConvergenceState.DIVERGING:
            return f"Negative progress rate {progress_rate:.4f}"
        return f"Rate={progress_rate:.4f}, var={variance:.3f}"

    def get_all_states(self) -> dict[str, str]:
        return {k: v.value for k, v in self._states.items()}

    def get_stats(self) -> dict[str, Any]:
        state_counts: dict[str, int] = defaultdict(int)
        for state in self._states.values():
            state_counts[state.value] += 1
        return {
            "tracks": len(self._tracks),
            "states": dict(state_counts),
            "alerts": len(self._alerts),
        }
