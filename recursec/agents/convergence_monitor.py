"""Convergence monitor — detects when to stop or pivot.

Implements:
1. Progress tracking metrics
2. Diminishing returns detection
3. Coverage estimation
4. Stagnation detection
5. Strategy pivot recommendations
6. Time-based convergence
7. Finding rate analysis
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ConvergenceState(str, Enum):
    EXPLORING = "exploring"         # Active discovery
    PROGRESSING = "progressing"     # Finding new things
    PLATEAU = "plateau"             # Slowing down
    DIMINISHING = "diminishing"     # Very slow progress
    CONVERGED = "converged"         # No new progress
    STAGNANT = "stagnant"          # Stuck


class PivotReason(str, Enum):
    DIMINISHING_RETURNS = "diminishing_returns"
    COVERAGE_COMPLETE = "coverage_complete"
    TIME_LIMIT = "time_limit"
    BUDGET_EXHAUSTED = "budget_exhausted"
    REPEATED_FAILURES = "repeated_failures"
    NO_FINDINGS = "no_findings"


@dataclass
class ProgressSnapshot:
    """A point-in-time progress snapshot."""
    timestamp: float = field(default_factory=time.time)
    findings_count: int = 0
    tools_run: int = 0
    tokens_used: int = 0
    unique_vulns: int = 0
    coverage_estimate: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": self.findings_count,
            "tools": self.tools_run,
            "coverage": round(self.coverage_estimate, 2),
        }


@dataclass
class PivotRecommendation:
    """A recommendation to change strategy."""
    reason: PivotReason = PivotReason.DIMINISHING_RETURNS
    current_phase: str = ""
    recommended_phase: str = ""
    explanation: str = ""
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason.value,
            "from": self.current_phase[:15],
            "to": self.recommended_phase[:15],
            "confidence": round(self.confidence, 2),
        }


class ConvergenceMonitor:
    """Monitors assessment progress and detects convergence.

    Tracks finding rate, coverage, and progress
    to determine when to stop or pivot strategy.
    """

    def __init__(
        self,
        window_size: int = 5,
        diminishing_threshold: float = 0.1,
        stagnation_minutes: float = 10.0,
    ) -> None:
        self._snapshots: list[ProgressSnapshot] = []
        self._window_size = window_size
        self._diminishing_threshold = diminishing_threshold
        self._stagnation_minutes = stagnation_minutes
        self._state = ConvergenceState.EXPLORING
        self._start_time = time.time()
        self._log = logger.bind(component="convergence_monitor")

    def record_snapshot(
        self,
        findings_count: int,
        tools_run: int = 0,
        tokens_used: int = 0,
        unique_vulns: int = 0,
    ) -> ProgressSnapshot:
        """Record a progress snapshot."""
        coverage = self._estimate_coverage(findings_count, tools_run)

        snapshot = ProgressSnapshot(
            findings_count=findings_count,
            tools_run=tools_run,
            tokens_used=tokens_used,
            unique_vulns=unique_vulns,
            coverage_estimate=coverage,
        )
        self._snapshots.append(snapshot)

        # Update state
        self._update_state()

        return snapshot

    def _estimate_coverage(
        self,
        findings: int,
        tools: int,
    ) -> float:
        """Estimate assessment coverage (0-1)."""
        # Heuristic: coverage based on tool diversity and finding rate
        tool_coverage = min(1.0, tools / 15)  # Assume 15 tools is full coverage
        finding_signal = min(1.0, findings / 20)  # Assume 20 findings is thorough

        return tool_coverage * 0.6 + finding_signal * 0.4

    def _update_state(self) -> None:
        """Update convergence state based on recent snapshots."""
        if len(self._snapshots) < 2:
            self._state = ConvergenceState.EXPLORING
            return

        # Get recent window
        window = self._snapshots[-self._window_size:]

        # Calculate finding rate (findings per snapshot)
        rates = []
        for i in range(1, len(window)):
            delta = window[i].findings_count - window[i - 1].findings_count
            rates.append(delta)

        if not rates:
            return

        avg_rate = sum(rates) / len(rates)
        latest_rate = rates[-1]

        # Detect stagnation (no new findings for N minutes)
        if len(self._snapshots) >= 3:
            recent_3 = self._snapshots[-3:]
            if all(s.findings_count == recent_3[0].findings_count for s in recent_3):
                time_since_progress = time.time() - self._snapshots[-3].timestamp
                if time_since_progress > self._stagnation_minutes * 60:
                    self._state = ConvergenceState.STAGNANT
                    return

        if avg_rate <= 0:
            self._state = ConvergenceState.CONVERGED
        elif avg_rate < self._diminishing_threshold:
            self._state = ConvergenceState.DIMINISHING
        elif latest_rate < avg_rate * 0.5:
            self._state = ConvergenceState.PLATEAU
        elif latest_rate > 0:
            self._state = ConvergenceState.PROGRESSING
        else:
            self._state = ConvergenceState.EXPLORING

    @property
    def state(self) -> ConvergenceState:
        return self._state

    @property
    def should_pivot(self) -> bool:
        """Whether the current strategy should be changed."""
        return self._state in (
            ConvergenceState.DIMINISHING,
            ConvergenceState.CONVERGED,
            ConvergenceState.STAGNANT,
        )

    @property
    def should_stop(self) -> bool:
        """Whether the assessment should stop."""
        return self._state == ConvergenceState.CONVERGED

    def get_pivot_recommendation(
        self,
        current_phase: str,
    ) -> PivotRecommendation | None:
        """Get a pivot recommendation if appropriate."""
        if not self.should_pivot:
            return None

        phase_transitions = {
            "reconnaissance": ("scanning", "Move to vulnerability scanning"),
            "scanning": ("exploitation", "Move to exploitation of found vulns"),
            "exploitation": ("validation", "Move to finding validation"),
            "validation": ("reporting", "Move to report generation"),
        }

        next_phase, explanation = phase_transitions.get(
            current_phase,
            ("reporting", "Assessment converged"),
        )

        return PivotRecommendation(
            reason=PivotReason.DIMINISHING_RETURNS,
            current_phase=current_phase,
            recommended_phase=next_phase,
            explanation=explanation,
            confidence=0.7,
        )

    def get_finding_rate(self) -> float:
        """Get the current finding rate per minute."""
        if len(self._snapshots) < 2:
            return 0.0

        recent = self._snapshots[-2:]
        time_delta = recent[1].timestamp - recent[0].timestamp
        if time_delta <= 0:
            return 0.0

        finding_delta = recent[1].findings_count - recent[0].findings_count
        return finding_delta / (time_delta / 60)

    def build_convergence_prompt(self) -> str:
        """Build a prompt about convergence status."""
        if not self._snapshots:
            return ""

        latest = self._snapshots[-1]
        elapsed = time.time() - self._start_time

        lines = [
            "## Assessment Progress\n",
            f"State: {self._state.value}",
            f"Findings: {latest.findings_count}",
            f"Coverage: {latest.coverage_estimate:.0%}",
            f"Finding rate: {self.get_finding_rate():.1f}/min",
            f"Elapsed: {elapsed / 60:.0f} min",
        ]

        if self.should_pivot:
            lines.append(f"\nRECOMMENDATION: Consider pivoting strategy ({self._state.value})")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "state": self._state.value,
            "snapshots": len(self._snapshots),
            "finding_rate": round(self.get_finding_rate(), 2),
            "should_pivot": self.should_pivot,
            "should_stop": self.should_stop,
            "elapsed_min": round((time.time() - self._start_time) / 60, 1),
        }
