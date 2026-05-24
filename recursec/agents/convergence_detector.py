"""Convergence detector — detects agent stalls and loops.

Implements:
1. Progress rate monitoring
2. Loop detection (action repetition)
3. Diminishing returns detection
4. Stall detection (no new findings)
5. Convergence criteria evaluation
6. Convergence prompt for LLM
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ConvergenceState(str, Enum):
    EXPLORING = "exploring"       # Active discovery
    PROGRESSING = "progressing"   # Finding new results
    SLOWING = "slowing"           # Rate declining
    STALLED = "stalled"           # No new findings
    LOOPING = "looping"           # Repeating actions
    CONVERGED = "converged"       # Done, no more to find
    DIVERGING = "diverging"       # Expanding without focus


class ActionType(str, Enum):
    SCAN = "scan"
    EXPLOIT = "exploit"
    RECON = "recon"
    VALIDATE = "validate"
    REPORT = "report"
    REASON = "reason"
    SPAWN = "spawn"
    OTHER = "other"


@dataclass
class ProgressPoint:
    """A snapshot of progress at a moment."""
    timestamp: float = field(default_factory=time.time)
    action_type: ActionType = ActionType.OTHER
    action_detail: str = ""
    new_findings: int = 0
    total_findings: int = 0
    unique_targets: int = 0
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action_type.value[:5],
            "findings": self.new_findings,
            "total": self.total_findings,
        }


class ConvergenceDetector:
    """Detects when agents should stop, redirect, or escalate.

    Monitors progress rate, detects loops, and
    evaluates convergence criteria to prevent
    wasteful exploration.
    """

    def __init__(
        self,
        stall_threshold_s: float = 300.0,
        loop_window: int = 10,
        loop_ratio: float = 0.6,
        min_finding_rate: float = 0.001,
        convergence_window: int = 20,
    ) -> None:
        self._history: deque[ProgressPoint] = deque(maxlen=500)
        self._state = ConvergenceState.EXPLORING
        self._stall_threshold_s = stall_threshold_s
        self._loop_window = loop_window
        self._loop_ratio = loop_ratio
        self._min_finding_rate = min_finding_rate
        self._convergence_window = convergence_window
        self._last_finding_time: float = time.time()
        self._state_transitions: list[tuple[float, ConvergenceState]] = []
        self._log = logger.bind(component="convergence")

    def record(
        self,
        action_type: ActionType,
        action_detail: str = "",
        new_findings: int = 0,
        total_findings: int = 0,
        unique_targets: int = 0,
        confidence: float = 0.0,
    ) -> ConvergenceState:
        """Record a progress point and return current state."""
        now = time.time()

        point = ProgressPoint(
            timestamp=now,
            action_type=action_type,
            action_detail=action_detail,
            new_findings=new_findings,
            total_findings=total_findings,
            unique_targets=unique_targets,
            confidence=confidence,
        )
        self._history.append(point)

        if new_findings > 0:
            self._last_finding_time = now

        # Evaluate convergence
        new_state = self._evaluate()
        if new_state != self._state:
            self._state_transitions.append((now, new_state))
            self._state = new_state

        return self._state

    def _evaluate(self) -> ConvergenceState:
        """Evaluate current convergence state."""
        if len(self._history) < 3:
            return ConvergenceState.EXPLORING

        # Check for looping
        if self._detect_loop():
            return ConvergenceState.LOOPING

        # Check for stall
        if self._detect_stall():
            return ConvergenceState.STALLED

        # Check finding rate
        rate = self._finding_rate()

        if rate <= 0:
            time_since = time.time() - self._last_finding_time
            if time_since > self._stall_threshold_s * 2:
                return ConvergenceState.CONVERGED
            return ConvergenceState.STALLED

        if rate < self._min_finding_rate:
            return ConvergenceState.SLOWING

        # Check for divergence (many targets, few findings)
        if self._detect_divergence():
            return ConvergenceState.DIVERGING

        return ConvergenceState.PROGRESSING

    def _detect_loop(self) -> bool:
        """Detect repeated action patterns."""
        recent = list(self._history)[-self._loop_window:]
        if len(recent) < self._loop_window:
            return False

        actions = [p.action_detail for p in recent]
        unique = set(actions)

        # If most actions are the same = loop
        if len(unique) <= 2:
            most_common_count = max(actions.count(a) for a in unique)
            ratio = most_common_count / len(actions)
            return ratio >= self._loop_ratio

        return False

    def _detect_stall(self) -> bool:
        """Detect no new findings for threshold duration."""
        time_since = time.time() - self._last_finding_time
        return time_since > self._stall_threshold_s

    def _finding_rate(self) -> float:
        """Calculate findings per second over recent window."""
        recent = list(self._history)[-self._convergence_window:]
        if len(recent) < 2:
            return 0.0

        total_findings = sum(p.new_findings for p in recent)
        duration = recent[-1].timestamp - recent[0].timestamp

        if duration <= 0:
            return 0.0

        return total_findings / duration

    def _detect_divergence(self) -> bool:
        """Detect expanding scope without findings."""
        recent = list(self._history)[-self._convergence_window:]
        if len(recent) < 5:
            return False

        # Check if unique targets are growing but findings aren't
        first_half = recent[:len(recent) // 2]
        second_half = recent[len(recent) // 2:]

        targets_first = max((p.unique_targets for p in first_half), default=0)
        targets_second = max((p.unique_targets for p in second_half), default=0)
        findings_first = sum(p.new_findings for p in first_half)
        findings_second = sum(p.new_findings for p in second_half)

        # More targets but fewer findings = diverging
        return (
            targets_second > targets_first * 1.5
            and findings_second < findings_first * 0.5
        )

    def should_stop(self) -> bool:
        """Whether the agent should stop."""
        return self._state in (
            ConvergenceState.CONVERGED,
            ConvergenceState.STALLED,
            ConvergenceState.LOOPING,
        )

    def get_recommendation(self) -> str:
        """Get action recommendation based on state."""
        recommendations = {
            ConvergenceState.EXPLORING: "Continue exploration",
            ConvergenceState.PROGRESSING: "Continue current approach",
            ConvergenceState.SLOWING: "Try different tools or techniques",
            ConvergenceState.STALLED: "Change strategy or escalate",
            ConvergenceState.LOOPING: "Break loop — try new approach",
            ConvergenceState.CONVERGED: "Assessment complete — report",
            ConvergenceState.DIVERGING: "Narrow scope and focus",
        }
        return recommendations.get(self._state, "Unknown state")

    def build_convergence_prompt(self) -> str:
        """Build convergence context for LLM."""
        lines = ["## Convergence\n"]
        lines.append(f"State: {self._state.value}")
        lines.append(f"Recommendation: {self.get_recommendation()}")

        # Progress metrics
        rate = self._finding_rate()
        lines.append(f"Finding rate: {rate:.4f}/s")

        time_since = time.time() - self._last_finding_time
        lines.append(f"Time since last finding: {time_since:.0f}s")

        # Recent history
        recent = list(self._history)[-5:]
        if recent:
            lines.append(f"\nRecent ({len(recent)}):")
            for p in recent:
                lines.append(
                    f"  {p.action_type.value[:5]} "
                    f"(+{p.new_findings} findings, "
                    f"total={p.total_findings})"
                )

        # State transitions
        if self._state_transitions:
            lines.append(f"\nTransitions ({len(self._state_transitions)}):")
            for ts, state in self._state_transitions[-3:]:
                lines.append(f"  → {state.value}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "state": self._state.value,
            "history_length": len(self._history),
            "finding_rate": self._finding_rate(),
            "transitions": len(self._state_transitions),
            "should_stop": self.should_stop(),
        }
