"""Convergence monitor — detects when agents are going in circles.

Implements:
1. Finding rate tracking (new findings per time window)
2. Novelty detection (are findings genuinely new?)
3. Stagnation detection (no progress for N steps)
4. Loop detection (repeated action sequences)
5. Early termination recommendation
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
    PROGRESSING = "progressing"    # Making good progress
    SLOWING = "slowing"           # Progress slowing down
    STAGNATING = "stagnating"     # Little to no new progress
    LOOPING = "looping"           # Repeating same actions
    CONVERGED = "converged"       # Task appears complete


@dataclass
class ProgressSnapshot:
    """A point-in-time progress measurement."""
    timestamp: float = field(default_factory=time.time)
    total_findings: int = 0
    unique_findings: int = 0
    actions_taken: int = 0
    tokens_used: int = 0
    agents_active: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": self.total_findings,
            "unique": self.unique_findings,
            "actions": self.actions_taken,
        }


@dataclass
class ActionRecord:
    """Record of an agent action for loop detection."""
    agent_id: str = ""
    action_type: str = ""
    target: str = ""
    tool: str = ""
    timestamp: float = field(default_factory=time.time)

    @property
    def signature(self) -> str:
        return f"{self.action_type}:{self.tool}:{self.target}"


@dataclass
class ConvergenceReport:
    """Convergence analysis report."""
    state: ConvergenceState = ConvergenceState.PROGRESSING
    finding_rate: float = 0.0           # Findings per minute
    novelty_ratio: float = 1.0          # Unique/total findings
    stagnation_steps: int = 0           # Steps without progress
    loop_detected: bool = False
    loop_pattern: str = ""
    recommendation: str = ""
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value[:8],
            "rate": f"{self.finding_rate:.1f}/min",
            "novelty": f"{self.novelty_ratio:.0%}",
            "stagnation": self.stagnation_steps,
            "loop": self.loop_detected,
        }


class ConvergenceMonitor:
    """Monitors agent progress and detects convergence/loops.

    Tracks finding rates, novelty, action patterns,
    and recommends when to stop or change strategy.
    """

    def __init__(
        self,
        stagnation_threshold: int = 10,
        loop_window: int = 20,
        min_novelty: float = 0.2,
    ) -> None:
        self._snapshots: deque[ProgressSnapshot] = deque(maxlen=100)
        self._actions: deque[ActionRecord] = deque(maxlen=200)
        self._finding_hashes: set[str] = set()
        self._stagnation_threshold = stagnation_threshold
        self._loop_window = loop_window
        self._min_novelty = min_novelty
        self._steps_without_progress = 0
        self._last_unique_count = 0
        self._log = logger.bind(component="convergence")

    def record_snapshot(
        self,
        total_findings: int,
        unique_findings: int,
        actions_taken: int,
        tokens_used: int = 0,
        agents_active: int = 0,
    ) -> None:
        """Record a progress snapshot."""
        snapshot = ProgressSnapshot(
            total_findings=total_findings,
            unique_findings=unique_findings,
            actions_taken=actions_taken,
            tokens_used=tokens_used,
            agents_active=agents_active,
        )
        self._snapshots.append(snapshot)

        # Track stagnation
        if unique_findings > self._last_unique_count:
            self._steps_without_progress = 0
            self._last_unique_count = unique_findings
        else:
            self._steps_without_progress += 1

    def record_action(
        self,
        agent_id: str,
        action_type: str,
        target: str = "",
        tool: str = "",
    ) -> None:
        """Record an agent action."""
        action = ActionRecord(
            agent_id=agent_id,
            action_type=action_type,
            target=target,
            tool=tool,
        )
        self._actions.append(action)

    def record_finding(self, finding_hash: str) -> bool:
        """Record a finding. Returns True if genuinely new."""
        if finding_hash in self._finding_hashes:
            return False
        self._finding_hashes.add(finding_hash)
        return True

    def analyze(self) -> ConvergenceReport:
        """Analyze current convergence state."""
        report = ConvergenceReport()

        # Finding rate
        report.finding_rate = self._compute_finding_rate()

        # Novelty ratio
        report.novelty_ratio = self._compute_novelty()

        # Loop detection
        loop_detected, loop_pattern = self._detect_loops()
        report.loop_detected = loop_detected
        report.loop_pattern = loop_pattern

        # Stagnation
        report.stagnation_steps = self._steps_without_progress

        # Determine state
        report.state = self._determine_state(report)

        # Recommendation
        report.recommendation = self._generate_recommendation(report)

        # Confidence
        report.confidence = self._compute_confidence(report)

        return report

    def _compute_finding_rate(self) -> float:
        """Compute findings per minute over recent window."""
        if len(self._snapshots) < 2:
            return 0.0

        recent = list(self._snapshots)[-10:]
        if len(recent) < 2:
            return 0.0

        time_span = recent[-1].timestamp - recent[0].timestamp
        if time_span <= 0:
            return 0.0

        finding_delta = recent[-1].unique_findings - recent[0].unique_findings
        return (finding_delta / time_span) * 60.0

    def _compute_novelty(self) -> float:
        """Compute ratio of unique to total findings."""
        if not self._snapshots:
            return 1.0

        latest = self._snapshots[-1]
        if latest.total_findings == 0:
            return 1.0

        return latest.unique_findings / latest.total_findings

    def _detect_loops(self) -> tuple[bool, str]:
        """Detect repeated action sequences."""
        if len(self._actions) < self._loop_window:
            return False, ""

        recent = [a.signature for a in list(self._actions)[-self._loop_window:]]

        # Check for repeated subsequences
        for pattern_len in range(2, min(6, len(recent) // 2)):
            for start in range(len(recent) - pattern_len * 2 + 1):
                pattern = recent[start:start + pattern_len]
                repeat_start = start + pattern_len
                if recent[repeat_start:repeat_start + pattern_len] == pattern:
                    return True, " → ".join(pattern[:3])

        return False, ""

    def _determine_state(self, report: ConvergenceReport) -> ConvergenceState:
        """Determine convergence state from metrics."""
        if report.loop_detected:
            return ConvergenceState.LOOPING

        if report.stagnation_steps >= self._stagnation_threshold:
            return ConvergenceState.CONVERGED

        if report.stagnation_steps >= self._stagnation_threshold // 2:
            return ConvergenceState.STAGNATING

        if report.novelty_ratio < self._min_novelty:
            return ConvergenceState.SLOWING

        if report.finding_rate < 0.5 and len(self._snapshots) > 5:
            return ConvergenceState.SLOWING

        return ConvergenceState.PROGRESSING

    def _generate_recommendation(self, report: ConvergenceReport) -> str:
        """Generate recommendation based on state."""
        recommendations = {
            ConvergenceState.PROGRESSING: "Continue current approach",
            ConvergenceState.SLOWING: "Consider changing strategy or scanning deeper",
            ConvergenceState.STAGNATING: "Switch to different attack surface or tools",
            ConvergenceState.LOOPING: f"Break loop: stop repeating {report.loop_pattern}",
            ConvergenceState.CONVERGED: "Assessment complete — move to reporting",
        }
        return recommendations.get(report.state, "Continue")

    def _compute_confidence(self, report: ConvergenceReport) -> float:
        """Compute confidence in convergence assessment."""
        if len(self._snapshots) < 3:
            return 0.3

        confidence = 0.5

        # More data = higher confidence
        confidence += min(0.2, len(self._snapshots) * 0.02)

        # Clear signals boost confidence
        if report.loop_detected:
            confidence += 0.2
        if report.stagnation_steps > self._stagnation_threshold:
            confidence += 0.15

        return min(1.0, confidence)

    def build_convergence_prompt(self) -> str:
        """Build convergence context for LLM."""
        report = self.analyze()
        lines = ["## Convergence Monitor\n"]

        lines.append(f"State: {report.state.value}")
        lines.append(f"Finding rate: {report.finding_rate:.1f}/min")
        lines.append(f"Novelty: {report.novelty_ratio:.0%}")
        lines.append(f"Stagnation: {report.stagnation_steps} steps")

        if report.loop_detected:
            lines.append(f"LOOP DETECTED: {report.loop_pattern}")

        lines.append(f"\nRecommendation: {report.recommendation}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        report = self.analyze()
        return {
            "state": report.state.value,
            "snapshots": len(self._snapshots),
            "actions": len(self._actions),
            "unique_findings": len(self._finding_hashes),
            "stagnation_steps": self._steps_without_progress,
        }
