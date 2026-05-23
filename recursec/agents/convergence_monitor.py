"""Convergence monitor — detects stagnation and diminishing returns.

Implements:
1. Finding rate tracking over time windows
2. Stagnation detection (no new findings for N cycles)
3. Diminishing returns estimation
4. Coverage estimation
5. Budget efficiency tracking
6. Auto-termination recommendations
7. Phase transition triggers
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
    EXPLORING = "exploring"           # Actively finding new things
    PRODUCTIVE = "productive"         # Good finding rate
    SLOWING = "slowing"               # Finding rate decreasing
    STAGNANT = "stagnant"             # No new findings
    DIMINISHING = "diminishing"       # Returns not worth cost
    CONVERGED = "converged"           # Effectively done


class ConvergenceAction(str, Enum):
    CONTINUE = "continue"             # Keep going
    CHANGE_STRATEGY = "change_strategy"  # Try different approach
    CHANGE_TOOL = "change_tool"       # Try different tool
    DEEPER_SCAN = "deeper_scan"       # Go deeper on current area
    WIDER_SCAN = "wider_scan"         # Expand scope
    ESCALATE = "escalate"             # Move to next phase
    TERMINATE = "terminate"           # Stop this branch


@dataclass
class ConvergenceSample:
    """A data point for convergence tracking."""
    timestamp: float = field(default_factory=time.time)
    findings: int = 0
    tokens_used: int = 0
    tool_calls: int = 0
    unique_endpoints: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": self.findings,
            "tokens": self.tokens_used,
            "tools": self.tool_calls,
        }


@dataclass
class ConvergenceReport:
    """Report on convergence status."""
    state: ConvergenceState = ConvergenceState.EXPLORING
    recommended_action: ConvergenceAction = ConvergenceAction.CONTINUE
    finding_rate: float = 0.0          # Findings per minute
    token_efficiency: float = 0.0      # Findings per 1K tokens
    estimated_coverage: float = 0.0    # 0-1 estimated coverage
    stagnation_cycles: int = 0
    total_findings: int = 0
    total_tokens: int = 0
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "action": self.recommended_action.value,
            "finding_rate": round(self.finding_rate, 3),
            "efficiency": round(self.token_efficiency, 4),
            "coverage": round(self.estimated_coverage, 2),
            "stagnation": self.stagnation_cycles,
        }


class ConvergenceMonitor:
    """Monitors assessment convergence.

    Tracks finding rates, detects stagnation,
    estimates coverage, and recommends actions
    based on convergence analysis.
    """

    def __init__(
        self,
        window_size: int = 20,
        stagnation_threshold: int = 5,
    ) -> None:
        self._samples: deque[ConvergenceSample] = deque(maxlen=window_size)
        self._stagnation_threshold = stagnation_threshold
        self._total_findings = 0
        self._total_tokens = 0
        self._unique_findings: set[str] = set()
        self._start_time = time.time()
        self._log = logger.bind(component="convergence_monitor")

    def record_sample(
        self,
        findings: int = 0,
        tokens_used: int = 0,
        tool_calls: int = 0,
        unique_endpoints: int = 0,
        finding_ids: list[str] | None = None,
    ) -> None:
        """Record a convergence sample."""
        sample = ConvergenceSample(
            findings=findings,
            tokens_used=tokens_used,
            tool_calls=tool_calls,
            unique_endpoints=unique_endpoints,
        )
        self._samples.append(sample)
        self._total_findings += findings
        self._total_tokens += tokens_used

        if finding_ids:
            for fid in finding_ids:
                self._unique_findings.add(fid)

    def analyze(self) -> ConvergenceReport:
        """Analyze convergence state."""
        if len(self._samples) < 2:
            return ConvergenceReport(
                state=ConvergenceState.EXPLORING,
                recommended_action=ConvergenceAction.CONTINUE,
                total_findings=self._total_findings,
                total_tokens=self._total_tokens,
            )

        # Calculate finding rate
        elapsed_s = time.time() - self._start_time
        finding_rate = self._total_findings / max(1, elapsed_s / 60)

        # Token efficiency
        token_efficiency = 0.0
        if self._total_tokens > 0:
            token_efficiency = self._total_findings / (self._total_tokens / 1000)

        # Count stagnation (consecutive zero-finding samples)
        stagnation = 0
        for sample in reversed(self._samples):
            if sample.findings == 0:
                stagnation += 1
            else:
                break

        # Recent vs early finding rate
        half = len(self._samples) // 2
        early_samples = list(self._samples)[:max(1, half)]
        recent_samples = list(self._samples)[max(1, half):]

        early_findings = sum(s.findings for s in early_samples)
        recent_findings = sum(s.findings for s in recent_samples)

        # Determine state
        state = self._determine_state(
            stagnation=stagnation,
            early_findings=early_findings,
            recent_findings=recent_findings,
            finding_rate=finding_rate,
        )

        # Determine action
        action = self._determine_action(state, stagnation)

        # Estimate coverage (asymptotic)
        coverage = self._estimate_coverage()

        return ConvergenceReport(
            state=state,
            recommended_action=action,
            finding_rate=finding_rate,
            token_efficiency=token_efficiency,
            estimated_coverage=coverage,
            stagnation_cycles=stagnation,
            total_findings=self._total_findings,
            total_tokens=self._total_tokens,
            reasoning=f"State={state.value}, stagnation={stagnation}, "
                      f"early={early_findings}, recent={recent_findings}",
        )

    def _determine_state(
        self,
        stagnation: int,
        early_findings: int,
        recent_findings: int,
        finding_rate: float,
    ) -> ConvergenceState:
        """Determine convergence state."""
        if stagnation >= self._stagnation_threshold * 2:
            return ConvergenceState.CONVERGED

        if stagnation >= self._stagnation_threshold:
            return ConvergenceState.STAGNANT

        if early_findings > 0 and recent_findings == 0:
            return ConvergenceState.DIMINISHING

        if early_findings > recent_findings > 0:
            return ConvergenceState.SLOWING

        if recent_findings > 0:
            return ConvergenceState.PRODUCTIVE

        return ConvergenceState.EXPLORING

    def _determine_action(
        self,
        state: ConvergenceState,
        stagnation: int,
    ) -> ConvergenceAction:
        """Determine recommended action."""
        action_map = {
            ConvergenceState.EXPLORING: ConvergenceAction.CONTINUE,
            ConvergenceState.PRODUCTIVE: ConvergenceAction.CONTINUE,
            ConvergenceState.SLOWING: ConvergenceAction.CHANGE_STRATEGY,
            ConvergenceState.STAGNANT: ConvergenceAction.WIDER_SCAN,
            ConvergenceState.DIMINISHING: ConvergenceAction.ESCALATE,
            ConvergenceState.CONVERGED: ConvergenceAction.TERMINATE,
        }

        action = action_map.get(state, ConvergenceAction.CONTINUE)

        # Override for specific conditions
        if state == ConvergenceState.STAGNANT and stagnation >= self._stagnation_threshold + 2:
            action = ConvergenceAction.ESCALATE

        return action

    def _estimate_coverage(self) -> float:
        """Estimate coverage using asymptotic model.

        Uses the ratio of unique findings in recent
        samples vs total to estimate how much of the
        attack surface has been explored.
        """
        if not self._samples or self._total_findings == 0:
            return 0.0

        # Simple model: coverage approaches 1 as finding rate approaches 0
        recent_count = min(5, len(self._samples))
        recent = list(self._samples)[-recent_count:]
        recent_findings = sum(s.findings for s in recent)
        avg_recent = recent_findings / max(1, recent_count)

        # If average is 0, we're likely at high coverage
        if avg_recent == 0:
            return min(0.95, 0.5 + (len(self._samples) / 100))

        # Use decay model
        total_samples = len(self._samples)
        rate_ratio = avg_recent / max(0.01, self._total_findings / total_samples)
        coverage = 1.0 - rate_ratio
        return max(0.0, min(0.99, coverage))

    def should_terminate(self) -> bool:
        """Check if assessment should terminate."""
        report = self.analyze()
        return report.state == ConvergenceState.CONVERGED

    def build_convergence_prompt(self) -> str:
        """Build convergence context for LLM."""
        report = self.analyze()
        lines = [
            "## Convergence Status\n",
            f"State: {report.state.value}",
            f"Recommended: {report.recommended_action.value}",
            f"Finding rate: {report.finding_rate:.2f}/min",
            f"Efficiency: {report.token_efficiency:.4f} findings/K-tokens",
            f"Coverage: {report.estimated_coverage:.0%}",
            f"Stagnation: {report.stagnation_cycles} cycles",
            f"Total: {report.total_findings} findings, {report.total_tokens} tokens",
        ]
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        report = self.analyze()
        return {
            "state": report.state.value,
            "action": report.recommended_action.value,
            "finding_rate": round(report.finding_rate, 3),
            "coverage": round(report.estimated_coverage, 2),
            "total_findings": self._total_findings,
            "unique_findings": len(self._unique_findings),
            "samples": len(self._samples),
        }
