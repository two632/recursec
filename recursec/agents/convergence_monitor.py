"""Convergence monitor — stagnation detection and recovery.

Implements:
1. Finding rate tracking (findings per cycle)
2. Stagnation detection (no new findings)
3. Strategy diversity monitoring
4. Coverage tracking (% of attack surface tested)
5. Diminishing returns detection
6. Automatic strategy switching
7. Budget consumption tracking
8. Convergence criteria evaluation
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ConvergenceState(str, Enum):
    EXPLORING = "exploring"         # Active discovery
    PRODUCTIVE = "productive"       # Finding vulnerabilities
    PLATEAU = "plateau"             # Finding rate declining
    STAGNANT = "stagnant"           # No new findings for N cycles
    CONVERGED = "converged"         # Assessment is complete
    DIVERGING = "diverging"         # Too many strategies, no focus


@dataclass
class CycleMetrics:
    """Metrics for a single assessment cycle."""
    cycle: int = 0
    findings: int = 0
    new_findings: int = 0
    tools_used: int = 0
    tokens_used: int = 0
    duration_s: float = 0.0
    strategy: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cycle": self.cycle,
            "findings": self.findings,
            "new": self.new_findings,
            "tools": self.tools_used,
            "tokens": self.tokens_used,
        }


@dataclass
class ConvergenceReport:
    """Report on convergence status."""
    state: ConvergenceState = ConvergenceState.EXPLORING
    finding_rate: float = 0.0          # Findings per cycle (moving average)
    finding_rate_trend: float = 0.0    # Positive = increasing, negative = decreasing
    cycles_since_finding: int = 0
    total_findings: int = 0
    total_cycles: int = 0
    coverage_estimate: float = 0.0
    budget_consumed: float = 0.0
    recommendation: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "rate": round(self.finding_rate, 2),
            "trend": round(self.finding_rate_trend, 3),
            "stale_cycles": self.cycles_since_finding,
            "findings": self.total_findings,
            "cycles": self.total_cycles,
            "coverage": round(self.coverage_estimate, 2),
            "budget": round(self.budget_consumed, 2),
            "recommendation": self.recommendation[:40],
        }


class ConvergenceMonitor:
    """Monitors assessment convergence and detects stagnation.

    Tracks finding rate over time and determines when
    the assessment has reached diminishing returns or
    needs strategy changes.
    """

    def __init__(
        self,
        stagnation_threshold: int = 5,
        convergence_threshold: float = 0.05,
        window_size: int = 10,
        max_budget_tokens: int = 1000000,
    ) -> None:
        self._metrics: list[CycleMetrics] = []
        self._finding_hashes: set[str] = set()
        self._stagnation_threshold = stagnation_threshold
        self._convergence_threshold = convergence_threshold
        self._window_size = window_size
        self._max_budget_tokens = max_budget_tokens
        self._total_tokens = 0
        self._cycles_since_finding = 0
        self._strategies_tried: set[str] = set()
        self._coverage_regions: dict[str, bool] = {}
        self._log = logger.bind(component="convergence_monitor")

    def record_cycle(
        self,
        findings: int,
        new_findings: int,
        tools_used: int = 0,
        tokens_used: int = 0,
        duration_s: float = 0.0,
        strategy: str = "",
        finding_hashes: list[str] | None = None,
    ) -> ConvergenceReport:
        """Record a cycle and evaluate convergence."""
        cycle_num = len(self._metrics) + 1

        metric = CycleMetrics(
            cycle=cycle_num,
            findings=findings,
            new_findings=new_findings,
            tools_used=tools_used,
            tokens_used=tokens_used,
            duration_s=duration_s,
            strategy=strategy,
        )
        self._metrics.append(metric)

        self._total_tokens += tokens_used
        if strategy:
            self._strategies_tried.add(strategy)

        if finding_hashes:
            for h in finding_hashes:
                self._finding_hashes.add(h)

        # Update stagnation counter
        if new_findings > 0:
            self._cycles_since_finding = 0
        else:
            self._cycles_since_finding += 1

        return self.evaluate()

    def evaluate(self) -> ConvergenceReport:
        """Evaluate current convergence state."""
        report = ConvergenceReport()
        report.total_cycles = len(self._metrics)
        report.total_findings = sum(m.findings for m in self._metrics)
        report.cycles_since_finding = self._cycles_since_finding
        report.budget_consumed = self._total_tokens / max(1, self._max_budget_tokens)

        # Calculate finding rate (moving average)
        window = self._metrics[-self._window_size:]
        if window:
            report.finding_rate = sum(m.new_findings for m in window) / len(window)

        # Calculate trend
        if len(self._metrics) >= 4:
            first_half = self._metrics[-self._window_size:-self._window_size // 2] or self._metrics[:2]
            second_half = self._metrics[-self._window_size // 2:]
            rate_first = sum(m.new_findings for m in first_half) / max(1, len(first_half))
            rate_second = sum(m.new_findings for m in second_half) / max(1, len(second_half))
            report.finding_rate_trend = rate_second - rate_first

        # Coverage estimate
        report.coverage_estimate = self._estimate_coverage()

        # Determine state
        report.state = self._determine_state(report)

        # Generate recommendation
        report.recommendation = self._generate_recommendation(report)

        return report

    def _determine_state(self, report: ConvergenceReport) -> ConvergenceState:
        """Determine convergence state from metrics."""
        # Converged: high coverage + budget exhausted
        if report.budget_consumed >= 0.95:
            return ConvergenceState.CONVERGED

        # Stagnant: no findings for too long
        if report.cycles_since_finding >= self._stagnation_threshold:
            return ConvergenceState.STAGNANT

        # Plateau: finding rate declining significantly
        if report.finding_rate_trend < -self._convergence_threshold and report.total_cycles > 5:
            return ConvergenceState.PLATEAU

        # Diverging: too many strategies without focus
        if len(self._strategies_tried) > 10 and report.finding_rate < 0.1:
            return ConvergenceState.DIVERGING

        # Productive: positive finding rate
        if report.finding_rate > 0.3:
            return ConvergenceState.PRODUCTIVE

        return ConvergenceState.EXPLORING

    def _estimate_coverage(self) -> float:
        """Estimate attack surface coverage."""
        if not self._metrics:
            return 0.0

        total_cycles = len(self._metrics)
        strategies_used = len(self._strategies_tried)
        unique_findings = len(self._finding_hashes)

        # Heuristic: More cycles + more strategies + diminishing returns → higher coverage
        cycle_factor = 1 - math.exp(-total_cycles / 20)
        strategy_factor = min(1.0, strategies_used / 8)
        finding_factor = 1 - 1 / (1 + unique_findings * 0.1)

        # Weight-combine
        coverage = 0.4 * cycle_factor + 0.3 * strategy_factor + 0.3 * finding_factor
        return min(1.0, coverage)

    def _generate_recommendation(self, report: ConvergenceReport) -> str:
        """Generate actionable recommendation."""
        if report.state == ConvergenceState.CONVERGED:
            return "Assessment complete. Generate final report."

        if report.state == ConvergenceState.STAGNANT:
            return "Switch to untried strategy or increase exploitation depth."

        if report.state == ConvergenceState.PLATEAU:
            return "Finding rate declining. Try different attack vector or tool."

        if report.state == ConvergenceState.DIVERGING:
            return "Too many strategies. Focus on most promising findings."

        if report.state == ConvergenceState.PRODUCTIVE:
            return "Continue current approach. It is producing results."

        return "Continue exploration. Expand attack surface mapping."

    def mark_coverage(self, region: str, tested: bool = True) -> None:
        """Mark an attack surface region as tested."""
        self._coverage_regions[region] = tested

    def get_stats(self) -> dict[str, Any]:
        report = self.evaluate()
        return {
            "state": report.state.value,
            "cycles": report.total_cycles,
            "findings": report.total_findings,
            "rate": round(report.finding_rate, 2),
            "trend": round(report.finding_rate_trend, 3),
            "coverage": round(report.coverage_estimate, 2),
            "budget": round(report.budget_consumed, 2),
            "strategies_tried": len(self._strategies_tried),
            "recommendation": report.recommendation,
        }
