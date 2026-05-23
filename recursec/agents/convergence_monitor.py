"""Convergence monitor — detects when the agent should stop or change strategy.

Implements:
1. Finding rate monitoring (diminishing returns detection)
2. Token budget exhaustion prediction
3. Coverage estimation
4. Quality vs quantity tradeoff
5. Confidence saturation detection
6. Redundancy detection (same findings from different tools)
7. Time-based checkpointing
8. Adaptive stopping criteria
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ConvergenceSignal(str, Enum):
    CONTINUE = "continue"
    SLOW_DOWN = "slow_down"
    SWITCH_STRATEGY = "switch_strategy"
    ADVANCE_PHASE = "advance_phase"
    STOP = "stop"


class StopReason(str, Enum):
    BUDGET_EXHAUSTED = "budget_exhausted"
    MAX_CYCLES = "max_cycles"
    DIMINISHING_RETURNS = "diminishing_returns"
    FULL_COVERAGE = "full_coverage"
    CONFIDENCE_SATURATED = "confidence_saturated"
    TIME_LIMIT = "time_limit"
    USER_REQUESTED = "user_requested"


@dataclass
class ConvergenceMetric:
    """A metric tracked for convergence detection."""
    name: str = ""
    values: list[float] = field(default_factory=list)
    timestamps: list[float] = field(default_factory=list)
    trend: float = 0.0     # Positive = increasing, negative = decreasing

    @property
    def latest(self) -> float:
        return self.values[-1] if self.values else 0.0

    @property
    def average(self) -> float:
        if not self.values:
            return 0.0
        return sum(self.values) / len(self.values)

    def add(self, value: float) -> None:
        self.values.append(value)
        self.timestamps.append(time.time())
        self._update_trend()

    def _update_trend(self) -> None:
        """Calculate trend using simple linear regression on last N points."""
        n = min(10, len(self.values))
        if n < 2:
            self.trend = 0.0
            return

        recent = self.values[-n:]
        x_mean = (n - 1) / 2
        y_mean = sum(recent) / n

        numerator = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(recent))
        denominator = sum((i - x_mean) ** 2 for i in range(n))

        self.trend = numerator / denominator if denominator > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:20],
            "latest": round(self.latest, 3),
            "avg": round(self.average, 3),
            "trend": round(self.trend, 4),
            "points": len(self.values),
        }


@dataclass
class ConvergenceState:
    """Current convergence state."""
    signal: ConvergenceSignal = ConvergenceSignal.CONTINUE
    stop_reason: StopReason | None = None
    confidence: float = 0.0        # How confident we are in the signal
    finding_rate: float = 0.0      # Findings per cycle
    token_burn_rate: float = 0.0   # Tokens per cycle
    estimated_remaining_findings: int = 0
    estimated_remaining_tokens: int = 0
    coverage: float = 0.0          # 0-1

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal": self.signal.value,
            "stop_reason": self.stop_reason.value if self.stop_reason else None,
            "confidence": round(self.confidence, 2),
            "finding_rate": round(self.finding_rate, 3),
            "coverage": round(self.coverage, 2),
        }


@dataclass
class Checkpoint:
    """A time-based checkpoint of assessment state."""
    checkpoint_id: str = ""
    cycle_num: int = 0
    total_findings: int = 0
    unique_findings: int = 0
    tokens_used: int = 0
    strategies_tried: list[str] = field(default_factory=list)
    convergence_signal: ConvergenceSignal = ConvergenceSignal.CONTINUE
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.checkpoint_id,
            "cycle": self.cycle_num,
            "findings": self.total_findings,
            "unique": self.unique_findings,
            "tokens": self.tokens_used,
        }


class ConvergenceMonitor:
    """Monitors assessment convergence and signals when to stop or adapt.

    Tracks finding rates, token burn, coverage, and quality metrics
    to determine when the agent should stop, switch strategy, or
    advance to the next phase.
    """

    def __init__(
        self,
        token_budget: int = 500000,
        max_cycles: int = 100,
        time_limit_s: float = 3600.0,
        diminishing_returns_threshold: float = 0.1,
    ) -> None:
        self._token_budget = token_budget
        self._max_cycles = max_cycles
        self._time_limit_s = time_limit_s
        self._dr_threshold = diminishing_returns_threshold

        self._metrics: dict[str, ConvergenceMetric] = {
            "finding_rate": ConvergenceMetric(name="finding_rate"),
            "unique_finding_rate": ConvergenceMetric(name="unique_finding_rate"),
            "token_burn": ConvergenceMetric(name="token_burn"),
            "confidence": ConvergenceMetric(name="confidence"),
            "coverage": ConvergenceMetric(name="coverage"),
        }

        self._total_findings = 0
        self._unique_findings: set[str] = set()
        self._tokens_used = 0
        self._cycle_count = 0
        self._strategies_tried: set[str] = set()
        self._checkpoints: list[Checkpoint] = []
        self._checkpoint_counter = 0
        self._start_time = time.time()
        self._finding_hashes: set[str] = set()
        self._log = logger.bind(component="convergence_monitor")

    def record_cycle(
        self,
        findings: int = 0,
        unique_findings: int = 0,
        tokens_used: int = 0,
        confidence: float = 0.5,
        strategy: str = "",
        finding_ids: list[str] | None = None,
    ) -> ConvergenceState:
        """Record a cycle's results and assess convergence."""
        self._cycle_count += 1
        self._total_findings += findings
        self._tokens_used += tokens_used

        if strategy:
            self._strategies_tried.add(strategy)

        # Track unique findings
        if finding_ids:
            before = len(self._unique_findings)
            self._unique_findings.update(finding_ids)
            unique_findings = len(self._unique_findings) - before

        # Update metrics
        self._metrics["finding_rate"].add(float(findings))
        self._metrics["unique_finding_rate"].add(float(unique_findings))
        self._metrics["token_burn"].add(float(tokens_used))
        self._metrics["confidence"].add(confidence)

        # Estimate coverage
        coverage = self._estimate_coverage()
        self._metrics["coverage"].add(coverage)

        # Assess convergence
        return self._assess()

    def _assess(self) -> ConvergenceState:
        """Assess current convergence state."""
        state = ConvergenceState()

        # Finding rate
        fr = self._metrics["finding_rate"]
        state.finding_rate = fr.latest

        # Token burn rate
        tb = self._metrics["token_burn"]
        state.token_burn_rate = tb.average

        # Coverage
        state.coverage = self._metrics["coverage"].latest

        # Remaining budget
        state.estimated_remaining_tokens = self._token_budget - self._tokens_used

        # Check stop conditions
        stop_reason = self._check_stop_conditions()
        if stop_reason:
            state.signal = ConvergenceSignal.STOP
            state.stop_reason = stop_reason
            state.confidence = 0.9
            return state

        # Check diminishing returns
        if self._check_diminishing_returns():
            state.signal = ConvergenceSignal.SWITCH_STRATEGY
            state.confidence = 0.7
            return state

        # Check if coverage is high enough
        if state.coverage >= 0.85:
            state.signal = ConvergenceSignal.SLOW_DOWN
            state.confidence = 0.6
            return state

        # Default: continue
        state.signal = ConvergenceSignal.CONTINUE
        state.confidence = 0.5

        return state

    def _check_stop_conditions(self) -> StopReason | None:
        """Check hard stop conditions."""
        # Budget exhausted
        if self._tokens_used >= self._token_budget * 0.95:
            return StopReason.BUDGET_EXHAUSTED

        # Max cycles
        if self._cycle_count >= self._max_cycles:
            return StopReason.MAX_CYCLES

        # Time limit
        elapsed = time.time() - self._start_time
        if elapsed >= self._time_limit_s:
            return StopReason.TIME_LIMIT

        # Full coverage
        coverage = self._metrics["coverage"].latest
        if coverage >= 0.95 and self._cycle_count >= 10:
            return StopReason.FULL_COVERAGE

        # Confidence saturated (high confidence, not finding new things)
        conf = self._metrics["confidence"]
        ufr = self._metrics["unique_finding_rate"]
        if (conf.average >= 0.85 and ufr.trend <= 0 and
                self._cycle_count >= 15):
            return StopReason.CONFIDENCE_SATURATED

        return None

    def _check_diminishing_returns(self) -> bool:
        """Check if finding rate is showing diminishing returns."""
        fr = self._metrics["finding_rate"]

        if len(fr.values) < 5:
            return False

        # Check if finding rate trend is negative
        if fr.trend < -self._dr_threshold:
            return True

        # Check if last 3 cycles had zero findings
        recent = fr.values[-3:]
        if all(v == 0 for v in recent):
            return True

        return False

    def _estimate_coverage(self) -> float:
        """Estimate assessment coverage."""
        if self._cycle_count == 0:
            return 0.0

        # Simple model: coverage approaches 1.0 asymptotically
        # Based on unique finding rate decline
        base_coverage = min(0.5, self._cycle_count / max(1, self._max_cycles))

        # Bonus for strategies tried
        strategy_bonus = min(0.3, len(self._strategies_tried) * 0.05)

        # Bonus for findings
        finding_bonus = min(0.2, len(self._unique_findings) * 0.02)

        return min(1.0, base_coverage + strategy_bonus + finding_bonus)

    def create_checkpoint(self) -> Checkpoint:
        """Create a checkpoint of current state."""
        self._checkpoint_counter += 1
        cp = Checkpoint(
            checkpoint_id=f"cp-{self._checkpoint_counter}",
            cycle_num=self._cycle_count,
            total_findings=self._total_findings,
            unique_findings=len(self._unique_findings),
            tokens_used=self._tokens_used,
            strategies_tried=sorted(self._strategies_tried),
            convergence_signal=self._assess().signal,
        )
        self._checkpoints.append(cp)
        return cp

    def get_redundancy_ratio(self) -> float:
        """Get the ratio of redundant (duplicate) findings."""
        if self._total_findings == 0:
            return 0.0
        unique = len(self._unique_findings)
        return 1.0 - (unique / self._total_findings)

    def get_metric(self, name: str) -> ConvergenceMetric | None:
        return self._metrics.get(name)

    def get_stats(self) -> dict[str, Any]:
        elapsed = time.time() - self._start_time
        return {
            "cycles": self._cycle_count,
            "findings": self._total_findings,
            "unique_findings": len(self._unique_findings),
            "tokens": f"{self._tokens_used}/{self._token_budget}",
            "elapsed_s": round(elapsed, 1),
            "strategies_tried": len(self._strategies_tried),
            "checkpoints": len(self._checkpoints),
            "redundancy": round(self.get_redundancy_ratio(), 2),
            "metrics": {
                name: metric.to_dict()
                for name, metric in self._metrics.items()
            },
        }
