"""Convergence monitor — detects assessment stagnation and plateau.

Implements:
1. Finding rate tracking over time
2. Diminishing returns detection
3. Coverage estimation
4. Strategy exhaustion detection
5. Automatic phase transition triggers
6. Time-based stagnation alerts
7. Cost-effectiveness tracking
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ConvergenceStatus(str, Enum):
    ACCELERATING = "accelerating"    # Finding rate increasing
    STEADY = "steady"                # Stable finding rate
    DECELERATING = "decelerating"    # Finding rate decreasing
    PLATEAU = "plateau"              # No new significant findings
    STAGNANT = "stagnant"            # Extended plateau


class ActionRecommendation(str, Enum):
    CONTINUE = "continue"
    SWITCH_PHASE = "switch_phase"
    DEEPEN = "deepen"                # Go deeper on current target
    BROADEN = "broaden"              # Expand scope
    ESCALATE = "escalate"            # Use more aggressive tools
    STOP = "stop"                    # Assessment complete


@dataclass
class ConvergenceSnapshot:
    """A point-in-time convergence measurement."""
    timestamp: float = field(default_factory=time.time)
    total_findings: int = 0
    new_findings_since_last: int = 0
    unique_categories: int = 0
    tokens_spent: int = 0
    tools_run: int = 0
    phase: str = ""
    status: ConvergenceStatus = ConvergenceStatus.STEADY

    @property
    def cost_per_finding(self) -> float:
        if self.total_findings == 0:
            return float("inf")
        return self.tokens_spent / self.total_findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "new": self.new_findings_since_last,
            "categories": self.unique_categories,
            "tokens": self.tokens_spent,
            "status": self.status.value,
        }


@dataclass
class StrategyTracker:
    """Tracks which strategies have been tried."""
    strategy_name: str = ""
    times_used: int = 0
    findings_produced: int = 0
    tokens_consumed: int = 0
    last_used_at: float = 0.0

    @property
    def effectiveness(self) -> float:
        if self.tokens_consumed == 0:
            return 0.0
        return self.findings_produced / (self.tokens_consumed / 1000)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy_name[:20],
            "used": self.times_used,
            "findings": self.findings_produced,
            "effectiveness": round(self.effectiveness, 2),
        }


# ── Convergence thresholds ───────────────────────────────────

CONVERGENCE_THRESHOLDS: dict[str, Any] = {
    "plateau_window": 5,            # Snapshots with no new findings
    "stagnation_window": 10,        # Extended plateau
    "deceleration_rate": 0.3,       # Finding rate drop threshold
    "min_findings_per_phase": 1,    # Minimum findings before phase change
    "cost_ceiling_multiplier": 5.0, # Max cost relative to avg
    "max_same_strategy": 3,         # Max uses of same strategy without findings
}

# ── Strategy definitions ─────────────────────────────────────

AVAILABLE_STRATEGIES: list[str] = [
    "passive_recon",
    "active_recon",
    "port_scanning",
    "service_enumeration",
    "web_scanning",
    "vuln_scanning",
    "manual_testing",
    "exploitation",
    "code_review",
    "config_review",
    "fuzz_testing",
    "auth_testing",
    "api_testing",
    "crypto_testing",
]


class ConvergenceMonitor:
    """Monitors assessment convergence.

    Detects when finding rate plateaus,
    strategies are exhausted, and recommends
    phase transitions or assessment completion.
    """

    def __init__(self) -> None:
        self._snapshots: deque[ConvergenceSnapshot] = deque(maxlen=100)
        self._strategies: dict[str, StrategyTracker] = {}
        self._last_total_findings = 0
        self._log = logger.bind(component="convergence_monitor")

        # Initialize strategy trackers
        for strategy in AVAILABLE_STRATEGIES:
            self._strategies[strategy] = StrategyTracker(strategy_name=strategy)

    def record_snapshot(
        self,
        total_findings: int,
        unique_categories: int,
        tokens_spent: int,
        tools_run: int,
        phase: str = "",
    ) -> ConvergenceSnapshot:
        """Record a convergence snapshot."""
        new_findings = total_findings - self._last_total_findings
        self._last_total_findings = total_findings

        snapshot = ConvergenceSnapshot(
            total_findings=total_findings,
            new_findings_since_last=new_findings,
            unique_categories=unique_categories,
            tokens_spent=tokens_spent,
            tools_run=tools_run,
            phase=phase,
        )

        # Determine status
        snapshot.status = self._evaluate_status(new_findings)
        self._snapshots.append(snapshot)

        return snapshot

    def _evaluate_status(self, new_findings: int) -> ConvergenceStatus:
        """Evaluate convergence status."""
        if len(self._snapshots) < 2:
            return ConvergenceStatus.STEADY

        recent = list(self._snapshots)[-5:]
        recent_new = [s.new_findings_since_last for s in recent]

        # Check for plateau
        plateau_window = CONVERGENCE_THRESHOLDS["plateau_window"]
        if len(recent) >= plateau_window:
            if all(n == 0 for n in recent_new[-plateau_window:]):
                stag_window = CONVERGENCE_THRESHOLDS["stagnation_window"]
                if len(self._snapshots) >= stag_window:
                    extended = list(self._snapshots)[-stag_window:]
                    if all(s.new_findings_since_last == 0 for s in extended):
                        return ConvergenceStatus.STAGNANT
                return ConvergenceStatus.PLATEAU

        # Check acceleration/deceleration
        if len(recent) >= 3:
            avg_old = sum(recent_new[:2]) / 2.0 if len(recent_new) >= 2 else 0
            avg_new = sum(recent_new[-2:]) / 2.0 if len(recent_new) >= 2 else 0

            if avg_new > avg_old * 1.2:
                return ConvergenceStatus.ACCELERATING
            if avg_old > 0 and avg_new < avg_old * CONVERGENCE_THRESHOLDS["deceleration_rate"]:
                return ConvergenceStatus.DECELERATING

        return ConvergenceStatus.STEADY

    def record_strategy_use(
        self,
        strategy_name: str,
        findings_produced: int = 0,
        tokens_consumed: int = 0,
    ) -> None:
        """Record use of a strategy."""
        tracker = self._strategies.get(strategy_name)
        if not tracker:
            tracker = StrategyTracker(strategy_name=strategy_name)
            self._strategies[strategy_name] = tracker

        tracker.times_used += 1
        tracker.findings_produced += findings_produced
        tracker.tokens_consumed += tokens_consumed
        tracker.last_used_at = time.time()

    def get_recommendation(self) -> ActionRecommendation:
        """Get recommended action based on convergence."""
        if not self._snapshots:
            return ActionRecommendation.CONTINUE

        latest = self._snapshots[-1]

        if latest.status == ConvergenceStatus.STAGNANT:
            # Check if we've tried everything
            unused = self._get_unused_strategies()
            if not unused:
                return ActionRecommendation.STOP
            return ActionRecommendation.BROADEN

        if latest.status == ConvergenceStatus.PLATEAU:
            # Try deeper or switch phase
            exhausted = self._get_exhausted_strategies()
            if len(exhausted) > len(self._strategies) * 0.7:
                return ActionRecommendation.SWITCH_PHASE
            return ActionRecommendation.DEEPEN

        if latest.status == ConvergenceStatus.DECELERATING:
            return ActionRecommendation.ESCALATE

        return ActionRecommendation.CONTINUE

    def get_next_strategy(self) -> str | None:
        """Recommend the next strategy to try."""
        # Prefer unused strategies
        unused = self._get_unused_strategies()
        if unused:
            return unused[0]

        # Then low-use, high-effectiveness strategies
        active = [
            s for s in self._strategies.values()
            if s.times_used < CONVERGENCE_THRESHOLDS["max_same_strategy"]
        ]
        if active:
            active.sort(key=lambda s: s.effectiveness, reverse=True)
            return active[0].strategy_name

        return None

    def _get_unused_strategies(self) -> list[str]:
        """Get strategies not yet used."""
        return [
            name for name, tracker in self._strategies.items()
            if tracker.times_used == 0
        ]

    def _get_exhausted_strategies(self) -> list[str]:
        """Get strategies that are exhausted (used max times without findings)."""
        return [
            name for name, tracker in self._strategies.items()
            if (
                tracker.times_used >= CONVERGENCE_THRESHOLDS["max_same_strategy"]
                and tracker.findings_produced == 0
            )
        ]

    def build_convergence_prompt(self) -> str:
        """Build convergence context for LLM."""
        lines = ["## Assessment Convergence\n"]

        if self._snapshots:
            latest = self._snapshots[-1]
            lines.append(f"Status: {latest.status.value}")
            lines.append(f"Total findings: {latest.total_findings}")
            lines.append(f"Tokens spent: {latest.tokens_spent}")
            lines.append(f"Cost per finding: {latest.cost_per_finding:.0f} tokens")
            lines.append("")

        # Strategy summary
        recommendation = self.get_recommendation()
        lines.append(f"Recommendation: {recommendation.value}")

        next_strategy = self.get_next_strategy()
        if next_strategy:
            lines.append(f"Suggested next: {next_strategy}")

        # Top strategies by effectiveness
        effective = sorted(
            [s for s in self._strategies.values() if s.times_used > 0],
            key=lambda s: s.effectiveness,
            reverse=True,
        )[:3]
        if effective:
            lines.append("\nMost effective strategies:")
            for s in effective:
                lines.append(f"  - {s.strategy_name}: {s.effectiveness:.2f} findings/K tokens")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "snapshots": len(self._snapshots),
            "strategies_used": sum(1 for s in self._strategies.values() if s.times_used > 0),
            "total_strategies": len(self._strategies),
            "current_status": self._snapshots[-1].status.value if self._snapshots else "none",
        }
