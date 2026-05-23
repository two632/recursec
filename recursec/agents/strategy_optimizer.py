"""Strategy optimizer — dynamically adjusts assessment strategy.

Implements:
1. Multi-armed bandit for strategy selection
2. Performance tracking per strategy
3. Dynamic switching based on convergence signals
4. Exploration/exploitation balance
5. Context-aware strategy recommendation
6. Strategy composition (combining strategies)
7. Regret minimization
8. Time-horizon aware selection

Strategies managed:
- Breadth-first: Wide coverage, shallow depth
- Depth-first: Deep testing of specific areas
- Risk-prioritized: Focus on highest risk areas
- Coverage-driven: Fill gaps in coverage
- Exploitation-focused: Maximize findings
- Adaptive: Switch based on performance
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AssessmentStrategy(str, Enum):
    BREADTH_FIRST = "breadth_first"
    DEPTH_FIRST = "depth_first"
    RISK_PRIORITIZED = "risk_prioritized"
    COVERAGE_DRIVEN = "coverage_driven"
    EXPLOITATION_FOCUSED = "exploitation_focused"
    ADAPTIVE = "adaptive"
    STEALTH = "stealth"


@dataclass
class StrategyArm:
    """A strategy 'arm' in the multi-armed bandit."""
    strategy: AssessmentStrategy = AssessmentStrategy.BREADTH_FIRST
    times_pulled: int = 0
    total_reward: float = 0.0
    avg_reward: float = 0.0
    last_reward: float = 0.0
    findings_generated: int = 0
    avg_finding_rate: float = 0.0  # Findings per minute
    best_for: list[str] = field(default_factory=list)

    @property
    def ucb_score(self) -> float:
        if self.times_pulled == 0:
            return float("inf")
        exploitation = self.avg_reward
        exploration = math.sqrt(2 * math.log(max(1, self.times_pulled + 10)) / self.times_pulled)
        return exploitation + exploration

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy.value,
            "pulls": self.times_pulled,
            "avg_reward": round(self.avg_reward, 3),
            "ucb": round(self.ucb_score, 3) if self.times_pulled > 0 else "inf",
            "findings": self.findings_generated,
        }


@dataclass
class StrategyContext:
    """Context for strategy selection."""
    target_type: str = ""
    current_phase: str = ""
    findings_so_far: int = 0
    coverage_pct: float = 0.0
    budget_remaining_pct: float = 1.0
    convergence_state: str = "starting"
    time_elapsed_s: float = 0.0
    recent_finding_rate: float = 0.0
    top_severity: str = ""


@dataclass
class StrategyRecommendation:
    """A strategy recommendation with reasoning."""
    strategy: AssessmentStrategy = AssessmentStrategy.ADAPTIVE
    confidence: float = 0.5
    reasoning: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    expected_improvement: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy.value,
            "confidence": round(self.confidence, 2),
            "reasoning": self.reasoning[:100],
            "params": self.parameters,
        }


class StrategyOptimizer:
    """Dynamic strategy optimization using multi-armed bandit.

    Learns which strategies work best in different contexts
    and recommends optimal strategies.
    """

    def __init__(
        self,
        exploration_rate: float = 0.3,
        initial_strategy: AssessmentStrategy = AssessmentStrategy.BREADTH_FIRST,
    ) -> None:
        self._exploration_rate = exploration_rate
        self._current_strategy = initial_strategy
        self._arms: dict[str, StrategyArm] = {}
        self._context_history: list[tuple[StrategyContext, AssessmentStrategy, float]] = []
        self._switch_count = 0
        self._log = logger.bind(component="strategy_optimizer")

        # Initialize arms
        for strategy in AssessmentStrategy:
            self._arms[strategy.value] = StrategyArm(strategy=strategy)

    def select_strategy(
        self,
        context: StrategyContext,
    ) -> StrategyRecommendation:
        """Select the best strategy for the current context."""
        # Context-based rules first
        rule_rec = self._rule_based_selection(context)
        if rule_rec.confidence > 0.8:
            self._current_strategy = rule_rec.strategy
            return rule_rec

        # Multi-armed bandit selection
        ucb_rec = self._ucb_selection(context)

        # Combine rule-based and UCB
        if rule_rec.confidence > ucb_rec.confidence:
            rec = rule_rec
        else:
            rec = ucb_rec

        if rec.strategy != self._current_strategy:
            self._switch_count += 1
            self._log.info(
                "strategy_switch",
                old=self._current_strategy.value,
                new=rec.strategy.value,
                reason=rec.reasoning[:50],
            )

        self._current_strategy = rec.strategy
        return rec

    def record_reward(
        self,
        strategy: AssessmentStrategy,
        reward: float,
        findings: int = 0,
        context: StrategyContext | None = None,
    ) -> None:
        """Record the reward from using a strategy."""
        arm = self._arms.get(strategy.value)
        if not arm:
            return

        arm.times_pulled += 1
        arm.total_reward += reward
        arm.avg_reward = arm.total_reward / arm.times_pulled
        arm.last_reward = reward
        arm.findings_generated += findings

        if context:
            self._context_history.append((context, strategy, reward))
            if len(self._context_history) > 500:
                self._context_history = self._context_history[-500:]

    # ── Strategy Selection ───────────────────────────────

    def _rule_based_selection(
        self,
        context: StrategyContext,
    ) -> StrategyRecommendation:
        """Rule-based strategy selection."""
        rec = StrategyRecommendation()

        # Stalled → switch to depth-first or different approach
        if context.convergence_state == "stalled":
            rec.strategy = AssessmentStrategy.DEPTH_FIRST
            rec.confidence = 0.85
            rec.reasoning = "Stalled — switching to depth-first for new findings"
            return rec

        # Low coverage → breadth-first
        if context.coverage_pct < 0.3:
            rec.strategy = AssessmentStrategy.BREADTH_FIRST
            rec.confidence = 0.8
            rec.reasoning = "Low coverage — broadening scope"
            return rec

        # Budget low → risk-prioritized
        if context.budget_remaining_pct < 0.2:
            rec.strategy = AssessmentStrategy.RISK_PRIORITIZED
            rec.confidence = 0.9
            rec.reasoning = "Low budget — focusing on highest risks"
            return rec

        # Critical findings → exploitation-focused
        if context.top_severity == "critical":
            rec.strategy = AssessmentStrategy.EXPLOITATION_FOCUSED
            rec.confidence = 0.75
            rec.reasoning = "Critical findings found — focusing on exploitation"
            return rec

        # Good finding rate → continue current
        if context.recent_finding_rate > 0.5:
            rec.strategy = self._current_strategy
            rec.confidence = 0.7
            rec.reasoning = "Good progress — continuing current strategy"
            return rec

        # Diverging → coverage-driven
        if context.convergence_state == "diverging":
            rec.strategy = AssessmentStrategy.COVERAGE_DRIVEN
            rec.confidence = 0.75
            rec.reasoning = "Diverging — switching to coverage-driven"
            return rec

        rec.confidence = 0.4
        return rec

    def _ucb_selection(
        self,
        context: StrategyContext,
    ) -> StrategyRecommendation:
        """UCB-based strategy selection."""
        # Find best arm by UCB score
        best_arm = max(
            self._arms.values(),
            key=lambda a: a.ucb_score,
        )

        return StrategyRecommendation(
            strategy=best_arm.strategy,
            confidence=0.6 if best_arm.times_pulled > 3 else 0.3,
            reasoning=f"UCB selection: {best_arm.strategy.value} (score: {best_arm.ucb_score:.2f})",
            expected_improvement=best_arm.avg_reward,
        )

    def get_strategy_parameters(
        self,
        strategy: AssessmentStrategy,
    ) -> dict[str, Any]:
        """Get recommended parameters for a strategy."""
        params: dict[str, dict[str, Any]] = {
            AssessmentStrategy.BREADTH_FIRST.value: {
                "scan_depth": "shallow",
                "tool_count": "many",
                "parallel_tasks": 5,
                "time_per_target": 30,
                "enumeration_depth": 1,
            },
            AssessmentStrategy.DEPTH_FIRST.value: {
                "scan_depth": "deep",
                "tool_count": "few",
                "parallel_tasks": 2,
                "time_per_target": 120,
                "enumeration_depth": 3,
            },
            AssessmentStrategy.RISK_PRIORITIZED.value: {
                "scan_depth": "medium",
                "focus": "critical_vulns",
                "parallel_tasks": 3,
                "skip_low_risk": True,
            },
            AssessmentStrategy.COVERAGE_DRIVEN.value: {
                "scan_depth": "medium",
                "focus": "uncovered_areas",
                "parallel_tasks": 4,
                "coverage_target": 0.8,
            },
            AssessmentStrategy.EXPLOITATION_FOCUSED.value: {
                "scan_depth": "deep",
                "focus": "exploitation",
                "parallel_tasks": 2,
                "validate_all": True,
            },
            AssessmentStrategy.STEALTH.value: {
                "scan_depth": "shallow",
                "tool_noise_max": 0.3,
                "parallel_tasks": 1,
                "rate_limit": True,
                "delay_between_s": 5,
            },
        }
        return params.get(strategy.value, {})

    def get_arms(self) -> list[dict[str, Any]]:
        return [arm.to_dict() for arm in self._arms.values()]

    def get_stats(self) -> dict[str, Any]:
        total_pulls = sum(a.times_pulled for a in self._arms.values())
        best = max(self._arms.values(), key=lambda a: a.avg_reward) if self._arms else None
        return {
            "current": self._current_strategy.value,
            "total_pulls": total_pulls,
            "switches": self._switch_count,
            "best_strategy": best.strategy.value if best else "",
            "best_reward": round(best.avg_reward, 3) if best else 0,
        }
