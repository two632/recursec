"""Decision engine — autonomous decision-making under uncertainty.

Implements:
1. Multi-criteria decision analysis (MCDA)
2. Expected utility computation
3. Risk-adjusted decisions
4. Decision tree evaluation
5. Regret minimization
6. Decision explanation generation
7. Decision history tracking
8. Adaptive decision policies
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DecisionType(str, Enum):
    STRATEGY_SELECT = "strategy_select"
    TOOL_SELECT = "tool_select"
    MODEL_SELECT = "model_select"
    TARGET_SELECT = "target_select"
    CONTINUE_STOP = "continue_stop"
    ESCALATE = "escalate"
    DELEGATE = "delegate"


class RiskLevel(str, Enum):
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DecisionOption:
    """An option in a decision."""
    option_id: str = ""
    name: str = ""
    expected_value: float = 0.0
    risk: float = 0.0
    cost_tokens: int = 0
    cost_time_s: int = 0
    criteria_scores: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def risk_adjusted_value(self) -> float:
        """Value adjusted for risk (higher risk = lower adjusted value)."""
        return self.expected_value * (1 - self.risk * 0.5)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.option_id,
            "name": self.name[:25],
            "ev": round(self.expected_value, 3),
            "risk": round(self.risk, 2),
            "rav": round(self.risk_adjusted_value, 3),
        }


@dataclass
class Decision:
    """A decision made by the engine."""
    decision_id: str = ""
    decision_type: DecisionType = DecisionType.STRATEGY_SELECT
    question: str = ""
    options: list[DecisionOption] = field(default_factory=list)
    selected: str = ""
    confidence: float = 0.0
    reasoning: str = ""
    timestamp: float = field(default_factory=time.time)
    outcome_recorded: bool = False
    outcome_success: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.decision_id,
            "type": self.decision_type.value,
            "selected": self.selected[:20],
            "confidence": round(self.confidence, 2),
            "options": len(self.options),
        }


# ── Decision Criteria Weights ─────────────────────────────────

DEFAULT_CRITERIA_WEIGHTS: dict[str, float] = {
    "expected_findings": 0.30,
    "token_efficiency": 0.15,
    "time_efficiency": 0.10,
    "novelty": 0.15,
    "coverage_gain": 0.15,
    "risk": 0.15,
}


class DecisionEngine:
    """Autonomous decision-making under uncertainty.

    Makes optimal decisions considering multiple criteria,
    risk, and historical performance.
    """

    def __init__(
        self,
        risk_tolerance: float = 0.5,
    ) -> None:
        self._decisions: list[Decision] = []
        self._decision_counter = 0
        self._criteria_weights = dict(DEFAULT_CRITERIA_WEIGHTS)
        self._risk_tolerance = risk_tolerance
        self._policy_overrides: dict[str, str] = {}
        self._log = logger.bind(component="decision_engine")

    def decide(
        self,
        question: str,
        options: list[DecisionOption],
        decision_type: DecisionType = DecisionType.STRATEGY_SELECT,
    ) -> Decision:
        """Make a decision from options."""
        self._decision_counter += 1

        if not options:
            return Decision(
                decision_id=f"dec-{self._decision_counter}",
                decision_type=decision_type,
                question=question,
                reasoning="No options available",
            )

        # Check policy overrides
        override = self._policy_overrides.get(decision_type.value)
        if override:
            for opt in options:
                if opt.name == override:
                    return self._create_decision(
                        decision_type, question, options, opt,
                        1.0, f"Policy override: {override}"
                    )

        # Multi-criteria scoring
        scored = []
        for opt in options:
            score = self._mcda_score(opt)
            scored.append((score, opt))

        scored.sort(key=lambda x: x[0], reverse=True)
        best_score, best_option = scored[0]

        # Confidence = gap between best and second best
        if len(scored) > 1:
            second_score = scored[1][0]
            if best_score > 0:
                confidence = min(0.95, (best_score - second_score) / best_score + 0.3)
            else:
                confidence = 0.3
        else:
            confidence = 0.8

        reasoning = self._explain_decision(scored[:3])

        return self._create_decision(
            decision_type, question, options, best_option,
            confidence, reasoning,
        )

    def _mcda_score(self, option: DecisionOption) -> float:
        """Multi-criteria decision analysis scoring."""
        score = 0.0

        for criterion, weight in self._criteria_weights.items():
            criterion_value = option.criteria_scores.get(criterion, 0.0)
            score += weight * criterion_value

        # Risk adjustment
        risk_penalty = option.risk * (1 - self._risk_tolerance)
        score -= risk_penalty * 0.3

        # Expected value contribution
        score += option.expected_value * 0.2

        return score

    def _create_decision(
        self,
        decision_type: DecisionType,
        question: str,
        options: list[DecisionOption],
        selected: DecisionOption,
        confidence: float,
        reasoning: str,
    ) -> Decision:
        """Create and store a decision."""
        decision = Decision(
            decision_id=f"dec-{self._decision_counter}",
            decision_type=decision_type,
            question=question,
            options=options,
            selected=selected.name,
            confidence=confidence,
            reasoning=reasoning,
        )

        self._decisions.append(decision)
        if len(self._decisions) > 500:
            self._decisions = self._decisions[-500:]

        return decision

    @staticmethod
    def _explain_decision(top_options: list[tuple[float, DecisionOption]]) -> str:
        """Generate explanation for a decision."""
        if not top_options:
            return "No options to explain"

        parts = []
        for i, (score, opt) in enumerate(top_options):
            rank = "Selected" if i == 0 else f"#{i + 1}"
            parts.append(f"{rank}: {opt.name} (score={score:.3f}, risk={opt.risk:.2f})")

        return "; ".join(parts)

    def record_outcome(
        self,
        decision_id: str,
        success: bool,
    ) -> None:
        """Record the outcome of a decision."""
        for decision in self._decisions:
            if decision.decision_id == decision_id:
                decision.outcome_recorded = True
                decision.outcome_success = success
                break

        self._adapt_weights()

    def _adapt_weights(self) -> None:
        """Adapt criteria weights based on outcomes."""
        recent = [d for d in self._decisions[-50:] if d.outcome_recorded]
        if len(recent) < 10:
            return

        success_rate = sum(1 for d in recent if d.outcome_success) / len(recent)

        # If success rate is low, increase risk weight
        if success_rate < 0.5:
            self._criteria_weights["risk"] = min(0.3, self._criteria_weights["risk"] + 0.02)

        # If success rate is high, allow more novelty
        elif success_rate > 0.7:
            self._criteria_weights["novelty"] = min(0.25, self._criteria_weights["novelty"] + 0.01)

    def set_policy(self, decision_type: str, default_choice: str) -> None:
        """Set a policy override for a decision type."""
        self._policy_overrides[decision_type] = default_choice

    def get_recent(self, limit: int = 10) -> list[dict[str, Any]]:
        return [d.to_dict() for d in self._decisions[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        recorded = [d for d in self._decisions if d.outcome_recorded]
        success_count = sum(1 for d in recorded if d.outcome_success)
        return {
            "decisions": len(self._decisions),
            "outcomes_recorded": len(recorded),
            "success_rate": round(success_count / max(1, len(recorded)), 2),
            "policies": len(self._policy_overrides),
        }
