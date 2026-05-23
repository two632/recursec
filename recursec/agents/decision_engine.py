"""Autonomous decision engine — the core decision-making intelligence.

Makes strategic decisions by integrating:
1. Current state and context
2. Available actions and their expected outcomes
3. Historical performance data
4. Risk tolerance and constraints
5. Goal proximity assessment
6. Resource budget remaining
7. Time pressure
8. Adversarial considerations

Decision strategies:
- Greedy: Pick highest-value action
- UCB: Balance exploration/exploitation
- Risk-adjusted: Factor in risk tolerance
- Goal-directed: Maximize progress toward objective
- Adaptive: Switch strategy based on performance
- Monte Carlo: Simulate outcomes before deciding
"""

from __future__ import annotations

import json
import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class DecisionStrategy(str, Enum):
    GREEDY = "greedy"
    UCB = "ucb"
    RISK_ADJUSTED = "risk_adjusted"
    GOAL_DIRECTED = "goal_directed"
    ADAPTIVE = "adaptive"
    MONTE_CARLO = "monte_carlo"


class ActionType(str, Enum):
    SCAN = "scan"
    ENUMERATE = "enumerate"
    EXPLOIT = "exploit"
    VALIDATE = "validate"
    REPORT = "report"
    DELEGATE = "delegate"
    WAIT = "wait"
    RETRY = "retry"
    PIVOT = "pivot"
    ESCALATE = "escalate"
    STOP = "stop"


@dataclass
class Action:
    """A possible action the agent can take."""
    action_id: str = ""
    action_type: ActionType = ActionType.SCAN
    name: str = ""
    description: str = ""
    tool: str = ""
    target: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    expected_value: float = 0.5
    expected_risk: float = 0.3
    expected_time_s: float = 60.0
    expected_tokens: int = 2000
    prerequisites: list[str] = field(default_factory=list)
    # Tracking
    times_chosen: int = 0
    total_value: float = 0.0
    avg_value: float = 0.0

    @property
    def ucb_score(self) -> float:
        if self.times_chosen == 0:
            return float("inf")
        exploitation = self.avg_value
        exploration = math.sqrt(2 * math.log(max(1, self.times_chosen + 10)) / self.times_chosen)
        return exploitation + exploration

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.action_id,
            "type": self.action_type.value,
            "name": self.name[:100],
            "expected_value": round(self.expected_value, 2),
            "expected_risk": round(self.expected_risk, 2),
            "ucb": round(self.ucb_score, 3) if self.times_chosen > 0 else "inf",
        }


@dataclass
class DecisionContext:
    """Context for making a decision."""
    goal: str = ""
    target: str = ""
    phase: str = ""
    findings_count: int = 0
    steps_taken: int = 0
    steps_budget: int = 100
    tokens_used: int = 0
    tokens_budget: int = 50000
    time_elapsed_s: float = 0.0
    time_budget_s: float = 300.0
    risk_tolerance: float = 0.5    # 0=conservative, 1=aggressive
    recent_successes: int = 0
    recent_failures: int = 0
    coverage_areas: list[str] = field(default_factory=list)
    uncovered_areas: list[str] = field(default_factory=list)

    @property
    def budget_remaining(self) -> float:
        """Fraction of budget remaining (0-1)."""
        step_ratio = 1 - (self.steps_taken / max(1, self.steps_budget))
        token_ratio = 1 - (self.tokens_used / max(1, self.tokens_budget))
        time_ratio = 1 - (self.time_elapsed_s / max(1, self.time_budget_s))
        return min(step_ratio, token_ratio, time_ratio)

    @property
    def urgency(self) -> float:
        """How urgent the next action is (0=relaxed, 1=urgent)."""
        return 1.0 - self.budget_remaining


@dataclass
class Decision:
    """A decision made by the engine."""
    decision_id: str = ""
    selected_action: Action | None = None
    strategy_used: DecisionStrategy = DecisionStrategy.GREEDY
    confidence: float = 0.5
    reasoning: str = ""
    alternatives_considered: int = 0
    decision_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.decision_id,
            "action": self.selected_action.to_dict() if self.selected_action else None,
            "strategy": self.strategy_used.value,
            "confidence": round(self.confidence, 2),
            "reasoning": self.reasoning[:200],
            "alternatives": self.alternatives_considered,
            "time_ms": round(self.decision_time_ms, 1),
        }


DECISION_PROMPT = """You are an autonomous security agent making strategic decisions.

Current state:
- Goal: {goal}
- Target: {target}
- Phase: {phase}
- Findings so far: {findings}
- Steps: {steps_taken}/{steps_budget}
- Budget remaining: {budget_pct}%
- Recent performance: {successes} successes, {failures} failures
- Covered: {covered}
- Uncovered: {uncovered}

Available actions:
{actions_text}

Choose the best action. Consider:
1. What will make the most progress toward the goal?
2. What areas haven't been tested yet?
3. How much budget remains?
4. Should we exploit what we found or keep discovering?

Respond as JSON:
{{
  "selected_action": "action_id",
  "reasoning": "why this action",
  "confidence": 0.X,
  "should_stop": false
}}"""


class DecisionEngine:
    """Autonomous decision-making engine.

    Integrates context, history, and strategy to select
    the best action at each step.
    """

    def __init__(
        self,
        model_router: ModelRouter | None = None,
        default_strategy: DecisionStrategy = DecisionStrategy.ADAPTIVE,
    ) -> None:
        self._router = model_router
        self._default_strategy = default_strategy
        self._decisions: list[Decision] = []
        self._decision_counter = 0
        self._strategy_performance: dict[str, list[float]] = defaultdict(list)
        self._log = logger.bind(component="decision_engine")

    async def decide(
        self,
        context: DecisionContext,
        available_actions: list[Action],
        strategy: DecisionStrategy | None = None,
    ) -> Decision:
        """Make a decision given context and available actions."""
        start = time.time()
        self._decision_counter += 1

        strategy = strategy or self._select_strategy(context)

        if not available_actions:
            return Decision(
                decision_id=f"dec-{self._decision_counter}",
                strategy_used=strategy,
                reasoning="No actions available",
            )

        # Filter actions by prerequisites
        valid_actions = [
            a for a in available_actions
            if not a.prerequisites or all(p in context.coverage_areas for p in a.prerequisites)
        ]

        if not valid_actions:
            valid_actions = available_actions

        # Select action based on strategy
        if strategy == DecisionStrategy.GREEDY:
            selected = self._greedy_select(valid_actions, context)
        elif strategy == DecisionStrategy.UCB:
            selected = self._ucb_select(valid_actions)
        elif strategy == DecisionStrategy.RISK_ADJUSTED:
            selected = self._risk_adjusted_select(valid_actions, context)
        elif strategy == DecisionStrategy.GOAL_DIRECTED:
            selected = await self._goal_directed_select(valid_actions, context)
        elif strategy == DecisionStrategy.MONTE_CARLO:
            selected = self._monte_carlo_select(valid_actions, context)
        elif strategy == DecisionStrategy.ADAPTIVE:
            selected = await self._adaptive_select(valid_actions, context)
        else:
            selected = self._greedy_select(valid_actions, context)

        decision = Decision(
            decision_id=f"dec-{self._decision_counter}",
            selected_action=selected,
            strategy_used=strategy,
            confidence=selected.expected_value if selected else 0.0,
            reasoning=f"Selected by {strategy.value} strategy",
            alternatives_considered=len(valid_actions),
            decision_time_ms=(time.time() - start) * 1000,
        )

        self._decisions.append(decision)
        return decision

    def record_outcome(self, decision_id: str, value: float) -> None:
        """Record the outcome of a decision for learning."""
        for decision in self._decisions:
            if decision.decision_id == decision_id and decision.selected_action:
                action = decision.selected_action
                action.times_chosen += 1
                action.total_value += value
                action.avg_value = action.total_value / action.times_chosen

                self._strategy_performance[decision.strategy_used.value].append(value)
                break

    # ── Strategy Implementations ─────────────────────────

    def _greedy_select(self, actions: list[Action], context: DecisionContext) -> Action:
        """Select the action with highest expected value."""
        return max(actions, key=lambda a: a.expected_value)

    def _ucb_select(self, actions: list[Action]) -> Action:
        """Select using upper confidence bound."""
        return max(actions, key=lambda a: a.ucb_score)

    def _risk_adjusted_select(
        self,
        actions: list[Action],
        context: DecisionContext,
    ) -> Action:
        """Select with risk tolerance adjustment."""
        def risk_adjusted_value(action: Action) -> float:
            reward = action.expected_value
            risk = action.expected_risk
            tolerance = context.risk_tolerance
            return reward - risk * (1 - tolerance)

        return max(actions, key=risk_adjusted_value)

    async def _goal_directed_select(
        self,
        actions: list[Action],
        context: DecisionContext,
    ) -> Action:
        """Select using LLM reasoning about goal progress."""
        if not self._router:
            return self._greedy_select(actions, context)

        actions_text = "\n".join(
            f"- [{a.action_id}] {a.action_type.value}: {a.name} "
            f"(value: {a.expected_value:.1f}, risk: {a.expected_risk:.1f}, "
            f"time: {a.expected_time_s:.0f}s)"
            for a in actions[:10]
        )

        prompt = DECISION_PROMPT.format(
            goal=context.goal[:200],
            target=context.target,
            phase=context.phase,
            findings=context.findings_count,
            steps_taken=context.steps_taken,
            steps_budget=context.steps_budget,
            budget_pct=round(context.budget_remaining * 100),
            successes=context.recent_successes,
            failures=context.recent_failures,
            covered=", ".join(context.coverage_areas[:5]) or "None",
            uncovered=", ".join(context.uncovered_areas[:5]) or "Unknown",
            actions_text=actions_text,
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="planning",
            temperature=0.2,
            max_tokens=256,
        )

        data = self._parse_json(response)
        selected_id = data.get("selected_action", "")

        for action in actions:
            if action.action_id == selected_id:
                return action

        return self._greedy_select(actions, context)

    def _monte_carlo_select(
        self,
        actions: list[Action],
        context: DecisionContext,
        simulations: int = 100,
    ) -> Action:
        """Select using Monte Carlo simulation."""
        scores: dict[str, float] = defaultdict(float)

        for action in actions:
            for _ in range(simulations):
                # Simulate outcome
                success_prob = action.expected_value * (1 - action.expected_risk * 0.5)
                outcome = 1.0 if random.random() < success_prob else 0.0

                # Adjust for budget
                time_cost = action.expected_time_s / max(1, context.time_budget_s)
                if context.budget_remaining - time_cost < 0:
                    outcome *= 0.5  # Penalize going over budget

                scores[action.action_id] += outcome

        # Normalize
        for aid in scores:
            scores[aid] /= simulations

        best_id = max(scores, key=scores.get)
        for action in actions:
            if action.action_id == best_id:
                return action

        return actions[0]

    async def _adaptive_select(
        self,
        actions: list[Action],
        context: DecisionContext,
    ) -> Action:
        """Adaptively switch between strategies based on performance."""
        # Pick strategy based on context
        if context.budget_remaining < 0.2:
            # Low budget: be greedy
            return self._greedy_select(actions, context)
        elif context.recent_failures > context.recent_successes:
            # Failing: try UCB for exploration
            return self._ucb_select(actions)
        elif context.urgency > 0.7:
            # Urgent: risk-adjusted
            return self._risk_adjusted_select(actions, context)
        elif self._router:
            # Normal: use LLM reasoning
            return await self._goal_directed_select(actions, context)
        else:
            return self._ucb_select(actions)

    def _select_strategy(self, context: DecisionContext) -> DecisionStrategy:
        """Select the best strategy based on current context."""
        if self._default_strategy != DecisionStrategy.ADAPTIVE:
            return self._default_strategy

        if context.budget_remaining < 0.2:
            return DecisionStrategy.GREEDY
        elif context.recent_failures > 3:
            return DecisionStrategy.UCB
        elif self._router:
            return DecisionStrategy.GOAL_DIRECTED
        else:
            return DecisionStrategy.UCB

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}

    def get_stats(self) -> dict[str, Any]:
        by_strategy: dict[str, int] = defaultdict(int)
        by_action: dict[str, int] = defaultdict(int)
        for d in self._decisions:
            by_strategy[d.strategy_used.value] += 1
            if d.selected_action:
                by_action[d.selected_action.action_type.value] += 1
        return {
            "total_decisions": len(self._decisions),
            "by_strategy": dict(by_strategy),
            "by_action": dict(by_action),
        }
